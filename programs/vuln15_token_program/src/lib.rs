//! VULN 15 — arbitrary "token program" → phantom deposit → SOL theft.
//!
//! "TokenGate": users deposit SPL tokens and later withdraw an equal amount
//! of SOL from the protocol vault (a bridge-style one-way gate).
//!
//! The BUG (two unchecked accounts in one instruction):
//!   * `token_program` is an `UncheckedAccount` — the deposit CPI is built
//!     with `spl_token::instruction::transfer(&token_program.key(), ...)`,
//!     so ANY program id is accepted as the token program;
//!   * `user_ata` is not validated either (no owner/mint/owner-program
//!     checks).
//!
//! The credited `amount` comes straight from the instruction argument and
//! the CPI result is never reconciled with balances. An attacker passes
//! THEIR OWN program (which pretends the SPL `Transfer` succeeded — opcode 3
//! is a no-op there) and gets a phantom credit without transferring anything,
//! then drains the protocol SOL vault.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("E3k5CK9repYC1Phw4mUMRQaNrcdhpYpGS35AmFBP4pHk");

#[program]
pub mod vuln15_token_program {
    use super::*;

    /// Create the SOL vault + token vault, fund the SOL side.
    pub fn initialize(ctx: Context<Initialize>, funding: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.treasury.to_account_info(),
                    to: ctx.accounts.sol_vault.to_account_info(),
                },
            ),
            funding,
        )?;
        emit!(Initialized {
            sol_vault: ctx.accounts.sol_vault.key()
        });
        Ok(())
    }

    /// Deposit tokens -> credited amount. BUG: token_program/user_ata are
    /// unchecked; the CPI may target ANY program and `amount` is trusted.
    pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
        require!(amount > 0, GateError::ZeroAmount);

        // Hand-built SPL `Transfer` (opcode 3) against WHATEVER program id
        // the caller supplied — the builder API would validate the program
        // id, raw bytes do not.
        let mut ix_data = Vec::with_capacity(9);
        ix_data.push(3u8);
        ix_data.extend_from_slice(&amount.to_le_bytes());
        let ix = anchor_lang::solana_program::instruction::Instruction::new_with_bytes(
            *ctx.accounts.token_program.key,
            &ix_data,
            vec![
                anchor_lang::solana_program::instruction::AccountMeta::new(
                    *ctx.accounts.user_ata.key,
                    false,
                ),
                anchor_lang::solana_program::instruction::AccountMeta::new(
                    ctx.accounts.vault_ata.key(),
                    false,
                ),
                anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                    *ctx.accounts.user.key,
                    true,
                ),
            ],
        );

        anchor_lang::solana_program::program::invoke(
            &ix,
            &[
                ctx.accounts.user_ata.to_account_info(),
                ctx.accounts.vault_ata.to_account_info(),
                ctx.accounts.user.to_account_info(),
            ],
        )?;

        // Credited unconditionally — the fake token program did nothing.
        let dep = &mut ctx.accounts.deposit;
        dep.owner = ctx.accounts.user.key();
        dep.amount = dep
            .amount
            .checked_add(amount)
            .ok_or(GateError::Overflow)?;
        Ok(())
    }

    /// Withdraw SOL backed by the credited token amount.
    pub fn withdraw_sol(ctx: Context<WithdrawSol>, amount: u64) -> Result<()> {
        let dep = &ctx.accounts.deposit;
        require!(dep.amount >= amount, GateError::NotEnoughDeposit);

        // sol_vault is program-owned — lamports move directly.
        let from = ctx.accounts.sol_vault.to_account_info();
        let to = ctx.accounts.user.to_account_info();
        let new_from = from
            .lamports()
            .checked_sub(amount)
            .ok_or(GateError::VaultEmpty)?;
        **from.lamports.borrow_mut() = new_from;
        let new_to = to
            .lamports()
            .checked_add(amount)
            .ok_or(GateError::Overflow)?;
        **to.lamports.borrow_mut() = new_to;

        let dep = &mut ctx.accounts.deposit;
        dep.amount = dep.amount.checked_sub(amount).unwrap();
        Ok(())
    }
}

#[event]
pub struct Initialized {
    pub sol_vault: Pubkey,
}

#[error_code]
pub enum GateError {
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("invalid token instruction")]
    InvalidTokenInstruction,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("not enough credited deposit")]
    NotEnoughDeposit,
    #[msg("SOL vault has no liquidity left")]
    VaultEmpty,
}

#[account]
pub struct Deposit {
    pub owner: Pubkey,
    pub amount: u64,
}

/// The SOL vault: an Anchor data account that also HOLDS the withdrawable
/// lamports (lamports on a data account are perfectly legal).
#[account]
pub struct SolVault {
    pub _reserved: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"sol_vault"], bump, space = 8 + 8)]
    pub sol_vault: Account<'info, SolVault>,
    #[account(
        init,
        payer = payer,
        seeds = [b"token_vault"],
        bump,
        token::mint = mint,
        token::authority = sol_vault
    )]
    pub vault_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    #[account(mut)]
    pub treasury: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct DepositTokens<'info> {
    #[account(init_if_needed, payer = user, seeds = [b"deposit", user.key().as_ref()], bump, space = 8 + 32 + 8)]
    pub deposit: Account<'info, Deposit>,
    /// CHECK: THE BUG #1 — should be `Program<'info, Token>`; the CPI below
    /// is built with whatever program id the caller supplies.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: THE BUG #2 — no owner/mint/owner-program validation at all;
    /// with the fake token program this account is never even read.
    #[account(mut)]
    pub user_ata: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [b"token_vault"],
        bump,
        token::mint = mint,
        token::authority = sol_vault
    )]
    pub vault_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    #[account(mut, seeds = [b"sol_vault"], bump)]
    pub sol_vault: Account<'info, SolVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSol<'info> {
    #[account(mut, seeds = [b"deposit", user.key().as_ref()], bump)]
    pub deposit: Account<'info, Deposit>,
    #[account(mut, seeds = [b"sol_vault"], bump)]
    pub sol_vault: Account<'info, SolVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
