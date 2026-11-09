//! VULN 06 — Integer underflow on the user balance (silent wrap).
//!
//! "Wrapping Bank": same shape as vuln01 but the access control on
//! `withdraw` is INTENTIONALLY correct here (only the balance owner can
//! withdraw). The theft comes from arithmetic:
//!
//!   * the per-user check is missing (only the GLOBAL vault balance is
//!     checked), and
//!   * `wrapping_sub` silently wraps the user balance around zero.
//!
//! The attacker has balance 0, asks for the whole vault — the wrap sets
//! their ledger to ~u64::MAX and they receive OTHER users' tokens.
//!
//! The workspace profile ships with `overflow-checks = false`, which is how
//! a lot of production code was configured; a plain `-` would behave exactly
//! the same. `wrapping_sub` is used here so the demo is deterministic under
//! any profile.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("EV2U5AjGiFhUPiNHFzZPYyn5E9HuNRdyfM92mShrqoEK");

#[program]
pub mod vuln06_overflow {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.user_ata.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;
        let bal = &mut ctx.accounts.user_balance;
        bal.amount = bal.amount.checked_add(amount).unwrap();
        Ok(())
    }

    /// Access control is fine here: the PDA is bound to the signer.
    /// BUG: the solvency check looks at the GLOBAL vault, and the balance
    /// update uses wrapping_sub -> silent underflow.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        // Checks GLOBAL vault liquidity instead of the user's balance.
        require!(amount <= ctx.accounts.vault.amount, BankError::InsufficientVaultLiquidity);

        let bal = &mut ctx.accounts.user_balance;
        // BUG: silently wraps when amount > bal.amount.
        bal.amount = bal.amount.wrapping_sub(amount);

        let vault_bump = ctx.bumps.vault;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[&[b"vault".as_ref(), &[vault_bump]]],
            ),
            amount,
        )
    }
}

#[event]
pub struct Initialized {
    pub vault: Pubkey,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        seeds = [b"vault"],
        bump,
        token::mint = mint,
        token::authority = vault
    )]
    pub vault: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"balance", user.key().as_ref()],
        bump,
        space = 8 + 8
    )]
    pub user_balance: Account<'info, UserBalance>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, constraint = user_ata.owner == user.key(),
        constraint = user_ata.mint == vault.mint)]
    pub user_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"balance", user.key().as_ref()], bump)]
    pub user_balance: Account<'info, UserBalance>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct UserBalance {
    pub amount: u64,
}

#[error_code]
pub enum BankError {
    #[msg("vault does not have enough liquidity")]
    InsufficientVaultLiquidity,
}
