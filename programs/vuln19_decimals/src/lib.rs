//! VULN 19 — Mint decimals are never validated (unit confusion).
//!
//! "SOL-Backed Converter": users deposit an accepted asset and receive
//! internal credits; credits are later paid out in the payout mint (a
//! USDC-like 6-decimals token) at the fixed "1 unit of credit = 1 base unit"
//! rate. The credit conversion formula is
//!
//!     credits = amount * 10^(6 - deposit_mint.decimals)
//!
//! and `deposit_mint.decimals` is read from the mint account that the CALLER
//! passes in. THE BUG: the deposit mint is never constrained to the
//! whitelisted asset, so the attacker brings their own mint with 0 decimals
//! and the multiplier becomes 10^6: depositing 2 worthless units mints 2
//! million credits, which are then cashed out from the USDC vault.
//!
//! A classic unit-confusion audit finding: any value derived from
//! attacker-controlled account data must be range-checked or the account
//! itself must be pinned.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("2ujSuQ9sAjyaBij29XXh8UktiRmqq5eaddKRz3zfTNpF");

/// The ONLY asset the protocol is supposed to accept (a 6-decimals token).
/// The bug is that nothing in the code enforces this constant.
pub const EXPECTED_DEPOSIT_DECIMALS: u8 = 6;

#[program]
pub mod vuln19_decimals {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        // Pin the payout mint (deployer choice) for withdraw validation.
        ctx.accounts.usdc_vault.mint_pinned = ctx.accounts.usdc_mint.key();
        ctx.accounts.usdc_vault.amount = 0;
        Ok(())
    }

    /// Deposit the accepted asset; credits are minted by the formula above.
    ///
    /// BUG: `deposit_mint` is NOT checked against a whitelist and its
    /// decimals drive the credit multiplier.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, Err19::ZeroAmount);

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_ta.to_account_info(),
                    to: ctx.accounts.deposit_vault_ta.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;

        let dec = ctx.accounts.deposit_mint.decimals;
        // The ONLY range check present — and it is still insufficient: any
        // mint with 0..5 decimals passes and changes the credit multiplier.
        require!(dec <= EXPECTED_DEPOSIT_DECIMALS, Err19::DecimalsTooLarge);

        // Unit confusion: with a 0-decimals mint this is 10^6 per unit.
        let mult = 10u64.pow((EXPECTED_DEPOSIT_DECIMALS - dec) as u32);
        let credits = amount
            .checked_mul(mult)
            .ok_or(Err19::Overflow)?;

        let c = &mut ctx.accounts.credits;
        c.amount = c.amount.checked_add(credits).ok_or(Err19::Overflow)?;
        Ok(())
    }

    /// Cash out credits in the payout (USDC-like) mint.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let c = &mut ctx.accounts.credits;
        require!(c.amount >= amount, Err19::NotEnoughCredits);
        require!(
            ctx.accounts.usdc_mint.key() == ctx.accounts.usdc_vault.mint_pinned,
            Err19::WrongPayoutMint
        );

        let vault_seeds = [b"usdc_vault".as_ref(), &[ctx.bumps.usdc_vault]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.usdc_vault_ta.to_account_info(),
                    to: ctx.accounts.user_usdc_ta.to_account_info(),
                    authority: ctx.accounts.usdc_vault.to_account_info(),
                },
                &[&vault_seeds],
            ),
            amount,
        )?;

        c.amount -= amount;
        Ok(())
    }
}

#[error_code]
pub enum Err19 {
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("deposit mint has too many decimals")]
    DecimalsTooLarge,
    #[msg("not enough credits")]
    NotEnoughCredits,
    #[msg("payout mint mismatch")]
    WrongPayoutMint,
}

#[account]
pub struct UsdcVault {
    pub mint_pinned: Pubkey,
    pub amount: u64,
}

#[account]
pub struct Credits {
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The payout mint, pinned at genesis.
    pub usdc_mint: Account<'info, Mint>,
    #[account(init, payer = payer, seeds = [b"usdc_vault"], bump, space = 8 + 32 + 8)]
    pub usdc_vault: Account<'info, UsdcVault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// THE BUG: unconstrained deposit mint; decimals are read from here.
    pub deposit_mint: Account<'info, Mint>,
    #[account(mut)]
    pub deposit_vault_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(init_if_needed, payer = user, seeds = [b"credits", user.key().as_ref()], bump, space = 8 + 8)]
    pub credits: Account<'info, Credits>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub usdc_mint: Account<'info, Mint>,
    #[account(mut, seeds = [b"usdc_vault"], bump)]
    pub usdc_vault: Account<'info, UsdcVault>,
    /// Payout token account owned by the usdc_vault PDA.
    #[account(mut)]
    pub usdc_vault_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_usdc_ta: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"credits", user.key().as_ref()], bump)]
    pub credits: Account<'info, Credits>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
