//! VULN 12 — Share inflation (first depositor + donation + integer rounding).
//!
//! "ShareVault" is a classic proportional vault: deposits mint shares
//!
//!     shares = amount * total_shares / total_assets      (integer, floor)
//!
//! where `total_assets` is taken from the vault token account balance — so
//! ANYONE can inflate it by donating tokens directly to the vault, bypassing
//! the share accounting.
//!
//! Attack (ERC-4626 "inflation attack"):
//!   1. Attacker is the first depositor: deposit(1) -> 1 share, balance 1.
//!   2. Attacker DONATES 99_999 tokens straight to the vault: balance 100_000.
//!   3. Victim deposits 50_000 -> shares = 50_000 * 1 / 100_000 = 0 (floor).
//!      The victim's tokens are IN the vault, but the victim owns nothing.
//!   4. Attacker withdraws their 1 share -> takes the WHOLE vault balance.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("DuwSRMJec2MxdQzhoT9T9mC5kfkRRGu1pLSg3nNV9b1g");

#[program]
pub mod vuln12_inflation {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.total_shares = 0;
        Ok(())
    }

    /// BUG: `shares` is floored to 0 whenever the donate-inflated balance
    /// exceeds `amount * total_shares` — yet the tokens are still taken.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        let balance = ctx.accounts.vault_ata.amount;

        let shares = if vault.total_shares == 0 {
            amount
        } else {
            // Rounding DOWN against an inflated balance is the theft vector.
            amount * vault.total_shares / balance
        };

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.user_ata.to_account_info(),
                    to: ctx.accounts.vault_ata.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;

        let vault = &mut ctx.accounts.vault;
        vault.total_shares = vault
            .total_shares
            .checked_add(shares)
            .ok_or(InflationError::Overflow)?;
        let share = &mut ctx.accounts.user_share;
        share.amount = share
            .amount
            .checked_add(shares)
            .ok_or(InflationError::Overflow)?;
        Ok(())
    }

    /// Proportional withdrawal: shares * balance / total_shares.
    pub fn withdraw(ctx: Context<Withdraw>, shares: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        require!(vault.total_shares > 0, InflationError::NoShares);
        let share = &ctx.accounts.user_share;
        require!(share.amount >= shares, InflationError::NotEnoughShares);

        let balance = ctx.accounts.vault_ata.amount;
        let assets = shares * balance / vault.total_shares;
        require!(assets > 0, InflationError::ZeroAssets);

        let vault_bump = ctx.bumps.vault;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault_ata.to_account_info(),
                    to: ctx.accounts.destination_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[&[b"vault".as_ref(), &[vault_bump]]],
            ),
            assets,
        )?;

        let vault = &mut ctx.accounts.vault;
        vault.total_shares = vault.total_shares.checked_sub(shares).unwrap();
        let share = &mut ctx.accounts.user_share;
        share.amount = share.amount.checked_sub(shares).unwrap();
        Ok(())
    }
}

#[error_code]
pub enum InflationError {
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("vault has no shares")]
    NoShares,
    #[msg("not enough shares")]
    NotEnoughShares,
    #[msg("assets round down to zero")]
    ZeroAssets,
}

#[account]
pub struct Vault {
    pub total_shares: u64,
}

#[account]
pub struct UserShare {
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"vault"], bump, space = 8 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(
        init,
        payer = payer,
        seeds = [b"token_vault"],
        bump,
        token::mint = mint,
        token::authority = vault
    )]
    pub vault_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(init_if_needed, payer = user, seeds = [b"share", user.key().as_ref()], bump, space = 8 + 8)]
    pub user_share: Account<'info, UserShare>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        seeds = [b"token_vault"],
        bump,
        token::mint = mint,
        token::authority = vault
    )]
    pub vault_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    /// No constraint on how user_ata relates to the vault's mint beyond
    /// token program's own check — fine here, the bug is in the math.
    #[account(mut, constraint = user_ata.owner == user.key())]
    pub user_ata: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"share", user.key().as_ref()], bump)]
    pub user_share: Account<'info, UserShare>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    #[account(
        mut,
        seeds = [b"token_vault"],
        bump,
        token::mint = mint,
        token::authority = vault
    )]
    pub vault_ata: Account<'info, TokenAccount>,
    pub mint: Account<'info, anchor_spl::token::Mint>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
