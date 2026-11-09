//! VULN 18 — Token-2022 transfer fee treated as a full deposit.
//!
//! "Token Buy-Back": the protocol buys tokens back for SOL from a treasury
//! vault at a fixed rate (1 unit = 1 lamport for simplicity). The seller
//! transfers their tokens in and the program pays lamports for the NOMINAL
//! amount taken from the instruction — it never measures the actual balance
//! delta of the treasury token account.
//!
//! THE BUG: with a Token-2022 mint carrying the TransferFee extension, a
//! transfer of N units credits the destination with N * (1 - fee). The
//! program still pays for N. An attacker mints their own Token-2022 asset
//! with a 10% transfer fee, "sells" it to the protocol in a loop and every
//! round pumps ~fee% of the treasury SOL out: the vault receives fewer
//! tokens than it pays for, until it is completely drained.
//!
//! The fix is to whitelist the accepted mint AND account for the actual
//! vault balance delta (`before - after`), never the instruction amount.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};

declare_id!("GZe9eTjFeWcN1jZWxasTESn6BzqoGLeQxW5YQ4MiaPhx");

#[program]
pub mod vuln18_token2022 {
    use super::*;

    /// One-time setup: treasury SOL vault.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.vault.bought = 0;
        Ok(())
    }

    /// Fund the buy-back treasury with SOL (honest liquidity).
    pub fn fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Sell `amount` token units to the protocol for lamports (1:1 rate).
    ///
    /// BUG #1: `mint` is completely unconstrained — any Token-2022 (or even
    /// SPL Token) asset is accepted. BUG #2: the payout is computed from the
    /// instruction `amount`, not from the real token delta received by the
    /// treasury, so a TransferFee-configured mint steals the difference.
    pub fn sell(ctx: Context<Sell>, amount: u64) -> Result<()> {
        require!(amount > 0, Err18::ZeroAmount);

        // Tokens go into the treasury token account (owned by the vault PDA).
        // With a transfer-fee mint only `amount * (1 - fee)` arrives, but the
        // program pays for the full `amount` below.
        token_interface::transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                TransferChecked {
                    from: ctx.accounts.seller_ta.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.treasury_ta.to_account_info(),
                    authority: ctx.accounts.seller.to_account_info(),
                },
            ),
            amount,
            ctx.accounts.mint.decimals,
        )?;

        // Payout in SOL at the fixed 1:1 rate — based on the NOMINAL amount.
        let vault = ctx.accounts.vault.to_account_info();
        let to = ctx.accounts.seller.to_account_info();
        let new_vault = vault
            .lamports()
            .checked_sub(amount)
            .ok_or(Err18::InsufficientTreasury)?;
        **vault.lamports.borrow_mut() = new_vault;
        let new_to = to.lamports().checked_add(amount).ok_or(Err18::Overflow)?;

        **to.lamports.borrow_mut() = new_to;

        let v = &mut ctx.accounts.vault;
        v.bought = v.bought.checked_add(amount).ok_or(Err18::Overflow)?;
        Ok(())
    }
}

#[error_code]
pub enum Err18 {
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("treasury has insufficient lamports")]
    InsufficientTreasury,
}

#[account]
pub struct BuybackVault {
    pub bought: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"vault"], bump, space = 8 + 8)]
    pub vault: Account<'info, BuybackVault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, BuybackVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Sell<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, BuybackVault>,
    /// Token account of the treasury: owned by the vault PDA.
    #[account(mut)]
    pub treasury_ta: InterfaceAccount<'info, TokenAccount>,
    /// THE BUG #1: no constraint tying this mint to a whitelisted asset.
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(mut)]
    pub seller_ta: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub seller: Signer<'info>,
    /// THE BUG #2 lives in the handler: payout by nominal amount.
    /// Token program is passed through as an interface — Token-2022 allowed.
    pub token_program: Interface<'info, TokenInterface>,
    /// CHECK: vault PDA signs the treasury token account.
    #[account(seeds = [b"vault"], bump)]
    pub vault_authority: UncheckedAccount<'info>,
}
