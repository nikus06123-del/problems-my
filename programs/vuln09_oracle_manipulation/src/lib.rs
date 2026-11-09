//! VULN 09 — Price oracle not validated (no owner / freshness / bounds).
//!
//! "Oracle Believer" lending protocol: collateral is valued by multiplying
//! the user's collateral units by a "price" taken from an account the
//! CALLER passes. The instruction never verifies that:
//!   * the account is the protocol's oracle PDA (owner check),
//!   * the price is fresh (no slot/timestamp check),
//!   * the price is sane (no min/max sanity bounds).
//!
//! The attacker forges a plain account (owned by their own program) whose
//! first 8 bytes are a price large enough to make 1 collateral unit cover
//! the ENTIRE lending vault, then borrows everyone's liquidity.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("9hEAbWKYFmgjd3SBRsBU4yiyTiPEcaWqGM8ZUuKDcVW5");

#[program]
pub mod vuln09_oracle_manipulation {
    use super::*;

    /// One-time setup: protocol oracle + lending vault.
    /// Oracle layout: 8-byte anchor discriminator + [price: u64] = 16 bytes.
    pub fn initialize(ctx: Context<Initialize>, initial_price: u64) -> Result<()> {
        // NOTE: must go through the typed account — anchor's exit() rewrites
        // Account<T> from its cached copy, so raw buffer writes are lost.
        ctx.accounts.oracle.price = initial_price;

        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// Honest path: deposit collateral units.
    pub fn deposit_collateral(ctx: Context<DepositCollateral>, amount: u64) -> Result<()> {
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
        let pos = &mut ctx.accounts.position;
        pos.collateral = pos.collateral.checked_add(amount).unwrap();
        Ok(())
    }

    /// BUG: `oracle` is an UncheckedAccount; bytes [8..16] are trusted as
    /// the price. No owner check, no freshness, no bounds.
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let oracle_data = ctx.accounts.oracle.try_borrow_data()?;
        if oracle_data.len() < 16 {
            return Err(Fault::BadOracle.into());
        }
        let price = u64::from_le_bytes(oracle_data[8..16].try_into().unwrap());
        drop(oracle_data);

        let collateral = ctx.accounts.position.collateral;
        let value = collateral.saturating_mul(price); // collateral units * price
        require!(amount <= value, Fault::OverBorrow);

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
    #[account(init, payer = payer, seeds = [b"oracle"], bump, space = 8 + 8)]
    pub oracle: Account<'info, OracleFeed>,
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
pub struct DepositCollateral<'info> {
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"pos", user.key().as_ref()],
        bump,
        space = 8 + 8
    )]
    pub position: Account<'info, UserPosition>,
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
pub struct Borrow<'info> {
    #[account(mut, seeds = [b"pos", user.key().as_ref()], bump)]
    pub position: Account<'info, UserPosition>,
    #[account(mut)]
    pub user: Signer<'info>,
    // BUG: the price feed is whatever the caller passes.
    /// CHECK: vulnerable — must be the protocol oracle PDA with freshness.
    pub oracle: UncheckedAccount<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct OracleFeed {
    pub price: u64,
}

#[account]
pub struct UserPosition {
    pub collateral: u64,
}

#[error_code]
pub enum Fault {
    #[msg("oracle data invalid")]
    BadOracle,
    #[msg("borrow exceeds collateral value")]
    OverBorrow,
}
