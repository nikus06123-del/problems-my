//! VULN 02 — Account substitution / type confusion (missing mint & owner
//! constraints).
//!
//! "UnbackedCoin": a collateralized stablecoin. To mint 1 stable token you
//! are supposed to prove ownership of 1 unit of REAL collateral. The
//! `mint_stable` instruction reads the balance of the passed "collateral
//! account" and mints against it — but NEVER verifies:
//!   1. that the account's mint is the real collateral mint,
//!   2. that the account's owner is the caller,
//!   3. that the collateral ever reaches the protocol vault.
//!
//! The attacker mints a worthless token of their own (they are its mint
//! authority), holds 1,000,000 of it in their own token account, passes that
//! account as "collateral", mints 1,000,000 stablecoins, then redeems them
//! for the REAL collateral sitting in the protocol vault.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Burn, Mint, MintTo, Token, TokenAccount, Transfer};

declare_id!("1XeQ8irpogAJTxNP7MiAk5SgAi7UZkyi7RmTASxVhRY");

#[program]
pub mod vuln02_account_substitution {
    use super::*;

    /// One-time setup of the stablecoin state (called by the deployer).
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.stable_mint = ctx.accounts.stable_mint.key();
        state.collateral_mint = ctx.accounts.collateral_mint.key();
        state.bump = ctx.bumps.state;
        state.vault_bump = ctx.bumps.vault;
        Ok(())
    }

    /// Honest path: lock real collateral into the protocol vault.
    pub fn deposit_collateral(ctx: Context<DepositCollateral>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_collateral_ata.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// BUG: `collateral_ata` is a plain TokenAccount with ZERO constraints.
    /// Any token account with a big enough `amount` field "backs" the mint.
    pub fn mint_stable(ctx: Context<MintStable>, amount: u64) -> Result<()> {
        // BUG: reads `amount` from an attacker-chosen account.
        let backing = ctx.accounts.collateral_ata.amount;
        require!(amount <= backing, CoinError::InsufficientCollateral);

        let state_bump = ctx.accounts.state.bump;
        let seeds = &[b"state".as_ref(), &[state_bump]];
        token::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                MintTo {
                    mint: ctx.accounts.stable_mint.to_account_info(),
                    to: ctx.accounts.stable_to.to_account_info(),
                    authority: ctx.accounts.state.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )
    }

    /// Honest path: burn stablecoins, receive real collateral back.
    pub fn redeem(ctx: Context<Redeem>, amount: u64) -> Result<()> {
        token::burn(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.stable_mint.to_account_info(),
                    from: ctx.accounts.stable_from.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;
        let vault_bump = ctx.accounts.state.vault_bump;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.collateral_to.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[&[b"vault".as_ref(), &[vault_bump]]],
            ),
            amount,
        )
    }
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"state"], bump, space = 8 + 32 + 32 + 1 + 1)]
    pub state: Account<'info, CoinState>,
    #[account(init, payer = payer, seeds = [b"vault"], bump,
        token::mint = collateral_mint, token::authority = vault)]
    pub vault: Account<'info, TokenAccount>,
    pub collateral_mint: Account<'info, Mint>,
    #[account(
        init,
        payer = payer,
        mint::decimals = 6,
        mint::authority = state
    )]
    pub stable_mint: Account<'info, Mint>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct DepositCollateral<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        constraint = user_collateral_ata.owner == user.key(),
        constraint = user_collateral_ata.mint == state.collateral_mint
    )]
    pub user_collateral_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, CoinState>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MintStable<'info> {
    // BUG: no `constraint = collateral_ata.mint == state.collateral_mint`,
    // no `constraint = collateral_ata.owner == user.key()`.
    #[account(mut)]
    pub collateral_ata: Account<'info, TokenAccount>,
    // Destination is also unchecked, but the theft happens regardless.
    #[account(mut)]
    pub stable_to: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, CoinState>,
    #[account(mut, constraint = stable_mint.key() == state.stable_mint)]
    pub stable_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, constraint = stable_from.owner == user.key(),
        constraint = stable_from.mint == state.stable_mint)]
    pub stable_from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub collateral_to: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(seeds = [b"state"], bump)]
    pub state: Account<'info, CoinState>,
    #[account(mut)]
    pub stable_mint: Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct CoinState {
    pub stable_mint: Pubkey,
    pub collateral_mint: Pubkey,
    pub bump: u8,
    pub vault_bump: u8,
}

#[error_code]
pub enum CoinError {
    #[msg("insufficient collateral backing")]
    InsufficientCollateral,
}
