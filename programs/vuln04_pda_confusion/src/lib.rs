//! VULN 04 — PDA seed design flaw: ONE vault PDA shared by ALL pools.
//!
//! "Shared Vault Pools": anyone can create a pool. Deposits of every pool
//! flow into the same global token-account PDA derived as [b"vault"].
//! Per-pool accounting (`pool.total`) is maintained, but the withdrawal
//! limit is checked against the GLOBAL vault balance instead of the
//! caller's pool share — so a second pool created by the attacker can
//! withdraw first pool's deposits.
//!
//! PDA namespaces must be scoped per role: a global seed like [b"vault"]
//! makes every pool a co-owner of the same funds.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("EUHsG3fkkb4EohJBdy9HJbZEKS8UecKQej5uQk1S1hSr");

#[program]
pub mod vuln04_pda_confusion {
    use super::*;

    /// One-time setup of the global vault.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// Permissionless pool creation. Note: every pool stores the SAME
    /// global vault address.
    pub fn create_pool(ctx: Context<CreatePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.authority = ctx.accounts.authority.key();
        pool.total = 0;
        pool.bump = ctx.bumps.pool;
        pool.vault = ctx.accounts.vault.key();
        Ok(())
    }

    /// Honest deposit: signed by pool authority, tokens enter global vault.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.user_ata.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;
        ctx.accounts.pool.total = ctx.accounts.pool.total.checked_add(amount).unwrap();
        Ok(())
    }

    /// BUG: the limit is `vault.amount` (GLOBAL vault holding everyone's
    /// deposits) instead of `pool.total`. Any pool authority can sweep it.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pool = &ctx.accounts.pool;
        require!(pool.authority == ctx.accounts.authority.key(), PoolError::NotAuthority);
        require!(
            amount <= ctx.accounts.vault.amount, // <-- should be pool.total
            PoolError::InsufficientFunds
        );

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
        )?;
        Ok(())
    }
}

#[event]
pub struct Initialized {
    pub vault: Pubkey,
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

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
pub struct CreatePool<'info> {
    #[account(
        init,
        payer = authority,
        seeds = [b"pool", authority.key().as_ref()],
        bump,
        space = 8 + 32 + 8 + 1 + 32
    )]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"pool", authority.key().as_ref()], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut, constraint = user_ata.owner == authority.key(),
        constraint = user_ata.mint == vault.mint)]
    pub user_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // NOTE: the pool is derived from `authority` seeds, so the attacker can
    // only touch their own pool — but the vault is shared, which is the flaw.
    #[account(mut, seeds = [b"pool", authority.key().as_ref()], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub total: u64,
    pub bump: u8,
    pub vault: Pubkey,
}

#[error_code]
pub enum PoolError {
    #[msg("not pool authority")]
    NotAuthority,
    #[msg("insufficient funds")]
    InsufficientFunds,
}
