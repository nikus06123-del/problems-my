//! VULN 07 — Account re-initialization (`init_if_needed` rebind attack).
//!
//! "Snipeable Savings": a savings account is a PDA derived from a
//! user-chosen TAG (like a username), NOT from the authority. Two bugs
//! compose:
//!
//!   1. `open_savings` uses `init_if_needed` — a closed account can be
//!      re-initialized from scratch;
//!   2. `user` is an unchecked account, so the new `authority` is whatever
//!      the caller passes.
//!
//! Flow: victim opens "tag" savings, uses it, closes it (their legit right),
//! and later deposits again. The attacker (a bot watching for closes) calls
//! `open_savings(tag, attacker)` in between — the empty account is
//! re-created with the ATTACKER as authority — and drains the fresh
//! deposits. The victim's deposits are irrecoverable: the address is the
//! same, the owner is not.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("7CkJ3L8hpHbE6mDRvXwU7MyDNpEMw5prj3Tsujt9hLDU");

#[program]
pub mod vuln07_reinit {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// BUG #2: `user` is not a Signer, so anyone "opens" an account for any
    /// pubkey. BUG #1: `init_if_needed` re-creates a closed account.
    pub fn open_savings(ctx: Context<OpenSavings>, tag: String) -> Result<()> {
        let savings = &mut ctx.accounts.savings;
        if savings.authority == Pubkey::default() {
            savings.authority = ctx.accounts.user.key();
            savings.balance = 0;
            savings.tag = tag;
        }
        Ok(())
    }

    /// Deposits are permissionless by design (anyone may top up any
    /// savings account). The only guard is the authority check in withdraw.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let savings = &mut ctx.accounts.savings;
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
        savings.balance = savings.balance.checked_add(amount).unwrap();
        Ok(())
    }

    /// The authority's legitimate right: close and reclaim rent.
    pub fn close_savings(ctx: Context<CloseSavings>) -> Result<()> {
        require!(
            ctx.accounts.savings.authority == ctx.accounts.user.key(),
            Fault::NotAuthority
        );
        // Anchor zeroes the data, reallocs to 0 and reassigns to System.
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let savings = &mut ctx.accounts.savings;
        require!(savings.authority == ctx.accounts.user.key(), Fault::NotAuthority);
        require!(savings.balance >= amount, Fault::InsufficientBalance);
        savings.balance = savings.balance.checked_sub(amount).unwrap();

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
#[instruction(tag: String)]
pub struct OpenSavings<'info> {
    // PDA seeded ONLY by the user-chosen tag — same address for any authority.
    #[account(
        init_if_needed,
        payer = payer,
        seeds = [b"savings", tag.as_bytes()],
        bump,
        space = 8 + 32 + 8 + 4 + 64
    )]
    pub savings: Account<'info, Savings>,
    // BUG: not a Signer — attacker passes any pubkey here.
    /// CHECK: vulnerable — must be a Signer.
    pub user: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"savings", savings.tag.as_bytes()], bump)]
    pub savings: Account<'info, Savings>,
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
pub struct CloseSavings<'info> {
    #[account(mut, close = user, seeds = [b"savings", savings.tag.as_bytes()], bump)]
    pub savings: Account<'info, Savings>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"savings", savings.tag.as_bytes()], bump)]
    pub savings: Account<'info, Savings>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Savings {
    pub authority: Pubkey,
    pub balance: u64,
    pub tag: String,
}

#[error_code]
pub enum Fault {
    #[msg("not the savings authority")]
    NotAuthority,
    #[msg("insufficient balance")]
    InsufficientBalance,
}
