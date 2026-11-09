//! VULN 01 — Missing authority/signer check on a privileged instruction.
//!
//! "Untrusted Bank": users deposit tokens into a shared vault and their
//! balance is tracked in a per-user PDA. The `withdraw` instruction never
//! verifies that the caller is actually the owner of the balance account:
//! `authority` is a plain unchecked account, it is NOT a Signer, and nothing
//! ties `user_balance.authority` to the account being drawn down.
//!
//! Result: ANYONE can drain ANY user's balance to ANY token account.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("6TSqBs2dvRzsDg52g9qh8Nf4TUKRdAM5YjjoXyHFpDh8");

#[program]
pub mod vuln01_missing_signer {
    use super::*;

    /// One-time setup: create the shared vault token account (owned by the
    /// vault PDA so the program can move funds out of it).
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// Honest path: user signs, tokens move into the vault, balance credited.
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
        ctx.accounts.user_balance.amount = ctx
            .accounts
            .user_balance
            .amount
            .checked_add(amount)
            .unwrap();
        Ok(())
    }

    /// BUG: `authority` below should be a `Signer` AND the balance PDA should
    /// be derived as [b"balance", authority.key] — neither is enforced.
    /// Anyone can pass someone else's `user_balance` and any destination.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let bal = &mut ctx.accounts.user_balance;
        require!(bal.amount >= amount, BankError::InsufficientBalance);
        bal.amount = bal.amount.checked_sub(amount).unwrap();

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
        token::authority = vault,
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
        space = 8 + 32 + 8
    )]
    pub user_balance: Account<'info, UserBalance>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(
        mut,
        constraint = user_ata.owner == user.key(),
        constraint = user_ata.mint == vault.mint
    )]
    pub user_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    // BUG #1: this PDA is NOT bound to the caller. Any balance record works.
    #[account(mut)]
    pub user_balance: Account<'info, UserBalance>,
    // BUG #2: `authority` is an unchecked account — no signature required.
    /// CHECK: vulnerable — should be Signer and should own user_balance.
    pub authority: UncheckedAccount<'info>,
    // BUG #3: destination is not tied to the balance owner either.
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct UserBalance {
    pub authority: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum BankError {
    #[msg("insufficient balance")]
    InsufficientBalance,
}
