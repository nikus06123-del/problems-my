//! VULN 20 — privileged PDA authority derived from an UNVALIDATED account.
//!
//! "Escrow Swap": every user funds a personal escrow token account owned by
//! the escrow PDA (seeds [b"escrow", user]). `swap` pulls the input from the
//! escrow and pays 2x token B to the caller. Both CPIs are signed by the
//! PROGRAM's own PDAs (that part is correct — the escrow belongs to the PDA,
//! so the PDA must sign).
//!
//! THE BUG: the `user` account that drives the escrow seed derivation is
//! accepted WITHOUT a Signer constraint. The attacker passes the VICTIM as
//! `user` and the victim's escrow PDA as `escrow`: the seeds constraint is
//! satisfied (it IS the victim's escrow), the program happily signs the
//! transfer with the escrow PDA — and the payout goes to the attacker.
//! One transaction drains any victim's escrow without their signature.
//!
//! THE FIX is one word: `pub user: Signer<'info>` (the signer must bind the
//! PDA seeds), plus pinning the mints of the user-supplied accounts.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("BYmkvyqBEKQW4mjwHj2eP1w75VxiokGvjzvYxG8mmmnN");

#[program]
pub mod vuln20_escrow_authority {
    use super::*;

    /// Create the pool: pin mints A/B, record the pool-side token accounts.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let p = &mut ctx.accounts.pool;
        p.mint_a = ctx.accounts.mint_a.key();
        p.mint_b = ctx.accounts.mint_b.key();
        Ok(())
    }

    /// Fill the pool with token B (honest liquidity).
    pub fn fund_b(ctx: Context<FundB>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_ta.to_account_info(),
                    to: ctx.accounts.pool_ta_b.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Fund the caller's personal escrow (held by the escrow PDA).
    pub fn fund_escrow(ctx: Context<FundEscrow>, amount: u64) -> Result<()> {
        // The escrow token account is created by the client (owner = escrow
        // PDA); here we only move tokens in. `user` signs — honest case.
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_ta.to_account_info(),
                    to: ctx.accounts.escrow_ta.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Swap `amount` of the caller's escrowed token A for `amount * 2` of B.
    ///
    /// BUG: `user` is not required to sign. The escrow authority PDA is
    /// derived from this unvalidated account, so anyone can "be" the user
    /// and drain someone else's escrow with the program's own signature.
    pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        require!(amount > 0, Err20::ZeroAmount);
        let out = amount.checked_mul(2).ok_or(Err20::Overflow)?;

        // Pull the input from the (victim's) escrow: signed by the escrow
        // authority PDA derived from the UNVALIDATED `user` account.
        let escrow_seeds = [
            b"escrow".as_ref(),
            ctx.accounts.user.key.as_ref(),
            &[ctx.bumps.escrow_authority],
        ];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_ta.to_account_info(),
                    to: ctx.accounts.pool_ta_a.to_account_info(),
                    authority: ctx.accounts.escrow_authority.to_account_info(),
                },
                &[&escrow_seeds],
            ),
            amount,
        )?;

        // Pay out real token B to whatever destination was passed.
        let pool_seeds = [b"pool".as_ref(), &[ctx.bumps.pool]];
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.pool_ta_b.to_account_info(),
                    to: ctx.accounts.user_out_ta.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                &[&pool_seeds],
            ),
            out,
        )
    }
}

#[error_code]
pub enum Err20 {
    #[msg("zero amount")]
    ZeroAmount,
    #[msg("arithmetic overflow")]
    Overflow,
}

#[account]
pub struct Pool {
    pub mint_a: Pubkey,
    pub mint_b: Pubkey,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"pool"], bump, space = 8 + 32 + 32)]
    pub pool: Account<'info, Pool>,
    pub mint_a: Account<'info, Mint>,
    pub mint_b: Account<'info, Mint>,
    /// Pool-side token accounts (created by the deployer, owned by pool PDA).
    #[account(mut)]
    pub pool_ta_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub pool_ta_b: Account<'info, TokenAccount>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundB<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub pool_ta_b: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct FundEscrow<'info> {
    /// The escrow token account: owned by the escrow authority PDA of `user`.
    #[account(mut)]
    pub escrow_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub pool_ta_a: Account<'info, TokenAccount>,
    #[account(mut)]
    pub pool_ta_b: Account<'info, TokenAccount>,
    /// THE BUG: this account drives the escrow seeds but is NOT a Signer —
    /// in the attack it is the VICTIM's key.
    /// CHECK: unvalidated "user" — must be a Signer, that is the bug.
    pub user: AccountInfo<'info>,
    /// CHECK: address is pinned to the PDA of `user` by the seeds
    /// constraint below — used only as a CPI signer.
    #[account(seeds = [b"escrow", user.key().as_ref()], bump)]
    pub escrow_authority: UncheckedAccount<'info>,
    /// BUG (secondary): not checked to be owned by `escrow_authority` — the
    /// token program's owner check is what actually stops arbitrary accounts.
    #[account(mut)]
    pub escrow_ta: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_out_ta: Account<'info, TokenAccount>,
    /// The actual transaction signer — NOT bound to `user` in any way.
    #[account(mut)]
    pub caller: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
