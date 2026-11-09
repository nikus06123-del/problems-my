//! VULN 10 — Broken check-effects-interactions: state commits TOO LATE.
//!
//! "Reentrant Faucet": a permissionless claim. Anyone may trigger payout of
//! a fixed reward to a recipient; a per-recipient ClaimState PDA marks it
//! done. The payout happens FIRST, the `claimed` flag is written LAST.
//!
//! Two consequences of that ordering:
//!
//! 1. Classic callback reentrancy (A -> attacker -> A) is now BLOCKED at the
//!    runtime level on modern Agave: the nested invocation of a program that
//!    is already on the call stack fails with
//!    `ReentrancyNotAllowed` ("Cross-program invocation reentrancy not
//!    allowed for this instruction"). Only DIRECT self-recursion (A -> A)
//!    is still permitted. So the old "notify a listener program before
//!    committing state" exploit no longer runs — this is a runtime defense.
//!
//! 2. But the ordering bug itself is just as exploitable through direct
//!    self-recursion: `claim` takes a caller-supplied `op` flag and, when
//!    `op == 1`, RE-INVOKES ITSELF (same privileged PDA signatures) with
//!    `op == 0` BEFORE setting the flag. The nested call passes the same
//!    (still false) guard, pays a second reward out of the shared vault,
//!    and only then both frames commit `claimed = true`. One permissionless
//!    transaction, two payouts.
//!
//! The lesson: the guard must be flipped BEFORE any money moves, and a
//! program must never let the caller branch its control flow into
//! re-executing privileged effects.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("HPXU63wP1TBu6d78F5C8tyECCHBauZ5rPee44MFeotoC");

pub const REWARD_AMOUNT: u64 = 100;

#[program]
pub mod vuln10_reentrancy {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// Claim records are created up-front by whoever wants a claim slot.
    pub fn initialize_claim(ctx: Context<InitializeClaim>) -> Result<()> {
        ctx.accounts.claim_state.claimed = false;
        Ok(())
    }

    /// Permissionless claim: no signer needed for `recipient` by design
    /// (any keeper may trigger it). The guard is `claim_state.claimed`.
    /// BUG: `op == 1` re-enters this same instruction before the guard
    /// value commits — the caller picks the double payout.
    pub fn claim<'a, 'b, 'c, 'info>(ctx: Context<'a, 'b, 'c, 'info, Claim<'info>>, op: u8) -> Result<()> {
        let state = &ctx.accounts.claim_state;
        // CHECK (first entry)
        if state.claimed {
            return Err(Fault::AlreadyClaimed.into());
        }

        // EFFECT: pay the reward out of the shared vault.
        let vault_bump = ctx.bumps.vault;
        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                token::Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient_ata.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[&[b"vault".as_ref(), &[vault_bump]]],
            ),
            REWARD_AMOUNT,
        )?;

        // INTERACTION BUG: a caller-controlled re-invocation of the SAME
        // privileged payout runs BEFORE the state update below. Direct
        // self-recursion (A -> A) is allowed by the runtime, so the nested
        // frame passes the same still-false guard and pays again.
        if op == 1 {
            // Anchor method discriminator: sha256("global:claim")[0..8]
            let mut data = vec![62u8, 198, 214, 193, 213, 159, 108, 210];
            data.push(0u8); // nested op = 0: one more payout, recursion stops

            // NOTE: a CPI into a BPF program requires the callee program's
            // own account to be present among the account infos — including
            // when the callee is the caller itself.
            let nested_ix = anchor_lang::solana_program::instruction::Instruction {
                program_id: crate::ID,
                accounts: vec![
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        ctx.accounts.recipient.key(),
                        false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        ctx.accounts.recipient_ata.key(),
                        false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        ctx.accounts.vault.key(),
                        false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new(
                        ctx.accounts.claim_state.key(),
                        false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        ctx.accounts.token_program.key(),
                        false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        ctx.accounts.self_program.key(),
                        false,
                    ),
                ],
                data,
            };
            let nested_infos = vec![
                ctx.accounts.recipient.to_account_info(),
                ctx.accounts.recipient_ata.to_account_info(),
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.claim_state.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.self_program.to_account_info(),
            ];
            anchor_lang::solana_program::program::invoke_signed(
                &nested_ix,
                &nested_infos,
                &[
                    &[b"vault".as_ref(), &[vault_bump]],
                    &[b"claim", ctx.accounts.recipient.key.as_ref(), &[ctx.bumps.claim_state]],
                ],
            )?;
        }

        // STATE UPDATE TOO LATE: the second payout already happened above.
        ctx.accounts.claim_state.claimed = true;
        Ok(())
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
pub struct InitializeClaim<'info> {
    #[account(init, payer = payer, seeds = [b"claim", recipient.key.as_ref()], bump, space = 8 + 1)]
    pub claim_state: Account<'info, ClaimState>,
    /// CHECK: the recipient of the future claim.
    pub recipient: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    /// CHECK: permissionless by design (any keeper may claim for anyone).
    pub recipient: UncheckedAccount<'info>,
    #[account(mut, constraint = recipient_ata.owner == recipient.key())]
    pub recipient_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"claim", recipient.key.as_ref()], bump)]
    pub claim_state: Account<'info, ClaimState>,
    pub token_program: Program<'info, Token>,
    /// CHECK: this program's own account — a CPI into a BPF program needs
    /// the callee account present, even for a self-invocation.
    #[account(constraint = self_program.key() == crate::ID @ Fault::BadProgram)]
    pub self_program: UncheckedAccount<'info>,
}

#[account]
pub struct ClaimState {
    pub claimed: bool,
}

#[error_code]
pub enum Fault {
    #[msg("reward already claimed")]
    AlreadyClaimed,
    #[msg("wrong program account passed")]
    BadProgram,
}
