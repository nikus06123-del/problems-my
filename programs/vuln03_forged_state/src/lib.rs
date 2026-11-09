//! VULN 03 — Trusting user-supplied state: account parsed from an
//! `UncheckedAccount` with NO owner check.
//!
//! "Unverified Ledger": the program records reward entitlements in per-user
//! ledger accounts (PDAs it owns) and pays them out later. The payout
//! instruction deserializes the ledger MANUALLY from raw bytes and only
//! checks an 8-byte "discriminator" prefix. It never checks
//! `account.owner == program_id` (nor that the PDA seeds match the user).
//!
//! A discriminator is NOT authentication — the 8 bytes are public knowledge
//! and trivially replicated. The attacker creates a plain account owned by
//! THEIR OWN program containing [disc][u64::amount] and drains the whole
//! reward vault.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount};

declare_id!("H1W4DzzYBd6iz6UnqEddqjSVcZyFQanJPmSSZt79LJYu");

/// The 8-byte prefix the (buggy) payout instruction "verifies".
/// Same value the honest `record_rewards` writes; public knowledge.
pub const LEDGER_PREFIX: [u8; 8] = [0x4c, 0x45, 0x44, 0x47, 0x45, 0x52, 0x30, 0x31]; // "LEDGER01"

#[program]
pub mod vuln03_forged_state {
    use super::*;

    /// One-time setup: reward vault.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        emit!(Initialized { vault: ctx.accounts.vault.key() });
        Ok(())
    }

    /// Honest path: accrue rewards into the caller's ledger PDA.
    pub fn record_rewards(ctx: Context<RecordRewards>, amount: u64) -> Result<()> {
        let ledger = &mut ctx.accounts.ledger;
        ledger.owner = ctx.accounts.user.key();
        ledger.amount = ledger.amount.checked_add(amount).unwrap();
        Ok(())
    }

    /// BUG: `ledger` is an `UncheckedAccount`, parsed by hand, and only the
    /// 8-byte prefix is checked. No owner check. No PDA-seed check.
    pub fn claim_rewards(ctx: Context<ClaimRewards>, amount: u64) -> Result<()> {
        let ledger_data = ctx.accounts.ledger.try_borrow_data()?;
        if ledger_data.len() < 16 {
            return Err(Fault::BadLedger.into());
        }
        if ledger_data[0..8] != LEDGER_PREFIX {
            return Err(Fault::BadLedger.into());
        }
        let entitled = u64::from_le_bytes(ledger_data[8..16].try_into().unwrap());
        drop(ledger_data);

        require!(entitled >= amount, Fault::NotEntitled);

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
pub struct RecordRewards<'info> {
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"ledger", user.key().as_ref()],
        bump,
        space = 8 + 32 + 8
    )]
    pub ledger: Account<'info, RewardLedger>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    // BUG: unchecked + no owner/PDA validation. Bytes are all that matter.
    /// CHECK: vulnerable — must be the program-owned ledger PDA.
    pub ledger: UncheckedAccount<'info>,
    /// CHECK: unused — a real signer requirement was forgotten.
    pub user: UncheckedAccount<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct RewardLedger {
    pub owner: Pubkey,
    pub amount: u64,
}

#[error_code]
pub enum Fault {
    #[msg("ledger data does not parse")]
    BadLedger,
    #[msg("entitlement too small")]
    NotEntitled,
}
