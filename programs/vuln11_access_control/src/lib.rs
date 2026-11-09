//! VULN 11 — Missing access control on a privileged instruction.
//!
//! "Fee Collector": every deposit leaves 10% in the protocol fee vault and
//! the amount is accounted in a Config PDA. `claim_fees` pays the accumulated
//! fees out to a recipient — and is supposed to be callable by the admin
//! only. The BUG: the `admin` account is declared in the context but NEVER
//! checked (no `Signer`, no constraint) — anyone can route the fees to
//! themselves.
//!
//! This is one of the most frequent audit findings: a privileged instruction
//! whose only protection is the *presence* of an account, not a check.

use anchor_lang::prelude::*;

declare_id!("J7Uo56tAnC8ke8kKNS975aYEpRgvRVBeZizHK2pqdmG2");

#[program]
pub mod vuln11_access_control {
    use super::*;

    /// One-time setup: config + fee vault. `admin` is recorded here, but
    /// nothing ever reads it back — that is the root cause.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = ctx.accounts.admin.key();
        cfg.fees_collected = 0;
        Ok(())
    }

    /// User deposits SOL into the protocol vault; 10% is accounted as fees.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount >= 10, FeeError::AmountTooSmall);
        let fee = amount / 10;

        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.fee_vault.to_account_info(),
                },
            ),
            amount,
        )?;

        let cfg = &mut ctx.accounts.config;
        cfg.fees_collected = cfg
            .fees_collected
            .checked_add(fee)
            .ok_or(FeeError::Overflow)?;
        Ok(())
    }

    /// BUG: pays out `fees_collected` to ANY recipient. `admin` sits in the
    /// context but is never validated — no signer constraint, no key check.
    pub fn claim_fees(ctx: Context<ClaimFees>) -> Result<()> {
        let amount = ctx.accounts.config.fees_collected;
        require!(amount > 0, FeeError::NothingToClaim);

        // fee_vault is program-owned, so lamports move directly (what the
        // system program refuses, the owning program is allowed to do).
        let from = ctx.accounts.fee_vault.to_account_info();
        let to = ctx.accounts.recipient.to_account_info();
        let new_from = from
            .lamports()
            .checked_sub(amount)
            .ok_or(FeeError::InsufficientVaultBalance)?;
        **from.lamports.borrow_mut() = new_from;
        let new_to = to
            .lamports()
            .checked_add(amount)
            .ok_or(FeeError::Overflow)?;
        **to.lamports.borrow_mut() = new_to;

        let cfg = &mut ctx.accounts.config;
        cfg.fees_collected = 0;
        Ok(())
    }
}

#[error_code]
pub enum FeeError {
    #[msg("amount too small")]
    AmountTooSmall,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("no fees accumulated")]
    NothingToClaim,
    #[msg("vault has fewer lamports than accounted fees")]
    InsufficientVaultBalance,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub fees_collected: u64,
}

/// The protocol fee vault: an Anchor data account that also HOLDS the fee
/// lamports (lamports on a data account are perfectly legal).
#[account]
pub struct FeeVault {
    pub _reserved: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"config"], bump, space = 8 + 32 + 8)]
    pub config: Account<'info, Config>,
    /// CHECK: THE BUG itself — the admin of the protocol is never verified:
    /// no signer constraint, no comparison with config.admin. Any account
    /// (or none) can be passed here.
    pub admin: UncheckedAccount<'info>,
    #[account(init, payer = payer, seeds = [b"fee_vault"], bump, space = 8 + 8)]
    pub fee_vault: Account<'info, FeeVault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"fee_vault"], bump)]
    pub fee_vault: Account<'info, FeeVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClaimFees<'info> {
    #[account(mut, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"fee_vault"], bump)]
    pub fee_vault: Account<'info, FeeVault>,
    /// CHECK: THE BUG — the admin is required to be *present* but never
    /// verified: not a signer, not compared with config.admin.
    pub admin: UncheckedAccount<'info>,
    /// CHECK: fully attacker-controlled fee recipient (the exploit routes
    /// protocol fees here; this is the second half of the bug).
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
