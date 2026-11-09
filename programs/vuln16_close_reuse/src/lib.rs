//! VULN 16 — Account close + resurrection (use-after-free) in one transaction.
//!
//! "Staking Pool": a global `state` PDA stores who is authorized to withdraw
//! from the protocol vault. `close_state` is meant for admin migrations, but
//! the BUG is double:
//!   1) `close_state` has NO authority check — anyone can close the state;
//!   2) nothing prevents re-initializing the same PDA seeds right after the
//!      close (the seeds are free again once the account is gone).
//!
//! The attacker chains THREE instructions in ONE transaction:
//!   close_state() -> initialize(authorized = attacker) -> withdraw(all)
//! The vault is drained atomically. This is the classic "closing accounts"
//! issue described by Neodyme: a closed account resurrects with attacker
//! controlled data because program-owned PDA seeds are only unique while
//! the account exists.
//!
//! NOTE: unlike vuln07 (init_if_needed partial re-init of a LIVE account),
//! here the account is fully destroyed first — the PDA "identity" survives
//! while its data history does not.

use anchor_lang::prelude::*;

declare_id!("DT96jaDJ52QzTiVQFxjokispd9QZ2jostRpUZQQ1ooWG");

#[program]
pub mod vuln16_close_reuse {
    use super::*;

    /// One-time setup of the withdraw authority. `authorized` signs and
    /// becomes recorded in the state. Note: nothing stops this from running
    /// AGAIN on the same (closed → freed) PDA seeds — that is the exploit.
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let st = &mut ctx.accounts.state;
        st.authorized = ctx.accounts.authorized.key();
        Ok(())
    }

    /// One-time setup of the vault PDA (done once by the deployer).
    pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
        ctx.accounts.vault._reserved = 0;
        Ok(())
    }

    /// BUG: meant to be admin-only, but there is NO signer/authority check.
    /// Anyone may destroy the protocol state. This is a MANUAL close: the
    /// rent goes to `refund`, lamports are zeroed, the data is REALLOC'ed to
    /// zero bytes and the owner is reassigned to the system program — after
    /// that the PDA seeds are completely free again, even within the same
    /// transaction (Anchor's `close = ..` attribute would leave a
    /// closed-account discriminator that blocks immediate re-init).
    pub fn close_state(ctx: Context<CloseState>) -> Result<()> {
        let st = ctx.accounts.state.to_account_info();
        let dst = ctx.accounts.refund.to_account_info();

        // rent refund
        let new_dst = dst
            .lamports()
            .checked_add(st.lamports())
            .ok_or(Err16::Overflow)?;
        **dst.lamports.borrow_mut() = new_dst;

        // full deallocation (BUG): 0 lamports + 0 data + system owner makes
        // the runtime treat the account as nonexistent — resurrection ready.
        **st.lamports.borrow_mut() = 0;
        st.realloc(0, false)?;
        st.assign(&anchor_lang::solana_program::system_program::ID);
        Ok(())
    }

    /// User deposits SOL into the protocol vault.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
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

    /// Withdraw requires `authorized` to sign and to match state.authorized.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let st = &ctx.accounts.state;
        require!(
            ctx.accounts.authorized.key() == st.authorized,
            Err16::NotAuthorized
        );
        require!(ctx.accounts.authorized.is_signer, Err16::NotAuthorized);

        let vault = ctx.accounts.vault.to_account_info();
        let to = ctx.accounts.recipient.to_account_info();
        let new_vault = vault
            .lamports()
            .checked_sub(amount)
            .ok_or(Err16::InsufficientVault)?;
        **vault.lamports.borrow_mut() = new_vault;
        let new_to = to.lamports().checked_add(amount).ok_or(Err16::Overflow)?;
        **to.lamports.borrow_mut() = new_to;
        Ok(())
    }
}

#[error_code]
pub enum Err16 {
    #[msg("not authorized")]
    NotAuthorized,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("vault has insufficient lamports")]
    InsufficientVault,
}

#[account]
pub struct VaultState {
    pub authorized: Pubkey,
}

#[account]
pub struct Vault {
    pub _reserved: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"state"], bump, space = 8 + 32)]
    pub state: Account<'info, VaultState>,
    /// The withdraw authority recorded at genesis (must sign).
    pub authorized: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(init, payer = payer, seeds = [b"vault"], bump, space = 8 + 8)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseState<'info> {
    /// Manual close (see the handler): no `close = ..` attribute, the
    /// handler deallocates the account completely.
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, VaultState>,
    /// CHECK: BUG #1 — no check whatsoever that the caller has any right to
    /// close the protocol state. Also receives the rent refund.
    #[account(mut)]
    pub refund: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, VaultState>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, Vault>,
    pub authorized: Signer<'info>,
    /// CHECK: paid by the (attacker-controlled) authorized key.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
