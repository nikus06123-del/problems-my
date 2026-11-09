//! VULN 13 — attacker-supplied sysvar (Clock) bypasses a time check.
//!
//! "OrderEscrow": users escrow SOL in per-order PDAs with an expiry
//! timestamp. After expiry ANYONE may `sweep` the order — a common
//! cleanup-incentive design (the sweeper gets the escrow as a reward).
//!
//! The BUG: `sweep` reads the Clock from an `UncheckedAccount` via
//! `Clock::from_account_info` instead of `Clock::get()`. `from_account_info`
//! does NOT verify the account is the real sysvar — any account with
//! attacker-written bytes works. The attacker forges a Clock "in the year
//! 2096" and sweeps ACTIVE orders, taking other users' escrowed SOL.

use anchor_lang::prelude::*;

declare_id!("EiFd2Ycg1u2e3snWdUKFmD18hHmDDa5TbUqxEDPpbuqf");

#[program]
pub mod vuln13_fake_sysvar {
    use super::*;

    /// User escrows `amount` lamports in an order PDA valid for `ttl_secs`.
    pub fn create_order(
        ctx: Context<CreateOrder>,
        order_id: u64,
        amount: u64,
        ttl_secs: i64,
    ) -> Result<()> {
        require!(amount >= 1_000_000, EscrowError::AmountTooSmall);
        let now = Clock::get()?.unix_timestamp;

        let order = &mut ctx.accounts.order;
        order.creator = ctx.accounts.creator.key();
        order.amount = amount;
        order.expires_at = now.checked_add(ttl_secs).ok_or(EscrowError::Overflow)?;

        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.creator.to_account_info(),
                    to: ctx.accounts.order.to_account_info(),
                },
            ),
            amount,
        )
    }

    /// Creator cancels a live order and gets everything back.
    pub fn cancel_order(ctx: Context<CancelOrder>, order_id: u64) -> Result<()> {
        require!(
            ctx.accounts.order.creator == ctx.accounts.creator.key(),
            EscrowError::NotCreator
        );
        ctx.accounts.order.close(ctx.accounts.creator.to_account_info())?;
        emit!(OrderClosed { order_id });
        Ok(())
    }

    /// Permissionless cleanup: after expiry the sweeper takes the escrow.
    /// BUG: "network time" is hand-parsed out of an UNCHECKED account — no
    /// id/owner verification at all. (On modern solana-program 2.x even the
    /// unsafe-looking `Clock::from_account_info` is guarded by a key check
    /// and the `sol_get_clock_sysvar` syscall, so hand-parsing sysvar bytes
    /// from a caller-supplied account is the realistic vulnerable pattern.)
    pub fn sweep(ctx: Context<Sweep>, order_id: u64) -> Result<()> {
        // "Clock layout" (8-byte LE fields): slot, epoch_start_timestamp,
        // epoch, leader_schedule_epoch, unix_timestamp@32.
        let data = &ctx.accounts.clock.try_borrow_data()?;
        if data.len() < 40 {
            return Err(EscrowError::InvalidClockAccount.into());
        }
        let now = i64::from_le_bytes(data[32..40].try_into().unwrap());
        let order = &ctx.accounts.order;
        require!(now > order.expires_at, EscrowError::NotExpired);

        // `close` moves ALL lamports (escrow amount + rent) to the executor.
        let executor = ctx.accounts.executor.to_account_info();
        ctx.accounts.order.close(executor)?;
        emit!(OrderSwept {
            order_id,
            executor: ctx.accounts.executor.key(),
        });
        Ok(())
    }
}

#[event]
pub struct OrderClosed {
    pub order_id: u64,
}

#[event]
pub struct OrderSwept {
    pub order_id: u64,
    pub executor: Pubkey,
}

#[error_code]
pub enum EscrowError {
    #[msg("amount too small")]
    AmountTooSmall,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("only the creator can cancel")]
    NotCreator,
    #[msg("order has not expired yet")]
    NotExpired,
    #[msg("clock account does not look like a Clock")]
    InvalidClockAccount,
}

#[account]
pub struct Order {
    pub creator: Pubkey,
    pub amount: u64,
    pub expires_at: i64,
}

#[derive(Accounts)]
#[instruction(order_id: u64)]
pub struct CreateOrder<'info> {
    #[account(
        init,
        payer = creator,
        seeds = [b"order", creator.key().as_ref(), &order_id.to_le_bytes()],
        bump,
        space = 8 + 32 + 8 + 8
    )]
    pub order: Account<'info, Order>,
    #[account(mut)]
    pub creator: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(order_id: u64)]
pub struct CancelOrder<'info> {
    #[account(
        mut,
        close = creator,
        seeds = [b"order", creator.key().as_ref(), &order_id.to_le_bytes()],
        bump
    )]
    pub order: Account<'info, Order>,
    #[account(mut)]
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(order_id: u64)]
pub struct Sweep<'info> {
    #[account(
        mut,
        close = executor,
        seeds = [b"order", order.creator.as_ref(), &order_id.to_le_bytes()],
        bump
    )]
    pub order: Account<'info, Order>,
    /// CHECK: THE BUG — this is supposed to be the real Clock sysvar, but
    /// the program hand-deserializes its bytes without verifying the
    /// account id (`Clock::get()` or `Sysvar<'info, Clock>` would be safe).
    /// The attacker forges an account whose data "is" a Clock in 2096.
    pub clock: UncheckedAccount<'info>,
    /// CHECK: cleanup reward recipient — permissionless by design; safe to
    /// leave unchecked because the swept lamports are the reward itself.
    #[account(mut)]
    pub executor: UncheckedAccount<'info>,
}
