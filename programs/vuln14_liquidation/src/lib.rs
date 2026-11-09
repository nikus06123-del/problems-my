//! VULN 14 — liquidation without a health-factor check.
//!
//! "MicroLend": users post SOL collateral and borrow up to 80% LTV (the
//! borrow instruction enforces that). `liquidate` is supposed to fire only
//! when a position goes UNDERWATER (debt > 80% of collateral): the
//! liquidator repays the debt to the pool and seizes the collateral plus a
//! 5% bonus paid from the pool's insurance reserve.
//!
//! The BUG: `liquidate` performs NO health check at all. Anyone can
//! "liquidate" a perfectly HEALTHY position:
//!   * pay the (small) debt,
//!   * seize the (much larger) collateral,
//!   * pocket the bonus from the insurance fund.
//!
//! A position with 10 SOL collateral and 5 SOL debt (LTV 50% — healthy by
//! design) is a 5.5 SOL profit for anyone who calls liquidate.

use anchor_lang::prelude::*;

declare_id!("56zEiAzPEMuzd3rMAsa2qNM6cQ9mHEg4hLg38kQ4v5FW");

/// Maximum LTV: borrow allowed while debt + amount <= 80% of collateral.
pub const MAX_LTV_NUM: u64 = 80;
pub const MAX_LTV_DEN: u64 = 100;
/// Liquidation bonus paid from the pool reserve.
pub const LIQ_BONUS_NUM: u64 = 5;
pub const LIQ_BONUS_DEN: u64 = 100;

#[program]
pub mod vuln14_liquidation {
    use super::*;

    /// Create the pool PDA and fund it with liquidity.
    pub fn initialize(ctx: Context<Initialize>, funding: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.treasury.to_account_info(),
                    to: ctx.accounts.pool.to_account_info(),
                },
            ),
            funding,
        )?;
        emit!(PoolFunded { funding });
        Ok(())
    }

    /// Deposit SOL collateral into a per-user position PDA.
    pub fn deposit_collateral(ctx: Context<DepositCollateral>, amount: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.position.to_account_info(),
                },
            ),
            amount,
        )?;

        let pos = &mut ctx.accounts.position;
        pos.owner = ctx.accounts.user.key();
        pos.collateral = pos
            .collateral
            .checked_add(amount)
            .ok_or(LendError::Overflow)?;
        Ok(())
    }

    /// Borrow: enforced LTV cap — this position can only become unhealthy
    /// through a collateral/price change, which is what liquidation is for.
    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let pos = &ctx.accounts.position;
        let new_debt = pos
            .debt
            .checked_add(amount)
            .ok_or(LendError::Overflow)?;
        require!(
            new_debt * MAX_LTV_DEN <= pos.collateral * MAX_LTV_NUM,
            LendError::OverLtv
        );

        // The pool is program-owned — lamports move directly.
        let from = ctx.accounts.pool.to_account_info();
        let to = ctx.accounts.user.to_account_info();
        let new_from = from
            .lamports()
            .checked_sub(amount)
            .ok_or(LendError::PoolEmpty)?;
        **from.lamports.borrow_mut() = new_from;
        let new_to = to
            .lamports()
            .checked_add(amount)
            .ok_or(LendError::Overflow)?;
        **to.lamports.borrow_mut() = new_to;

        let pos = &mut ctx.accounts.position;
        pos.debt = new_debt;
        Ok(())
    }

    /// BUG: no health check. Healthy positions are "liquidated" for profit.
    /// Steps: (1) liquidator repays the debt into the pool, (2) the pool
    /// pays a 5% bonus from its reserve, (3) the position is closed and the
    /// liquidator receives ALL remaining lamports (the full collateral).
    pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
        let debt = ctx.accounts.position.debt;
        let collateral = ctx.accounts.position.collateral;
        let victim = ctx.accounts.position.owner;

        // The missing check — in a fixed version it would be:
        // require!(debt * LIQ_BONUS_DEN > collateral * (MAX_LTV_NUM - 5),
        //         LendError::NotLiquidatable);

        // 1) liquidator repays the debt
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.liquidator.to_account_info(),
                    to: ctx.accounts.pool.to_account_info(),
                },
            ),
            debt,
        )?;

        // 2) insurance-fund bonus
        let bonus = collateral
            .checked_mul(LIQ_BONUS_NUM)
            .ok_or(LendError::Overflow)?
            .checked_div(LIQ_BONUS_DEN)
            .ok_or(LendError::Overflow)?;
        if bonus > 0 {
            // Insurance reserve is program-owned — direct lamport move.
            let from = ctx.accounts.pool.to_account_info();
            let to = ctx.accounts.liquidator.to_account_info();
            let new_from = from
                .lamports()
                .checked_sub(bonus)
                .ok_or(LendError::PoolEmpty)?;
            **from.lamports.borrow_mut() = new_from;
            let new_to = to
                .lamports()
                .checked_add(bonus)
                .ok_or(LendError::Overflow)?;
            **to.lamports.borrow_mut() = new_to;
        }

        // 3) seize the full collateral (close sends all remaining lamports)
        let liquidator = ctx.accounts.liquidator.to_account_info();
        ctx.accounts.position.close(liquidator)?;
        emit!(Liquidated {
            victim,
            debt_repaid: debt,
            bonus,
        });
        Ok(())
    }
}

#[event]
pub struct PoolFunded {
    pub funding: u64,
}

#[event]
pub struct Liquidated {
    pub victim: Pubkey,
    pub debt_repaid: u64,
    pub bonus: u64,
}

#[error_code]
pub enum LendError {
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("borrow exceeds max LTV")]
    OverLtv,
    #[msg("position is healthy — not liquidatable")]
    NotLiquidatable,
    #[msg("pool has no liquidity left")]
    PoolEmpty,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub collateral: u64,
    pub debt: u64,
}

/// The lending pool: an Anchor data account that also HOLDS the liquidity
/// and the insurance reserve (lamports on a data account are legal).
#[account]
pub struct Pool {
    pub _reserved: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"pool"], bump, space = 8 + 8)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub treasury: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositCollateral<'info> {
    #[account(
        init_if_needed,
        payer = user,
        seeds = [b"position", user.key().as_ref()],
        bump,
        space = 8 + 32 + 8 + 8
    )]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut, seeds = [b"position", user.key().as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    #[account(mut, close = liquidator, seeds = [b"position", position.owner.as_ref()], bump)]
    pub position: Account<'info, Position>,
    #[account(mut, seeds = [b"pool"], bump)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub liquidator: Signer<'info>,
    pub system_program: Program<'info, System>,
}
