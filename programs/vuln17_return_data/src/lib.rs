//! VULN 17 — Trusting CPI return data without checking the source program.
//!
//! "Points Redemption": users accumulate `lots` (loyalty points) and redeem
//! them for SOL at the current oracle price. The redemption instruction
//! performs a CPI to the price oracle and reads the reply with
//! `get_return_data()`. The BUG: the reply is trusted because of its *shape*
//! (8 bytes) — the program never verifies that the return data came from the
//! REAL oracle (the `program_id` half of the `(program_id, data)` pair is
//! ignored and the `price_program` account passed in is not constrained
//! either).
//!
//! Any program can therefore answer the CPI. The attacker's contract returns
//! an inflated price (2 SOL per lot instead of 0.001) and redeems the same
//! handful of lots for the entire vault.
//!
//! See also: vuln15 (fake token program CPI) — there the fake CPI pretends a
//! transfer happened; here the fake CPI poisons a *price feed* through
//! return data.

use anchor_lang::prelude::*;

declare_id!("J247M7nb2BC6LGtauptEUKjizFwEaPfUe1iepz2xbyco");

#[program]
pub mod vuln17_return_data {
    use super::*;

    /// One-time setup: vault PDA (holds SOL).
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        ctx.accounts.vault.funded = 0;
        Ok(())
    }

    /// Fund the redemption vault (honest liquidity).
    pub fn fund(ctx: Context<Fund>, amount: u64) -> Result<()> {
        anchor_lang::system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.user.to_account_info(),
                    to: ctx.accounts.vault.to_account_info(),
                },
            ),
            amount,
        )?;
        let v = &mut ctx.accounts.vault;
        v.funded = v.funded.checked_add(amount).ok_or(Err17::Overflow)?;
        Ok(())
    }

    /// Earn loyalty lots for free (simulated activity reward).
    pub fn earn(ctx: Context<Earn>) -> Result<()> {
        let c = &mut ctx.accounts.credits;
        c.lots = c.lots.checked_add(10).ok_or(Err17::Overflow)?;
        Ok(())
    }

    /// Redeem `lots` for SOL at the oracle price.
    ///
    /// BUG: the CPI answer is accepted from WHATEVER `price_program` was
    /// passed in — `get_return_data()` is only checked for length.
    pub fn redeem(ctx: Context<Redeem>, lots: u64) -> Result<()> {
        let credits = &mut ctx.accounts.credits;
        require!(credits.lots >= lots, Err17::NotEnoughLots);

        // CPI: op 7 = "get price". The honest oracle replies with the u64
        // little-endian price of one lot.
        let ix = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.price_program.key(),
            accounts: vec![],
            data: vec![7u8],
        };
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[ctx.accounts.price_program.to_account_info()],
        )?;

        // BUG: `get_return_data` returns (program_id, data); the program id
        // MUST be checked against the trusted oracle. It is not.
        let (_src, data) = anchor_lang::solana_program::program::get_return_data()
            .ok_or(Err17::NoReturnData)?;
        require!(data.len() == 8, Err17::BadReturnData);
        let price = u64::from_le_bytes(data[..8].try_into().unwrap());

        let payout = lots.checked_mul(price).ok_or(Err17::Overflow)?;
        require!(payout > 0, Err17::ZeroPayout);

        credits.lots -= lots;

        // Pay out of the program-owned vault PDA.
        let vault = ctx.accounts.vault.to_account_info();
        let to = ctx.accounts.destination.to_account_info();
        let new_vault = vault
            .lamports()
            .checked_sub(payout)
            .ok_or(Err17::InsufficientVault)?;
        **vault.lamports.borrow_mut() = new_vault;
        let new_to = to.lamports().checked_add(payout).ok_or(Err17::Overflow)?;
        **to.lamports.borrow_mut() = new_to;
        Ok(())
    }
}

#[error_code]
pub enum Err17 {
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("not enough lots")]
    NotEnoughLots,
    #[msg("price program did not answer")]
    NoReturnData,
    #[msg("bad return data shape")]
    BadReturnData,
    #[msg("zero payout")]
    ZeroPayout,
    #[msg("vault has insufficient lamports")]
    InsufficientVault,
}

#[account]
pub struct RedemptionVault {
    pub funded: u64,
}

#[account]
pub struct Credits {
    pub lots: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, seeds = [b"vault"], bump, space = 8 + 8)]
    pub vault: Account<'info, RedemptionVault>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Fund<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, RedemptionVault>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Earn<'info> {
    #[account(init_if_needed, payer = user, seeds = [b"credits", user.key().as_ref()], bump, space = 8 + 8)]
    pub credits: Account<'info, Credits>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Redeem<'info> {
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, RedemptionVault>,
    #[account(mut, seeds = [b"credits", user.key().as_ref()], bump)]
    pub credits: Account<'info, Credits>,
    #[account(mut)]
    pub user: Signer<'info>,
    /// CHECK: THE BUG — unconstrained "price program". The attacker passes
    /// their own contract here; its reply is trusted blindly.
    pub price_program: UncheckedAccount<'info>,
    /// CHECK: redemption proceeds go wherever the caller wants.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
}
