//! Honest price oracle used as the trusted CPI counterparty in the vuln17
//! test suite. Educational purpose only — deployed on a local test validator.
//!
//! Op 7 ("get price") replies with a fixed u64 little-endian price:
//! 1_000_000 lamports per lot (0.001 SOL).

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, program::set_return_data,
};

entrypoint!(process_instruction);

/// Honest price of one loyalty lot, in lamports.
pub const LOT_PRICE_LAMPORTS: u64 = 1_000_000;

fn process_instruction(
    _program_id: &solana_program::pubkey::Pubkey,
    _accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first().copied().unwrap_or(255) {
        7 => {
            set_return_data(&LOT_PRICE_LAMPORTS.to_le_bytes());
            msg!("oracle: price = {} lamports/lot", LOT_PRICE_LAMPORTS);
            Ok(())
        }
        _ => Err(solana_program::program_error::ProgramError::InvalidInstructionData),
    }
}
