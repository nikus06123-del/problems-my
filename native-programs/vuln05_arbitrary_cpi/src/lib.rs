//! VULN 05 — Arbitrary CPI with PDA signer delegation (native program).
//!
//! "Fee Distributor": fees accumulate in a SPL token account whose authority
//! is the program PDA [b"fees"]. Sweeping the treasury is delegated to a
//! pluggable "settlement program" chosen BY THE CALLER. The distributor
//! hands its own PDA signing privilege to that arbitrary program.
//!
//! Whoever controls the settlement program controls the fees. The attacker
//! deploys a malicious "settlement program" (here: the `attacker` program,
//! mode 2) that moves the ENTIRE fee vault to the attacker's own token
//! account using the delegated PDA signature.

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
};

entrypoint!(process_instruction);

/// SPL Token program id (mainnet/localnet token program).
#[allow(dead_code)]
const SPL_TOKEN_ID: Pubkey =
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    msg!("fee_distributor::process_instruction op={}", data.first().copied().unwrap_or(255));
    match data.first().copied().unwrap_or(255) {
        // op 1: sweep fees through the caller-supplied settlement program;
        // data[1] is the caller's "settlement plan" passed through verbatim.
        1 => sweep(program_id, accounts, data.get(1).copied().unwrap_or(0)),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// accounts[0] fee_pda           — PDA [b"fees"] (authority of the fee vault)
/// accounts[1] settlement_program— ARBITRARY program (BUG)
/// accounts[2] fee_vault_ta      — SPL token account owned by fee_pda
/// accounts[3] treasury_ta       — intended destination (forwarded, ignored
///                                 by the attacker)
/// accounts[4] token_program     — SPL Token program
/// accounts[5..] extra           — blindly forwarded (attacker puts their ATA here)
fn sweep(program_id: &Pubkey, accounts: &[AccountInfo], plan: u8) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let fee_pda = &accounts[0];
    let settlement_program = &accounts[1];
    let fee_vault = &accounts[2];
    let treasury = &accounts[3];
    let token_program = &accounts[4];

    // Verify the fee PDA is really ours (this check is fine).
    let (expected_pda, bump) = Pubkey::find_program_address(&[b"fees"], program_id);
    if fee_pda.key != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }
    // Verify the vault really belongs to the PDA (also fine).
    if fee_vault.data_len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }
    let vault_owner = Pubkey::new_from_array(
        fee_vault.try_borrow_data()?[32..64]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    );
    if vault_owner != expected_pda {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // BUG: the "settlement program" is caller-chosen and we hand it our PDA
    // as a SIGNER. The intended destination (treasury) and the vault are
    // forwarded — but the callee may do anything it wants with the privilege.
    let mut metas = vec![
        AccountMeta::new_readonly(expected_pda, true), // signer
        AccountMeta::new(*fee_vault.key, false),
        AccountMeta::new_readonly(*treasury.key, false),
        AccountMeta::new_readonly(*token_program.key, false),
    ];
    let mut infos = vec![
        fee_pda.clone(),
        fee_vault.clone(),
        treasury.clone(),
        token_program.clone(),
    ];
    for extra in &accounts[5..] {
        metas.push(AccountMeta::new(*extra.key, false));
        infos.push(extra.clone());
    }

    let settle_ix = Instruction::new_with_bytes(*settlement_program.key, &[plan], metas);
    msg!("delegating sweep to {}", settlement_program.key);
    invoke_signed(&settle_ix, &infos, &[&[b"fees".as_ref(), &[bump]]])
}
