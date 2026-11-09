//! VULN 08 — Duplicate mutable accounts not rejected.
//!
//! "Ledger Swap" (native program): users hold internal balances in
//! program-owned `Book` PDAs, backed 1:1 by lamports in a program reserve.
//! `internal_swap` moves credits between two books:
//!
//!   let a = from.amount;          // read BOTH balances first...
//!   let b = to.amount;
//!   from.amount = a - amount;     // ...then write them back
//!   to.amount  = b + amount;
//!
//! Nothing checks `from != to`. Passing the SAME book for both roles makes
//! the second write win: `amount + amount` — the caller doubles their
//! credits out of thin air, then redeems them for real lamports of OTHER
//! depositors.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
    sysvar::{rent::Rent, Sysvar},
};

entrypoint!(process_instruction);

const BOOK_MAGIC: [u8; 8] = [0x42, 0x4f, 0x4f, 0x4b, 0x30, 0x30, 0x30, 0x31]; // "BOOK0001"
const BOOK_SPACE: usize = 8 + 8; // magic + amount

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first().copied().unwrap_or(255) {
        // op 0: deposit — transfer lamports from user into reserve, credit book
        0 => deposit(program_id, accounts, read_u64(data, 1)?),
        // op 1: internal_swap(from_book, to_book, amount)
        1 => internal_swap(accounts, read_u64(data, 1)?),
        // op 2: redeem — burn credits, pay real lamports from the reserve
        2 => redeem(program_id, accounts, read_u64(data, 1)?),
        // op 3: init_book — create the book PDA [b"book", owner] (magic + 0)
        3 => init_book(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// accounts[0] = book PDA (to create), accounts[1] = owner (signer),
/// accounts[2] = payer (signer), accounts[3] = system program
fn init_book(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let ai = &mut accounts.iter();
    let book = next_account_info(ai)?;
    let owner = next_account_info(ai)?;
    let payer = next_account_info(ai)?;
    let system_program = next_account_info(ai)?;

    if !owner.is_signer || !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_program.key != &solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected, bump) = Pubkey::find_program_address(&[b"book", owner.key.as_ref()], program_id);
    if book.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    let lamports = Rent::get()?.minimum_balance(BOOK_SPACE);
    invoke_signed(
        &system_instruction::create_account(
            payer.key,
            book.key,
            lamports,
            BOOK_SPACE as u64,
            program_id,
        ),
        &[payer.clone(), book.clone(), system_program.clone()],
        &[&[b"book", owner.key.as_ref(), &[bump]]],
    )?;
    // Owner program may write data into its own accounts.
    let mut book_data = book.try_borrow_mut_data()?;
    book_data[0..8].copy_from_slice(&BOOK_MAGIC);
    book_data[8..16].copy_from_slice(&0u64.to_le_bytes());
    msg!("book {} created", book.key);
    Ok(())
}

fn read_u64(data: &[u8], off: usize) -> Result<u64, ProgramError> {
    if data.len() < off + 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(u64::from_le_bytes(data[off..off + 8].try_into().unwrap()))
}

fn write_book(acc: &AccountInfo, amount: u64) -> Result<(), ProgramError> {
    let mut data = acc.try_borrow_mut_data()?;
    data[8..16].copy_from_slice(&amount.to_le_bytes());
    Ok(())
}

fn read_book(acc: &AccountInfo) -> Result<u64, ProgramError> {
    let data = acc.try_borrow_data()?;
    if data.len() < BOOK_SPACE || data[0..8] != BOOK_MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes(data[8..16].try_into().unwrap()))
}

/// accounts[0] = book PDA  (created by the caller via op 3, owned by this
///                          program, data = magic + 0)
/// accounts[1] = user (signer, pays)
/// accounts[2] = reserve PDA
/// accounts[3] = system program (needed for the transfer CPI)
fn deposit(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ai = &mut accounts.iter();
    let book = next_account_info(ai)?;
    let user = next_account_info(ai)?;
    let reserve = next_account_info(ai)?;
    let system_program = next_account_info(ai)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system_program.key != &solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected, _bump) = Pubkey::find_program_address(&[b"reserve"], program_id);
    if reserve.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }

    // Move real lamports into the reserve (reserve PDA exists already).
    if amount > 0 {
        invoke_signed(
            &system_instruction::transfer(user.key, reserve.key, amount),
            &[user.clone(), reserve.clone(), system_program.clone()],
            &[],
        )?;
    }
    let cur = read_book(book)?;
    let new_balance = cur.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
    write_book(book, new_balance)?;
    msg!("deposit ok, book={}", new_balance);
    Ok(())
}

/// BUG: from_book and to_book are two mutable accounts that may be EQUAL.
/// accounts[0] = from_book, accounts[1] = to_book
fn internal_swap(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ai = &mut accounts.iter();
    let from_book = next_account_info(ai)?;
    let to_book = next_account_info(ai)?;

    let a = read_book(from_book)?;
    let b = read_book(to_book)?;
    if a < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    // Classic read-both-then-write pattern; duplicate input corrupts it.
    write_book(from_book, a - amount)?;
    write_book(to_book, b.saturating_add(amount))?; // wrapping add is fine: credits
    msg!("swap ok from={} to={}", a - amount, b + amount);
    Ok(())
}

/// accounts[0] = book, accounts[1] = recipient, accounts[2] = reserve PDA,
/// accounts[3] = system program
fn redeem(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ai = &mut accounts.iter();
    let book = next_account_info(ai)?;
    let recipient = next_account_info(ai)?;
    let reserve = next_account_info(ai)?;
    let system_program = next_account_info(ai)?;

    if system_program.key != &solana_program::system_program::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (expected, bump) = Pubkey::find_program_address(&[b"reserve"], program_id);
    if reserve.key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    let cur = read_book(book)?;
    if cur < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    write_book(book, cur - amount)?;
    let min_lamports = Rent::get()?.minimum_balance(0);
    if **reserve.lamports.borrow() < amount + min_lamports {
        return Err(ProgramError::InsufficientFunds);
    }
    invoke_signed(
        &system_instruction::transfer(reserve.key, recipient.key, amount),
        &[reserve.clone(), recipient.clone(), system_program.clone()],
        &[&[b"reserve", &[bump]]],
    )?;
    msg!("redeem ok, paid {} lamports", amount);
    Ok(())
}

/// Helper unused but kept for completeness.
#[allow(dead_code)]
fn reserve_is_rent_exempt(reserve: &AccountInfo) -> bool {
    Rent::get().map(|r| **reserve.lamports.borrow() >= r.minimum_balance(0)).unwrap_or(false)
}
