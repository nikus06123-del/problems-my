import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import fs from "fs";
import path from "path";
import { expect } from "chai";

// ---------------------------------------------------------------------------
// Program IDs (keypairs in keys/ are gitignored; regenerate with solana-keygen)
// ---------------------------------------------------------------------------
export const PROG_IDS = {
  vuln01: new PublicKey("6TSqBs2dvRzsDg52g9qh8Nf4TUKRdAM5YjjoXyHFpDh8"),
  vuln02: new PublicKey("1XeQ8irpogAJTxNP7MiAk5SgAi7UZkyi7RmTASxVhRY"),
  vuln03: new PublicKey("H1W4DzzYBd6iz6UnqEddqjSVcZyFQanJPmSSZt79LJYu"),
  vuln04: new PublicKey("EUHsG3fkkb4EohJBdy9HJbZEKS8UecKQej5uQk1S1hSr"),
  vuln05: new PublicKey("HVKUuXZRopCRHD6Ne2KJ3Aqapb99sHRdhG8asyDdz1NQ"),
  vuln06: new PublicKey("EV2U5AjGiFhUPiNHFzZPYyn5E9HuNRdyfM92mShrqoEK"),
  vuln07: new PublicKey("7CkJ3L8hpHbE6mDRvXwU7MyDNpEMw5prj3Tsujt9hLDU"),
  vuln08: new PublicKey("J1uGvwWWaxXroKxHjVHpgJ9eY8vp4r1iSXTpNYCHSP49"),
  vuln09: new PublicKey("9hEAbWKYFmgjd3SBRsBU4yiyTiPEcaWqGM8ZUuKDcVW5"),
  vuln10: new PublicKey("HPXU63wP1TBu6d78F5C8tyECCHBauZ5rPee44MFeotoC"),
  attacker: new PublicKey("J4veNunZYUEu59ta7EjjRk4RE9CFnbB5jm8W4dCsJPU3"),
};

export const provider = anchor.getProvider() as AnchorProvider;
export const connection = provider.connection;
export const deployer = provider.wallet as Wallet;

export const BN = anchor.BN;
export { PublicKey, Keypair, SystemProgram, Transaction, TransactionInstruction, ComputeBudgetProgram, sendAndConfirmTransaction, TOKEN_PROGRAM_ID, LAMPORTS_PER_SOL, expect };
export { createMint, createAccount, mintTo, getAccount };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
export async function airdrop(pubkey: PublicKey, sol = 20): Promise<void> {
  const sig = await connection.requestAirdrop(pubkey, sol * LAMPORTS_PER_SOL);
  await connection.confirmTransaction(sig, "confirmed");
}

export function loadIdl(name: string): any {
  const p = path.join(__dirname, "..", "target", "idl", `${name}.json`);
  return JSON.parse(fs.readFileSync(p, "utf-8"));
}

export function anchorProgram(name: string, programId: PublicKey): Program {
  const idl = loadIdl(name);
  // anchor 0.32.x takes the program id from idl.address; make sure it matches
  // the deployed key.
  if (new PublicKey(idl.address).toString() !== programId.toString()) {
    throw new Error(`IDL address ${idl.address} != expected ${programId}`);
  }
  return new Program(idl, provider);
}

export function findPda(seeds: (Buffer | Uint8Array)[], programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(seeds, programId);
}

export function seedsBuf(...parts: (string | Buffer | number | Uint8Array)[]): Buffer[] {
  return parts.map((p) => (typeof p === "string" ? Buffer.from(p, "utf-8") : Buffer.from(p as any)));
}

export async function tokenBalance(tokenAccount: PublicKey): Promise<bigint> {
  return (await getAccount(connection, tokenAccount)).amount;
}

export async function solBalance(pubkey: PublicKey): Promise<number> {
  return (await connection.getAccountInfo(pubkey))?.lamports ?? 0;
}

export async function newFundedKeypair(sol = 20): Promise<Keypair> {
  const kp = Keypair.generate();
  await airdrop(kp.publicKey, sol);
  return kp;
}

/// Raw instruction to a native program: data[0] = op + optional payload
export function nativeIx(
  programId: PublicKey,
  op: number,
  payload: Buffer | null,
  keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[],
): TransactionInstruction {
  const data = Buffer.from([op, ...(payload ? payload : [])]);
  return new TransactionInstruction({
    programId,
    keys: keys.map((k) => ({ pubkey: k.pubkey, isSigner: k.isSigner, isWritable: k.isWritable })),
    data,
  });
}

export async function sendTx(
  ixs: TransactionInstruction[],
  signers: Keypair[],
  units?: number,
): Promise<string> {
  const tx = new Transaction();
  if (units) tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units }));
  for (const ix of ixs) tx.add(ix);
  return sendAndConfirmTransaction(connection, tx, signers);
}

/**
 * Sends a transaction paid & signed by `payer` even when the target
 * instruction does NOT require the payer's signature (typical for the
 * exploits here: the vulnerable program simply never checks). A 1-lamport
 * self-transfer forces the payer into the required-signer list so the
 * runtime accepts the fee payer signature.
 */
export async function sendSelfSigned(
  ixs: TransactionInstruction[],
  payer: Keypair,
  units?: number,
): Promise<string> {
  const tx = new Transaction();
  tx.feePayer = payer.publicKey;
  if (units) tx.add(ComputeBudgetProgram.setComputeUnitLimit({ units }));
  tx.add(
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: payer.publicKey,
      lamports: 1,
    }),
  );
  for (const ix of ixs) tx.add(ix);
  tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
  tx.sign(payer);
  const sig = await connection.sendRawTransaction(tx.serialize());
  await connection.confirmTransaction(sig, "confirmed");
  return sig;
}
