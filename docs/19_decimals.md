# 19 — Непроверенные decimals mint'а (unit confusion)

**Класс:** Unvalidated decimals — конверсия единиц строится на
`mint.decimals`, считанном из переданного вызывающим аккаунта, а сам mint
не ограничен whitelist'ом.
**Файлы:** `programs/vuln19_decimals/`, `tests/19_decimals.test.ts`.
**Последствие:** атакующий с самовыпущенным mint'ом на 0 знаков за
несколько транзакций выгребает из payout-хранилища весь обеспечивающий
депозит честных пользователей.

## 1. Суть уязвимости

Многие протоколы (конвертеры, мосты, reward-системы) начисляют внутренние
кредиты из «человеческих» единиц актива. Типовая формула:

```
credits = amount * 10^(BASE_DECIMALS - deposit_mint.decimals)
```

`deposit_mint.decimals` — это просто байт в данных аккаунта, который
**передал вызывающий**. Если аккаунт не привязан constraint'ом к
whitelist'у, атакующий приносит собственный mint:

- с `decimals = 0` множитель становится `10^6` — два «мусорных» юнита
  превращаются в 2 000 000 кредитов;
- с `decimals = 9` формула ломается в обратную сторону (или паникует на
  underflow, если вычитание без checked).

Это учебниковая unit confusion: одно значение из недоверенного источника
управляет всей экономикой инструкции. Рядовая проверка
`decimals <= 6` проблему не решает — она лишь отсекает «неправильное
направление».

## 2. Уязвимый код

```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // переводим токены в депозитное хранилище ...
    let dec = ctx.accounts.deposit_mint.decimals;          // БАГ: чей угодно mint
    require!(dec <= EXPECTED_DEPOSIT_DECIMALS, Err19::DecimalsTooLarge);

    let mult = 10u64.pow((EXPECTED_DEPOSIT_DECIMALS - dec) as u32);
    let credits = amount.checked_mul(mult).ok_or(Err19::Overflow)?;
    credits.amount += credits;                              // 2 юнита -> 2e6 кредитов
    Ok(())
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// БАГ: нет constraint `deposit_mint.key() == WHITELISTED_MINT`
    pub deposit_mint: Account<'info, Mint>,
    // ...
}
```

## 3. Как эксплуатируется

Тест `tests/19_decimals.test.ts`:

1. Честный сценарий: 6-знаковый «USDC» — депозит 1_000_000 даёт ровно
   1_000_000 кредитов.
2. Атакующий выпускает свой mint с `decimals = 0`, минтит себе 100 юнитов
   (реальная стоимость — ноль) и депонирует 2 юнита.
3. Формула начисляет `2 * 10^6 = 2_000_000` кредитов.
4. `withdraw(2_000_000)` выдаёт 2 USDC из хранилища, обеспеченного
   честными депозитами.
5. Цикл повторяется 4 раза — хранилище обнулено (10 USDC украдены).

```ts
await program.methods.deposit(new BN(2))            // 2 юнита мусорного mint'а
  .accounts({ depositMint: fakeMint, depositVaultTa: fakeVaultTa,
              userTa: attackerFakeTa, user: attacker.publicKey,
              credits: creditsOf(attacker) })
  .signers([attacker]).rpc();

await program.methods.withdraw(new BN(2_000_000))   // 2 USDC из казны
  .accounts({ usdcMint, usdcVault, usdcVaultTa, userUsdcTa: attackerUsdcTa,
              credits: creditsOf(attacker), user: attacker.publicKey })
  .signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

- Кредиты атакующего: ровно 2_000_000 за 2 депонированных юнита.
- `usdcVaultTa` обнулён — 10_000_000 base units (10 USDC) ушли атакующему.
- Честный депозит перед атакой подтвердил корректный курс 1:1 — ошибка
  именно в множителе для подменённого mint'а.

## 5. Реальные кейсы

- Класс «unchecked decimals / wrong unit scaling» — частый finding в
  аудиторских отчётах мостов и конвертеров; Sec3 (X-Ray) публиковал серии
  автоматических находок «decimals not checked» по mainnet-программам.
- **Cashio (2022, ~$28M)** — родственный корень: подмена *обеспечивающего*
  mint'а; здесь демонстрируется минимальный вариант той же ошибки через
  decimals вместо самого mint'а.
- Находки вида «decimals not checked» массово выдавал автоматический
  сканер Sec3 X-Ray по mainnet-программам (2022): в сочетании с
  open-инструкциями это прямая дорога к unit confusion.

## 6. Исправление

```rust
// ДО (баг): decimals из переданного аккаунта управляют множителем
let dec = ctx.accounts.deposit_mint.decimals;

// ПОСЛЕ: жёсткий пин mint'а — decimals больше не управляют ничем
#[account(constraint = deposit_mint.key() == crate::WHITELISTED_MINT @ Err19::WrongMint)]
pub deposit_mint: Account<'info, Mint>,
let mult = 10u64.pow((EXPECTED_DEPOSIT_DECIMALS - crate::WHITELISTED_DECIMALS) as u32);
```

Правила:

1. Любой аккаунт, чьи поля участвуют в расчёте сумм, либо пиннится
   constraint'ом, либо проходит проверку на допустимые значения из
   доверенного источника.
2. Все умножения степенями десятки — только с константами, а не с данными
   аккаунтов; разность `BASE - dec` считать в checked-арифметике.
3. Квоты/лимиты: одна инструкция не должна уметь выдавать больше X% казны,
   даже если вся арифметика «сошлась».

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/19_decimals.test.ts
```
