# 20 — Swap доверяет любому аккаунту-входу (пул «продаёт» сам себе)

**Класс:** Unvalidated swap inputs — обмен не проверяет, что входной
токен-аккаунт действительно принадлежит вызывающему и содержит ожидаемый
mint. Входом может оказаться собственный аккаунт пула.
**Файлы:** `programs/vuln20_mint_mismatch/`, `tests/20_mint_mismatch.test.ts`.
**Последствие:** пул обменивает сам с себя: self-transfer «оплачивает»
вход нулевой ценой, а реальный актив утекает из пула, пока не кончится.

## 1. Суть уязвимости

Классический AMM-инвариант: *за каждый выходной токен покупатель платит
входным*. Инвариант держится только тогда, когда вход и выход — это два
разных, принадлежащих разным сторонам аккаунта. Проверять нужно:

1. mint входного аккаунта (`user_in_ta.mint == pool.mint_a`);
2. что входной аккаунт — не один из аккаунтов самого пула
   (`user_in_ta != pool_ta_a`);
3. что выходной аккаунт корректен (`user_out_ta.mint == pool.mint_b`).

Современная SPL Token-программа сама отвергает перевод между разными
mint'ами (ошибка `MintMismatch`, 0x3), поэтому «перелив» чужого актива
минуя проверки в чистом виде уже не работает. Но пункт 2 токен-программа
проверить не может: authority аккаунта пула — это PDA пула, и уязвимая
программа сама подписывает CPI своими seed'ами. self-transfer
`pool_ta_a -> pool_ta_a` легален и ничего не меняет, а программа считает
вход «оплаченным» и выплачивает 2x из реального резерва.

## 2. Уязвимый код

```rust
pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
    let out = amount.checked_mul(2).ok_or(Err20::Overflow)?;

    // БАГ: user_in_ta принимается как есть — это может быть сам pool_ta_a
    token::transfer(CpiContext::new(..., Transfer {
        from: ctx.accounts.user_in_ta.to_account_info(),   // = pool_ta_a в атаке
        to: ctx.accounts.pool_ta_a.to_account_info(),
        authority: ctx.accounts.user.to_account_info(),
    }), amount)?;

    // выплата 2x из реального резерва
    token::transfer(CpiContext::new_with_signer(..., Transfer {
        from: ctx.accounts.pool_ta_b.to_account_info(),
        to: ctx.accounts.user_out_ta.to_account_info(),
        authority: ctx.accounts.pool.to_account_info(),
    }, &[&pool_seeds]), out)
}
```

## 3. Как эксплуатируется

Тест `tests/20_mint_mismatch.test.ts`:

1. Честный сценарий: 100 A → 200 B, инвариант выполняется.
2. Атакующий вызывает `swap(amount = ВЕСЬ баланс pool_a)` пять раз,
   передавая `userInTa = poolTaA` (аккаунт пула!) и
   `userOutTa = свой аккаунт`:
   - первая CPI: `pool_ta_a → pool_ta_a` — self-transfer, баланс пула A
     не меняется, атакующий ничего не платит;
   - вторая CPI: `pool_ta_b → атакующий` — 2x от номинала.
3. Пять раундов по 2 × 100 A = 1000 B уходит атакующему без всякой оплаты.

```ts
await program.methods.swap(new BN(poolABalance.toString()))
  .accounts({
    pool, poolTaA, poolTaB,
    userInTa: poolTaA,        // <- БАГ: аккаунт пула в роли входа
    userOutTa: attackerTaB,
    user: attacker.publicKey,
  })
  .signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

- Баланс `pool_ta_a` НЕ уменьшился — входная сторона атаки бесплатна.
- Баланс `pool_ta_b` упал ровно на 10 × 100 A (пять раундов × 2x).
- Аккаунт атакующего получил ровно столько же реального токена B.
- Честный swap перед атакой подтвердил корректную работу пула — ошибка
  именно в отсутствии проверки входного аккаунта.

## 5. Реальные кейсы

- Класс «swap does not validate accounts» — регулярный critical-finding
  аудитов AMM/маркетплейсов на Solana (OtterSec, Neodyme) с 2022 года:
  вход и выход совпадают, вход — аккаунт самого пула, или LP-аккаунты
  подменяются.
- Родственный корень у **Cashio (2022, ~$28M)** и **Raydium (2022, ~$4.4M)**:
  деньги выводились «правильными» инструкциями протокола — проблема была
  в том, что инструкции не проверяли *принадлежность* и *подлинность*
  переданных аккаунтов.

## 6. Исправление

```rust
// ДО (баг): вход принимается как есть
pub user_in_ta: Account<'info, TokenAccount>,

// ПОСЛЕ: пин mint'а + запрет аккаунтов пула во входе
#[account(
    mut,
    constraint = user_in_ta.mint == pool.mint_a @ Err20::WrongInMint,
    constraint = user_in_ta.key() != pool_ta_a.key() @ Err20::SelfTrade,
    constraint = user_in_ta.owner == user.key() @ Err20::ForeignInput,
)]
pub user_in_ta: Account<'info, TokenAccount>,
```

Правила:

1. Инвариант AMM: вход и выход — всегда разные аккаунты, принадлежащие
   разным сторонам; оба пиннятся mint-constraint'ом.
2. Проверка `user_in_ta != pool_ta_*` обязательна: токен-программа не
   защищает протокол от использования его собственных аккаунтов.
3. Пересчёт резерва после каждой инструкции: сумма входов пула за
   транзакцию должна соответствовать сумме выходов (в противоход
   инварианту цены).

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/20_mint_mismatch.test.ts
```
