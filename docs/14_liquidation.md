# 14 — Ликвидация без проверки health-factor

**Класс:** Missing health check in liquidation — «ликвидация» здоровых позиций.
**Файлы:** `programs/vuln14_liquidation/`, `tests/14_liquidation.test.ts`.
**Последствие:** атакующий «ликвидирует» здоровую позицию: гасит небольшой
долг, забирает весь залог и бонус из страхового резерва.

## 1. Суть уязвимости

Лендинг-протокол корректно ограничивает заём LTV ≤ 80%: позиция становится
«под водой» только из-за движения цены обеспечения. Ликвидация существует
ровно для этого случая: ликвидатор гасит долг пулу и забирает залог с
бонусом 5% из страхового резерва.

БАГ: инструкция `liquidate` **не проверяет** health-factor позиции вообще.
Любая позиция — хоть LTV 10% — может быть «ликвидирована»:

- ликвидатор платит долг (маленький),
- получает залог целиком (большой) через `close`,
- получает бонус из пула.

Для позиции 10 SOL залога / 5 SOL долга (LTV 50% — здоровая) это гарантированный
профит ~5.5 SOL за одну транзакцию.

## 2. Уязвимый код

```rust
pub fn liquidate(ctx: Context<Liquidate>) -> Result<()> {
    let debt = ctx.accounts.position.debt;
    let collateral = ctx.accounts.position.collateral;

    // БАГ: проверка health-factor ОТСУТСТВУЕТ. Должно быть:
    // require!(debt * 100 > collateral * 80, LendError::NotLiquidatable);

    // 1) ликвидатор гасит долг в пул
    system transfer liquidator -> pool (debt)?;
    // 2) бонус 5% из страхового резерва
    let bonus = collateral * LIQ_BONUS_NUM / LIQ_BONUS_DEN;
    direct lamport move pool -> liquidator (bonus)?;
    // 3) позиция закрывается — ликвидатор получает весь залог
    ctx.accounts.position.close(ctx.accounts.liquidator.to_account_info())?;
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/14_liquidation.test.ts`:

1. Пул фондируется 10 SOL. Жертва: залог 10 SOL, заём 5 SOL (LTV 50%).
2. Тест подтверждает, что cap работает: попытка занять сверх 80% отклоняется
   (`OverLtv`).
3. Атакующий вызывает `liquidate` по ЗДОРОВОЙ позиции: платит 5 SOL,
   получает 10 SOL залога + 0.5 SOL бонуса.

```ts
await program.methods.liquidate()
  .accounts({ position, pool, liquidator: attacker.publicKey })
  .signers([attacker]).rpc();

const profit = (await solBalance(attacker.publicKey)) - attackerBefore;
assert.isAtLeast(profit, 5.5 * LAMPORTS_PER_SOL - 10_000); // -5 долг, +10 залог, +0.5 бонус
```

## 4. Результат атаки (проверяется тестом)

- Профит атакующего ≈ 5.5 SOL (в диапазоне 5.5–5.6 SOL с рентой и комиссиями).
- Позиция жертвы удалена — залог 10 SOL утерян за долг 5 SOL.
- Пул: −0.5 SOL страхового резерва (бонус), долг возвращён.

## 5. Реальные кейсы

- Отсутствие/ошибка health-check в liquidate — регулярный finding
  аудита лендингов; частный случай «привилегированная операция без условия
  применимости».
- Экономический аналог: «liquidable-at-profit» баги (ранние версии
  fork'ов Compound на разных цепях) — ликвидатор получал больше, чем
  компенсировал, на здоровых позициях.

## 6. Исправление

```rust
// ПОСЛЕ: ликвидировать можно только под-водную позицию
require!(
    ctx.accounts.position.debt * LIQ_BONUS_DEN
        > ctx.accounts.position.collateral * (MAX_LTV_NUM - 5),
    LendError::NotLiquidatable
);
```

Правила:

1. Каждая «принудительная» операция обязана проверять предусловие
   применимости (health-factor, истечение, состояние).
2. Бонус ликвидатора платить пропорционально погашенному долгу и из
   отдельного резерва, не из залога сверх долга.
3. Тест-минимум аудита: ликвидация здоровой позиции НЕВОЗМОЖНА.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/14_liquidation.test.ts
```
