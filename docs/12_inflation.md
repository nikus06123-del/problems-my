# 12 — Share-inflation атака (первый депонент + донат + округление)

**Класс:** Vault share inflation / «inflation attack» (аналог ERC-4626).
**Файлы:** `programs/vuln12_inflation/`, `tests/12_inflation.test.ts`.
**Последствие:** депозит жертвы попадает в vault, но шеров не получает —
атакующий своим единственным шаром забирает весь vault.

## 1. Суть уязвимости

Share-vault конвертирует депозиты в «шеры» пропорционально:

```
shares = amount * total_shares / total_assets      (целочисленно, вниз)
assets = shares * total_assets / total_shares      (целочисленно, вниз)
```

где `total_assets` — **фактический** баланс token-аккаунта vault. Три
составляющие атаки:

1. **Первый депонент задаёт курс.** Депозит 1 токена даёт 1 шар: курс
   1:1, `total_shares = 1`.
2. **Донат раздувает `total_assets`.** Любой может перевести токены прямо в
   vault-аккаунт — шеры при этом не выпускаются, а балансовый расчёт идёт от
   фактического баланса.
3. **Округление вниз до нуля.** При `total_shares = 1` и раздутом балансе
   депозит жертвы даёт `amount * 1 / huge = 0` шеров. Токены приняты, доля —
   ноль.

Затем атакующий сжигает свой 1 шар и получает весь баланс vault, включая
депозит жертвы.

## 2. Уязвимый код

```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let balance = ctx.accounts.vault_ata.amount;        // фактический баланс
    let shares = if vault.total_shares == 0 {
        amount
    } else {
        // БАГ: округление вниз против раздутого донатом баланса
        amount * vault.total_shares / balance
    };
    token::transfer(user_ata -> vault_ata, amount)?;    // токены приняты всегда
    vault.total_shares += shares;                        // может быть 0!
    user_share.amount += shares;
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/12_inflation.test.ts`:

1. Атакующий — первый депонент: `deposit(1)` → 1 шар, баланс vault 1.
2. Атакующий «донирует» 99 999 токенов прямо в vault (в тесте — mint в
   адрес vault; эквивалентно прямому transfer) → баланс 100 000, шеров по-прежнему 1.
3. Жертва `deposit(50_000)`: `50_000 * 1 / 100_000 = 0` шеров. Токены ушли в
   vault, доля нулевая.
4. Атакующий `withdraw(1)`: `1 * 150_000 / 1 = 150_000` — весь vault.

```ts
// жертва получает 0 шеров за 50_000 токенов
const share = await program.account.userShare.fetch(shareOf(victim));
assert.equal(share.amount.toString(), "0");
// атакующий одним шаром забирает всё
await program.methods.withdraw(new BN(1)).accounts({ ... }).signers([attacker]).rpc();
assert.equal((await tokenBalance(tokenVault)).toString(), "0");
```

## 4. Результат атаки (проверяется тестом)

- `userShare` жертвы = 0 при внесённых 50 000 токенах — выводить нечего.
- Баланс vault после выхода атакующего = 0: депозит жертвы украден.
- Баланс атакующего: его исходные 99 999 + 150 000 из vault (в т.ч. 50 000 жертвы).

## 5. Реальные кейсы

- **ERC-4626 inflation attack** — классическая атака на стандартный vault
  Ethereum (первые публичные разборы — Bezier Finance, 2022; команда Midas
  потеряла ~$2.4M от связанных векторов округления). На Solana паттерн
  регулярно встречается в аудита share-моделей (Saber-подобные vault,
  стейкинг-программы).

## 6. Исправление

```rust
// 1) Считать total_assets из УЧЁТА, а не из баланса:
//    total_assets хранится в Vault и меняется только программой;
//    донат не увеличивает долю существующих шеров, а попадает в резерв.
// 2) Запрещать нулевые шеры и минимальный первый депозит:
require!(shares > 0, InflationError::ZeroShares);
// 3) Виртуальные шеры / dead shares при инициализации:
let shares = amount * (vault.total_shares + OFFSET) / (balance + OFFSET);
```

Правила:

1. Не доверять балансовому источнику `total_assets` — хранить учётное
   значение и выводить донаты через отдельный permissionless-механизм.
2. Запрет депозитов, округляющихся до 0 шеров (fail, а не «принял молча»).
3. Стандартная защита — виртуальные/деад-шеры и минимальная начальная
   ликвидность протокола.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/12_inflation.test.ts
```
