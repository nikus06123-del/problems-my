# 08 — Дубликаты аккаунтов: один аккаунт дважды в списке

**Класс:** Duplicate mutable accounts — одна и та же учётная запись передана
на двух позициях, обе помечены `mut`.
**Файлы:** `native-programs/vuln08_duplicate_accounts/`,
`tests/08_duplicate_accounts.test.ts`.
**Последствие:** «внутренний обмен» между одинаковыми аккаунтами удваивает
бухгалтерские кредиты, которыми затем выкупается реальный резерв.

## 1. Суть уязвимости

Рантайм Solana **не запрещает** передавать один и тот же аккаунт дважды
(суммарно одинаковых AccountInfo может быть сколько угодно). Если программа
читает `accounts[0]` как «источник», `accounts[1]` как «получатель» и делает
вычитание/сложение, то при `from == to` получается:

```
from.amount -= amount   // прочитано 5, записано 0
to.amount   += amount   // прочитано 0 (или 5), записано 10
```

Итог: сумма двух «участников» **увеличилась из ниоткуда**. Классическая
вариация — это списание с одного и того же счётчика дважды, инверсия кредитов
или «самообмен», после которого бумажный баланс превышает обеспеченность.

Программа «Ledger book» (нативная) поддерживает счета-книги: `deposit`
кредитует счёт за реальный SOL в резерве, `swap` — «внутренний обмен»
кредитами между книгами, `redeem` — выкуп кредитов за SOL из резерва.

## 2. Уязвимый код (нативный Rust)

```rust
fn swap(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let ai = &mut accounts.iter();
    let from = next_account_info(ai)?;   // БАГ: не проверяется from != to
    let to   = next_account_info(ai)?;

    let from_amt = u64::from_le_bytes(from.try_borrow_data()?[8..16].try_into().unwrap());
    let to_amt   = u64::from_le_bytes(to.try_borrow_data()?[8..16].try_into().unwrap());
    require!(from_amt >= amount, ProgramError::InsufficientFunds);

    let mut from_data = from.try_borrow_mut_data()?;
    let mut to_data   = to.try_borrow_mut_data()?;
    // БАГ: если from.key == to.key, оба borrow ссылаются на ОДНИ байты
    from_data[8..16].copy_from_slice(&(from_amt - amount).to_le_bytes());
    to_data[8..16].copy_from_slice(&(to_amt + amount).to_le_bytes());
    Ok(())
}
```

При `from == to` вычитание и сложение применяются к одним и тем же байтам:
итог = `from_amt + amount`. Кредиты удваиваются без реального обеспечения.

## 3. Как эксплуатируется

Тест `tests/08_duplicate_accounts.test.ts`:

1. Жертва депонирует 1 SOL, атакующий — 0.5 SOL. В резерве 1.5 SOL.
2. Атакующий вызывает `internal_swap(from = СВОЯ книга, to = ТА ЖЕ книга, 0.5 SOL)`.
3. Кредиты его книги удваиваются: 0.5 → 1.0 SOL без внесения обеспечения.
4. `redeem(1.0 SOL)` — программа выплачивает из резерва, забирая
   **обеспечение жертвы**.

```ts
await swap(attackerBook, attackerBook, 500000000, attacker); // from == to!
assert.equal((await bookAmount(attackerBook)).toString(), "1000000000"); // x2

const before = await solBalance(attacker.publicKey);
await redeem(attackerBook, attacker, 1000000000);
assert.equal(await solBalance(reservePda), 500000000); // на 1 SOL жертвы остался полрезерва
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await bookAmount(attackerBook)).toString(), "1000000000");  // фейковые кредиты
assert.equal(after - before, 1000000000 - 5000);                          // выкуплены за SOL
assert.equal(await solBalance(reservePda), 500000000);                    // жертва недообеспечена
```

## 5. Реальные кейсы

Класс «duplicate accounts» детально описан Neodyme в
«Think Memory, Not What» (2021) и стал обязательной проверкой аудитов:
программы, где `from`/`to`, `left`/`right` или `pool_a`/`pool_b` не сверяются,
позволяют самообмен и арбитраж против резервов. Аналогичные дубликаты
приводили к дрейну маркет-мейкеров и «free mint»-багам в AMM 2021–2022
(до введения обязательных identity/constraint-проверок в шаблонах Anchor).

## 6. Исправление

```rust
fn swap_fixed(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let from = next_account_info(ai)?;
    let to   = next_account_info(ai)?;
    if from.key == to.key {
        return Err(ProgramError::InvalidArgument);   // 1) запрет дубликата
    }
    // 2) проверка владельца/принадлежности программе
    if from.owner != program_id || to.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    // 3) только затем арифметика
}
```

В Anchor это закрывается декларативно:

```rust
#[account(mut, constraint = from_account.key() != to_account.key @ Fault::DuplicateAccounts)]
pub from_account: Account<'info, Ledger>,
#[account(mut, constraint = to_account.key() != from_account.key @ Fault::DuplicateAccounts)]
pub to_account: Account<'info, Ledger>,
```

Правила:

1. Для каждой пары «источник/получатель» — явный `constraint !=`.
2. Проверять `owner` всех аккаунтов, чьи данные вы мутируете.
3. При сложных инвариантах (Σ балансов константа) — сверять сумму до и после.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/08_duplicate_accounts.test.ts
```
