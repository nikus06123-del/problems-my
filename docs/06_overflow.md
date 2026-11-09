# 06 — Целочисленное переполнение (wrapping) в балансе

**Класс:** Integer overflow / underflow с отключённой проверкой переполнения.
**Файлы:** `programs/vuln06_overflow/`, `tests/06_overflow.test.ts`.
**Последствие:** отрицательный баланс → вывод «несуществующих» средств из
общего хранилища.

## 1. Суть уязвимости

В Rust `+`/`-` в release-сборке по умолчанию **не паникуют** при переполнении,
а «заворачиваются» (wrapping): `1u64 - 501u64 = 2^64 - 500`. В Solana SBF-сборке
паника при переполнении включается флагом `overflow-checks = true`, но
**Workspace-профиль может его отключить** (что делали некоторые проекты ради
экономии CU), либо разработчик использует `wrapping_sub` сам, либо приводит
типы (`as`) с усечением.

Протокол «накопительного счёта» здесь проверяет, что запрос не превышает
баланс **хранилища**, а уменьшает баланс **пользователя**. Логика:

```
require!(amount <= vault.amount)        // хватит ли в хранилище
balance.amount -= amount                // ← 1 - 501 = 2^64 - 500
vault → user: amount                    // реально выводим 501
```

## 2. Уязвимый код

```rust
// Cargo.toml (workspace) — ЧАСТЬ УЯЗВИМОСТИ:
// [profile.release]
// overflow-checks = false      // защита рантайма выключена

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let bal = &mut ctx.accounts.user_balance;
    // Проверки: amount <= vault.amount — но НЕ amount <= bal.amount!
    require!(amount <= ctx.accounts.vault.amount, Fault::InsufficientFunds);

    // БАГ: unchecked вычитание в release-сборке заворачивается
    bal.amount = bal.amount.wrapping_sub(amount);

    // переводим amount из общего хранилища атакующему
    token::transfer(/* vault → user */, amount)?;
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/06_overflow.test.ts`:

1. Жертва депонирует 500, атакующий — 1 токен. В хранилище 501.
2. Атакующий запрашивает `withdraw(501)`:
   - `501 <= 501` (проверка хранилища) — проходит;
   - `1 - 501` в его балансе **заворачивается**: `18446744073709551116`;
   - 501 токена уходят из хранилища атакующему — включая 500 жертвы.

```ts
await program.methods.withdraw(new BN(501))
  .accounts({ userBalance: attackerBalance, user: attacker.publicKey,
              destinationAta: attackerAta, vault: vaultPda })
  .signers([attacker]).rpc();

assert.equal((await tokenBalance(attackerAta)).toString(), "501");
assert.equal((await tokenBalance(vaultPda)).toString(), "0");
const bal = await program.account.userBalance.fetch(attackerBalance);
assert.equal(bal.amount.toString(), "18446744073709551116"); // 2^64 - 500
```

После атаки у атакующего «баланс» почти `u64::MAX` — протокол можно ещё
добить вызовом withdraw, но хранилище уже пусто.

## 4. Реальные кейсы

- Целочисленные баги — вечный класс EVM/SVM-DeFi. В Solana-экосистеме
  переполнения ловили в ранних версиях lending/стейкинга (например,
  находки в `spl-token-lending` и маркет-мейкерах приводили к некорректным
  коллатеральным расчётам), а паника рантайма («program panicked») до 2021
  сама вызывала DoS-инциденты, поэтому часть команд отключала проверки —
  и получала wrapping.
- Известный связанный инцидент с числами — **Zeta Markets/DEX-маржинальные
  расчёты** (2022): ошибки округления/типов в маржинальных формулах
  эксплуатировались для арбитража против хранилища.

## 5. Исправление

```rust
pub fn withdraw_fixed(ctx: Context<WithdrawFixed>, amount: u64) -> Result<()> {
    let bal = &mut ctx.accounts.user_balance;
    // 1) лимит по СОБСТВЕННОМУ балансу пользователя
    require!(amount <= bal.amount, Fault::InsufficientBalance);

    // 2) checked-арифметика — паника/ошибка вместо wrapping
    bal.amount = bal.amount.checked_sub(amount).ok_or(Fault::Math)?;

    token::transfer(/* vault → user */, amount)?;
    Ok(())
}
```

Правила:

1. **Никогда** не использовать `wrapping_add/sub/mul`; только `checked_`
   (возврат ошибки) или `saturating_` (где «прижимание к краю» — сознательно).
2. Держать `overflow-checks = true` в профиле сборки (это последний рубеж:
   паника отменит транзакцию).
3. Осторожно с `as`-приведениями (`u64 as i64`, `u128 as u64`) — усечение
   меняет знак/значение; использовать `try_from`.
4. Проверять лимит по **тому** счётчику, который уменьшается.

## 6. Запуск

```bash
./scripts/run_tests.sh tests/06_overflow.test.ts
```

> Примечание: тест демонстрирует wrapping именно потому, что в workspace-профиле
> выставлен `overflow-checks = false`. Уберите флаг — и атака станет паникой
> рантайма (откат транзакции).
