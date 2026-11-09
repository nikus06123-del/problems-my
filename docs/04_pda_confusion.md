# 04 — Общий глобальный PDA-хранилище (PDA confusion)

**Класс:** неверная изоляция средств: одно глобальное хранилище на всех.
**Файлы:** `programs/vuln04_pda_confusion/`, `tests/04_pda_confusion.test.ts`.
**Последствие:** владелец любого пула выводит депозиты **всех остальных пулов**.

## 1. Суть уязвимости

Ошибка изоляции: несколько «клиентов» протокола (пулов, позиций, кампаний)
хранят средства **в одном общем PDA-аккаунте**, а лимиты вывода считаются по
данным чужого счётчика. Типовые варианты:

- `create_pool` для всех пулов сохраняет один и тот же `vault`;
- `withdraw` проверяет `amount <= vault.amount` (глобальный баланс) вместо
  `amount <= pool.total` (баланс своего пула).

В результате «свой» пул становится пропуском ко всем деньгам системы.

## 2. Уязвимый код

```rust
pub fn create_pool(ctx: Context<CreatePool>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    pool.authority = ctx.accounts.authority.key();
    pool.total = 0;
    // БАГ: каждый пул запоминает ОДИН и тот же глобальный vault
    pool.vault = ctx.accounts.vault.key();
    Ok(())
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let pool = &ctx.accounts.pool;
    require!(pool.authority == ctx.accounts.authority.key(), Fault::NotOwner);

    // БАГ: лимит берётся из ГЛОБАЛЬНОГО vault, а не из pool.total
    require!(amount <= ctx.accounts.vault.amount, Fault::InsufficientFunds);

    // ... перевод из общего vault любому authority ...
}
```

Проверка владения пулом есть — но она защищает только название пула, а не его
деньги: все пулы делят один vault, и лимит считается по нему же.

## 3. Как эксплуатируется

Тест `tests/04_pda_confusion.test.ts`:

1. Жертва создаёт пул и вносит в него 1000 токенов (в общий vault).
2. Атакующий создаёт **свой пустой** пул: `attackerPool.total = 0`.
3. Атакующий вызывает `withdraw(1000)` со своим пулом. Проверка
   `amount <= vault.amount` проходит, потому что vault — общий.

```ts
await program.methods.withdraw(new BN(1000)).accounts({
  pool: attackerPool,          // пустой пул атакующего
  authority: attacker.publicKey,
  destinationAta: attackerAta,
  vault: vaultPda,             // общий vault с деньгами всех пулов
}).signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(attackerAta)).toString(), "1000"); // чужие депозиты
assert.equal((await tokenBalance(vaultPda)).toString(), "0");
```

## 5. Реальные кейсы

- Фаусеты и пул-протоколы 2022 года неоднократно ловили этот класс: например,
  у **Saber** вскоре после запуска фабрик «stable pools» находили ошибки
  изоляции позиций/требований; серия протоколов с «faucet-функциональностью»
  (включая демонстрационные фикстуры аудиторских отчётов) теряла средства
  из-за вывода через чужие/общие хранилища.
- Класс описан Neodyme в материалах по аудиту Solana-программ («общение с
  состоянием через общие PDA»), регулярно встречается в программах,
  написанных «по шаблону» без отдельного vault на клиента.

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct WithdrawFixed<'info> {
    #[account(
        mut,
        seeds = [b"pool", authority.key().as_ref()],
        bump,
        has_one = authority,                       // пул действительно ваш
        constraint = pool.vault == vault.key()     // и vault этого пула...
        @ Fault::WrongVault
    )]
    pub pool: Account<'info, Pool>,
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [b"vault", pool.key().as_ref()],   // ...индивидуальный vault пула
        bump
    )]
    pub vault: Account<'info, TokenAccount>,
    // ...
}

pub fn withdraw_fixed(ctx: Context<WithdrawFixed>, amount: u64) -> Result<()> {
    require!(amount <= ctx.accounts.pool.total, Fault::InsufficientFunds); // лимит СВОГО пула
    // ...
}
```

Правила:

1. Средства каждого клиента — в **собственном** PDA-vault
   (`seeds = [b"vault", pool.key()]`) — тогда чужие деньги физически недостижимы.
2. Лимиты считаются по данным **своего** состояния, никогда — по глобальным
   остаткам общего аккаунта.
3. `constraint = pool.vault == vault.key()` — связь состояния и хранилища
   обязательна даже при индивидуальных vault.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/04_pda_confusion.test.ts
```
