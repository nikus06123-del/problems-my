# 13 — Подделка sysvar-аккаунта (Clock) и свип активных эскроу

**Класс:** unchecked sysvar — «время» читается из аккаунта атакующего.
**Файлы:** `programs/vuln13_fake_sysvar/`, `tests/13_fake_sysvar.test.ts`,
эксплойт: режим 1 программы `native-programs/attacker`.
**Последствие:** атакующий «переводит часы в 2096 год» и забирает эскроу
ордеров, которые ещё действуют.

## 1. Суть уязвимости

Эскроу-ордера хранят SOL в персональном PDA с меткой `expires_at`. После
истечения любой желающий может вызвать `sweep` — забрать просроченный эскроу
как награду за уборку (типовой design cleanup-механизма). Время истечения
сравнивается с «сейчас», которое программа берёт **не** из `Clock::get()`, а
из переданного ей аккаунта:

- аккаунт `clock` — `UncheckedAccount` без проверки id/владельца,
- байты парсятся вручную (`unix_timestamp` по смещению 32).

Примечание по современному тулчейну: в solana-program 2.x даже небезопасно
выглядящий `Clock::from_account_info` защищён проверкой ключа и syscall'ом
`sol_get_clock_sysvar`, поэтому реалистичный уязвимый паттерн — именно
ручной парсинг байтов из аккаунта вызывающего (штатный тип `Sysvar<'info,
Clock>` или `Clock::get()` закрывает вектор полностью).

Атакующий создаёт аккаунт, чьи байты «читаются» как Clock с unix_timestamp
в далёком будущем, — и все ордера выглядят просроченными.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct Sweep<'info> {
    #[account(mut, close = executor, seeds = [b"order", order.creator.as_ref(), ...], bump)]
    pub order: Account<'info, Order>,
    /// CHECK: БАГ — должен быть настоящий Clock sysvar, но программа
    /// парсит байты без проверки id (Clock::get() был бы безопасен).
    pub clock: UncheckedAccount<'info>,
    #[account(mut)]
    pub executor: UncheckedAccount<'info>,
}

pub fn sweep(ctx: Context<Sweep>, order_id: u64) -> Result<()> {
    let data = &ctx.accounts.clock.try_borrow_data()?;
    let now = i64::from_le_bytes(data[32..40].try_into().unwrap()); // unix_timestamp
    require!(now > ctx.accounts.order.expires_at, EscrowError::NotExpired);
    // close() переводит ВСЕ лэмпорты (эскроу + рента) исполнителю
    ctx.accounts.order.close(ctx.accounts.executor.to_account_info())?;
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/13_fake_sysvar.test.ts` + режим 1 `attacker` (forge-аккаунт):

1. Жертва эскроит 1 SOL в ордер с TTL 3600 секунд.
2. Честный `sweep` с настоящим `SysvarC1ock...` отклоняется (`NotExpired`) —
   проверка времени в целом работает.
3. Атакующий через программу-атакующего создаёт forge-PDA и записывает в
   него 40 байтов: все пять полей «Clock» = 4 000 000 000 («2096 год»).
4. `sweep` с `clock = forgePda`: проверка проходит, `close` переводит
   эскроу + ренту атакующему. Ордер уничтожен — жертва не может даже
   отменить его (`cancel` падает: аккаунта нет).

```ts
const payload = Buffer.alloc(40);
for (let i = 0; i < 5; i++) payload.writeBigUInt64LE(BigInt(4_000_000_000), i * 8);
// forge через программу атакующего (mode 1), затем:
const sweepIx = await program.methods.sweep(new BN(ORDER_ID))
  .accounts({ order: victimOrder, clock: forgePda, executor: attacker.publicKey })
  .instruction();
await sendSelfSigned([sweepIx], attacker);
```

## 4. Результат атаки (проверяется тестом)

- Баланс атакующего вырос минимум на 1 SOL (эскроу + рента ордера).
- Аккаунт ордера удалён (`getAccountInfo == null`).
- Повторная `cancel` жертвы падает: эскроу вернуть некому и неоткуда.

## 5. Реальные кейсы

- Класс «unchecked sysvar / caller-supplied context» — постоянный finding
  в аудита Solana-программ (Neodyme «Think Memory», Sec3 X-Ray): любой
  аккаунт, который программа «доверяет» без проверки id/владельца,
  подменяем.
- Аналогичные векторы фиксировались в программах, принимавших fake Rent /
  EpochSchedule аккаунты для обхода тайм-локов и арендных ограничений.

## 6. Исправление

```rust
// ДО (баг): байты из произвольного аккаунта
let now = i64::from_le_bytes(data[32..40].try_into().unwrap());

// ПОСЛЕ: настоящий sysvar, без параметров
let now = Clock::get()?.unix_timestamp;
```

Правила:

1. Время берём только из `Clock::get()` или типизированного
   `Sysvar<'info, Clock>` (Anchor сам проверяет id).
2. Никогда не принимать sysvar как `UncheckedAccount`/`AccountInfo`.
3. Для ордеров с наградой за свип — отдельная награда из протокольного
   резерва, а не весь эскроу; свип не уничтожает возможность возврата.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/13_fake_sysvar.test.ts
```
