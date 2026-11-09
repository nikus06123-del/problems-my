# 10 — Нарушенный порядок «проверки → эффекты → взаимодействия» (реентрантность)

**Класс:** Broken check-effects-interactions: изменение состояния ПОСЛЕ
перевода средств/внешних вызовов.
**Файлы:** `programs/vuln10_reentrancy/`, `tests/10_reentrancy.test.ts`.
**Последствие:** одна permissionless-транзакция получает **двойную** выплату
из reward-хранилища.

## 1. Суть уязвимости

«Reentrant Faucet» — permissionless-фасет: любой может триггернуть выплату
награды получателю; флаг `claim_state.claimed` должен предотвращать повтор.
Баг: порядок действий в `claim` —

```
1. ПРОВЕРКА  guard: claimed == false        ✓
2. ЭФФЕКТ    перевод REWARD из vault        ← деньги ушли
3. (атака)   повторный вызов claim          ← guard всё ещё false!
4. STATE     claimed = true                 ← слишком поздно
```

Классический паттерн Ethereum-реентрантности: любое «взаимодействие»
(перевод токенов, вызов внешней программы) до фиксации состояния открывает
окно повторного входа.

## 2. Что изменил рантайм Solana (важно!)

В современном Agave **косвенная** реентрантность (A → B → A, например через
callback-программу атакующего) **запрещена рантаймом**:

```
Program log: Cross-program invocation reentrancy not allowed for this instruction
```

Это `InstructionError::ReentrancyNotAllowed`. **Прямая саморекурсия (A → A)
по-прежнему разрешена** — и это ровно то, чем пользуется наш exploit.

Наша уязвимая программа исторически содержала «listener-callback» (устаревший
вариант атаки). Сегодня рантайм его гасит, поэтому уязвимый код демонстрирует
тот же нарушенный порядок через **управляемую вызывающим самореинъекцию**:
флаг `op` в аргументах инструкции заставляет программу вызвать саму себя
(`op = 0`) до фиксации состояния.

## 3. Уязвимый код

```rust
pub fn claim(ctx: Context<Claim>, op: u8) -> Result<()> {
    // ПРОВЕРКА
    if ctx.accounts.claim_state.claimed {
        return Err(Fault::AlreadyClaimed.into());
    }

    // ЭФФЕКТ: выплата из общего vault
    token::transfer(vault → recipient_ata, REWARD_AMOUNT)?;

    // БАГ: управляемая вызывающим реинъекция ДО фиксации состояния.
    // Прямая саморекурсия (A→A) разрешена рантаймом.
    if op == 1 {
        let mut data = vec![62u8, 198, 214, 193, 213, 159, 108, 210]; // disc(claim)
        data.push(0u8); // вложенный op = 0 — рекурсия останавливается
        // self-CPI: те же привилегированные PDA-подписи vault
        invoke_signed(&nested_ix, &nested_infos, &[vault_seeds, claim_seeds])?;
    }

    // STATE СЛИШКОМ ПОЗДНО
    ctx.accounts.claim_state.claimed = true;
    Ok(())
}
```

Вложенный кадр проходит ту же проверку (`claimed` всё ещё false), получает
вторую выплату и фиксирует флаг; внешний кадр фиксирует его повторно.

## 4. Как эксплуатируется

Тест `tests/10_reentrancy.test.ts`:

1. Vault наполнен ровно на две награды (200 токенов). Атакующий создал свой
   claim-slot.
2. Атакующий вызывает `claim(op = 1)` — **без подписи получателя**,
   permissionless, только комиссия платится атакующим.
3. Одна транзакция → две выплаты в ATA атакующего.

```ts
const ix = await program.methods.claim(1).accounts({
  recipient: attacker.publicKey,
  recipientAta: attackerAta,
  vault: vaultPda,
  claimState: attackerClaim,
  tokenProgram: TOKEN_PROGRAM_ID,
  selfProgram: PROG_IDS.vuln10,   // CPI в BPF-программу требует её аккаунт
}).instruction();

await sendSelfSigned([ix], attacker, 600_000); // double CU: два claim в одной tx
```

## 5. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(attackerAta)).toString(), "200"); // 2 награды за 1 транзакцию
assert.equal((await tokenBalance(vaultPda)).toString(), "0");
assert.equal(state.claimed, true);                                 // флаг наконец-то установлен

// повторный claim — уже честно отклонён
assert.isTrue(failed);  // "claim must be single-use once the state finally commits"
```

## 6. Реальные кейсы

- **Audius (2022)** — self-CPI позволил обойти инварианты управляющего
  контракта и реинициализировать конфиг (см. doc 07).
- Исторический класс Ethereum (The DAO, 2016) в Solana смягчён рантаймом
  (ReentrancyNotAllowed для A→B→A), но **порядок операций** остаётся
  обязательным: window между «деньги ушли» и «флаг установлен» exploitable
  через прямую саморекурсию, flash-loan-композиции и CPI-обходы (см. doc 05).
- Neodyme и OtterSec регулярно находят в Solana-протоколах «state после
  interaction» даже вне классической реентрантности — например, двойной
  вывод через два вызова в одной транзакции, где guard обновляется после
  транферного CPI.

## 7. Исправление

```rust
pub fn claim_fixed(ctx: Context<Claim>) -> Result<()> {
    // 1) ПРОВЕРКА
    if ctx.accounts.claim_state.claimed {
        return Err(Fault::AlreadyClaimed.into());
    }

    // 2) ЭФФЕКТЫ — сначала состояние:
    ctx.accounts.claim_state.claimed = true;   // флаг ДО денег
    // + никакой управляемой вызывающим рекурсии: убрать `op`

    // 3) ВЗАИМОДЕЙСТВИЕ — деньги в конце:
    token::transfer(vault → recipient_ata, REWARD_AMOUNT)?;
    Ok(())
}
```

Правила:

1. **Проверки → Эффекты → Взаимодействия** — состояние всегда фиксируется
   до переводов и внешних вызовов.
2. Никаких caller-управляемых ветвлений в привилегированном коде (`op`,
   «plan», «mode» из данных инструкции — источник эксплойтов).
3. Для двойных гарантий — семафор-флаг с early-return в начале инструкции
   (в Solana за транзакцию аккаунт мог измениться — проверяйте reload).
4. Знайте рантайм: косвенная реентрантность (A→B→A) в современном Agave
   отклоняется (`ReentrancyNotAllowed`), но полагаться только на рантайм
   нельзя — прямая саморекурсия и ошибочный порядок операций остаются
   эксплуатируемыми.

## 8. Запуск

```bash
./scripts/run_tests.sh tests/10_reentrancy.test.ts
```
