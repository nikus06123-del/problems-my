# 16 — Закрытие аккаунта и «воскрешение» (use-after-free) в одной транзакции

**Класс:** Account close + resurrection — программа уничтожает аккаунт без
проверки прав, а PDA-семена освобождаются и могут быть пересозданы заново —
даже в той же самой транзакции.
**Файлы:** `programs/vuln16_close_reuse/`, `tests/16_close_reuse.test.ts`.
**Последствие:** любой пользователь одной атомарной транзакцией уничтожает
state протокола, пересоздаёт его с собой в роли authority и опустошает всё
хранилище.

## 1. Суть уязвимости

В Solana аккаунт существует, пока у него есть лэмпорты и данные. PDA
уникален только пока аккаунт жив: как только лэмпорты обнулены, данные
усечены до нуля, а владелец сброшен на system program, семена свободны —
адрес можно создать заново с любым содержимым.

Ошибка возникает из двух недосмотров:

1. «Техническая» инструкция `close_state` (рассчитана на миграции) не
   проверяет, кто её вызывает;
2. нигде не запрещена повторная инициализация тех же PDA-семян.

По отдельности каждый баг выглядит безобидно; вместе они дают классический
use-after-free: «идентичность» PDA переживает уничтожение, история данных —
нет. Anchor-атрибут `close = ..` оставляет closed-account-дискриминатор,
который блокирует мгновенный ре-инит — поэтому атакуемая программа
использует «ручное» закрытие: `lamports = 0` + `realloc(0)` + смена
владельца на system program.

## 2. Уязвимый код

```rust
pub fn close_state(ctx: Context<CloseState>) -> Result<()> {
    let st = ctx.accounts.state.to_account_info();
    let dst = ctx.accounts.refund.to_account_info();

    // рента -> refund
    let new_dst = dst.lamports().checked_add(st.lamports()).ok_or(Err16::Overflow)?;
    **dst.lamports.borrow_mut() = new_dst;

    // БАГ: полное освобождение без какой-либо проверки прав
    **st.lamports.borrow_mut() = 0;
    st.realloc(0, false)?;
    st.assign(&system_program::ID);
    Ok(())
}

#[derive(Accounts)]
pub struct CloseState<'info> {
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, VaultState>,
    /// CHECK: БАГ — никто не проверяет право закрывать state.
    #[account(mut)]
    pub refund: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}
```

## 3. Как эксплуатируется

Тест `tests/16_close_reuse.test.ts` собирает **одну транзакцию** из трёх
инструкций:

```ts
const closeIx = await program.methods.closeState()
  .accounts({ state, refund: attacker.publicKey }).instruction();
const initIx = await program.methods.initialize()
  .accounts({ state, authorized: attacker.publicKey, payer: attacker.publicKey })
  .instruction();
const withdrawIx = await program.methods.withdraw(new BN(all))
  .accounts({ state, vault, authorized: attacker.publicKey, recipient: attacker.publicKey })
  .instruction();
await sendTx([closeIx, initIx, withdrawIx], [attacker]);
```

Пошагово:

1. Честный пользователь внёс 20 SOL в протокольный vault; `state.authorized`
   — ключ команды, вывод требует подписи authority.
2. Атакующий вызывает `closeState` — state уничтожается, рента уходит ему.
3. Той же транзакцией `initialize` пересоздаёт PDA `[b"state"]` уже с
   `authorized = атакующий` (п payer'ом и подписантом выступает он сам).
4. `withdraw` выводит весь vault — проверка `authorized` проходит, потому
   что в новом state именно атакующий записан authority.

## 4. Результат атаки (проверяется тестом)

- Баланс атакующего вырос на весь vault (~20 SOL за вычетом комиссии).
- В vault остались только ~10 000 лэмпортов.
- `state.authorized == attacker` — протокол «легально» отдал деньги новому
  authority.
- Попытка withdraw до атаки падает с `NotAuthorized` — защита работала ровно
  до первого close.

## 5. Реальные кейсы

- **Neodyme, «Solana Security: Closing Accounts»** — канонический разбор
  класса: закрытый аккаунт можно пересоздать в той же транзакции, если
  программа не оставляет закрытого дискриминатора/данных.
- **OptiFi (сентябрь 2022)** — при апгрейде команда случайно закрыла
  аккаунт собственной AMM-программы (~$700K заморожено). Инцидент показал,
  насколько необратимо закрытие и почему каждая close-инструкция должна
  быть привилегированной.
- Класс «account close / re-init» — регулярный finding аудиторских отчётов
  (OtterSec, Neodyme, Sec3) для маркетплейсов и эскроу.

## 6. Исправление

```rust
// ДО (баг): ручное закрытие без проверки прав
**st.lamports.borrow_mut() = 0;
st.realloc(0, false)?;
st.assign(&system_program::ID);

// ПОСЛЕ: Anchor close + строгая проверка authority
#[account(
    mut,
    seeds = [b"state"], bump,
    close = refund,
    constraint = caller.key() == state.authorized @ Err16::NotAuthorized
)]
pub state: Account<'info, VaultState>,
```

Правила:

1. Anchor `close = ..` оставляет closed-дискриминатор — не «обходите» его
   ручным realloc(0): это защита, а не помеха.
2. Любая инструкция, меняющая lamports/владельца/длину данных, обязана
   проверять authority (`Signer` + сверка с state).
3. Повторный `initialize` тех же семян должен быть невозможен: либо
   используйте флаг `initialized` в отдельном вечном аккаунте, либо
   односторонний «seal»-аккаунт, который нельзя закрыть.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/16_close_reuse.test.ts
```
