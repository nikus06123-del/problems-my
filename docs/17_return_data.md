# 17 — Доверие CPI return data без проверки программы-источника

**Класс:** Unchecked return data — программа читает ответ CPI через
`get_return_data()` и проверяет только форму данных (длину), игнорируя
половину пары `(program_id, data)`.
**Файлы:** `programs/vuln17_return_data/`, `tests/17_return_data.test.ts`,
`native-programs/oracle/`, режим 7 программы атакующего.
**Последствие:** любой контракт подменяет «оракула» и одной транзакцией
выкупает всё хранилище по завышенной цене.

## 1. Суть уязвимости

`get_return_data()` в Solana возвращает пару `(Pubkey, Vec<u8>)`:
программный id того, кто вернул данные, и сами байты. Ответ остаётся в
реестре только в пределах текущей инструкции и перезаписывается каждым
следующим CPI — поэтому доверять можно только данным конкретной,
проверенной программы.

Уязвимый паттерн появляется, когда разработчик:

- строит CPI к аккаунту `price_program`, который **не ограничен** ни
  constraint'ом, ни типом `Program<'info, ...>`;
- читает ответ и проверяет лишь `data.len() == 8`.

В итоге «оракул» — это любая программа, которую передал вызывающий.
Атакующий пишет контракт, который на запрос цены отвечает нужным ему
числом через `set_return_data`, и операция «redeem по цене оракула»
превращается в свободную раздачу казны.

## 2. Уязвимый код

```rust
// CPI: op 7 = "get price"
let ix = Instruction {
    program_id: ctx.accounts.price_program.key(),  // БАГ: кто угодно
    accounts: vec![],
    data: vec![7u8],
};
invoke(&ix, &[ctx.accounts.price_program.to_account_info()])?;

// БАГ: program_id из пары игнорируется
let (_src, data) = get_return_data().ok_or(Err17::NoReturnData)?;
require!(data.len() == 8, Err17::BadReturnData);
let price = u64::from_le_bytes(data[..8].try_into().unwrap());
```

## 3. Как эксплуатируется

Тест `tests/17_return_data.test.ts`:

1. Честный сценарий: оракул (`native-programs/oracle`, op 7 →
   `1_000_000` лэмпортов за лот) отвечает честно; пользователь обменивает
   2 лота на 0.002 SOL — суммы сходятся.
2. Атакующий получает 10 лотов бесплатно (`earn`).
3. Вызывает `redeem(10)`, передав в `priceProgram` **программу атакующего**
   (режим 7: `set_return_data(&2_000_000_000u64.to_le_bytes())` — 2 SOL за
   лот вместо 0.001).
4. Выплата `10 * 2_000_000_000 = 20 SOL` опустошает vault целиком.

```ts
await program.methods.redeem(new BN(10))
  .accounts({
    vault, credits, user: attacker.publicKey,
    priceProgram: PROG_IDS.attacker,      // <- фейковый «оракул»
    destination: attacker.publicKey,
  })
  .signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

- Баланс атакующего вырос на ~20 SOL — весь funding хранилища.
- В vault остались лишь лэмпорты ренты.
- `credits.lots == 0` — «выкуп» оформлен как легитимный.
- Честный тест перед атакой подтверждает: с настоящим оракулом те же лоты
  стоят 0.002 SOL — цена завышена в 2000 раз.

## 5. Реальные кейсы

- Класс «unchecked CPI source / return data» — стандартный finding аудитов
  оракул-интеграций; Sec3 и Neodyme в циклах статей (2022) отдельно
  разбирали доверие к `get_return_data`.
- **Wormhole (2022, ~$325M)** — родственный корень: доверие к *подписи*
  вместо доверия к *источнику*. Здесь та же ошибка сделана относительно
  return data вместо verify-signatures.
- **Mango Markets (2022, ~$114M)** — итоговый ущерб посчитан по цене
  оракула; здесь показан минимальный механизм, которым цену может задать
  сам атакующий.

## 6. Исправление

```rust
// ДО (баг)
let (_src, data) = get_return_data().ok_or(Err17::NoReturnData)?;

// ПОСЛЕ: проверяем ОБЕ половины пары
let (src, data) = get_return_data().ok_or(Err17::NoReturnData)?;
require!(src == crate::TRUSTED_ORACLE_ID @ Err17::UntrustedOracle);
require!(data.len() == 8, Err17::BadReturnData);
```

Правила:

1. Пинните аккаунты внешних программ типом `Program<'info, OracleProgram>`
   или constraint'ом — тогда подмена невозможна на этапе вывода контекстов.
2. `get_return_data()` без сравнения `program_id` — всегда баг.
3. Числа из внешнего мира ограничивайте разумным диапазоном
   (`price <= MAX_SANE_PRICE`) — даже скомпрометированный оракул не должен
   уметь выплачивать больше X% казны за одну инструкцию.

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/17_return_data.test.ts
```
