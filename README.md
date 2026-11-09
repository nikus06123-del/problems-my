# problems-my — База уязвимостей Solana-программ с рабочими эксплойтами

Учебный репозиторий: **20 классов уязвимостей** Solana-программ, каждая из
которых **доказуемо приводит к краже средств**. Для каждого класса — уязвимая
программа, **работающий exploit-тест** (реально крадёт SOL/токены на локальном
валидаторе) и разбор исправления.

> ⚠️ Только для обучения и аудита собственных программ. Все атаки выполняются
> на локальном тестовом валидаторе против демонстрационных программ этого
> репозитория.

## Что здесь есть

- **18 уязвимых Anchor-программ** (`programs/vuln01..vuln20`) — по одной на класс.
- **4 нативных (без Anchor) программы** (`native-programs/`): две уязвимые
  (arbitrary CPI, duplicate accounts), **программа атакующего** с режимами
  (подделка аккаунтов-данных, дрейн делегированного vault, фейковая
  token-программа, **фейковый оракул через return data**) и честный оракул
  для контраста.
- **20 exploit-тестов** (`tests/`) — 46 проверяемых сценариев, каждый
  подтверждает фактическую кражу балансами.
- **Русская база знаний** (`docs/`) — механика, пошаговая эксплуатация,
  реальные инциденты (Cashio, Mango Markets, Wormhole, Audius, Raydium),
  исправления до/после.

## Каталог уязвимостей

| # | Класс | Что крадут | Кейс | Документ |
|---|-------|------------|------|----------|
| 01 | Нет проверки подписи/владельца при выводе | Токены жертвы целиком | Neodyme/Sec3 класс ошибок | [docs/01](docs/01_missing_signer.md) |
| 02 | Подмена аккаунта-обеспечения | Эмит под фейк-залог, выкуп реального обеспечения | Cashio ~$28M | [docs/02](docs/02_account_substitution.md) |
| 03 | Поддельный аккаунт состояния | Reward-выплаты | Crema ~$8.9M | [docs/03](docs/03_forged_state.md) |
| 04 | Общий глобальный vault | Депозиты чужих пулов | Saber-подобные | [docs/04](docs/04_pda_confusion.md) |
| 05 | Произвольный CPI + подпись PDA | Весь fee-vault | Wormhole ~$325M | [docs/05](docs/05_arbitrary_cpi.md) |
| 06 | Integer overflow (wrapping) | Резерв хранилища | класс DeFi | [docs/06](docs/06_overflow.md) |
| 07 | Реинициализация `init_if_needed` | Свежие депозиты жертвы | Audius ~$6M | [docs/07](docs/07_reinit.md) |
| 08 | Дубликат mut-аккаунта | Резерв обеспеченности | Neodyme класс | [docs/08](docs/08_duplicate_accounts.md) |
| 09 | Непроверенный оракул | Вся ликвидность lending | Mango ~$114M | [docs/09](docs/09_oracle_manipulation.md) |
| 10 | Нарушенный check-effects-interactions | Двойные выплаты | класс Ethereum-атак | [docs/10](docs/10_reentrancy.md) |
| 11 | Нет проверки прав на privileged-инструкцию | Комиссии протокола | Raydium ~$4.4M | [docs/11](docs/11_access_control.md) |
| 12 | Share-inflation (округление + донат) | Депозиты последующих вкладчиков | ERC-4626 класс | [docs/12](docs/12_inflation.md) |
| 13 | Подделка sysvar (Clock) | Эскроу действующих ордеров | Neodyme/Sec3 класс | [docs/13](docs/13_fake_sysvar.md) |
| 14 | Ликвидация без health-check | Залог здоровых позиций | класс аудитов лендингов | [docs/14](docs/14_liquidation.md) |
| 15 | Непроверенная token-программа | SOL через фантомный депозит | класс Token-2022 | [docs/15](docs/15_token_program.md) |
| 16 | Close + воскрешение аккаунта (UAF) | Весь vault одной транзакцией | Neodyme «Closing Accounts», OptiFi | [docs/16](docs/16_close_reuse.md) |
| 17 | Доверие return data без проверки источника | Вся казна по фейковой цене | класс unchecked CPI source | [docs/17](docs/17_return_data.md) |
| 18 | Token-2022 transfer fee против номинального учёта | Комиссия с каждого buy-back | класс расширений T22 | [docs/18](docs/18_token2022.md) |
| 19 | Непроверенные decimals (unit confusion) | Весь payout-хранилище | класс «decimals not checked» (Sec3) | [docs/19](docs/19_decimals.md) |
| 20 | Privileged PDA из непроверенного аккаунта | Чужой escrow целиком, без подписи жертвы | класс аудитов «unvalidated authority derivation» | [docs/20](docs/20_escrow_authority.md) |

## Запуск эксплойтов

Требования: Solana CLI (Agave) с `cargo-build-sbf`, Node 18+, npm, Anchor 0.32.1.

```bash
npm install                 # зависимости TS-клиента
anchor build                # сборка программ + генерация IDL
python3 scripts/fix_idl.py  # IDL нового формата -> формат клиента 0.32
./scripts/run_tests.sh      # поднятие валидатора + все 46 exploit-тестов
```

Один тест:

```bash
./scripts/run_tests.sh tests/09_oracle_manipulation.test.ts
```

Экономия диска (использовать уже собранные `.so`):

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh
```

Ожидаемый результат: **46 passing**.

## Архитектура тестового стенда

```
Anchor.toml            18 Anchor-программ + 4 нативных (через [[test.genesis]])
programs/              vuln01..vuln20 (Anchor, solana-program 2.1.x)
native-programs/       vuln05, vuln08, attacker, oracle (нативный Rust, свой workspace)
tests/util.ts          helper'ы: PDA, airdrop, балансы, sendSelfSigned
scripts/run_tests.sh   сборка -> fix_idl -> solana-test-validator -> ts-mocha
```

Нюанс окружения: современные Agave-валидаторы требуют, чтобы CPI в System- и
BPF-программы содержали аккаунт самой вызываемой программы; PDA может «подписать»
создание аккаунта только через `invoke_signed`; инструкции без требуемых
подписантов оплачиваются через 1-lamport self-transfer (`sendSelfSigned`).

## План развития

- [ ] Аудит реально загруженных в репозиторий протокольных программ (по запросу).
- [x] Расширение базы до 15 классов (доступ-контроль, inflation, sysvar, ликвидации, token-program).
- [x] Расширение до 20 классов (close/UAF, return data, Token-2022, decimals, mint-mismatch).
- [ ] Публикация отчётов аудита в `reports/`.

## Лицензия

MIT — только для образовательных целей.
