# problems-my — База уязвимостей Solana-программ с рабочими эксплойтами

Учебный репозиторий: **10 классов уязвимостей** Solana-программ, каждая из
которых **доказуемо приводит к краже средств**. Для каждого класса — уязвимая
программа, **работающий exploit-тест** (реально крадёт SOL/токены на локальном
валидаторе) и разбор исправления.

> ⚠️ Только для обучения и аудита собственных программ. Все атаки выполняются
> на локальном тестовом валидаторе против демонстрационных программ этого
> репозитория.

## Что здесь есть

- **10 уязвимых Anchor-программ** (`programs/vuln01..vuln10`) — по одной на класс.
- **3 нативных (без Anchor) программы** (`native-programs/`): две уязвимые
  (arbitrary CPI, duplicate accounts) и **программа атакующего** с режимами:
  подделка аккаунтов-данных, дрейн делегированного vault.
- **10 exploit-тестов** (`tests/`) — 22 проверяемых сценария, каждый
  подтверждает фактическую кражу балансами.
- **Русская база знаний** (`docs/`) — механика, пошаговая эксплуатация,
  реальные инциденты (Cashio, Mango Markets, Wormhole, Audius), исправления
  до/после.

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

## Запуск эксплойтов

Требования: Solana CLI (Agave) с `cargo-build-sbf`, Node 18+, Yarn, Anchor 0.32.1.

```bash
yarn install                # зависимости TS-клиента
anchor build                # сборка программ + генерация IDL
python3 scripts/fix_idl.py  # IDL нового формата -> формат клиента 0.32
./scripts/run_tests.sh      # поднятие валидатора + все 22 exploit-теста
```

Один тест:

```bash
./scripts/run_tests.sh tests/09_oracle_manipulation.test.ts
```

Экономия диска (использовать уже собранные `.so`):

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh
```

Ожидаемый результат: **22 passing**.

## Архитектура тестового стенда

```
Anchor.toml            8 Anchor-программ + 3 нативных (через [[test.genesis]])
programs/              vuln01..vuln10 (Anchor, solana-program 2.1.x)
native-programs/       vuln05, vuln08, attacker (нативный Rust, свой workspace)
tests/util.ts          helper'ы: PDA, airdrop, балансы, sendSelfSigned
scripts/run_tests.sh   сборка -> fix_idl -> solana-test-validator -> ts-mocha
```

Нюанс окружения: современные Agave-валидаторы требуют, чтобы CPI в System- и
BPF-программы содержали аккаунт самой вызываемой программы; PDA может «подписать»
создание аккаунта только через `invoke_signed`; инструкции без требуемых
подписантов оплачиваются через 1-lamport self-transfer (`sendSelfSigned`).

## План развития

- [ ] Аудит реально загруженных в репозиторий протокольных программ (по запросу).
- [ ] Расширение базы: семантические уязвимости (флэш-лоан композиции, precision loss, fee-логика).
- [ ] Публикация отчётов аудита в `reports/`.

## Лицензия

MIT — только для образовательных целей.
