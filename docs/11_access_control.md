# 11 — Отсутствие проверки прав на привилегированную инструкцию

**Класс:** Missing access control — «привилегированная» инструкция без
проверки подписанта/администратора.
**Файлы:** `programs/vuln11_access_control/`, `tests/11_access_control.test.ts`.
**Последствие:** любой пользователь уводит накопленные комиссии протокола
себе, просто передав свой кошелёк «администратором».

## 1. Суть уязвимости

Протокол накапливает комиссии (10% с каждого депозита) в PDA-хранилище и
учитывает их в config-аккаунте. Вывод комиссий — привилегированная операция:
она должна быть доступна только администратору. Самая частая ошибка из
аудитов — проверка отсутствует вообще:

- аккаунт `admin` **объявлен** в контексте (создаёт иллюзию контроля),
- но ни не помечен `Signer`, ни не сравнивается с `config.admin`.

Инструкция «проверяет» только то, что аккаунт *передан* — а передать можно
что угодно. Итог: `claim_fees` превращается в permissionless-вывод чужих
денег.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct ClaimFees<'info> {
    #[account(mut, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"fee_vault"], bump)]
    pub fee_vault: Account<'info, FeeVault>,
    /// CHECK: БАГ — админ требуется «к присутствию», но не проверяется:
    /// не Signer, не сравнивается с config.admin.
    pub admin: UncheckedAccount<'info>,
    /// CHECK: получатель комиссий — полностью под контролем атакующего.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

pub fn claim_fees(ctx: Context<ClaimFees>) -> Result<()> {
    let amount = ctx.accounts.config.fees_collected;
    require!(amount > 0, FeeError::NothingToClaim);
    // ... перевод лэмпортов из fee_vault в recipient ...
    ctx.accounts.config.fees_collected = 0;
    Ok(())
}
```

## 3. Как эксплуатируется

Тест `tests/11_access_control.test.ts`:

1. Два честных пользователя депонируют по 5 SOL — комиссия 1 SOL копится в
   `fee_vault` и учитывается в `config.fees_collected`.
2. Атакующий вызывает `claimFees`, передав **свой** кошелёк и как `admin`,
   и как `recipient`. Ни одной подписи администратора в транзакции нет.
3. 1 SOL комиссий уходит атакующему, счётчик комиссий обнуляется.

```ts
const ix = await program.methods.claimFees()
  .accounts({
    config, feeVault,
    admin: attacker.publicKey,      // "админ" = атакующий, ничего не проверяется
    recipient: attacker.publicKey,  // комиссии идут ему
  })
  .instruction();
await sendSelfSigned([ix], attacker);   // ни одного обязательного подписанта
```

## 4. Результат атаки (проверяется тестом)

- Баланс атакующего вырос минимум на 1 SOL (вся накопленная комиссия).
- `config.fees_collected == 0` — «вывод» прошёл как легитимный.
- В vault остались только депозиты (9 SOL): уязвимость крадёт комиссии, но
  атакующий повторяет её после каждой порции депозитов.

## 5. Реальные кейсы

- **Raydium AMM (декабрь 2022)** — баг в обновлении программы пула позволил
  выводить средства поставщиков ликвидности без должных проверок авторизации;
  украдено ~$4.4M, компенсировано из казны команды.
- Класс «missing authority check» — один из двух самых частых findings в
  отчётах Neodyme/Sec3 (2021–2022) и всех основных аудиторских бюро.

## 6. Исправление

```rust
// ДО (баг): админ не проверяется
pub admin: UncheckedAccount<'info>,

// ПОСЛЕ: строго Signer + сверка с config
#[account(constraint = admin.key() == config.admin @ FeeError::NotAdmin)]
pub admin: Signer<'info>,
```

Правила:

1. Каждая привилегированная инструкция обязана иметь `Signer<'info>`-поле
   администратора с `has_one`/`constraint`-сверкой на config.
2. Наличие аккаунта в списке — не проверка; Anchor проверяет только структуру.
3. В CI — линтер/тест «каждый privileged-метод вызывается только админом».

## 7. Как запустить

```bash
SKIP_BUILD=1 ./scripts/run_tests.sh tests/11_access_control.test.ts
```
