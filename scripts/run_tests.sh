#!/usr/bin/env bash
# Fresh validator + full exploit test suite.
# Usage: ./scripts/run_tests.sh [pattern]
set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# Rebuild programs + IDLs, then post-process the IDLs (new spec -> legacy
# layout for the TS client) before the validator starts.
# SKIP_BUILD=1 reuses the existing target/deploy/*.so + target/idl (saves disk).
if [ "$SKIP_BUILD" != "1" ]; then
  anchor build > /tmp/anchor-build.log 2>&1 || { tail -20 /tmp/anchor-build.log; exit 1; }
  rm -rf target/debug target/release
fi
python3 scripts/fix_idl.py

pkill -f solana-test-validator 2>/dev/null || true
sleep 2
rm -rf .test-ledger

solana-test-validator --reset \
  --bpf-program 6TSqBs2dvRzsDg52g9qh8Nf4TUKRdAM5YjjoXyHFpDh8 target/deploy/vuln01_missing_signer.so \
  --bpf-program 1XeQ8irpogAJTxNP7MiAk5SgAi7UZkyi7RmTASxVhRY target/deploy/vuln02_account_substitution.so \
  --bpf-program H1W4DzzYBd6iz6UnqEddqjSVcZyFQanJPmSSZt79LJYu target/deploy/vuln03_forged_state.so \
  --bpf-program EUHsG3fkkb4EohJBdy9HJbZEKS8UecKQej5uQk1S1hSr target/deploy/vuln04_pda_confusion.so \
  --bpf-program HVKUuXZRopCRHD6Ne2KJ3Aqapb99sHRdhG8asyDdz1NQ target/deploy/vuln05_arbitrary_cpi.so \
  --bpf-program EV2U5AjGiFhUPiNHFzZPYyn5E9HuNRdyfM92mShrqoEK target/deploy/vuln06_overflow.so \
  --bpf-program 7CkJ3L8hpHbE6mDRvXwU7MyDNpEMw5prj3Tsujt9hLDU target/deploy/vuln07_reinit.so \
  --bpf-program J1uGvwWWaxXroKxHjVHpgJ9eY8vp4r1iSXTpNYCHSP49 target/deploy/vuln08_duplicate_accounts.so \
  --bpf-program 9hEAbWKYFmgjd3SBRsBU4yiyTiPEcaWqGM8ZUuKDcVW5 target/deploy/vuln09_oracle_manipulation.so \
  --bpf-program HPXU63wP1TBu6d78F5C8tyECCHBauZ5rPee44MFeotoC target/deploy/vuln10_reentrancy.so \
  --bpf-program J4veNunZYUEu59ta7EjjRk4RE9CFnbB5jm8W4dCsJPU3 target/deploy/attacker.so \
  > /tmp/validator.log 2>&1 &

echo "waiting for validator..."
for i in $(seq 1 60); do
  if solana cluster-version > /dev/null 2>&1; then break; fi
  sleep 1
done
solana cluster-version

export ANCHOR_PROVIDER_URL="http://127.0.0.1:8899"
export ANCHOR_WALLET="$HOME/.config/solana/id.json"

if [ ! -x node_modules/.bin/ts-mocha ]; then
  echo "installing node deps..."
  yarn install --silent > /dev/null 2>&1
fi

# IDLs are generated in the new spec format; the TS client needs account
# types inlined into accounts[].type — post-process before running tests.
python3 scripts/fix_idl.py

if [ $# -gt 0 ]; then
  yarn ts-mocha -p ./tsconfig.json -t 1000000 "$@"
else
  yarn ts-mocha -p ./tsconfig.json -t 1000000 'tests/**/*.test.ts'
fi
EXIT=$?
pkill -f solana-test-validator 2>/dev/null || true
exit $EXIT
