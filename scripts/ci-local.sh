#!/usr/bin/env bash
# Run the same gates `.github/workflows/ci.yml` runs, locally.
# Useful as a pre-push hook (see `.githooks/pre-push`) and on demand
# when GitHub Actions minutes are exhausted.
#
# Skips: cargo deny is skipped with a warning if `cargo-deny` is not
# installed. Everything else is hard-required — a failure stops the
# script with a non-zero exit code.
#
# Usage:
#   scripts/ci-local.sh         # full suite
#   FAST=1 scripts/ci-local.sh  # skip the slow `cargo test` step

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

bold=$(tput bold 2>/dev/null || true)
reset=$(tput sgr0 2>/dev/null || true)

step() {
    local name=$1; shift
    local start
    start=$(date +%s)
    printf '\n%s==> %s%s\n' "$bold" "$name" "$reset"
    if "$@"; then
        local elapsed=$(( $(date +%s) - start ))
        printf '    %sok%s (%ds)\n' "$bold" "$reset" "$elapsed"
    else
        local rc=$?
        printf '    %sFAILED%s (rc=%d)\n' "$bold" "$reset" "$rc"
        exit "$rc"
    fi
}

step "cargo fmt --check"            cargo fmt --all -- --check
step "cargo clippy -D warnings"     cargo clippy --all-targets -- -D warnings

if [[ "${FAST:-0}" != "1" ]]; then
    step "cargo test --workspace"   cargo test --workspace --all-features
else
    printf '\n%s==> cargo test%s skipped (FAST=1)\n' "$bold" "$reset"
fi

step "cargo doc -D warnings"        env RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace

if command -v cargo-deny >/dev/null 2>&1; then
    step "cargo deny check"         cargo deny check
else
    printf '\n%s==> cargo deny%s skipped (cargo-deny not installed; `cargo install --locked cargo-deny`)\n' "$bold" "$reset"
fi

printf '\n%sAll gates passed.%s\n' "$bold" "$reset"
