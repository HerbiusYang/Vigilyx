#!/usr/bin/env bash
set -euo pipefail

# RUSTSEC-2023-0071 was removed from the 0.9.4 lock graph. Fail if a future
# dependency change silently reintroduces the affected RSA line.
if grep -qE '^name = "rsa"$' Cargo.lock; then
  echo "RustSec guard failed: rsa has re-entered Cargo.lock" >&2
  exit 1
fi

# yara-x 1.19 is the newest release and still pins Wasmtime 43. The current
# advisory requires attacker-controlled cross-engine Store/type mixing; Vigilyx
# only gives untrusted mail bytes to precompiled rules. Keep the exception
# narrowly pinned and fail as soon as the dependency shape changes.
if ! cargo tree --locked -p yara-x --depth 1 | grep -qE 'wasmtime v43\.0\.2$'; then
  echo "RUSTSEC exception must be reviewed: yara-x no longer uses wasmtime 43.0.2" >&2
  exit 1
fi

cargo audit \
  --ignore RUSTSEC-2026-0222
