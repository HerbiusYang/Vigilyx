#!/usr/bin/env bash
set -euo pipefail

# RUSTSEC-2023-0071 was removed from the JWT lock graph by using jsonwebtoken's
# aws-lc-rs backend. Fail if a future dependency change silently
# reintroduces the affected RSA line.
if grep -qE '^name = "rsa"$' Cargo.lock; then
  echo "RustSec guard failed: rsa has re-entered Cargo.lock" >&2
  exit 1
fi

# SQLx 0.9 resolves its optional SQLite driver into Cargo.lock even though this
# workspace only uses PostgreSQL. RUSTSEC-2026-0459 affects that unused driver's
# bundled SQLite. Permit the lock-only advisory only after proving SQLite is
# absent from every workspace feature/target graph. Fail closed if resolution
# fails or a future feature activates SQLite; never extend this to used crates.
dependency_tree="$(cargo tree --locked --workspace --all-features --target all --prefix none --color never)"
if grep -qE '^(libsqlite3-sys|sqlx-sqlite|rusqlite) v' <<< "$dependency_tree"; then
  echo "RustSec exception must be reviewed: SQLite is active in the workspace" >&2
  exit 1
fi

cargo audit \
  --ignore RUSTSEC-2026-0459
