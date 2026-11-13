#!/usr/bin/env bash
# P0 baseline: replay the deployed semantic_scan (rules + shadow classifier) on the PoC eval sets.
set -u
for name in demo test redteam; do
  case $name in test) input=/app/backups/intent-poc-20261110/data/split/test.jsonl;; *) input=/app/backups/intent-poc-20261110/data/$name.jsonl;; esac
  rm -f /home/CCAB_VIGILYX/backups/intent-poc-20261110/logs/baseline_$name.status
  docker exec -w /app -e CARGO_BUILD_JOBS=16 -e VIGILYX_SEMANTIC_EXTERNAL_INPUT=$input     -e VIGILYX_SEMANTIC_EXTERNAL_OUTPUT=/app/backups/intent-poc-20261110/baseline/$name vigilyx-rust-builder     cargo test --offline --locked --profile release-fast -p vigilyx-engine --test semantic_external_harness     -- --ignored --nocapture > /home/CCAB_VIGILYX/backups/intent-poc-20261110/logs/baseline_$name.log 2>&1
  echo $? > /home/CCAB_VIGILYX/backups/intent-poc-20261110/logs/baseline_$name.status
done
