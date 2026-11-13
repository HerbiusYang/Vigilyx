#!/usr/bin/env bash
# Run from the deployment root. Resume the original services even when a
# dependency restart, migration, bootstrap, or SSH session fails.
set -euo pipefail

run_migrations="${1:?expected true or false}"
case "$run_migrations" in true|false) ;; *) exit 2 ;; esac
compose=(docker compose -f deploy/docker/docker-compose.yml)
running=()

restore_services() {
    local status=$? restore_failed=false index
    trap - EXIT HUP INT TERM
    # Restore the API/engine before resuming capture.
    for ((index=${#running[@]}-1; index>=0; index--)); do
        if ! docker start "${running[index]}" >/dev/null; then
            echo "Error: failed to restore ${running[index]}" >&2
            restore_failed=true
        fi
    done
    if $restore_failed && [ "$status" -eq 0 ]; then status=1; fi
    exit "$status"
}
trap restore_services EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Quiesce clients before Compose can restart PostgreSQL or Valkey. Capture is
# paused first so a database restart cannot fill/trim the bounded Streams.
for name in vigilyx-sniffer vigilyx-mta vigilyx-engine-standalone vigilyx; do
    if [ "$(docker container inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = true ]; then
        running+=("$name")
        docker stop "$name" >/dev/null
    fi
done

"${compose[@]}" up -d --wait --wait-timeout 120 postgres redis
"${compose[@]}" run --rm --no-deps postgres-role-init
if $run_migrations; then
    "${compose[@]}" run --rm --no-deps postgres-migrate
else
    echo "  Schema migration skipped: this deployment did not build a new API binary."
fi
"${compose[@]}" run --rm --no-deps audit-bootstrap
