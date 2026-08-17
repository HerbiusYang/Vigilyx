#!/usr/bin/env bash
set -euo pipefail

# Runs the opt-in vigilyx-db integration suite against disposable local
# containers. This script never uses deploy/docker/.env or the remote server.

TEST_SUFFIX="$(date +%s)-$$"
VALKEY_CONTAINER="vigilyx-test-valkey-${TEST_SUFFIX}"
POSTGRES_CONTAINER="vigilyx-test-postgres-${TEST_SUFFIX}"

cleanup() {
  docker rm -f "$VALKEY_CONTAINER" "$POSTGRES_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Floating minor tags are acceptable here: these are short-lived disposable
# containers for one-off local integration tests, removed on script exit.
# Long-running images are digest-pinned in deploy/docker/docker-compose.yml.
docker run --detach --rm \
  --name "$VALKEY_CONTAINER" \
  --publish 127.0.0.1::6379 \
  valkey/valkey:8.0-alpine \
  valkey-server --save '' --appendonly no >/dev/null

docker run --detach --rm \
  --name "$POSTGRES_CONTAINER" \
  --env POSTGRES_USER=vigilyx_test \
  --env POSTGRES_PASSWORD=vigilyx_test \
  --env POSTGRES_DB=vigilyx_test \
  --publish 127.0.0.1::5432 \
  postgres:17-alpine >/dev/null

for _ in $(seq 1 30); do
  if docker exec "$VALKEY_CONTAINER" valkey-cli ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 1
done

for _ in $(seq 1 30); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U vigilyx_test -d vigilyx_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

VALKEY_PORT="$(docker port "$VALKEY_CONTAINER" 6379/tcp | awk -F: 'NR == 1 { print $NF }')"
POSTGRES_PORT="$(docker port "$POSTGRES_CONTAINER" 5432/tcp | awk -F: 'NR == 1 { print $NF }')"

if [[ ! "$VALKEY_PORT" =~ ^[0-9]+$ ]] || [[ ! "$POSTGRES_PORT" =~ ^[0-9]+$ ]]; then
  echo "failed to resolve disposable container ports" >&2
  exit 1
fi

export VIGILYX_ALLOW_REAL_INFRA_TESTS=1
export VIGILYX_TEST_REDIS_URL="redis://127.0.0.1:${VALKEY_PORT}"
export VIGILYX_TEST_DATABASE_URL="postgres://vigilyx_test:vigilyx_test@127.0.0.1:${POSTGRES_PORT}/vigilyx_test"
export TEST_DATABASE_URL="$VIGILYX_TEST_DATABASE_URL"
export PG_MIN_CONNECTIONS=0
export PG_MAX_CONNECTIONS=20

cargo test -p vigilyx-db --features infra-tests \
  --test real_valkey --test real_postgres -- --test-threads=1

cargo test -p vigilyx-engine --features infra-tests \
  intel::tests::test_ -- --test-threads=1

cargo test -p vigilyx-engine --features infra-tests \
  modules::link_reputation::tests::test_xred_mooo_com_with_intel -- --test-threads=1
