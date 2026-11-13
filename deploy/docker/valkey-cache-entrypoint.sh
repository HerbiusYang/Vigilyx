#!/bin/sh
# Disposable Valkey instance for operational read aggregates.
# It must never be used for Streams, PEL, DLQ, Pub/Sub, or heartbeats.
set -eu
umask 077

: "${CACHE_REDIS_PASSWORD:?CACHE_REDIS_PASSWORD must be set for the read cache}"
CACHE_MAXMEMORY="${CACHE_MAXMEMORY:-256mb}"

cat > /tmp/valkey-cache.conf <<EOF
requirepass ${CACHE_REDIS_PASSWORD}
appendonly no
save ""
maxmemory ${CACHE_MAXMEMORY}
maxmemory-policy allkeys-lfu
EOF

# Keep the password out of the server process environment and command line.
unset CACHE_REDIS_PASSWORD

exec valkey-server /tmp/valkey-cache.conf
