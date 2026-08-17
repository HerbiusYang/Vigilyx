#!/bin/sh
# ═══════════════════════════════════════════════════
# Valkey entrypoint - generates the config from env, then execs valkey-server
# ═══════════════════════════════════════════════════
# Why: passing --requirepass on the command line exposes the password via
# `ps` / `docker inspect` / `docker top`. Writing it to a config file keeps
# it out of the process list. The config lives in /tmp (container tmpfs),
# never on a persisted volume.
set -eu

: "${REDIS_PASSWORD:?REDIS_PASSWORD must be set}"

cat > /tmp/valkey.conf <<EOF
requirepass ${REDIS_PASSWORD}
appendonly yes
maxmemory 256mb
# This instance is the message bus, not a cache: it holds at-least-once
# delivery state (stream PELs, DLQs, sid->user mappings, engine heartbeat).
# allkeys-lru would silently evict entire streams/keys under memory pressure
# — including unacknowledged messages — breaking delivery guarantees with no
# signal. noeviction makes writes fail loudly instead; the sniffer already
# surfaces this via its xadd_failures counter and error logs.
maxmemory-policy noeviction
EOF

# Drop the password from this process's environment before exec so the
# server (and any child tools) cannot leak it via /proc/<pid>/environ.
unset REDIS_PASSWORD

exec valkey-server /tmp/valkey.conf
