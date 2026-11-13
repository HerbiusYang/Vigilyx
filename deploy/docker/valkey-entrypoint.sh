#!/bin/sh
# ═══════════════════════════════════════════════════
# Valkey entrypoint - generates the config from env, then execs valkey-server
# ═══════════════════════════════════════════════════
# Why: passing --requirepass on the command line exposes the password via
# `ps` / `docker inspect` / `docker top`. Writing it to a config file keeps
# it out of the process list. The config lives in /tmp (container tmpfs),
# never on a persisted volume.
set -eu
umask 077

: "${REDIS_PASSWORD:?REDIS_PASSWORD must be set}"
: "${REDIS_API_PASSWORD:?REDIS_API_PASSWORD must be set}"
: "${REDIS_ENGINE_PASSWORD:?REDIS_ENGINE_PASSWORD must be set}"
: "${REDIS_SNIFFER_PASSWORD:?REDIS_SNIFFER_PASSWORD must be set}"
: "${REDIS_MTA_PASSWORD:?REDIS_MTA_PASSWORD must be set}"

validate_acl_password() {
    password_name="$1"
    password_value="$2"
    if [ "${#password_value}" -lt 32 ]; then
        echo "$password_name must be at least 32 characters" >&2
        exit 1
    fi
    case "$password_value" in
        *[!A-Za-z0-9_-]*)
            echo "$password_name must contain only URL/config-safe characters" >&2
            exit 1
            ;;
    esac
}

validate_acl_password REDIS_PASSWORD "$REDIS_PASSWORD"
validate_acl_password REDIS_API_PASSWORD "$REDIS_API_PASSWORD"
validate_acl_password REDIS_ENGINE_PASSWORD "$REDIS_ENGINE_PASSWORD"
validate_acl_password REDIS_SNIFFER_PASSWORD "$REDIS_SNIFFER_PASSWORD"
validate_acl_password REDIS_MTA_PASSWORD "$REDIS_MTA_PASSWORD"

if [ "$REDIS_PASSWORD" = "$REDIS_API_PASSWORD" ] \
    || [ "$REDIS_PASSWORD" = "$REDIS_ENGINE_PASSWORD" ] \
    || [ "$REDIS_PASSWORD" = "$REDIS_SNIFFER_PASSWORD" ] \
    || [ "$REDIS_PASSWORD" = "$REDIS_MTA_PASSWORD" ] \
    || [ "$REDIS_API_PASSWORD" = "$REDIS_ENGINE_PASSWORD" ] \
    || [ "$REDIS_API_PASSWORD" = "$REDIS_SNIFFER_PASSWORD" ] \
    || [ "$REDIS_API_PASSWORD" = "$REDIS_MTA_PASSWORD" ] \
    || [ "$REDIS_ENGINE_PASSWORD" = "$REDIS_SNIFFER_PASSWORD" ] \
    || [ "$REDIS_ENGINE_PASSWORD" = "$REDIS_MTA_PASSWORD" ] \
    || [ "$REDIS_SNIFFER_PASSWORD" = "$REDIS_MTA_PASSWORD" ]; then
    echo "Valkey health and service-role passwords must all differ" >&2
    exit 1
fi

cat > /tmp/valkey.conf <<EOF
user default off
user vigilyx_health on >${REDIS_PASSWORD} +ping
user vigilyx_api on >${REDIS_API_PASSWORD} ~vigilyx:* &vigilyx:* +@all -@admin -@dangerous
user vigilyx_engine on >${REDIS_ENGINE_PASSWORD} ~vigilyx:stream:* ~vigilyx:engine:* &vigilyx:engine:* +@all -@admin -@dangerous
user vigilyx_sniffer on >${REDIS_SNIFFER_PASSWORD} ~vigilyx:stream:sessions ~vigilyx:stream:http_sessions ~vigilyx:sid_to_user ~vigilyx:sniffer:* &vigilyx:stats:update &vigilyx:sniffer:* +@all -@admin -@dangerous
user vigilyx_mta on >${REDIS_MTA_PASSWORD} ~vigilyx:stream:* ~vigilyx:engine:* ~vigilyx:mta:* &vigilyx:engine:* &vigilyx:mta:* +@all -@admin -@dangerous
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
unset REDIS_PASSWORD REDIS_API_PASSWORD REDIS_ENGINE_PASSWORD REDIS_SNIFFER_PASSWORD REDIS_MTA_PASSWORD

exec valkey-server /tmp/valkey.conf
