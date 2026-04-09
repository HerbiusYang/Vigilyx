#!/bin/bash
# ═══════════════════════════════════════════════════
# Vigilyx deployment mode switcher
# Usage: switch-mode.sh mirror|mta
# ═══════════════════════════════════════════════════
#
# Switches between mirror (passive sniffer) and MTA (inline proxy) modes.
# This is a deploy-time operation — it restarts containers using compose profiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="deploy/docker/docker-compose.yml"
FAST_OVERRIDE="deploy/docker/docker-compose.fast.yml"
ENV_FILE="deploy/docker/.env"

if [ $# -lt 1 ]; then
    echo "Usage: $0 mirror|mta"
    echo ""
    echo "  mirror  — passive traffic mirroring (starts sniffer, stops MTA)"
    echo "  mta     — MTA proxy mode (starts MTA, stops sniffer)"
    exit 1
fi

MODE="$1"

if [ "$MODE" != "mirror" ] && [ "$MODE" != "mta" ]; then
    echo "Error: mode must be 'mirror' or 'mta', got '$MODE'"
    exit 1
fi

cd "$PROJECT_DIR"

echo "Switching to $MODE mode..."

# Update VIGILYX_MODE in .env if it exists
if [ -f "$ENV_FILE" ]; then
    if grep -q '^VIGILYX_MODE=' "$ENV_FILE"; then
        sed -i "s/^VIGILYX_MODE=.*/VIGILYX_MODE=$MODE/" "$ENV_FILE"
    else
        echo "VIGILYX_MODE=$MODE" >> "$ENV_FILE"
    fi
    echo "Updated $ENV_FILE: VIGILYX_MODE=$MODE"
fi

# Start the target profile, stop the other
OTHER_MODE=$([ "$MODE" = "mirror" ] && echo "mta" || echo "mirror")

echo "Starting $MODE services..."
docker compose -f "$COMPOSE_FILE" -f "$FAST_OVERRIDE" --profile "$MODE" up -d

echo "Stopping $OTHER_MODE services..."
docker compose -f "$COMPOSE_FILE" -f "$FAST_OVERRIDE" --profile "$OTHER_MODE" stop 2>/dev/null || true

echo ""
echo "Mode switched to: $MODE"
docker compose -f "$COMPOSE_FILE" ps
