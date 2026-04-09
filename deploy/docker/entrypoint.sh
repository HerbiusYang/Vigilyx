#!/bin/sh
# ═══════════════════════════════════════════════════
# Vigilyx container entrypoint script
# Start both the API and Engine processes inside the same container
# ═══════════════════════════════════════════════════
#
# Why are there two processes?
#   vigilyx-api    = HTTP/WS server (handles frontend requests and serves static pages)
#   vigilyx-engine = security analysis engine (receives mail from Redis Streams -> runs the pipeline -> writes back results)
#   They share PostgreSQL and Redis, co-located for UDS fallback during migration.
#
# Logging:
#   Both processes write to stdout/stderr (Docker-native logging).
#   Use `docker compose logs vigilyx` to view.
#
# Signal handling:
#   tini (PID 1) forwards SIGTERM to this script, and this script forwards it to both child processes.

set -e

# Ensure the data directory exists
mkdir -p /app/data

# Remove any leftover UDS socket from the previous run
rm -f /app/data/vigilyx.sock

# Signal forwarding: gracefully shut down both processes on SIGTERM/SIGINT
# The trap must be registered before starting child processes to eliminate the signal race window
API_PID=""
ENGINE_PID=""
shutdown() {
    echo "[entrypoint] Shutting down..."
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
    [ -n "$ENGINE_PID" ] && kill "$ENGINE_PID" 2>/dev/null || true
    [ -n "$API_PID" ] && wait "$API_PID" 2>/dev/null || true
    [ -n "$ENGINE_PID" ] && wait "$ENGINE_PID" 2>/dev/null || true
    echo "[entrypoint] All processes stopped."
    exit 0
}
trap shutdown TERM INT

echo "[entrypoint] Starting Vigilyx API server..."
./vigilyx-api 2>&1 &
API_PID=$!

# Wait for the API to become ready (Engine startup needs the API UDS server or Redis)
echo "[entrypoint] Waiting for API to be ready..."
WAIT=0
while [ $WAIT -lt 15 ]; do
    if curl -sf http://127.0.0.1:${API_PORT:-8088}/api/health >/dev/null 2>&1; then
        echo "[entrypoint] API ready."
        break
    fi
    sleep 1
    WAIT=$((WAIT + 1))
done

if [ $WAIT -ge 15 ]; then
    echo "[entrypoint] WARNING: API health check timed out, starting engine anyway..."
fi

# Skip the standalone engine in MTA mode because the MTA container embeds its own engine and dual engines would race
# Controlled by the STANDALONE_ENGINE=false environment variable
STANDALONE_ENGINE="${STANDALONE_ENGINE:-true}"

if [ "$STANDALONE_ENGINE" = "false" ]; then
    echo "[entrypoint] STANDALONE_ENGINE=false, skipping standalone engine (MTA mode)"
    echo "[entrypoint] Running API only (PID=$API_PID)"

    # Monitor only the API process
    while true; do
        if ! kill -0 "$API_PID" 2>/dev/null; then
            echo "[entrypoint] API process exited unexpectedly!"
            exit 1
        fi
        sleep 5
    done
else
    echo "[entrypoint] Starting Vigilyx Security Engine..."
    ./vigilyx-engine 2>&1 &
    ENGINE_PID=$!

    echo "[entrypoint] All processes started (API=$API_PID, Engine=$ENGINE_PID)"

    # Monitor child processes: if either exits, terminate the whole container and let Docker restart policy recover it
    while true; do
        if ! kill -0 "$API_PID" 2>/dev/null; then
            echo "[entrypoint] API process exited unexpectedly!"
            kill "$ENGINE_PID" 2>/dev/null || true
            exit 1
        fi
        if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
            echo "[entrypoint] Engine process exited unexpectedly!"
            kill "$API_PID" 2>/dev/null || true
            exit 1
        fi
        sleep 5
    done
fi
