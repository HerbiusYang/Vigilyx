#!/bin/bash

# Vigilyx one-command startup script
# Usage: ./start.sh <interface-name> [remote-host:port]
# Example: ./start.sh eth0                     (local capture)
#          ./start.sh eth0 203.0.113.10:5000    (remote mode)

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Status symbols
SYM_OK="✔"
SYM_FAIL="✘"
SYM_WARN="⚠"
SYM_WAIT="◌"

# Load configuration from .env
if [ -f .env ]; then
    API_PORT=$(grep -E "^API_PORT=" .env | cut -d= -f2 | tr -d '[:space:]')
    # Export the NLP inference thread count for the Python process
    VIGILYX_NUM_THREADS=$(grep -E "^VIGILYX_NUM_THREADS=" .env | cut -d= -f2 | tr -d '[:space:]')
    [ -n "$VIGILYX_NUM_THREADS" ] && export VIGILYX_NUM_THREADS
fi
API_PORT="${API_PORT:-8088}"

# Log directory
mkdir -p logs data

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $1"; }
ok()   { echo -e "  ${GREEN}${SYM_OK}${NC} $1"; }
fail() { echo -e "  ${RED}${SYM_FAIL}${NC} $1"; }
warn() { echo -e "  ${YELLOW}${SYM_WARN}${NC} $1"; }

# Wait for an HTTP port to become available; returns 0 on success and 1 on timeout
wait_for_http() {
    local url="$1" max_wait="$2" label="$3"
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Cleanup function
cleanup() {
    echo ""
    log "Stopping all services..."

    # Stop processes listed in the PID file
    if [ -f .pids ]; then
        while read pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < .pids
        rm -f .pids
    fi

    # Force-stop any leftover processes
    pkill -f "vigilyx-api" 2>/dev/null || true
    pkill -f "vigilyx-engine" 2>/dev/null || true
    pkill -f "vigilyx-sniffer" 2>/dev/null || true
    pkill -f "uvicorn.*vigilyx" 2>/dev/null || true
    pkill -f "vite.*vigilyx" 2>/dev/null || true

    # Remove lingering UDS socket files and heartbeat files
    rm -f data/vigilyx.sock
    rm -f data/engine-status.json

    sleep 1
    ok "All services stopped"
    exit 0
}

# Trap signals
trap cleanup SIGINT SIGTERM EXIT

# --- Check dependencies ---
log "Checking dependencies..."
command -v cargo >/dev/null || { fail "Rust is required"; exit 1; }
command -v node >/dev/null  || { fail "Node.js is required"; exit 1; }
command -v curl >/dev/null  || { fail "curl is required for health checks"; exit 1; }

# Install frontend dependencies
[ -d "frontend/node_modules" ] || {
    log "Installing frontend dependencies..."
    cd frontend && npm install --silent && cd ..
}

# --- Build the backend ---
if [ "${FULL_RELEASE:-}" = "1" ] || [[ " $* " =~ " --full-release " ]]; then
    CARGO_PROFILE="release"
    CARGO_TARGET_DIR="target/release"
    log "Building backend (Full Release: LTO=fat, codegen-units=1)..."
else
    CARGO_PROFILE="release-fast"
    CARGO_TARGET_DIR="target/release-fast"
    log "Building backend (Fast Release: LTO=thin, $(nproc) cores in parallel)..."
fi
cargo build --profile "$CARGO_PROFILE" -p vigilyx-api -p vigilyx-engine -p vigilyx-sniffer 2>&1 | grep -E "(Compiling|Finished|error)" || true

# Clear the PID file
> .pids

# --- Status-tracking variables ---
STATUS_API="fail"
STATUS_ENGINE="fail"
STATUS_INTEL="skip"
STATUS_FRONTEND="fail"
STATUS_SNIFFER="skip"
ENGINE_DETAIL=""

# --- Start the API ---
log "Starting API server..."
RUST_BACKTRACE=1 \
    DATABASE_URL="sqlite:./data/vigilyx.db" \
    "./$CARGO_TARGET_DIR/vigilyx-api" > logs/api.log 2>&1 &
API_PID=$!
echo $API_PID >> .pids

# Wait for the API health check to pass (up to 10 seconds)
if wait_for_http "http://127.0.0.1:${API_PORT}/api/health" 10 "API"; then
    ok "API server started (port ${API_PORT}, PID: $API_PID)"
    STATUS_API="ok"
else
    if ! kill -0 $API_PID 2>/dev/null; then
        fail "API server failed to start (process exited)"
        # Print the last few lines of the error log
        echo -e "  ${DIM}$(tail -3 logs/api.log 2>/dev/null)${NC}"
    else
        fail "API server did not pass the health check (PID: $API_PID is still running)"
    fi
    STATUS_API="fail"
    STATUS_ENGINE="fail"
fi

# --- Start AI + intel services (VT scraping + NLP phishing detection) ---
# Note: this must start before the security engine, because the engine checks NLP availability during startup
STATUS_NLP="skip"
if command -v python3.11 >/dev/null && [ -d "python/vigilyx_ai" ]; then

    # Python version
    PY=python3.11

    # Mainland mirror-source configuration
    PIP_MIRROR="https://mirrors.aliyun.com/pypi/simple/"
    PIP_TRUSTED="mirrors.aliyun.com"
    export HF_ENDPOINT="https://hf-mirror.com"

    # 1. Ensure Python dependencies are installed
    if ! $PY -c "import transformers, torch" 2>/dev/null; then
        log "Installing Python AI dependencies (transformers + torch) [mirror: Aliyun]..."
        cd python && $PY -m pip install -e . -i "$PIP_MIRROR" --trusted-host "$PIP_TRUSTED" && cd "$PROJECT_ROOT"
        if ! $PY -c "import transformers, torch" 2>/dev/null; then
            fail "Python AI dependencies failed to install; skipping AI service"
            STATUS_INTEL="fail"
        fi
    fi

    # 2. Check the NLP model cache (only test for file existence; do not load the model into memory)
    if [ "$STATUS_INTEL" != "fail" ]; then
        log "Checking NLP phishing-model cache..."
        NLP_MODEL_READY=$($PY -c "
import sys, os
os.environ.setdefault('HF_ENDPOINT', 'https://hf-mirror.com')
try:
    from huggingface_hub import try_to_load_from_cache
    models = [
        'MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7',
        'joeddav/xlm-roberta-large-xnli',
        'facebook/bart-large-mnli',
    ]
    for m in models:
        # Only check whether config.json is cached; do not load the model into memory
        cached = try_to_load_from_cache(m, 'config.json')
        if cached is not None and isinstance(cached, str):
            print(f'OK:{m}')
            sys.exit(0)
    # If the cache is empty, try downloading the first model (first run only)
    print('DOWNLOAD')
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    m = models[0]
    AutoTokenizer.from_pretrained(m)
    AutoModelForSequenceClassification.from_pretrained(m)
    print(f'OK:{m}')
    sys.exit(0)
except Exception as e:
    print(f'FAIL:{e}')
    sys.exit(1)
" 2>&1)

        if echo "$NLP_MODEL_READY" | grep -q "^OK:"; then
            NLP_MODEL_NAME=$(echo "$NLP_MODEL_READY" | grep "^OK:" | sed 's/^OK://')
            ok "NLP model ready: $NLP_MODEL_NAME"
        else
            fail "NLP model unavailable: $NLP_MODEL_READY"
            fail "Manual download: HF_ENDPOINT=https://hf-mirror.com $PY -c \"from transformers import pipeline; pipeline('zero-shot-classification', model='MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7')\""
            STATUS_INTEL="fail"
            STATUS_NLP="fail"
        fi
    fi

    # 3. Start the services
    if [ "$STATUS_INTEL" != "fail" ]; then
        log "Starting AI + intel services (NLP phishing detection + VT scraping)..."
        cd python && $PY -m uvicorn vigilyx_ai.api:app --host 127.0.0.1 --port 8900 > ../logs/intel.log 2>&1 &
        INTEL_PID=$!
        echo $INTEL_PID >> .pids
        cd "$PROJECT_ROOT"

        if wait_for_http "http://127.0.0.1:8900/health" 30 "Intel"; then
            ok "AI + intel services started (port 8900, PID: $INTEL_PID)"
            STATUS_INTEL="ok"
            STATUS_NLP="ok"
        else
            if kill -0 $INTEL_PID 2>/dev/null; then
                warn "AI + intel services are still starting... (PID: $INTEL_PID)"
                STATUS_INTEL="warn"
                STATUS_NLP="warn"
            else
                fail "AI + intel services failed to start"
                echo -e "  ${DIM}$(tail -5 logs/intel.log 2>/dev/null)${NC}"
                STATUS_INTEL="fail"
            fi
        fi
    fi
else
    warn "python3.11 is not installed or python/vigilyx_ai is missing; skipping AI service"
    STATUS_INTEL="skip"
fi

# --- Start the security engine and frontend in parallel (they do not depend on each other, so this saves time) ---

# Start the frontend
log "Starting frontend server..."
cd frontend && npm run dev > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID >> .pids
cd "$PROJECT_ROOT"

# Start the security analysis engine (after API + AI/NLP)
if [ "$STATUS_API" = "ok" ]; then
    log "Starting security analysis engine..."
    RUST_BACKTRACE=1 \
        DATABASE_URL="sqlite:./data/vigilyx.db" \
        "./$CARGO_TARGET_DIR/vigilyx-engine" > logs/engine.log 2>&1 &
    ENGINE_PID=$!
    echo $ENGINE_PID >> .pids
fi

# Wait for the frontend to become ready (up to 8 seconds)
if wait_for_http "http://127.0.0.1:3000" 8 "Frontend"; then
    ok "Frontend server started (port 3000, PID: $FRONTEND_PID)"
    STATUS_FRONTEND="ok"
else
    if kill -0 $FRONTEND_PID 2>/dev/null; then
        warn "Frontend process is running but the port is not ready yet (PID: $FRONTEND_PID)"
        STATUS_FRONTEND="warn"
    else
        fail "Frontend server failed to start"
        echo -e "  ${DIM}$(tail -3 logs/frontend.log 2>/dev/null)${NC}"
        STATUS_FRONTEND="fail"
    fi
fi

# Wait for the engine to publish its status to the API (up to 15 seconds; the engine is already starting in parallel while the frontend waits)
if [ "$STATUS_API" = "ok" ] && [ -n "$ENGINE_PID" ]; then
    ENGINE_WAIT=0
    ENGINE_MAX_WAIT=15
    while [ $ENGINE_WAIT -lt $ENGINE_MAX_WAIT ]; do
        if ! kill -0 $ENGINE_PID 2>/dev/null; then
            break
        fi
        ENGINE_JSON=$(curl -sf "http://127.0.0.1:${API_PORT}/api/internal/engine-status" 2>/dev/null || echo '{}')
        ENGINE_RUNNING=$(echo "$ENGINE_JSON" | grep -o '"running":\s*true' || true)
        if [ -n "$ENGINE_RUNNING" ]; then
            break
        fi
        sleep 1
        ENGINE_WAIT=$((ENGINE_WAIT + 1))
    done

    if [ -n "$ENGINE_RUNNING" ]; then
        ok "Security engine started (PID: $ENGINE_PID)"
        STATUS_ENGINE="ok"
    elif ! kill -0 $ENGINE_PID 2>/dev/null; then
        fail "Security engine failed to start (process exited)"
        echo -e "  ${DIM}$(tail -5 logs/engine.log 2>/dev/null)${NC}"
        ENGINE_DETAIL="process exited"
        STATUS_ENGINE="fail"
    else
        warn "Security engine process is running but not ready yet (PID: $ENGINE_PID, still initializing...)"
        ENGINE_DETAIL="initializing"
        STATUS_ENGINE="warn"
    fi
fi

# --- Start the probe ---
INTERFACE="${1:-}"
REMOTE_HOST="${2:-}"
SNIFFER_PID=""

if [ -z "$INTERFACE" ]; then
    fail "Please specify a network interface: ./start.sh <interface-name> [remote-host:port]"
    fail "Example: ./start.sh eth0"
    exit 1
fi

log "The probe requires root privileges. Please enter your password:"

# Pass the config file path via --env-file so sudo environment cleanup does not drop it
SNIFFER_ENV_FILE="$PROJECT_ROOT/.env"

if sudo -v; then
    if [ -n "$REMOTE_HOST" ]; then
        log "Starting traffic probe (interface: $INTERFACE, remote: $REMOTE_HOST)..."
        sudo "$PROJECT_ROOT/$CARGO_TARGET_DIR/vigilyx-sniffer" --interface "$INTERFACE" --remote-connect-v3 "$REMOTE_HOST" --env-file "$SNIFFER_ENV_FILE" > "$PROJECT_ROOT/logs/sniffer.log" 2>&1 &
    else
        log "Starting traffic probe (local capture, interface: $INTERFACE)..."
        sudo "$PROJECT_ROOT/$CARGO_TARGET_DIR/vigilyx-sniffer" --interface "$INTERFACE" --env-file "$SNIFFER_ENV_FILE" > "$PROJECT_ROOT/logs/sniffer.log" 2>&1 &
    fi
    SNIFFER_PID=$!
    echo $SNIFFER_PID >> .pids
    sleep 2

    if kill -0 $SNIFFER_PID 2>/dev/null; then
        ok "Traffic probe started (PID: $SNIFFER_PID)"
        STATUS_SNIFFER="ok"
    else
        fail "Traffic probe failed to start"
        echo -e "  ${DIM}$(tail -3 logs/sniffer.log 2>/dev/null)${NC}"
        STATUS_SNIFFER="fail"
    fi
else
    fail "sudo authentication failed; skipping probe startup"
    STATUS_SNIFFER="fail"
fi

# --- Startup summary ---
echo ""
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo -e "${BOLD}   Vigilyx Email Traffic Monitor${NC}"
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""

# Component status table
fmt_status() {
    case "$1" in
        ok)   echo -e "${GREEN}${SYM_OK} Running${NC}" ;;
        warn) echo -e "${YELLOW}${SYM_WARN} Starting${NC}" ;;
        skip) echo -e "${DIM}${SYM_WAIT} Skipped${NC}" ;;
        *)    echo -e "${RED}${SYM_FAIL} Not started${NC}" ;;
    esac
}

echo -e "   ${BOLD}Component Status${NC}"
echo -e "   ────────────────────────────────────"
printf "   %-16s %s\n" "API Server" "$(fmt_status $STATUS_API)"
printf "   %-16s %s" "Security Engine" "$(fmt_status $STATUS_ENGINE)"
[ -n "$ENGINE_DETAIL" ] && printf "  ${DIM}(%s)${NC}" "$ENGINE_DETAIL"
echo ""
printf "   %-16s %s\n" "AI + Intel" "$(fmt_status $STATUS_INTEL)"
printf "   %-16s %s\n" "NLP Phishing" "$(fmt_status $STATUS_NLP)"
printf "   %-16s %s\n" "Frontend" "$(fmt_status $STATUS_FRONTEND)"
printf "   %-16s %s\n" "Traffic Probe" "$(fmt_status $STATUS_SNIFFER)"
echo ""

# Access information
echo -e "   ${BOLD}Access${NC}"
echo -e "   ────────────────────────────────────"
echo -e "   Open in browser: ${CYAN}http://localhost:3000${NC}"
echo -e "   Login user:      ${YELLOW}admin${NC}"
echo -e "   Login password:  ${DIM}See API_PASSWORD in .env${NC}"
echo ""

# Logs and processes
echo -e "   ${BOLD}Log Files${NC}"
echo -e "   ────────────────────────────────────"
echo -e "   API:         logs/api.log"
echo -e "   Engine:      logs/engine.log"
echo -e "   AI+Intel:    logs/intel.log"
echo -e "   Frontend:    logs/frontend.log"
echo -e "   Probe:       logs/sniffer.log"
echo ""
echo -e "   ${BOLD}Process IDs${NC}"
echo -e "   ────────────────────────────────────"
echo -e "   API=${API_PID}${ENGINE_PID:+  Engine=$ENGINE_PID}  Frontend=${FRONTEND_PID}${SNIFFER_PID:+  Sniffer=$SNIFFER_PID}"
echo ""

# If the security engine did not start, print troubleshooting hints
if [ "$STATUS_ENGINE" != "ok" ]; then
    echo -e "   ${YELLOW}${SYM_WARN} Security engine is not running. Troubleshooting:${NC}"
    echo -e "   ${DIM}  1. Check engine logs: tail -50 logs/engine.log${NC}"
    echo -e "   ${DIM}  2. Check Redis: valkey-cli PING${NC}"
    echo -e "   ${DIM}  3. Check the database: ls -la data/vigilyx.db${NC}"
    echo -e "   ${DIM}  4. Query status manually: curl -s http://127.0.0.1:${API_PORT}/api/internal/engine-status | python3.11 -m json.tool${NC}"
    echo ""
fi

echo -e "   Press ${RED}Ctrl+C${NC} to stop all services"
echo -e "${BOLD}═══════════════════════════════════════════${NC}"
echo ""

# Wait for any child process to exit
wait
