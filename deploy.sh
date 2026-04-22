#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Vigilyx one-command deployment script
# ═══════════════════════════════════════════════════
#
# Uses a persistent build container for incremental compilation to speed up deployment significantly.
#
# Usage:
#   ./deploy.sh                  # Full deployment (frontend + backend)
#   ./deploy.sh --backend        # Backend only
#   ./deploy.sh --frontend       # Frontend only (fastest, ~10s)
#   ./deploy.sh --production     # Production release build (full Docker build, slower)
#   ./deploy.sh --skip-test      # Skip tests (for emergency fixes)
#   ./deploy.sh --skip-lint      # Skip clippy (for emergency fixes)
#   ./deploy.sh --sniffer        # Sniffer only
#   ./deploy.sh --config-only    # Sync config/scripts and recreate services without rebuilding images
#   ./deploy.sh --antivirus      # Enable/start ClamAV antivirus profile
#   ./deploy.sh --mta            # MTA proxy only
#   ./deploy.sh --tls            # Enable HTTPS (Caddy reverse proxy + self-signed/Let's Encrypt)
#   ./deploy.sh --init           # Initial build-container setup
#
# Prerequisites:
#   1. Passwordless SSH access to the target server
#   2. Run setup-builder.sh to initialize the build container (or use --init)
#
# Configuration methods (choose one):
#   a) Create deploy.conf (recommended): cp deploy.conf.example deploy.conf && edit it
#   b) Set an environment variable: export VIGILYX_SERVER=root@your-server
#   c) Edit the defaults in this file directly

set -euo pipefail

# -- Load the config file if it exists --
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/deploy.conf" ]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/deploy.conf"
fi

# -- Configuration (priority: deploy.conf > environment variables > defaults) --
SERVER="${VIGILYX_SERVER:?Set VIGILYX_SERVER (example: root@your-server-ip), or create deploy.conf}"
LOCAL_DIR="${VIGILYX_LOCAL_DIR:-${SCRIPT_DIR}/}"
REMOTE_DIR="${VIGILYX_REMOTE_DIR:-/home/vigilyx}"
COMPOSE_FILE="deploy/docker/docker-compose.yml"
FAST_OVERRIDE="deploy/docker/docker-compose.fast.yml"
BUILDER_NAME="vigilyx-rust-builder"
LOCAL_REPO_ROOT="${LOCAL_DIR%/}"
FRONTEND_NODE_VERSION="$(tr -d '[:space:]' < "${LOCAL_REPO_ROOT}/.nvmrc")"
FRONTEND_NPM_VERSION="$(
    python3 - <<'PY' "${LOCAL_REPO_ROOT}/frontend/package.json"
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    package_json = json.load(fh)

package_manager = package_json.get("packageManager", "")
if not package_manager.startswith("npm@"):
    raise SystemExit("frontend/package.json must declare packageManager as npm@<version>")

print(package_manager.split("@", 1)[1])
PY
)"
FRONTEND_NODE_IMAGE="node:${FRONTEND_NODE_VERSION}-bookworm"

# Default options
DO_FRONTEND=true
DO_BACKEND=true
DO_SNIFFER=true
DO_MTA=false
DO_ENGINE=false
DO_TEST=true
DO_LINT=true
DO_INIT=false
DO_TLS=false
DO_PRODUCTION=false
DO_ANTIVIRUS=false
DO_CONFIG_ONLY=false

# -- Parse arguments --
while [[ $# -gt 0 ]]; do
    case "$1" in
        --frontend)
            DO_BACKEND=false
            DO_SNIFFER=false
            shift ;;
        --backend)
            DO_FRONTEND=false
            DO_SNIFFER=false
            shift ;;
        --sniffer)
            DO_FRONTEND=false
            DO_BACKEND=false
            shift ;;
        --antivirus)
            DO_ANTIVIRUS=true
            shift ;;
        --mta)
            DO_FRONTEND=false
            DO_BACKEND=false
            DO_SNIFFER=false
            DO_MTA=true
            shift ;;
        --engine)
            DO_FRONTEND=false
            DO_BACKEND=false
            DO_SNIFFER=false
            DO_ENGINE=true
            shift ;;
        --skip-test)
            DO_TEST=false
            shift ;;
        --skip-lint)
            DO_LINT=false
            shift ;;
        --config-only)
            DO_CONFIG_ONLY=true
            shift ;;
        --tls)
            DO_TLS=true
            shift ;;
        --production|--prod)
            DO_PRODUCTION=true
            shift ;;
        --init)
            DO_INIT=true
            shift ;;
        --help|-h)
            head -20 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *)
            echo "Unknown argument: $1"
            exit 1 ;;
    esac
done

# -- Helper functions --
step() { echo ""; echo "━━━ $1 ━━━"; }
elapsed() { echo "  Time: $(( $(date +%s) - $1 ))s"; }
TOTAL_START=$(date +%s)

RSYNC_EXCLUDES=(
    "target"
    "node_modules"
    ".claude"
    ".codex"
    "/data"
    "logs"
    "frontend/dist"
    ".build-output"
    ".env"
    "deploy.conf"
    ".git/"
    ".DS_Store"
    "Thumbs.db"
    "__pycache__/"
    "*.pyc"
    "*.pyo"
    "*.pyd"
    ".pytest_cache/"
    ".mypy_cache/"
    ".ruff_cache/"
    ".venv/"
    "venv/"
    ".coverage"
    ".pids"
)

compose_up_with_retry() {
    local label="$1"
    local remote_cmd="$2"

    if ssh "$SERVER" "$remote_cmd"; then
        return 0
    fi

    echo "  ${label} deployment hit a transient Docker Compose conflict; retrying once..."
    sleep 3
    ssh "$SERVER" "$remote_cmd"
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

apply_capture_host_tuning() {
    ssh "$SERVER" "cd '${REMOTE_DIR}' && bash scripts/apply-capture-host-tuning.sh --env-file '${REMOTE_DIR}/deploy/docker/.env'"
}

rsync_source_tree() {
    local rsync_args=(-avz --no-times --delete --compress --partial
        --timeout=300
        -e "ssh -o ServerAliveInterval=10 -o ServerAliveCountMax=30 -o ConnectTimeout=30"
    )
    local pattern
    for pattern in "${RSYNC_EXCLUDES[@]}"; do
        rsync_args+=(--exclude "$pattern")
    done
    rsync "${rsync_args[@]}" "$LOCAL_DIR" "${SERVER}:${REMOTE_DIR}/"
}

cleanup_remote_sync_junk() {
    ssh "$SERVER" "cd '${REMOTE_DIR}' && \
        find . -type d \\( \
            -name '.git' -o \
            -name '__pycache__' -o \
            -name '.pytest_cache' -o \
            -name '.mypy_cache' -o \
            -name '.ruff_cache' -o \
            -name '.venv' -o \
            -name 'venv' \
        \\) -prune -exec rm -rf -- {} + && \
        find . -type f \\( \
            -name '.DS_Store' -o \
            -name 'Thumbs.db' -o \
            -name '.coverage' -o \
            -name '.pids' -o \
            -name '*.pyc' -o \
            -name '*.pyo' -o \
            -name '*.pyd' \
        \\) -delete"
}

run_remote_frontend_toolchain() {
    local task="$1"

    ssh "$SERVER" "cd '${REMOTE_DIR}' && \
        docker run --rm \
            -v '${REMOTE_DIR}:/workspace' \
            -w /workspace/frontend \
            ${FRONTEND_NODE_IMAGE} \
            bash -lc 'npm install -g npm@${FRONTEND_NPM_VERSION} >/dev/null 2>&1 && \
                bash ../scripts/check-frontend-toolchain.sh && \
                ${task}'"
}

# -- Step 0: initial setup (optional) --
if $DO_INIT; then
    step "Initial setup: sync source to remote server"
    rsync_source_tree
    cleanup_remote_sync_junk

    step "Initial setup: generate remote .env (if missing)"
    ssh "$SERVER" "
        if [ ! -f ${REMOTE_DIR}/deploy/docker/.env ]; then
            echo 'Generating .env ...'
            cd ${REMOTE_DIR} && bash scripts/generate-secrets.sh
        else
            echo '.env already exists; skipping generation'
        fi
    "

    step "Initial setup: create persistent build container"
    ssh "$SERVER" "cd ${REMOTE_DIR} && bash deploy/docker/setup-builder.sh"
    echo ""
    echo "Initialization complete."
    echo "  To customize configuration, edit the remote .env: ssh $SERVER 'vi ${REMOTE_DIR}/deploy/docker/.env'"
    echo "  Next deployments: ./deploy.sh"
    exit 0
fi

# -- Derived flags --
NEED_RUST_ARTIFACTS=false
if ! $DO_CONFIG_ONLY && ($DO_BACKEND || $DO_SNIFFER || $DO_MTA || $DO_ENGINE); then
    NEED_RUST_ARTIFACTS=true
fi

NEED_BUILDER=false
if $NEED_RUST_ARTIFACTS && { $DO_LINT || $DO_TEST || ! $DO_PRODUCTION; }; then
    NEED_BUILDER=true
fi

# -- Step 1: sync source code --
step "Sync source to remote server"
T=$(date +%s)
rsync_source_tree
cleanup_remote_sync_junk
elapsed $T

# -- Step 1.5: preflight-check remote .env --
if ! ssh "$SERVER" "test -f ${REMOTE_DIR}/deploy/docker/.env"; then
    echo ""
    echo "Error: remote .env is missing: ${REMOTE_DIR}/deploy/docker/.env"
    echo "Run ./deploy.sh --init first."
    echo "Or generate it manually: ssh $SERVER 'cd ${REMOTE_DIR} && bash scripts/generate-secrets.sh'"
    exit 1
fi

# -- Step 2: verify the build container exists --
if $NEED_BUILDER && ! ssh "$SERVER" "docker ps --format '{{.Names}}' | grep -q '^${BUILDER_NAME}$'"; then
    echo ""
    echo "Error: build container ${BUILDER_NAME} is not running."
    echo "Run ./deploy.sh --init first."
    exit 1
fi

# -- Step 3: Rust verification / build --
if $NEED_RUST_ARTIFACTS; then

    if $DO_LINT; then
        step "Clippy check (includes cargo check)"
        T=$(date +%s)
        ssh "$SERVER" "docker exec ${BUILDER_NAME} cargo clippy --workspace -- -D warnings"
        elapsed $T
    fi

    if $DO_TEST; then
        step "Run tests"
        T=$(date +%s)
        ssh "$SERVER" "docker exec ${BUILDER_NAME} cargo test --workspace"
        elapsed $T
    fi

    if ! $DO_PRODUCTION; then
        # -- Step 4: incrementally build release binaries --
        step "Incremental release-fast build"
        T=$(date +%s)

        BUILD_PACKAGES=""
        $DO_BACKEND && BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-api -p vigilyx-engine"
        $DO_SNIFFER && BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-sniffer"
        $DO_MTA && BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-mta"
        $DO_ENGINE && BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-engine"

        ssh "$SERVER" "docker exec ${BUILDER_NAME} cargo build --profile release-fast $BUILD_PACKAGES"
        elapsed $T

        # -- Step 5: copy binaries to the output directory --
        step "Copy build artifacts"
        ssh "$SERVER" "mkdir -p ${REMOTE_DIR}/.build-output"
        ssh "$SERVER" "docker exec ${BUILDER_NAME} mkdir -p /app/.build-output"

        if $DO_BACKEND; then
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-api /app/.build-output/"
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-engine /app/.build-output/"
        fi
        if $DO_SNIFFER; then
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-sniffer /app/.build-output/"
        fi
        if $DO_ENGINE; then
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-engine /app/.build-output/"
        fi
        if $DO_MTA; then
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-mta /app/.build-output/"
        fi
    fi
fi

# -- Step 6: build the frontend if needed --
if $DO_FRONTEND && ! $DO_PRODUCTION && ! $DO_CONFIG_ONLY; then
    step "Build frontend"
    T=$(date +%s)
    run_remote_frontend_toolchain "npm ci && npx vite build"
    elapsed $T
elif $DO_FRONTEND && $DO_PRODUCTION && ! $DO_CONFIG_ONLY; then
    echo ""
    echo "━━━ Production-mode frontend build ━━━"
    echo "  The frontend will be built and packaged by Dockerfile.api during image build."
fi

# -- Step 7: package the Docker runtime image --
if ! $DO_CONFIG_ONLY; then
    step "Build runtime Docker images"
    T=$(date +%s)

    COMPOSE_CMD="cd ${REMOTE_DIR}"
    BUILD_TARGETS=""

    if $DO_BACKEND || $DO_FRONTEND; then
        BUILD_TARGETS="$BUILD_TARGETS vigilyx"
    fi
    if $DO_SNIFFER; then
        BUILD_TARGETS="$BUILD_TARGETS sniffer"
    fi
    if $DO_MTA; then
        BUILD_TARGETS="$BUILD_TARGETS mta"
    fi
    if $DO_ENGINE; then
        BUILD_TARGETS="$BUILD_TARGETS engine"
    fi

    if [ -n "$BUILD_TARGETS" ]; then
        if $DO_PRODUCTION; then
            ssh "$SERVER" "cd ${REMOTE_DIR} && \
                set -a && \
                [ -f deploy/docker/.env ] && . deploy/docker/.env >/dev/null 2>&1 || true && \
                set +a && \
                docker compose -f ${COMPOSE_FILE} build $BUILD_TARGETS"
        else
            # Use the fast override: Dockerfile.api.fast only COPYs prebuilt binaries (~5s packaging)
            ssh "$SERVER" "cd ${REMOTE_DIR} && \
                docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} build $BUILD_TARGETS"
        fi
    fi

    elapsed $T
else
    step "Build runtime Docker images"
    echo "  Skipped image build (--config-only)"
fi

# -- Step 8: deploy (targeted restart to avoid unnecessary sniffer packet loss) --
step "Deploy containers"
T=$(date +%s)
TLS_PROFILE=""
if $DO_TLS; then
    TLS_PROFILE="--profile tls"
    REMOTE_IP=$(ssh "$SERVER" "hostname -I | awk '{print \$1}'")
    # Generate a self-signed certificate if it does not exist
    ssh "$SERVER" "
        CERT_DIR=\$(docker volume inspect vigilyx_caddy_data --format '{{.Mountpoint}}' 2>/dev/null || echo '/var/lib/docker/volumes/vigilyx_caddy_data/_data')
        mkdir -p \$CERT_DIR
        if [ ! -f \$CERT_DIR/vigilyx.crt ]; then
            echo 'Generating self-signed TLS certificate (IP: ${REMOTE_IP})...'
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                -nodes -days 3650 -subj '/CN=Vigilyx' \
                -addext 'subjectAltName=IP:${REMOTE_IP},IP:127.0.0.1,DNS:localhost' \
                -keyout \$CERT_DIR/vigilyx.key -out \$CERT_DIR/vigilyx.crt 2>/dev/null
            echo 'TLS certificate generated (valid for 10 years)'
        else
            echo 'TLS certificate already exists; skipping generation'
        fi
        sed -i '/^VIGILYX_DOMAIN=/d' '${REMOTE_DIR}/deploy/docker/.env'
        sed -i '/^CADDY_TLS_MODE=/d' '${REMOTE_DIR}/deploy/docker/.env'
        echo 'VIGILYX_DOMAIN=${REMOTE_IP}' >> '${REMOTE_DIR}/deploy/docker/.env'
        echo 'CADDY_TLS_MODE=files' >> '${REMOTE_DIR}/deploy/docker/.env'
        sed -i 's/^API_LISTEN=0.0.0.0/API_LISTEN=127.0.0.1/' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null || true
    "
    echo "  HTTPS: https://${REMOTE_IP}"
fi

# -- Detect deployment mode (env > DB > default mirror) --
# sniffer and mta now both live behind profiles (mirror / mta), so deploy.sh needs to know the active mode
DEPLOY_MODE=""
if ! $DO_MTA; then
    # Check VIGILYX_MODE in .env first (highest priority)
    DEPLOY_MODE=$(ssh "$SERVER" "grep -oP '(?<=^VIGILYX_MODE=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | tr -d '\"' | tr -d \"'\" | tr '[:upper:]' '[:lower:]'")
    # If env is unset, read the value from the DB config table
    if [ -z "$DEPLOY_MODE" ] || { [ "$DEPLOY_MODE" != "mirror" ] && [ "$DEPLOY_MODE" != "mta" ]; }; then
        DEPLOY_MODE=$(ssh "$SERVER" "docker exec vigilyx-postgres sh -lc \
            'psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -Atq -c \"SELECT value::jsonb->>\\x27mode\\x27 FROM config WHERE key=\\x27deployment_mode\\x27;\"' 2>/dev/null" || echo "")
    fi
    [ "$DEPLOY_MODE" != "mta" ] && DEPLOY_MODE="mirror"
    echo "  Deployment mode: ${DEPLOY_MODE} (source: $([ -n \"$(ssh "$SERVER" "grep -oP '(?<=^VIGILYX_MODE=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null")\" ] && echo 'env' || echo 'db/default'))"
fi

if $DO_ANTIVIRUS; then
    ssh "$SERVER" "
        if grep -q '^CLAMAV_ENABLED=' '${REMOTE_DIR}/deploy/docker/.env'; then
            sed -i 's/^CLAMAV_ENABLED=.*/CLAMAV_ENABLED=true/' '${REMOTE_DIR}/deploy/docker/.env'
        else
            echo 'CLAMAV_ENABLED=true' >> '${REMOTE_DIR}/deploy/docker/.env'
        fi
    "
fi

CLAMAV_ENABLED_RAW=$(ssh "$SERVER" "grep -oP '(?<=^CLAMAV_ENABLED=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | tr -d '\"' | tr -d \"'\"")
ANTIVIRUS_PROFILE=""
if is_truthy "$CLAMAV_ENABLED_RAW"; then
    ANTIVIRUS_PROFILE="--profile antivirus"
    echo "  Antivirus: enabled (ClamAV profile)"
else
    echo "  Antivirus: disabled"
fi

# -- Auto-compile supplement for MTA mode: ensure the MTA binary does not stay stale when --mta is omitted --
if [ "$DEPLOY_MODE" = "mta" ] && ! $DO_MTA && ($DO_BACKEND || $DO_SNIFFER); then
    echo "  Detected MTA mode; including MTA build and packaging automatically"
    DO_MTA=true
    if $DO_PRODUCTION; then
        ssh "$SERVER" "cd ${REMOTE_DIR} && \
            set -a && \
            [ -f deploy/docker/.env ] && . deploy/docker/.env >/dev/null 2>&1 || true && \
            set +a && \
            docker compose -f ${COMPOSE_FILE} build mta" || true
    else
        # Build the MTA as a follow-up if the earlier build stage already ran
        ssh "$SERVER" "docker exec ${BUILDER_NAME} cargo build --profile release-fast -p vigilyx-mta" || true
        ssh "$SERVER" "docker exec ${BUILDER_NAME} bash -c 'cp /app/target/release-fast/vigilyx-mta /app/.build-output/'" || true
        # Package the MTA image as a follow-up
        ssh "$SERVER" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} build mta" || true
    fi
fi

# Targeted restart strategy: choose the profile according to the detected mode
# sniffer uses --profile mirror, and mta uses --profile mta
MODE_PROFILE="--profile ${DEPLOY_MODE}"
UP_TARGETS=""
if $DO_BACKEND || $DO_FRONTEND; then
    UP_TARGETS="$UP_TARGETS vigilyx"
fi

# Start non-sniffer/non-mta services first to ensure Redis/API are ready
if [ -n "$UP_TARGETS" ]; then
    compose_up_with_retry "Main service" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} ${MODE_PROFILE} --profile ai ${ANTIVIRUS_PROFILE} ${TLS_PROFILE} up -d $UP_TARGETS"
fi

if [ -n "$ANTIVIRUS_PROFILE" ]; then
    compose_up_with_retry "ClamAV" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} --profile antivirus up -d clamav"
fi

# Apply host tuning for mirror mode even when only backend/config changed.
if [ "$DEPLOY_MODE" = "mirror" ]; then
    apply_capture_host_tuning
fi

# Start the data-plane service for the active mode (sniffer or mta)
if $DO_SNIFFER && [ "$DEPLOY_MODE" = "mirror" ]; then
    echo "  Restarting sniffer (capture gap ~3s)..."
    compose_up_with_retry "Sniffer" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} --profile mirror up -d sniffer"
fi

# MTA proxy deployment (explicit --mta or DB mode = mta)
if $DO_MTA || [ "$DEPLOY_MODE" = "mta" ]; then
    echo "  Starting MTA proxy..."
    if $DO_PRODUCTION; then
        compose_up_with_retry "MTA proxy" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} --profile mta ${ANTIVIRUS_PROFILE} up -d mta"
    else
        compose_up_with_retry "MTA proxy" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} --profile mta ${ANTIVIRUS_PROFILE} up -d mta"
    fi
fi

# Engine standalone deployment (explicit --engine)
if $DO_ENGINE; then
    echo "  Setting STANDALONE_ENGINE=false in remote .env (so the main container runs API-only)..."
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
        if grep -q '^STANDALONE_ENGINE=' deploy/docker/.env 2>/dev/null; then \
            sed -i 's/^STANDALONE_ENGINE=.*/STANDALONE_ENGINE=false/' deploy/docker/.env; \
        else \
            echo 'STANDALONE_ENGINE=false' >> deploy/docker/.env; \
        fi"

    echo "  Restarting main vigilyx container in API-only mode..."
    compose_up_with_retry "Main service (API-only)" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} ${MODE_PROFILE} --profile ai ${ANTIVIRUS_PROFILE} ${TLS_PROFILE} up -d vigilyx"

    echo "  Starting standalone Engine container..."
    if $DO_PRODUCTION; then
        compose_up_with_retry "Standalone engine" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} --profile engine-standalone up -d engine"
    else
        compose_up_with_retry "Standalone engine" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} --profile engine-standalone up -d engine"
    fi
fi

elapsed $T

# -- Step 9: verify frontend dist inside the image --
if ! $DO_PRODUCTION && ! $DO_CONFIG_ONLY && { $DO_BACKEND || $DO_FRONTEND; }; then
    step "Verify frontend dist availability"
    if ! ssh "$SERVER" "docker exec vigilyx test -f /app/frontend/dist/index.html 2>/dev/null"; then
        echo "Frontend dist is missing inside the image; rebuilding frontend and repackaging..."
        run_remote_frontend_toolchain "npm ci && npx vite build"
        ssh "$SERVER" "cd '${REMOTE_DIR}' && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} build vigilyx && \
            docker compose -f ${COMPOSE_FILE} ${MODE_PROFILE} --profile ai ${ANTIVIRUS_PROFILE} ${TLS_PROFILE} up -d vigilyx"
    fi
fi

# -- Done --
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Deployment complete. Total time: $(( $(date +%s) - TOTAL_START ))s"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Check status: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} ps'"
echo "API logs:     ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 vigilyx'"
echo "Engine logs:  ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 vigilyx'  # or: logs --tail 30 engine (if standalone)"
echo "Sniffer logs: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 sniffer'"
