#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Vigilyx one-command deployment script
# ═══════════════════════════════════════════════════
#
# Uses a persistent build container for incremental compilation to speed up deployment significantly.
#
# Usage:
#   ./deploy.sh                  # Full deployment (frontend + backend + active data plane; mirror by default)
#   ./deploy.sh --backend        # Backend only (also refreshes the active topology's engine-bearing service)
#   ./deploy.sh --frontend       # Frontend only (tests + build + package; dependency reconciliation pauses services)
#   ./deploy.sh --production     # Production release build (full Docker build, slower)
#   ./deploy.sh --skip-test      # Skip tests (for emergency fixes)
#   ./deploy.sh --skip-lint      # Skip clippy (for emergency fixes)
#   ./deploy.sh --sniffer        # Sniffer only (mirror deployment data plane)
#   ./deploy.sh --config-only    # Sync config/scripts and recreate services without rebuilding images
#   ./deploy.sh --antivirus      # Add ClamAV to the selected deployment (bare invocation still deploys all defaults)
#   ./deploy.sh --mta            # Full MTA topology (API/frontend + embedded-engine MTA; no sniffer)
#   ./deploy.sh --tls            # Enable HTTPS with bundled Caddy and self-signed certificates
#   ./deploy.sh --init           # Initial build-container setup
#
# Deprecated (no-op):
#   --engine                     # Mirror deployment now always runs a dedicated engine container.
#
# Prerequisites:
#   1. Passwordless SSH access to the target server
#   2. Run setup-builder.sh to initialize the build container (or use --init)
#
# Configuration methods (choose one):
#   a) Create deploy.conf (recommended): cp deploy.conf.example deploy.conf && chmod 600 deploy.conf && edit it
#   b) Set an environment variable: export VIGILYX_SERVER=root@your-server
#   c) Edit the defaults in this file directly
# Every deployment reconciles dependency configuration/roles and briefly
# pauses running services. Schema migrations require a freshly built API.

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./deploy.sh [options]

With no component option, deploy the frontend, API, and active data plane.
The active mode defaults to mirror and can be pinned to mta in the remote .env.

Component options:
  --backend        Rebuild/deploy the API and active engine-bearing service
  --frontend       Test, build, and deploy the frontend/API image only
  --sniffer        Rebuild/deploy the mirror-mode sniffer only
  --mta            Rebuild/deploy the full inline MTA topology
  --antivirus      Enable ClamAV in the selected deployment (additive to default full deployment)

Workflow options:
  --production     Use full Dockerfiles and release-grade cargo --release images
  --config-only    Sync configuration and recreate services without rebuilding
  --skip-test      Skip tests (emergency use only)
  --skip-lint      Skip clippy (emergency use only)
  --tls            Enable the bundled Caddy TLS profile
  --init           One-time source, environment, and persistent-builder setup
  --help, -h       Show this help

Deprecated:
  --engine         No-op; mirror deployments always use the dedicated engine
USAGE
}

# -- Load the config file if it exists --
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/deploy.conf" ]; then
    conf_perms=$(stat -f '%Lp' "${SCRIPT_DIR}/deploy.conf" 2>/dev/null || stat -c '%a' "${SCRIPT_DIR}/deploy.conf")
    if [ $((10#$conf_perms % 100)) -gt 0 ]; then
        echo "Error: deploy.conf must not be group/world-accessible (chmod 600 deploy.conf)." >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/deploy.conf"
fi

# Help must work before deployment configuration exists.
for arg in "$@"; do
    if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
        usage
        exit 0
    fi
done

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
MTA_FORCED=false
SNIFFER_EXPLICIT=false

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
            SNIFFER_EXPLICIT=true
            shift ;;
        --antivirus)
            DO_ANTIVIRUS=true
            shift ;;
        --mta)
            # A first MTA deployment still needs the API/frontend image because
            # migrations and the control plane use it. Treat --mta as a complete
            # topology, not as a component-only restart.
            DO_FRONTEND=true
            DO_BACKEND=true
            DO_SNIFFER=false
            DO_MTA=true
            MTA_FORCED=true
            shift ;;
        --engine)
            # DEPRECATED: kept as a no-op for backwards compatibility.
            # Mirror deployment now always runs engine as a dedicated container (via `./deploy.sh`).
            # This flag will be removed in phase 3 of the topology refactor.
            echo "warning: --engine is deprecated; mirror deployment always runs a dedicated engine container." >&2
            echo "         run './deploy.sh' (or './deploy.sh --backend') without --engine." >&2
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
            usage
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
    ".agents"
    ".claude"
    ".codex"
    # Isolated remote audit checkouts are operational artifacts, not sync inputs.
    ".codex-workspaces/"
    ".audit/"
    ".lotyra/"
    ".lotyra-leases.json"
    # Keep versioned decision records and evaluation evidence synchronized with
    # the deployment checkout; generated site output is excluded below.
    "reports/"
    # Remote database/volume backups may live below the deployment root.
    # They are operational state and must never be removed by --delete.
    "backups/"
    "/data"
    "crates/vigilyx-engine/data/"
    "crates/vigilyx-sniffer/data/"
    "logs"
    "frontend/dist"
    # VitePress output/cache are generated artifacts (also ignored by Git).
    # Keeping them out of source sync avoids stale hashed assets and noisy
    # --delete churn after a documentation build on either host.
    "site/.vitepress/dist/"
    "site/.vitepress/cache/"
    ".build-output"
    # Server-side rollback snapshots must survive rsync --delete.
    ".rollback/"
    ".env"
    "deploy.conf"
    # Deployment-local TLS private material must survive rsync --delete.
    "deploy/docker/certs/"
    # No trailing slash: a separate git dir leaves .git as a gitdir file.
    ".git"
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

compose_build_with_retry() {
    local label="$1"
    local remote_cmd="$2"
    local attempt

    for attempt in 1 2 3; do
        if ssh "$SERVER" "$remote_cmd"; then
            return 0
        fi

        if [ "$attempt" -eq 3 ]; then
            echo "  ${label} build failed after ${attempt} attempts." >&2
            return 1
        fi

        local delay=$((attempt * 3))
        echo "  ${label} build hit a transient registry/package error; retrying in ${delay}s (attempt $((attempt + 1))/3)..."
        sleep "$delay"
    done
}

run_remote_workspace_tests() {
    local test_log="/tmp/vigilyx_test_output.txt"
    local test_status="/tmp/vigilyx_test_status"
    local poll_secs="${VIGILYX_TEST_POLL_SECS:-15}"
    local timeout_secs="${VIGILYX_TEST_TIMEOUT_SECS:-1800}"
    local deadline=$(( $(date +%s) + timeout_secs ))
    local status=""

    # Keep the test process alive if the controlling SSH connection drops, and
    # persist the real cargo exit status instead of inferring success from logs.
    ssh "$SERVER" "rm -f '${test_log}' '${test_status}' && \
        (nohup sh -c 'docker exec ${BUILDER_NAME} cargo test --workspace -- --test-threads=${VIGILYX_TEST_THREADS:-8} > ${test_log} 2>&1; rc=\$?; echo \$rc > ${test_status}' \
        </dev/null >/dev/null 2>&1 &)"

    while [ "$(date +%s)" -lt "$deadline" ]; do
        status=$(ssh "$SERVER" "cat '${test_status}' 2>/dev/null || true")
        if [[ "$status" =~ ^[0-9]+$ ]]; then
            ssh "$SERVER" "tail -n 80 '${test_log}' 2>/dev/null || true"
            if [ "$status" -ne 0 ]; then
                echo "Error: remote Rust tests failed (exit ${status})." >&2
                echo "Full log: ssh ${SERVER} 'less ${test_log}'" >&2
                return "$status"
            fi
            return 0
        fi

        ssh "$SERVER" "tail -n 3 '${test_log}' 2>/dev/null || true"
        sleep "$poll_secs"
    done

    echo "Error: remote Rust tests exceeded ${timeout_secs}s." >&2
    echo "The background process may still be running; inspect: ssh ${SERVER} 'tail -n 80 ${test_log}'" >&2
    return 124
}

wait_for_api_readiness() {
    local timeout_secs="${VIGILYX_READINESS_TIMEOUT_SECS:-120}"
    local deadline=$(( $(date +%s) + timeout_secs ))
    local response=""

    if ! ssh "$SERVER" "docker ps --format '{{.Names}}' | grep -qx 'vigilyx'"; then
        echo "  API container is not part of this targeted deployment; readiness check skipped."
        return 0
    fi

    while [ "$(date +%s)" -lt "$deadline" ]; do
        if response=$(ssh "$SERVER" \
            "docker exec vigilyx curl -fsS --max-time 5 http://127.0.0.1:8088/api/health/ready" \
            2>/dev/null); then
            echo "  API readiness: ${response}"
            return 0
        fi
        sleep 2
    done

    echo "Error: API did not become ready within ${timeout_secs}s." >&2
    ssh "$SERVER" "cd '${REMOTE_DIR}' && \
        docker compose -f '${COMPOSE_FILE}' ps && \
        docker compose -f '${COMPOSE_FILE}' logs --tail 80 vigilyx engine 2>/dev/null || true" >&2
    return 1
}

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

check_local_secret_mode() {
    local secret_file mode
    for secret_file in "${LOCAL_REPO_ROOT}/.env" "${LOCAL_REPO_ROOT}/deploy/docker/.env"; do
        if [ ! -f "$secret_file" ]; then
            continue
        fi
        mode=$(stat -f '%Lp' "$secret_file" 2>/dev/null || stat -c '%a' "$secret_file")
        if [ "$mode" != "600" ]; then
            echo "Error: ${secret_file} must be mode 600 (current: ${mode}; run chmod 600)." >&2
            return 1
        fi
    done
}

rsync_source_tree() {
    # Archive mode preserves mtimes. Do not add --no-times: identical files with
    # different mtimes would be retransferred and could invalidate Cargo's
    # incremental fingerprints on every deployment.
    local rsync_args=(-az --delete --partial --stats
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
            -e HTTP_PROXY -e HTTPS_PROXY -e NO_PROXY \
            -e http_proxy -e https_proxy -e no_proxy \
            -e NPM_CONFIG_UPDATE_NOTIFIER=false \
            -e NPM_CONFIG_AUDIT=false \
            -e NPM_CONFIG_FUND=false \
            -v vigilyx_npm_cache:/root/.npm \
            -v '${REMOTE_DIR}:/workspace' \
            -w /workspace/frontend \
            ${FRONTEND_NODE_IMAGE} \
            bash -lc 'if [ \"\$(npm --version)\" != \"${FRONTEND_NPM_VERSION}\" ]; then \
                    npm install -g npm@${FRONTEND_NPM_VERSION}; \
                fi && \
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
if ! $DO_CONFIG_ONLY && { $DO_BACKEND || $DO_SNIFFER || $DO_MTA || $DO_ENGINE || { $DO_PRODUCTION && $DO_FRONTEND; }; }; then
    NEED_RUST_ARTIFACTS=true
fi

# Fast frontend builds reuse the API binary; config/sniffer deployments reuse
# its image. Running their old migrator could overwrite newer SQL functions
# already installed by a backend deployment or operational hotfix.
# Production frontend images compile the API too, so they must migrate.
RUN_SCHEMA_MIGRATIONS=false
if ! $DO_CONFIG_ONLY && { $DO_BACKEND || { $DO_PRODUCTION && $DO_FRONTEND; }; }; then
    RUN_SCHEMA_MIGRATIONS=true
fi

NEED_BUILDER=false
if $NEED_RUST_ARTIFACTS && { $DO_LINT || $DO_TEST || ! $DO_PRODUCTION; }; then
    NEED_BUILDER=true
fi

FRONTEND_BUILD_TASK="npm ci --prefer-offline --no-audit --no-fund"
if $DO_TEST; then
    FRONTEND_BUILD_TASK+=" && npm test"
fi
# package.json's build script is the supported production build: TypeScript
# checking must complete before Vite bundles the application.
FRONTEND_BUILD_TASK+=" && npm run build"

# -- Step 1: sync source code --
check_local_secret_mode
step "Sync source to remote server"
T=$(date +%s)
rsync_source_tree
cleanup_remote_sync_junk
elapsed "$T"

# -- Step 1.5: preflight-check remote .env --
if ! ssh "$SERVER" "test -f ${REMOTE_DIR}/deploy/docker/.env"; then
    echo ""
    echo "Error: remote .env is missing: ${REMOTE_DIR}/deploy/docker/.env"
    echo "Run ./deploy.sh --init first."
    echo "Or generate it manually: ssh $SERVER 'cd ${REMOTE_DIR} && bash scripts/generate-secrets.sh'"
    exit 1
fi

REMOTE_ENV_MODE=$(ssh "$SERVER" "stat -c '%a' '${REMOTE_DIR}/deploy/docker/.env'")
if [ "$REMOTE_ENV_MODE" != "600" ]; then
    echo ""
    echo "Error: remote deploy/docker/.env must be mode 600 (current: ${REMOTE_ENV_MODE})."
    echo "Run: ssh ${SERVER} 'chmod 600 ${REMOTE_DIR}/deploy/docker/.env'"
    exit 1
fi

# -- Step 1.55: idempotently provision secrets introduced by security upgrades --
# Source sync deliberately excludes .env, so an existing deployment must gain
# these values before Compose evaluates required-variable expressions.
ssh "$SERVER" "VIGILYX_REMOTE_DIR='${REMOTE_DIR}' bash -s" <<'REMOTE_SECURITY_SECRETS'
set -euo pipefail
umask 077
env_file="${VIGILYX_REMOTE_DIR}/deploy/docker/.env"
ensure_secret() {
    secret_name="$1"
    secret_bytes="$2"
    if grep -q "^${secret_name}=" "$env_file"; then
        current_value=$(sed -n "s/^${secret_name}=//p" "$env_file" | tail -n 1 | tr -d "'\"")
        if [ "${#current_value}" -lt 32 ] || printf '%s' "$current_value" | grep -q 'CHANGE_ME'; then
            echo "Error: ${secret_name} is present but weak/invalid; replace it in $env_file" >&2
            exit 1
        fi
    else
        secret_value=$(openssl rand -hex "$secret_bytes")
        printf '%s=%s\n' "$secret_name" "$secret_value" >> "$env_file"
        echo "  Remote .env: ${secret_name} generated"
    fi
}
ensure_secret VIGILYX_CONFIG_ENCRYPTION_KEY 32
ensure_secret PG_API_PASSWORD 24
ensure_secret PG_ENGINE_PASSWORD 24
ensure_secret PG_MTA_PASSWORD 24
ensure_secret REDIS_API_PASSWORD 24
ensure_secret REDIS_ENGINE_PASSWORD 24
ensure_secret REDIS_SNIFFER_PASSWORD 24
ensure_secret REDIS_MTA_PASSWORD 24
ensure_secret MQ_AUTH_TOKEN 24
ensure_secret SNIFFER_API_TOKEN 24
ensure_secret MTA_API_TOKEN 24

if ! grep -q '^AUDIT_USERNAME=' "$env_file"; then
    printf '%s\n' 'AUDIT_USERNAME=privacy-auditor' >> "$env_file"
    echo "  Remote .env: AUDIT_USERNAME initialized"
fi
if grep -q '^AUDIT_BOOTSTRAP_PASSWORD=' "$env_file"; then
    audit_password=$(sed -n 's/^AUDIT_BOOTSTRAP_PASSWORD=//p' "$env_file" | tail -n 1 | tr -d "'\"")
    if [ "${#audit_password}" -lt 12 ] || printf '%s' "$audit_password" | grep -q 'CHANGE_ME'; then
        echo "Error: AUDIT_BOOTSTRAP_PASSWORD is present but weak/invalid; replace it in $env_file" >&2
        exit 1
    fi
else
    audit_password="Vx!9$(openssl rand -hex 24)"
    printf 'AUDIT_BOOTSTRAP_PASSWORD=%s\n' "$audit_password" >> "$env_file"
    echo "  Remote .env: AUDIT_BOOTSTRAP_PASSWORD generated"
fi
chmod 600 "$env_file"
REMOTE_SECURITY_SECRETS

# -- Step 1.6: detect deployment mode (env > DB > default mirror) --
# sniffer and mta now both live behind profiles (mirror / mta), so deploy.sh needs to know the active mode
# before any build/up step. Done early so $DEPLOY_MODE is available throughout the rest of the script.
DEPLOY_MODE=""
DEPLOY_MODE_SOURCE=""
if ! $DO_MTA; then
    # Check VIGILYX_MODE in .env first (highest priority)
    DEPLOY_MODE=$(ssh "$SERVER" "grep -oP '(?<=^VIGILYX_MODE=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | tr -d '\"' | tr -d \"'\" | tr '[:upper:]' '[:lower:]'")
    if [ "$DEPLOY_MODE" = "mirror" ] || [ "$DEPLOY_MODE" = "mta" ]; then
        DEPLOY_MODE_SOURCE="env"
    else
        # If env is unset/invalid, read the value from the DB config table.
        DEPLOY_MODE=$(ssh "$SERVER" "docker exec -i vigilyx-postgres sh -lc \
            'psql -X -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -Atq'" 2>/dev/null <<'DEPLOY_MODE_SQL' || true
SELECT value::jsonb->>'mode' FROM config WHERE key='deployment_mode';
DEPLOY_MODE_SQL
        )
        if [ "$DEPLOY_MODE" = "mirror" ] || [ "$DEPLOY_MODE" = "mta" ]; then
            DEPLOY_MODE_SOURCE="db"
        else
            DEPLOY_MODE="mirror"
            DEPLOY_MODE_SOURCE="default"
        fi
    fi
    echo "  Deployment mode: ${DEPLOY_MODE} (source: ${DEPLOY_MODE_SOURCE})"
else
    DEPLOY_MODE="mta"
    DEPLOY_MODE_SOURCE="--mta"
    echo "  Deployment mode: mta (forced by --mta)"
fi

if [ "$DEPLOY_MODE" = "mta" ] && $SNIFFER_EXPLICIT; then
    echo "Error: --sniffer cannot deploy while VIGILYX_MODE is mta." >&2
    echo "Set VIGILYX_MODE=mirror in the remote .env before deploying the mirror sniffer." >&2
    exit 1
fi

# Resolve the active data plane before compilation and image packaging. A
# normal/backend deployment on an MTA host must rebuild the embedded engine in
# vigilyx-mta, and must not waste time building an inactive sniffer image.
if [ "$DEPLOY_MODE" = "mta" ]; then
    DO_SNIFFER=false
    if ! $DO_CONFIG_ONLY && $DO_BACKEND; then
        DO_MTA=true
        if ! $MTA_FORCED; then
            echo "  Active MTA mode: including the embedded-engine MTA build"
        fi
    fi
fi

# A frontend-only deployment preserves the active data plane. Backend,
# sniffer, and explicit MTA deployments manage their selected topology.
MANAGE_DATA_PLANE=false
if $DO_BACKEND || $DO_SNIFFER || $DO_MTA; then
    MANAGE_DATA_PLANE=true
fi

if [ "$DEPLOY_MODE" = "mta" ] && $MANAGE_DATA_PLANE; then
    ssh "$SERVER" "cd '${REMOTE_DIR}/deploy/docker' && bash -s" <<'REMOTE_MTA_TLS_PREFLIGHT'
set -euo pipefail
set -a
. ./.env
set +a
cert_source="${MTA_TLS_CERT_SOURCE:-./certs/mta.crt}"
key_source="${MTA_TLS_KEY_SOURCE:-./certs/mta.key}"
if [ ! -f "$cert_source" ] || [ ! -f "$key_source" ]; then
    echo "Error: MTA mode requires PEM files at $cert_source and $key_source" >&2
    echo "Set MTA_TLS_CERT_SOURCE/MTA_TLS_KEY_SOURCE or install deploy/docker/certs/mta.crt + mta.key." >&2
    exit 1
fi
key_mode=$(stat -c '%a' "$key_source")
if [ $((10#$key_mode % 100)) -ne 0 ]; then
    echo "Error: MTA private key must not be group/world-accessible (current mode: $key_mode)." >&2
    exit 1
fi
REMOTE_MTA_TLS_PREFLIGHT

    if $MTA_FORCED; then
        ssh "$SERVER" "cd '${REMOTE_DIR}' && \
            if grep -q '^VIGILYX_MODE=' deploy/docker/.env; then \
                sed -i 's/^VIGILYX_MODE=.*/VIGILYX_MODE=mta/' deploy/docker/.env; \
            else \
                echo 'VIGILYX_MODE=mta' >> deploy/docker/.env; \
            fi"
    fi
fi

# -- Step 1.7: topology migration (idempotent): force STANDALONE_ENGINE=false in remote .env --
# Mirror deployment now always runs the engine as a dedicated container (see `engine` service in docker-compose.yml).
# MTA deployment always runs the engine embedded in the MTA container.
# Either way the main vigilyx container must be API-only, so STANDALONE_ENGINE must be false.
# Legacy environments may still carry STANDALONE_ENGINE=true; this block converges them.
if $MANAGE_DATA_PLANE; then
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
    if grep -q '^STANDALONE_ENGINE=' deploy/docker/.env 2>/dev/null; then \
        current=\$(grep -oP '(?<=^STANDALONE_ENGINE=).*' deploy/docker/.env | tr -d '\"' | tr -d \"'\"); \
        if [ \"\$current\" != \"false\" ]; then \
            sed -i 's/^STANDALONE_ENGINE=.*/STANDALONE_ENGINE=false/' deploy/docker/.env; \
            echo '  Remote .env: STANDALONE_ENGINE normalized to false (was '\"\$current\"')'; \
        fi; \
    else \
        echo 'STANDALONE_ENGINE=false' >> deploy/docker/.env; \
        echo '  Remote .env: STANDALONE_ENGINE=false appended (was unset, compose default was true)'; \
    fi"
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
        elapsed "$T"
    fi

    if $DO_TEST; then
        step "Run tests"
        T=$(date +%s)
        run_remote_workspace_tests
        elapsed "$T"
    fi

    if ! $DO_PRODUCTION; then
        # -- Step 4: incrementally build release binaries --
        step "Incremental release-fast build"
        T=$(date +%s)

        BUILD_PACKAGES=""
        if [[ "$DO_BACKEND" == true ]]; then
            BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-api -p vigilyx-engine"
        fi
        if [[ "$DO_SNIFFER" == true ]]; then
            BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-sniffer"
        fi
        if [[ "$DO_MTA" == true ]]; then
            BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-mta"
        fi
        if [[ "$DO_ENGINE" == true ]]; then
            BUILD_PACKAGES="$BUILD_PACKAGES -p vigilyx-engine"
        fi

        ssh "$SERVER" "docker exec ${BUILDER_NAME} cargo build --profile release-fast $BUILD_PACKAGES"
        elapsed "$T"

        # -- Step 5: copy binaries to the output directory --
        step "Copy build artifacts"
        ssh "$SERVER" "mkdir -p ${REMOTE_DIR}/.build-output"
        ssh "$SERVER" "docker exec ${BUILDER_NAME} mkdir -p /app/.build-output"

        if $DO_BACKEND; then
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-api /app/.build-output/"
            ssh "$SERVER" "docker exec ${BUILDER_NAME} cp /app/target/release-fast/vigilyx-engine /app/.build-output/"
        fi
        # ONNX Runtime for the optional semantic intent model. The engine image
        # copies this directory; without the library the model stays disabled.
        ssh "$SERVER" "mkdir -p ${REMOTE_DIR}/.build-output/onnxruntime"
        if $DO_BACKEND || $DO_ENGINE; then
            if ! ssh "$SERVER" "bash ${REMOTE_DIR}/deploy/docker/fetch-onnxruntime.sh ${REMOTE_DIR}/.build-output/onnxruntime"; then
                echo "  WARNING: ONNX Runtime could not be fetched; the semantic intent model stays disabled" >&2
            fi
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
if [[ "$DO_FRONTEND" == true && "$DO_PRODUCTION" == false && "$DO_CONFIG_ONLY" == false ]]; then
    step "Verify and build frontend"
    T=$(date +%s)
    run_remote_frontend_toolchain "$FRONTEND_BUILD_TASK"
    elapsed "$T"
elif [[ "$DO_FRONTEND" == true && "$DO_PRODUCTION" == true && "$DO_CONFIG_ONLY" == false ]]; then
    step "Verify frontend before production image build"
    T=$(date +%s)
    run_remote_frontend_toolchain "$FRONTEND_BUILD_TASK"
    elapsed "$T"
    echo "  Dockerfile.api will rebuild and package the verified frontend in the production image."
fi

# -- Step 7: package the Docker runtime image --
if ! $DO_CONFIG_ONLY; then
    step "Build runtime Docker images"
    T=$(date +%s)

    BUILD_TARGETS=""

    if $DO_BACKEND || $DO_FRONTEND; then
        BUILD_TARGETS="$BUILD_TARGETS vigilyx"
    fi
    # Mirror deployment: engine always runs as a dedicated container, keep its image in sync with backend builds.
    if $DO_BACKEND && [ "$DEPLOY_MODE" = "mirror" ]; then
        BUILD_TARGETS="$BUILD_TARGETS engine"
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
            compose_build_with_retry "Runtime image" "cd ${REMOTE_DIR} && \
                set -a && \
                [ -f deploy/docker/.env ] && . deploy/docker/.env >/dev/null 2>&1 || true && \
                set +a && \
                docker compose -f ${COMPOSE_FILE} build $BUILD_TARGETS"
        else
            # Fast images package prebuilt binaries and runtime assets without running Cargo build (~5s).
            compose_build_with_retry "Runtime image" "cd ${REMOTE_DIR} && \
                docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} build $BUILD_TARGETS"
        fi
    fi

    elapsed "$T"
else
    step "Build runtime Docker images"
    echo "  Skipped image build (--config-only)"
fi

# -- Step 8: reconcile persistent dependencies and runtime credentials --
# Targeted service restarts below intentionally name each service without
# enabling its whole Compose profile. Explicit --profile flags start every
# service in that profile (for example, mirror also starts the sniffer), which
# would defeat the targeted restart and interrupt packet capture. Before doing
# targeted up commands with --no-deps, Compose must
# still reconcile PostgreSQL/Valkey configuration and least-privilege roles.
# A freshly built API also runs the one-shot schema migrator. This matters when an
# existing installation gains newly introduced PG_* / REDIS_* credentials.
step "Reconcile database and message-bus dependencies"
T=$(date +%s)
# The remote helper owns the pause/restore trap in one SSH session. It also
# pauses clients before dependency recreation, including parameter changes.
ssh "$SERVER" "cd '${REMOTE_DIR}' && bash scripts/reconcile-deployment.sh '${RUN_SCHEMA_MIGRATIONS}'"
elapsed "$T"

# -- Step 9: deploy requested components after the migration window --
step "Deploy containers"
T=$(date +%s)
if $DO_TLS; then
    REMOTE_IP=$(ssh "$SERVER" "hostname -I | awk '{print \$1}'")
    # Generate a self-signed certificate if it does not exist
    ssh "$SERVER" "
        CERT_DIR=\$(docker volume inspect vigilyx_caddy_data --format '{{.Mountpoint}}' 2>/dev/null || echo '/var/lib/docker/volumes/vigilyx_caddy_data/_data')
        mkdir -p \$CERT_DIR
        if [ ! -f \$CERT_DIR/vigilyx.crt ]; then
            echo 'Generating self-signed TLS certificate (IP: ${REMOTE_IP})...'
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                -nodes -days 397 -subj '/CN=Vigilyx' \
                -addext 'subjectAltName=IP:${REMOTE_IP},IP:127.0.0.1,DNS:localhost' \
                -keyout \$CERT_DIR/vigilyx.key -out \$CERT_DIR/vigilyx.crt 2>/dev/null
            echo 'TLS certificate generated (valid for 397 days)'
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

if $DO_ANTIVIRUS; then
    ssh "$SERVER" "
        if grep -q '^CLAMAV_ENABLED=' '${REMOTE_DIR}/deploy/docker/.env'; then
            sed -i 's/^CLAMAV_ENABLED=.*/CLAMAV_ENABLED=true/' '${REMOTE_DIR}/deploy/docker/.env'
        else
            echo 'CLAMAV_ENABLED=true' >> '${REMOTE_DIR}/deploy/docker/.env'
        fi
    "
fi

AI_ENABLED_RAW=$(ssh "$SERVER" "grep -oP '(?<=^AI_ENABLED=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | tail -n 1 | tr -d '\"' | tr -d \"'\"")
CLAMAV_ENABLED_RAW=$(ssh "$SERVER" "grep -oP '(?<=^CLAMAV_ENABLED=).*' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | tail -n 1 | tr -d '\"' | tr -d \"'\"")
if is_truthy "$CLAMAV_ENABLED_RAW" && { $MANAGE_DATA_PLANE || $DO_ANTIVIRUS; }; then
    echo "  Antivirus: enabled (ClamAV profile will be started)"
elif is_truthy "$CLAMAV_ENABLED_RAW"; then
    echo "  Antivirus: configured; current service state is preserved by this component deployment"
else
    echo "  Antivirus: integration disabled (CLAMAV_ENABLED=false; no ClamAV profile start requested)"
fi

# Targeted restart strategy: explicit service targets activate their own
# profiles. Do not pass --profile here: that starts every peer in the profile.
UP_TARGETS=""
if $DO_BACKEND || $DO_FRONTEND; then
    UP_TARGETS="$UP_TARGETS vigilyx"
fi
# Mirror deployment: ensure the dedicated engine container is (re)started whenever the backend is touched.
if $DO_BACKEND && [ "$DEPLOY_MODE" = "mirror" ]; then
    UP_TARGETS="$UP_TARGETS engine"
fi
if $DO_TLS; then
    # Caddy depends on the API; include both because this is a targeted --no-deps up.
    UP_TARGETS="$UP_TARGETS vigilyx caddy"
fi

# Start non-sniffer/non-mta services first to ensure Redis/API are ready
if [ -n "$UP_TARGETS" ]; then
    compose_up_with_retry "Main service" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} up -d --no-deps $UP_TARGETS"
fi

# Only recreate traffic-processing services when this invocation targets the
# backend or a data-plane component. Dependency reconciliation still pauses
# and restores containers that were running before the deployment.
if $MANAGE_DATA_PLANE; then
    if [ "$DEPLOY_MODE" = "mta" ]; then
        ssh "$SERVER" "docker stop vigilyx-sniffer vigilyx-engine-standalone >/dev/null 2>&1 || true"
    else
        ssh "$SERVER" "docker stop vigilyx-mta >/dev/null 2>&1 || true"
    fi
fi

if is_truthy "$CLAMAV_ENABLED_RAW" && { $MANAGE_DATA_PLANE || $DO_ANTIVIRUS; }; then
    compose_up_with_retry "ClamAV" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} up -d --no-deps clamav"
fi

if is_truthy "$AI_ENABLED_RAW" && $MANAGE_DATA_PLANE; then
    compose_up_with_retry "AI service" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} up -d --no-deps ai"
elif is_truthy "$AI_ENABLED_RAW"; then
    echo "  AI service: configured; current service state is preserved by this component deployment"
else
    echo "  AI integration: disabled (AI_ENABLED=false; no AI profile start requested)"
fi

# Host/network tuning is a separate operator task, not a deployment side effect.

# Start the data-plane service for the active mode (sniffer or mta)
if $DO_SNIFFER && [ "$DEPLOY_MODE" = "mirror" ]; then
    echo "  Ensuring sniffer is running the packaged image (recreate only when changed)..."
    compose_up_with_retry "Sniffer" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} up -d --no-deps sniffer"
fi

# MTA proxy deployment (explicit --mta or an MTA-targeting deployment)
if $MANAGE_DATA_PLANE && { $DO_MTA || [ "$DEPLOY_MODE" = "mta" ]; }; then
    echo "  Starting MTA proxy..."
    if $DO_PRODUCTION; then
        compose_up_with_retry "MTA TLS material" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} run --rm --no-deps mta-cert-install"
        compose_up_with_retry "MTA proxy" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} up -d --no-deps mta"
    else
        compose_up_with_retry "MTA TLS material" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} run --rm --no-deps mta-cert-install"
        compose_up_with_retry "MTA proxy" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} up -d --no-deps mta"
    fi
fi

elapsed "$T"

# -- Step 10: verify frontend dist inside the image --
if ! $DO_PRODUCTION && ! $DO_CONFIG_ONLY && { $DO_BACKEND || $DO_FRONTEND; }; then
    step "Verify frontend dist availability"
    if ! ssh "$SERVER" "docker exec vigilyx test -f /app/frontend/dist/index.html 2>/dev/null"; then
        echo "Frontend dist is missing inside the image; rebuilding frontend and repackaging..."
        run_remote_frontend_toolchain "$FRONTEND_BUILD_TASK"
        ssh "$SERVER" "cd '${REMOTE_DIR}' && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} build vigilyx && \
            docker compose -f ${COMPOSE_FILE} up -d --no-deps vigilyx"
    fi
fi

# -- Step 11: verify the deployed control plane and engine dependencies --
step "Verify deployment readiness"
wait_for_api_readiness
ssh "$SERVER" "cd '${REMOTE_DIR}' && python3 scripts/verify-deployment.py --mode '${DEPLOY_MODE}'"

# -- Done --
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Deployment complete. Total time: $(( $(date +%s) - TOTAL_START ))s"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Check status: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} ps'"
echo "API logs:     ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 vigilyx'"
echo "Engine logs:  ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 engine'   # mirror deployment"
echo "              ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 mta'      # MTA deployment (engine embedded)"
echo "Sniffer logs: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 sniffer'"
