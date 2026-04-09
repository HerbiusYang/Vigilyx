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

if $DO_PRODUCTION && $DO_ENGINE; then
    echo "Error: --production does not currently support --engine."
    echo "Reason: the standalone engine service currently only has a fast Dockerfile (deploy/docker/Dockerfile.engine.fast)."
    exit 1
fi

# -- Helper functions --
step() { echo ""; echo "━━━ $1 ━━━"; }
elapsed() { echo "  Time: $(( $(date +%s) - $1 ))s"; }
TOTAL_START=$(date +%s)

is_truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|on|ON|On)
            return 0 ;;
        *)
            return 1 ;;
    esac
}

apply_capture_host_tuning() {
    ssh "$SERVER" "
        IFACE=\$(grep '^SNIFFER_INTERFACE=' '${REMOTE_DIR}/deploy/docker/.env' 2>/dev/null | cut -d= -f2 | tr -d '\"' | tr -d \"'\")
        IFACE=\${IFACE:-eth0}

        if [ ! -d /sys/class/net/\$IFACE ]; then
            echo \"  Capture interface \$IFACE does not exist; skipping host network tuning\"
            exit 0
        fi

        CHANGED=0
        FLOW_ENTRIES=65536
        CPU_COUNT=\$(nproc 2>/dev/null || echo 1)
        RX_QUEUE_COUNT=\$(find /sys/class/net/\$IFACE/queues -maxdepth 1 -type d -name 'rx-*' | wc -l | tr -d ' ')

        format_cpumask() {
            local raw=\"\$1\"
            local grouped=\"\"
            while [ \${#raw} -gt 8 ]; do
                grouped=\",\${raw: -8}\${grouped}\"
                raw=\"\${raw:0:\${#raw}-8}\"
            done
            printf '%s' \"\${raw}\${grouped}\"
        }

        MAX_RX=\$(ethtool -g \$IFACE 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/{if(/^RX:/){print \$2; exit}}')
        MAX_TX=\$(ethtool -g \$IFACE 2>/dev/null | awk '/Pre-set maximums:/,/Current hardware settings:/{if(/^TX:/){print \$2; exit}}')
        CUR_RX=\$(ethtool -g \$IFACE 2>/dev/null | awk '/Current hardware settings:/,0{if(/^RX:/){print \$2; exit}}')
        CUR_TX=\$(ethtool -g \$IFACE 2>/dev/null | awk '/Current hardware settings:/,0{if(/^TX:/){print \$2; exit}}')
        if [ -n \"\$MAX_RX\" ] && [ \"\$CUR_RX\" != \"\$MAX_RX\" ]; then
            ethtool -G \$IFACE rx \$MAX_RX tx \${MAX_TX:-\$MAX_RX} 2>/dev/null && \
                echo \"  NIC \$IFACE ring buffer: RX \${CUR_RX:-unknown} -> \$MAX_RX, TX \${CUR_TX:-unknown} -> \${MAX_TX:-\$MAX_RX}\" && CHANGED=1
        fi

        if [ \"\$CPU_COUNT\" -gt 0 ] && [ \"\$CPU_COUNT\" -lt 64 ] && [ \"\$RX_QUEUE_COUNT\" -gt 0 ]; then
            MASK_RAW=\$(printf '%x' \$(( (1 << CPU_COUNT) - 1 )))
            RPS_MASK=\$(format_cpumask \"\$MASK_RAW\")
            PER_QUEUE=\$(( FLOW_ENTRIES / RX_QUEUE_COUNT ))
            [ \"\$PER_QUEUE\" -lt 4096 ] && PER_QUEUE=4096

            CUR_FLOW=\$(cat /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null || echo 0)
            if [ \"\$CUR_FLOW\" != \"\$FLOW_ENTRIES\" ]; then
                sysctl -qw net.core.rps_sock_flow_entries=\$FLOW_ENTRIES >/dev/null 2>&1 && \
                    echo \"  RFS flow entries: \$CUR_FLOW → \$FLOW_ENTRIES\" && CHANGED=1
            fi

            for q in /sys/class/net/\$IFACE/queues/rx-*; do
                [ -d \"\$q\" ] || continue
                CUR_MASK=\$(cat \"\$q/rps_cpus\" 2>/dev/null || echo '')
                if [ \"\$CUR_MASK\" != \"\$RPS_MASK\" ]; then
                    echo \"\$RPS_MASK\" > \"\$q/rps_cpus\" 2>/dev/null && CHANGED=1
                fi
                CUR_QUEUE_FLOW=\$(cat \"\$q/rps_flow_cnt\" 2>/dev/null || echo 0)
                if [ \"\$CUR_QUEUE_FLOW\" != \"\$PER_QUEUE\" ]; then
                    echo \"\$PER_QUEUE\" > \"\$q/rps_flow_cnt\" 2>/dev/null && CHANGED=1
                fi
            done

            DISPATCHER=/etc/NetworkManager/dispatcher.d/99-\${IFACE}-capture-tuning
            cat > \$DISPATCHER <<EOFD
#!/bin/bash
if [ \"\\\$1\" = \"\$IFACE\" ] && [ \"\\\$2\" = \"up\" ]; then
    ethtool -G \$IFACE rx \$MAX_RX tx \${MAX_TX:-\$MAX_RX} 2>/dev/null || true
    sysctl -qw net.core.rps_sock_flow_entries=\$FLOW_ENTRIES >/dev/null 2>&1 || true
    for q in /sys/class/net/\$IFACE/queues/rx-*; do
        [ -d \"\\\$q\" ] || continue
        echo \"\$RPS_MASK\" > \"\\\$q/rps_cpus\" 2>/dev/null || true
        echo \"\$PER_QUEUE\" > \"\\\$q/rps_flow_cnt\" 2>/dev/null || true
    done
fi
EOFD
            chmod +x \$DISPATCHER
            echo \"  RPS/RFS configured: mask=\$RPS_MASK, per_queue=\$PER_QUEUE, queues=\$RX_QUEUE_COUNT\"
        else
            echo \"  CPU count \$CPU_COUNT is outside the script's safe range or RX queues are unavailable; skipping automatic RPS/RFS tuning\"
        fi

        SYSCTL_CONF=/etc/sysctl.d/99-vigilyx-capture.conf
        cat > \$SYSCTL_CONF <<'EOSYS'
# Vigilyx high-traffic packet-capture tuning
net.core.rmem_max = 1073741824
net.core.rmem_default = 67108864
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 1200
net.core.netdev_budget_usecs = 8000
net.core.rps_sock_flow_entries = 65536
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
EOSYS
        sysctl -p \$SYSCTL_CONF >/dev/null 2>&1 && CHANGED=1

        if [ \$CHANGED -eq 0 ]; then
            echo '  Network tuning is already in place; no changes needed'
        fi

        exit 0
    "
}

# -- Step 0: initial setup (optional) --
if $DO_INIT; then
    step "Initial setup: sync source to remote server"
    rsync -avz --no-times --delete \
        --exclude 'target' \
        --exclude 'node_modules' \
        --exclude '.claude' \
        --exclude '/data' \
        --exclude 'logs' \
        --exclude 'frontend/dist' \
        --exclude '.build-output' \
        --exclude '.env' \
        --exclude 'deploy.conf' \
        "$LOCAL_DIR" "${SERVER}:${REMOTE_DIR}/"

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
if $DO_BACKEND || $DO_SNIFFER || $DO_MTA || $DO_ENGINE; then
    NEED_RUST_ARTIFACTS=true
fi

NEED_BUILDER=false
if $NEED_RUST_ARTIFACTS && { $DO_LINT || $DO_TEST || ! $DO_PRODUCTION; }; then
    NEED_BUILDER=true
fi

# -- Step 1: sync source code --
step "Sync source to remote server"
T=$(date +%s)
rsync -avz --no-times --delete \
    --exclude 'target' \
    --exclude 'node_modules' \
    --exclude '.claude' \
    --exclude '/data' \
    --exclude 'logs' \
    --exclude 'frontend/dist' \
    --exclude '.build-output' \
    --exclude '.env' \
    --exclude 'deploy.conf' \
    "$LOCAL_DIR" "${SERVER}:${REMOTE_DIR}/"
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
if $DO_FRONTEND && ! $DO_PRODUCTION; then
    step "Build frontend"
    T=$(date +%s)
    ssh "$SERVER" "cd ${REMOTE_DIR}/frontend && npx vite build"
    elapsed $T
elif $DO_FRONTEND && $DO_PRODUCTION; then
    echo ""
    echo "━━━ Production-mode frontend build ━━━"
    echo "  The frontend will be built and packaged by Dockerfile.api during image build."
fi

# -- Step 7: package the Docker runtime image --
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
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} ${MODE_PROFILE} --profile ai ${ANTIVIRUS_PROFILE} ${TLS_PROFILE} up -d $UP_TARGETS"
fi

if [ -n "$ANTIVIRUS_PROFILE" ]; then
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} --profile antivirus up -d clamav"
fi

# Apply host tuning for mirror mode even when only backend/config changed.
if [ "$DEPLOY_MODE" = "mirror" ]; then
    apply_capture_host_tuning
fi

# Start the data-plane service for the active mode (sniffer or mta)
if $DO_SNIFFER && [ "$DEPLOY_MODE" = "mirror" ]; then
    echo "  Restarting sniffer (capture gap ~3s)..."
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} --profile mirror up -d sniffer"
fi

# MTA proxy deployment (explicit --mta or DB mode = mta)
if $DO_MTA || [ "$DEPLOY_MODE" = "mta" ]; then
    echo "  Starting MTA proxy..."
    if $DO_PRODUCTION; then
        ssh "$SERVER" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} --profile mta ${ANTIVIRUS_PROFILE} up -d mta"
    else
        ssh "$SERVER" "cd ${REMOTE_DIR} && \
            docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} --profile mta ${ANTIVIRUS_PROFILE} up -d mta"
    fi
fi

# Engine standalone deployment (explicit --engine)
if $DO_ENGINE; then
    echo "  Starting standalone Engine container..."
    ssh "$SERVER" "cd ${REMOTE_DIR} && \
        docker compose -f ${COMPOSE_FILE} -f ${FAST_OVERRIDE} --profile engine-standalone up -d engine"
fi

elapsed $T

# -- Step 9: verify frontend dist inside the image --
if ! $DO_PRODUCTION && { $DO_BACKEND || $DO_FRONTEND; }; then
    step "Verify frontend dist availability"
    ssh "$SERVER" "
        # Frontend is baked into the Docker image (no host volume mount).
        # If the image was built without frontend dist, rebuild it.
        if ! docker exec vigilyx test -f /app/frontend/dist/index.html 2>/dev/null; then
            echo 'Frontend dist is missing inside the image; rebuilding frontend and repackaging...'
            cd '${REMOTE_DIR}/frontend' && npx vite build
            cd '${REMOTE_DIR}' && docker compose -f ${COMPOSE_FILE} -f deploy/docker/docker-compose.fast.yml build vigilyx
            docker compose -f ${COMPOSE_FILE} ${MODE_PROFILE} --profile ai ${ANTIVIRUS_PROFILE} ${TLS_PROFILE} up -d vigilyx
        fi
    "
fi

# -- Done --
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Deployment complete. Total time: $(( $(date +%s) - TOTAL_START ))s"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Check status: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} ps'"
echo "API logs:     ssh $SERVER 'docker exec vigilyx tail -30 /app/logs/api.log'"
echo "Engine logs:  ssh $SERVER 'docker exec vigilyx tail -30 /app/logs/engine.log'"
echo "Sniffer logs: ssh $SERVER 'docker compose -f ${REMOTE_DIR}/${COMPOSE_FILE} logs --tail 30 sniffer'"
