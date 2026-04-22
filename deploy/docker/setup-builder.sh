#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Vigilyx persistent Rust build container - one-command initialization
# ═══════════════════════════════════════════════════
#
# Purpose:
#   Create a long-lived Rust 1.95.0 container with the source tree and persistent target/cargo caches mounted in.
#   Later builds run via docker exec inside the container, enabling true incremental compilation.
#
# Usage:
#   ssh user@your-server "cd /path/to/project && bash deploy/docker/setup-builder.sh"
#
# Result:
#   - First build: ~3-5 minutes (download dependencies + full compile)
#   - Later incremental builds after code changes: ~30-60 seconds
#   - Rust version matches the Docker image, and the binaries stay compatible with debian:bookworm-slim

set -euo pipefail

BUILDER_NAME="vigilyx-rust-builder"
RUST_TOOLCHAIN_VERSION="1.95.0"
BUILDER_IMAGE="rust:${RUST_TOOLCHAIN_VERSION}-bookworm"
# Auto-detect the project root (setup-builder.sh lives under deploy/docker/)
PROJECT_DIR="${VIGILYX_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
CARGO_REGISTRY_VOL="vigilyx_cargo_registry"
CARGO_GIT_VOL="vigilyx_cargo_git"
BUILD_TARGET_VOL="vigilyx_build_target"
BUILD_OUTPUT_DIR="${PROJECT_DIR}/.build-output"
HTTP_PROXY_VALUE="${HTTP_PROXY:-${http_proxy:-}}"
HTTPS_PROXY_VALUE="${HTTPS_PROXY:-${https_proxy:-}}"
ALL_PROXY_VALUE="${ALL_PROXY:-${all_proxy:-}}"
NO_PROXY_VALUE="${NO_PROXY:-${no_proxy:-localhost,127.0.0.1,redis}}"

run_apt_install() {
    local sources_mode="$1"
    docker exec "$BUILDER_NAME" bash -lc "
        set -euo pipefail

        case '$sources_mode' in
            default)
                ;;
            main-updates)
                cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
                ;;
            main-only)
                cat > /etc/apt/sources.list.d/debian.sources <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian
Suites: bookworm
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
                ;;
            *)
                echo '[x] Unknown apt sources mode: $sources_mode' >&2
                exit 1
                ;;
        esac

        for attempt in 1 2 3; do
            if apt-get -o Acquire::Retries=3 update && \
               apt-get install -y --no-install-recommends libpcap-dev pkg-config; then
                rm -rf /var/lib/apt/lists/*
                exit 0
            fi

            echo \"[!] apt install attempt \${attempt}/3 failed for sources mode '$sources_mode'; retrying...\"
            rm -rf /var/lib/apt/lists/*
            sleep 3
        done

        exit 1
    "
}

install_build_dependencies() {
    if run_apt_install default; then
        return 0
    fi

    echo "[!] Primary apt install failed; retrying with Debian main + updates only..."
    if run_apt_install main-updates; then
        return 0
    fi

    echo "[!] Secondary apt install failed; retrying with Debian main only..."
    run_apt_install main-only
}

echo "=== Vigilyx persistent Rust builder initialization ==="

# 1. Create persistent volumes if they do not exist
for vol in "$CARGO_REGISTRY_VOL" "$CARGO_GIT_VOL" "$BUILD_TARGET_VOL"; do
    if ! docker volume inspect "$vol" >/dev/null 2>&1; then
        echo "[+] Creating volume: $vol"
        docker volume create "$vol"
    else
        echo "[=] Volume already exists: $vol"
    fi
done

# 2. Create the build-output directory on the host so it is visible in the container via bind mount
mkdir -p "$BUILD_OUTPUT_DIR"
# Note: if a file with the same name already exists, remove it first
[ -f "$BUILD_OUTPUT_DIR" ] && rm -f "$BUILD_OUTPUT_DIR" && mkdir -p "$BUILD_OUTPUT_DIR"

# 3. Stop and remove the old builder container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${BUILDER_NAME}$"; then
    echo "[*] Removing old builder container..."
    docker rm -f "$BUILDER_NAME" >/dev/null 2>&1 || true
fi

# 4. Require the configured rust image to exist locally.
if ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
    echo "[x] Missing local builder image: ${BUILDER_IMAGE}"
    echo "    Please pull it manually first:"
    echo "    docker pull ${BUILDER_IMAGE}"
    exit 1
fi

# 5. Create the long-lived build container
echo "[*] Creating builder container: $BUILDER_NAME"
docker run -d \
    --pull=never \
    --name "$BUILDER_NAME" \
    -v "${PROJECT_DIR}:/app" \
    -v "${BUILD_TARGET_VOL}:/app/target" \
    -v "${CARGO_REGISTRY_VOL}:/usr/local/cargo/registry" \
    -v "${CARGO_GIT_VOL}:/usr/local/cargo/git" \
    -e "HTTP_PROXY=${HTTP_PROXY_VALUE}" \
    -e "HTTPS_PROXY=${HTTPS_PROXY_VALUE}" \
    -e "ALL_PROXY=${ALL_PROXY_VALUE}" \
    -e "NO_PROXY=${NO_PROXY_VALUE}" \
    -w /app \
    "$BUILDER_IMAGE" \
    sleep infinity

echo "[*] Switching the default Rust toolchain to ${RUST_TOOLCHAIN_VERSION} ..."
docker exec "$BUILDER_NAME" rustup default "$RUST_TOOLCHAIN_VERSION"

# 6. Install Rust components (clippy + rustfmt)
echo "[*] Installing clippy and rustfmt..."
docker exec "$BUILDER_NAME" rustup component add clippy rustfmt

# 7. Install build dependencies (libpcap-dev for sniffer, pkg-config)
echo "[*] Installing build dependencies..."
install_build_dependencies

# 8. Verify the environment
echo ""
echo "=== Build environment ==="
docker exec "$BUILDER_NAME" rustc --version
docker exec "$BUILDER_NAME" cargo --version
docker exec "$BUILDER_NAME" cargo clippy --version
echo ""

# 9. Run the first build to warm the cache
echo "=== First build (warming the cache, please wait) ==="
echo "[*] cargo build --profile release-fast ..."
docker exec "$BUILDER_NAME" \
    cargo build --profile release-fast -p vigilyx-api -p vigilyx-engine -p vigilyx-sniffer 2>&1

# 10. Copy build artifacts to the output directory
echo "[*] Copying binaries to ${BUILD_OUTPUT_DIR}/"
docker exec "$BUILDER_NAME" mkdir -p /app/.build-output
docker exec "$BUILDER_NAME" bash -c "
    cp /app/target/release-fast/vigilyx-api /app/.build-output/ && \
    cp /app/target/release-fast/vigilyx-engine /app/.build-output/ && \
    cp /app/target/release-fast/vigilyx-sniffer /app/.build-output/
"

echo ""
echo "=== Initialization complete ==="
echo ""
echo "Binaries:"
ls -lh "$BUILD_OUTPUT_DIR"/
echo ""
echo "Use deploy.sh for future incremental builds and deployments."
echo "Or run manually:"
echo "  docker exec $BUILDER_NAME cargo build --profile release-fast -p vigilyx-api -p vigilyx-engine"
echo "  docker exec $BUILDER_NAME cp /app/target/release-fast/vigilyx-api /app/.build-output/"
echo "  docker exec $BUILDER_NAME cp /app/target/release-fast/vigilyx-engine /app/.build-output/"
