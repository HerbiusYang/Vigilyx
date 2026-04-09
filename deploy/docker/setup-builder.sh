#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Vigilyx persistent Rust build container - one-command initialization
# ═══════════════════════════════════════════════════
#
# Purpose:
#   Create a long-lived rust:latest container with the source tree and persistent target/cargo caches mounted in.
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
BUILDER_IMAGE="rust:1.94.1-bookworm"
# Auto-detect the project root (setup-builder.sh lives under deploy/docker/)
PROJECT_DIR="${VIGILYX_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
CARGO_REGISTRY_VOL="vigilyx_cargo_registry"
CARGO_GIT_VOL="vigilyx_cargo_git"
BUILD_TARGET_VOL="vigilyx_build_target"
BUILD_OUTPUT_DIR="${PROJECT_DIR}/.build-output"

echo "=== Vigilyx 持久化构建容器初始化 ==="

# 1. Create persistent volumes if they do not exist
for vol in "$CARGO_REGISTRY_VOL" "$CARGO_GIT_VOL" "$BUILD_TARGET_VOL"; do
    if ! docker volume inspect "$vol" >/dev/null 2>&1; then
        echo "[+] 创建 volume: $vol"
        docker volume create "$vol"
    else
        echo "[=] volume 已存在: $vol"
    fi
done

# 2. Create the build-output directory on the host so it is visible in the container via bind mount
mkdir -p "$BUILD_OUTPUT_DIR"
# Note: if a file with the same name already exists, remove it first
[ -f "$BUILD_OUTPUT_DIR" ] && rm -f "$BUILD_OUTPUT_DIR" && mkdir -p "$BUILD_OUTPUT_DIR"

# 3. Stop and remove the old builder container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${BUILDER_NAME}$"; then
    echo "[*] 移除旧的 builder 容器..."
    docker rm -f "$BUILDER_NAME" >/dev/null 2>&1 || true
fi

# 4. Pull the latest rust image
echo "[*] 拉取最新 rust 镜像..."
docker pull "$BUILDER_IMAGE"

# 5. Create the long-lived build container
echo "[*] 创建构建容器: $BUILDER_NAME"
docker run -d \
    --name "$BUILDER_NAME" \
    -v "${PROJECT_DIR}:/app" \
    -v "${BUILD_TARGET_VOL}:/app/target" \
    -v "${CARGO_REGISTRY_VOL}:/usr/local/cargo/registry" \
    -v "${CARGO_GIT_VOL}:/usr/local/cargo/git" \
    -w /app \
    "$BUILDER_IMAGE" \
    sleep infinity

# 6. Install Rust components (clippy + rustfmt)
echo "[*] 安装 clippy 和 rustfmt..."
docker exec "$BUILDER_NAME" rustup component add clippy rustfmt

# 7. Install build dependencies (libpcap-dev for sniffer, pkg-config)
echo "[*] 安装编译依赖..."
docker exec "$BUILDER_NAME" bash -c '
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcap-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
'

# 8. Verify the environment
echo ""
echo "=== 构建环境信息 ==="
docker exec "$BUILDER_NAME" rustc --version
docker exec "$BUILDER_NAME" cargo --version
docker exec "$BUILDER_NAME" cargo clippy --version
echo ""

# 9. Run the first build to warm the cache
echo "=== 首次编译（预热缓存，请耐心等待）==="
echo "[*] cargo build --profile release-fast ..."
docker exec "$BUILDER_NAME" \
    cargo build --profile release-fast -p vigilyx-api -p vigilyx-engine -p vigilyx-sniffer 2>&1

# 10. Copy build artifacts to the output directory
echo "[*] 复制二进制到 ${BUILD_OUTPUT_DIR}/"
docker exec "$BUILDER_NAME" mkdir -p /app/.build-output
docker exec "$BUILDER_NAME" bash -c "
    cp /app/target/release-fast/vigilyx-api /app/.build-output/ && \
    cp /app/target/release-fast/vigilyx-engine /app/.build-output/ && \
    cp /app/target/release-fast/vigilyx-sniffer /app/.build-output/
"

echo ""
echo "=== 初始化完成 ==="
echo ""
echo "二进制产物:"
ls -lh "$BUILD_OUTPUT_DIR"/
echo ""
echo "后续使用 deploy.sh 进行增量编译和部署。"
echo "或手动:"
echo "  docker exec $BUILDER_NAME cargo build --profile release-fast -p vigilyx-api -p vigilyx-engine"
echo "  docker exec $BUILDER_NAME cp /app/target/release-fast/vigilyx-api /app/.build-output/"
echo "  docker exec $BUILDER_NAME cp /app/target/release-fast/vigilyx-engine /app/.build-output/"
