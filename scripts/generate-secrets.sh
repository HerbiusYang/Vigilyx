#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Vigilyx Secret & Environment Generator
# ═══════════════════════════════════════════════════
#
# Usage:
#   bash scripts/generate-secrets.sh
#   → Generates deploy/docker/.env with random secrets + auto-detected NIC/IP
#
# Print mode (does not write to file):
#   bash scripts/generate-secrets.sh --print
#
# ═══════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Cryptographically secure random hex generator
gen() {
    openssl rand -hex "$1" 2>/dev/null \
        || head -c "$1" /dev/urandom | xxd -p | tr -d '\n'
}

# Auto-detect primary network interface (excludes lo/docker/veth/br-)
detect_interface() {
    local iface
    # Method 1: interface on the default route
    iface=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)
    if [ -n "$iface" ] && [ "$iface" != "lo" ]; then
        echo "$iface"
        return
    fi
    # Method 2: first non-virtual interface
    iface=$(ip -o link show 2>/dev/null | awk -F': ' '!/lo|docker|veth|br-/{print $2; exit}' || true)
    if [ -n "$iface" ]; then
        echo "$iface"
        return
    fi
    echo "eth0"
}

# Auto-detect host's primary IP (non-loopback)
detect_host_ip() {
    local ip
    # Method 1: source address for default route
    ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}' || true)
    if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ]; then
        echo "$ip"
        return
    fi
    # Method 2: first address from hostname -I
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$ip" ] && [ "$ip" != "127.0.0.1" ]; then
        echo "$ip"
        return
    fi
    echo ""
}

ENV_FILE="${PROJECT_ROOT}/deploy/docker/.env"
MODE="${1:-}"

if [ "$MODE" = "--print" ]; then
    echo "# Generated config (not written to file — copy manually to $ENV_FILE)" >&2
fi

if [ "$MODE" != "--print" ]; then
    if [ -f "$ENV_FILE" ]; then
        echo "WARNING: $ENV_FILE already exists!" >&2
        echo "  Backup and regenerate: mv $ENV_FILE ${ENV_FILE}.bak && $0" >&2
        echo "  Print only:            $0 --print" >&2
        exit 1
    fi
fi

DETECTED_IFACE=$(detect_interface)
DETECTED_IP=$(detect_host_ip)

generate_content() {
cat <<EOF
# Vigilyx environment config (generated $(date -u +%Y-%m-%dT%H:%M:%SZ))
# Security: chmod 600 this file!

# ── Database ──
PG_USER=vigilyx
PG_PASSWORD=$(gen 24)
PG_DB=vigilyx

# ── Redis ──
REDIS_PASSWORD=$(gen 24)

# ── API Authentication ──
API_JWT_SECRET=$(gen 32)
API_PASSWORD=$(gen 16)

# ── Internal service auth ──
INTERNAL_API_TOKEN=$(gen 24)
AI_INTERNAL_TOKEN=$(gen 24)

# ── Packet capture ──
SNIFFER_INTERFACE=${DETECTED_IFACE}

# ── Logging (never use debug in production) ──
RUST_LOG=info

# ── AI service (uncomment to enable, requires --profile ai) ──
# AI_ENABLED=true
# HF_ENDPOINT=https://hf-mirror.com

# ── TLS (used with --profile tls) ──
# Caddy auto-selects TLS mode based on VIGILYX_DOMAIN:
#   IP address → Caddy internal CA (browser must accept self-signed cert)
#   Hostname   → Let's Encrypt automatic (requires public DNS + ports 80/443)
#   Empty      → falls back to localhost (local access only)
EOF

if [ -n "$DETECTED_IP" ]; then
cat <<EOF
VIGILYX_DOMAIN=${DETECTED_IP}
EOF
else
cat <<EOF
# VIGILYX_DOMAIN=your-server-ip-or-domain
EOF
fi
}

if [ "$MODE" = "--print" ]; then
    generate_content
else
    generate_content > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "Done: config written to $ENV_FILE" >&2
    echo "  Detected NIC: $DETECTED_IFACE" >&2
    if [ -n "$DETECTED_IP" ]; then
        echo "  Detected IP:  $DETECTED_IP (written to VIGILYX_DOMAIN)" >&2
    else
        echo "  WARNING: could not detect non-loopback IP, set VIGILYX_DOMAIN manually" >&2
    fi
    echo "  Review config, then: cd ${PROJECT_ROOT}/deploy/docker && docker compose --profile mirror up -d" >&2
fi
