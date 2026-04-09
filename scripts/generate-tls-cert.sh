#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Generate self-signed TLS certificate for Vigilyx
# ═══════════════════════════════════════════════════
# Run this on the HOST (not inside a container).
# The cert is stored at deploy/docker/certs/ and mounted into Caddy.
#
# Usage:
#   bash scripts/generate-tls-cert.sh              # auto-detect IP
#   bash scripts/generate-tls-cert.sh 10.0.0.1     # specific IP
#   bash scripts/generate-tls-cert.sh example.com   # domain name
#
# ═══════════════════════════════════════════════════
set -euo pipefail

CERT_DIR="deploy/docker/certs"

# Auto-detect host IP if not provided
if [ -n "${1:-}" ]; then
    DOMAIN="$1"
else
    DOMAIN=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}' || true)
    if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "127.0.0.1" ]; then
        DOMAIN=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")
    fi
fi

# Determine SAN type
case "$DOMAIN" in
    localhost|127.*|0.0.0.0) SAN="IP:127.0.0.1,DNS:localhost" ;;
    *[!0-9.]*) SAN="DNS:${DOMAIN}" ;;  # contains non-numeric = hostname
    *) SAN="IP:${DOMAIN}" ;;            # all numeric = IP address
esac

mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/cert.pem" ] && [ -f "$CERT_DIR/key.pem" ]; then
    echo "Certificate already exists at $CERT_DIR/"
    echo "  To regenerate: rm $CERT_DIR/cert.pem $CERT_DIR/key.pem && $0"
    exit 0
fi

echo "Generating self-signed TLS certificate..."
echo "  Domain/IP: $DOMAIN"
echo "  SAN:       $SAN"
echo "  Validity:  3650 days (10 years)"

openssl ecparam -name prime256v1 -genkey -noout -out "$CERT_DIR/key.pem" 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" -days 3650 \
    -subj "/CN=${DOMAIN}/O=Vigilyx" \
    -addext "subjectAltName=${SAN}" 2>/dev/null

chmod 600 "$CERT_DIR/key.pem"
chmod 644 "$CERT_DIR/cert.pem"

echo "Done: certificate written to $CERT_DIR/"
echo "  cert: $CERT_DIR/cert.pem"
echo "  key:  $CERT_DIR/key.pem"
