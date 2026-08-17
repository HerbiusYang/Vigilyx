#!/bin/sh
set -eu

# ═══════════════════════════════════════════════════
# Caddy TLS entrypoint - auto-detects the IP and works out of the box
# ═══════════════════════════════════════════════════
#
# Zero-config: set nothing -> auto-detect the server IP -> internal CA
# Domain:   VIGILYX_DOMAIN=mail.example.com -> auto-issue via Let's Encrypt
# Manual:   CADDY_TLS_MODE=files + certificate paths -> custom certificates
#
# ═══════════════════════════════════════════════════

target_caddyfile="${CADDYFILE_TARGET:-/etc/caddy/Caddyfile}"
email="${CADDY_ACME_EMAIL:-}"
cert_file="${VIGILYX_TLS_CERT_FILE:-/data/vigilyx.crt}"
key_file="${VIGILYX_TLS_KEY_FILE:-/data/vigilyx.key}"
access_log="${CADDY_ACCESS_LOG:-true}"

# -- Check whether the target is an IP or localhost --
is_ip_or_localhost() {
    case "$1" in
        localhost|127.*|0.0.0.0|*:* ) return 0 ;;
    esac
    case "$1" in
        *[!0-9.]* ) return 1 ;;
        * ) return 0 ;;
    esac
}

# -- Auto-detect the server IP when VIGILYX_DOMAIN is unset --
if [ -z "${VIGILYX_DOMAIN:-}" ]; then
    auto_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
    if [ -n "$auto_ip" ] && [ "$auto_ip" != "127.0.0.1" ]; then
        domain="$auto_ip"
        echo "Auto-detected server IP: $domain"
    else
        domain="localhost"
        echo "WARNING: Could not detect non-loopback IP, falling back to localhost"
    fi
else
    domain="$VIGILYX_DOMAIN"
fi

# -- Select the TLS mode --
# Priority: explicit setting > automatic inference
# - IP/localhost -> internal (Caddy internal CA)
# - Domain -> auto (Let's Encrypt)
tls_mode="${CADDY_TLS_MODE:-}"
if [ -z "$tls_mode" ]; then
    if is_ip_or_localhost "$domain"; then
        tls_mode="internal"
    else
        tls_mode="auto"
    fi
    echo "TLS mode auto-selected: $tls_mode (domain=$domain)"
fi

# -- Safety check: auto mode does not support raw IPs --
if [ "$tls_mode" = "auto" ] && is_ip_or_localhost "$domain"; then
    echo "ERROR: CADDY_TLS_MODE=auto requires a DNS hostname, not '$domain'." >&2
    echo "  Use CADDY_TLS_MODE=internal for IP access, or set VIGILYX_DOMAIN to a hostname." >&2
    exit 1
fi

# -- Generate the reusable security-header block --
write_security_headers() {
    echo "    header {"
    echo "        Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
    echo "        X-Content-Type-Options \"nosniff\""
    echo "        X-Frame-Options \"DENY\""
    echo "        Referrer-Policy \"strict-origin-when-cross-origin\""
    echo "        Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
    echo "    }"
}

write_access_log() {
    case "$(printf '%s' "$access_log" | tr '[:upper:]' '[:lower:]')" in
        1|true|yes|on)
            echo "    log {"
            echo "        output stdout"
            echo "        format json"
            echo "    }"
            echo
            ;;
    esac
}

# -- Generate the reverse_proxy block --
# header_up overrides any client-supplied X-Forwarded-For so the backend only
# ever sees the real peer IP (Caddy v2 already sets X-Forwarded-Proto itself).
write_reverse_proxy() {
    echo "    reverse_proxy vigilyx:8088 {"
    echo "        header_up X-Forwarded-For {remote_host}"
    echo "    }"
}

# Never reflect the request Host header in an HTTP-to-HTTPS redirect.  A
# client can supply an arbitrary Host value, so using `{host}` here turns the
# redirect into an open redirect (CWE-601).  The canonical host is selected
# from the deployment configuration above and is the only host allowed into
# the generated redirect target.
write_http_redirect() {
    redirect_host="$domain"
    case "$redirect_host" in
        *:*)
            case "$redirect_host" in
                \[*\]) ;;
                *) redirect_host="[$redirect_host]" ;;
            esac
            ;;
    esac
    echo ":80 {"
    write_access_log
    printf "    redir https://%s{uri} permanent\n" "$redirect_host"
    echo "}"
}

# -- Generate the Caddyfile --
case "$tls_mode" in
    auto)
        {
            echo "{"
            if [ -n "$email" ]; then
                printf "    email %s\n" "$email"
            fi
            echo "}"
            echo
            printf "%s {\n" "$domain"
            write_access_log
            write_reverse_proxy
            echo
            write_security_headers
            echo "}"
            echo
            write_http_redirect
        } > "$target_caddyfile"
        ;;
    internal)
        # Caddy's "tls internal" CA has compatibility issues on some kernels.
        # Prefer pre-generated certs at /data/self-signed/ (mounted from host).
        # Older installations may not have the certificate files yet; fall back
        # to Caddy's internal CA so a restart cannot take the proxy offline.
        cert_dir="/etc/caddy/certs"
        tls_directive="tls internal"
        if [ -f "$cert_dir/cert.pem" ] && [ -f "$cert_dir/key.pem" ]; then
            tls_directive="tls $cert_dir/cert.pem $cert_dir/key.pem"
            echo "Using self-signed certificate from $cert_dir/"
        else
            echo "WARNING: Self-signed certificate not found at $cert_dir/; using Caddy internal CA"
        fi
        {
            # Use :443 catch-all instead of IP-based site address.
            # IP addresses don't use TLS SNI, so Caddy can't match by IP.
            echo ":443 {"
            printf "    %s\n" "$tls_directive"
            write_access_log
            write_reverse_proxy
            echo
            write_security_headers
            echo "}"
            echo
            write_http_redirect
        } > "$target_caddyfile"
        ;;
    files)
        if [ ! -r "$cert_file" ] || [ ! -r "$key_file" ]; then
            echo "ERROR: File-based TLS requires readable: $cert_file and $key_file" >&2
            exit 1
        fi
        {
            printf "%s {\n" "$domain"
            printf "    tls %s %s\n" "$cert_file" "$key_file"
            write_access_log
            write_reverse_proxy
            echo
            write_security_headers
            echo "}"
            echo
            write_http_redirect
        } > "$target_caddyfile"
        ;;
    *)
        echo "ERROR: Unknown CADDY_TLS_MODE='$tls_mode' (expected: auto, internal, or files)" >&2
        exit 1
        ;;
esac

echo "Caddyfile generated: domain=$domain, tls=$tls_mode"

if [ "${CADDY_RENDER_ONLY:-0}" = "1" ]; then
    cat "$target_caddyfile"
    exit 0
fi

exec caddy run --config "$target_caddyfile" --adapter caddyfile
