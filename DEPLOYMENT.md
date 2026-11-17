# Vigilyx First Deployment Guide

Complete guide for deploying Vigilyx on a remote Linux server with security hardening.

**Target audience**: System administrators deploying Vigilyx in enterprise environments.

Use this guide for a **new server**. To upgrade an installed environment while
retaining its configuration and data, follow [Updating](UPDATING.md).
The OS/Docker preparation below is for a new host; it is not part of an
application update on an existing shared server.

The deployment template uses `root@<server>` with
`VIGILYX_REMOTE_DIR=/home/CCAB_VIGILYX`; set the SSH target for your own server. The dedicated `vigilyx` account and
`/home/vigilyx` paths shown in the hardening and backup examples are generic
alternatives; replace them with the configured remote path when following this
repository's root based workflow.

---

## Table of Contents

- [1. Server Requirements](#1-server-requirements)
- [2. OS Security Baseline](#2-os-security-baseline)
- [3. Docker Installation](#3-docker-installation)
- [4. Vigilyx Deployment](#4-vigilyx-deployment)
- [Updating an existing deployment](UPDATING.md)
- [5. TLS / HTTPS Setup](#5-tls--https-setup)
- [6. Firewall Configuration](#6-firewall-configuration)
- [7. Backup and Recovery](#7-backup-and-recovery)
- [8. Monitoring and Maintenance](#8-monitoring-and-maintenance)
- [9. Security Checklist](#9-security-checklist)
- [10. Troubleshooting](#10-troubleshooting)

---

## 1. Server Requirements

### Hardware

| Component | Minimum | Recommended (with AI) |
|-----------|---------|----------------------|
| CPU | 4 cores | 16+ cores |
| RAM | 8 GB | 32 GB |
| Disk | 50 GB SSD | 200 GB SSD |
| Network | 1 NIC (capture) | 2 NICs (management + capture) |

### Software

| Component | Version |
|-----------|---------|
| OS | Rocky Linux 9 / Ubuntu 22.04+ / Debian 12+ |
| Docker Engine | 24+ |
| Docker Compose | v2.20+ |

The current checkout pins Rust `1.98.0`, Node `24.19.0`, npm `12.0.2`,
PostgreSQL `17.11`, Valkey `8.1.9`, Caddy `2.11.4`, ClamAV `1.5.4`, and
Python `3.12` for its build/runtime images. Image tags and digests in
`deploy/docker/` are the source of truth when this guide and a different
checkout disagree.

### Network

- The server must be positioned to see email traffic (mirror port / TAP / inline)
- A dedicated capture interface is recommended (separate from management)

---

## 2. OS Security Baseline

> Run all commands as root or with sudo.

### 2.1 System Updates

```bash
# Rocky Linux / RHEL
dnf update -y && dnf install -y epel-release

# Ubuntu / Debian
apt update && apt upgrade -y
```

### 2.2 SSH Hardening

```bash
# Backup original config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Apply security settings
cat >> /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# ── SSH Security Hardening ──
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
PermitEmptyPasswords no
Protocol 2
EOF

# Restart SSH
systemctl restart sshd
```

> **Before applying**: Ensure you have SSH key authentication working. Locking out password auth without a key means permanent lockout.

### 2.3 Create Dedicated Service User

```bash
# Create non-root user for Vigilyx operations
useradd -m -s /bin/bash vigilyx
usermod -aG docker vigilyx

# Set up SSH key for the vigilyx user (copy your public key)
mkdir -p /home/vigilyx/.ssh
cp ~/.ssh/authorized_keys /home/vigilyx/.ssh/
chown -R vigilyx:vigilyx /home/vigilyx/.ssh
chmod 700 /home/vigilyx/.ssh
chmod 600 /home/vigilyx/.ssh/authorized_keys
```

### 2.4 Kernel Security Parameters

```bash
cat >> /etc/sysctl.d/99-vigilyx-security.conf << 'EOF'
# ── Network Security ──
# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# ── Memory ──
# Redis recommendation
vm.overcommit_memory = 1

# Increase max open files for container workloads
fs.file-max = 2097152
EOF

sysctl -p /etc/sysctl.d/99-vigilyx-security.conf
```

### 2.5 Automatic Security Updates

```bash
# Rocky Linux / RHEL
dnf install -y dnf-automatic
sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer

# Ubuntu / Debian
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### 2.6 fail2ban (SSH Brute Force Protection)

```bash
# Install
dnf install -y fail2ban   # Rocky/RHEL
# apt install -y fail2ban  # Ubuntu/Debian

# Configure
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
bantime = 86400
EOF

systemctl enable --now fail2ban
```

### 2.7 Disable Unnecessary Services

```bash
# List running services
systemctl list-units --type=service --state=running

# Disable common unnecessary services (adjust for your environment)
systemctl disable --now cups 2>/dev/null        # Print service
systemctl disable --now avahi-daemon 2>/dev/null # mDNS
systemctl disable --now bluetooth 2>/dev/null    # Bluetooth
```

---

## 3. Docker Installation

### 3.1 Install Docker Engine

```bash
# Rocky Linux / RHEL
dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Ubuntu / Debian
curl -fsSL https://get.docker.com | sh
```

### 3.2 Docker Security Hardening

```bash
# Create daemon config
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  },
  "live-restore": true,
  "no-new-privileges": true,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  }
}
EOF
```

The Compose file applies non-root users, read-only filesystems, dropped
capabilities, and `no-new-privileges` per service. Do not enable daemon-wide
`userns-remap` without first validating the sniffer's host-network packet
capture and every bind/named-volume permission on a staging host.

```bash
# Enable and start Docker
systemctl enable --now docker

# Verify
docker info | grep -E "Server Version|Security Options|Logging Driver"
```

### 3.3 Docker Log Rotation

The daemon default above keeps 50 MB x 3 JSON log files. Vigilyx services
override this with Docker's `local` log driver at 50 MB x 5 files. Verify the
effective driver and file usage instead of assuming the daemon default applies:

```bash
docker inspect vigilyx --format '{{.HostConfig.LogConfig.Type}} {{json .HostConfig.LogConfig.Config}}'
docker system df
```

---

## 4. Vigilyx Deployment

### Recommended: deploy from a workstation

The workstation needs Bash, SSH, rsync, and Python 3. The target needs Bash,
Python 3, rsync, OpenSSL, Docker Engine 24+, and Compose v2.20+. Confirm SSH key
access, Docker access, enough disk space for source/images/build caches, and
registry access before initialization. The server must reach OCI registries,
Rust distribution/crate servers, npm, and Debian package mirrors. Configure
any required proxy on the target; a workstation proxy is not automatically
forwarded over SSH.

Obtain the complete release checkout or source archive on the workstation.
All following helper commands run from that checkout; builds/tests run remotely.

```bash
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
# Set VIGILYX_SERVER and VIGILYX_REMOTE_DIR; keep VIGILYX_LOCAL_DIR unset.

# On the target, pre-pull the image required by setup-builder.sh.
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init

# Review the generated configuration on the target before starting services.
ssh root@<server> "vi /home/CCAB_VIGILYX/deploy/docker/.env"
# Mirror: VIGILYX_MODE=mirror, SNIFFER_INTERFACE=<capture NIC>.
# Keep AI_ENABLED=false unless intentionally enabling the optional AI service.
# MTA: configure downstream/local domains/listen IP and install PEM files below.

# Choose ONE initial topology:
./deploy.sh --production             # mirror by default
# ./deploy.sh --production --mta     # MTA instead; install its TLS files first
```

Replace the example SSH target and remote directory with `deploy.conf` values.
`--init` generates `.env` only if missing, creates the persistent builder, and
warms its cache; it does not start the application. Do not run the separate
secret generator after initialization. The first application deployment must be
complete; component-only commands assume an existing installation.

For bundled HTTPS on a new host, add `--tls` to the selected deployment command
(for example, `./deploy.sh --production --tls`). Otherwise provision a host
reverse proxy in section 5. An existing host proxy and bundled Caddy must not
both claim ports 80/443. The default API is only reachable at
`127.0.0.1:8088` until a proxy or SSH tunnel is configured.

Finish with the readiness checks in section 4.4 and first login in section 4.5.
After installation, use [Updating](UPDATING.md) for version/component updates,
backups, and rollback. The sections below also describe the alternative of
building directly on the target without the workstation helper.

### 4.1 Get the Source Code

> Publishing to GitHub is optional. You can deploy from a private Git server, an internal mirror, an offline tarball, or `rsync` from your workstation.

```bash
cd /home
git clone <your-git-remote-or-local-mirror> CCAB_VIGILYX
cd /home/CCAB_VIGILYX

# Example without GitHub:
# rsync -av ./VIGILYX/ root@server:/home/CCAB_VIGILYX/
```

### 4.2 Generate Secrets

```bash
# Run from project root -- script auto-creates deploy/docker/.env with chmod 600
bash scripts/generate-secrets.sh

# Edit to set your network interface and enable optional features
vi deploy/docker/.env
# Required: SNIFFER_INTERFACE=<your capture interface>
# Optional: AI_ENABLED=true (also pass --profile ai to docker compose)
# Optional: HF_ENDPOINT=https://hf-mirror.com (China mainland)
# MTA: configure downstream/local domains and install PEM files as
# deploy/docker/certs/mta.crt + mta.key (private key mode 600)
# For SMTP clients on other hosts, set MTA_LISTEN to the intended host-interface IP.
# Compose defaults to 127.0.0.1 (local connections only).
```

The MTA profile intentionally refuses to start without TLS material: STARTTLS
is required and the SMTPS listener on 465 is enabled by default. Install the
certificate from the repository root before the first MTA start:

```bash
install -d -m 700 deploy/docker/certs
install -m 644 /path/to/fullchain.pem deploy/docker/certs/mta.crt
install -m 600 /path/to/private-key.pem deploy/docker/certs/mta.key
```

`mta-cert-install` copies these host-owned files into an MTA-only named volume,
sets the private key to mode `400` for the image's unprivileged user, and exits
before `vigilyx-mta` starts. To use different host paths, set
`MTA_TLS_CERT_SOURCE` and `MTA_TLS_KEY_SOURCE` in `.env`. Replace the source
files and recreate `mta-cert-install` plus `mta` when renewing the certificate.

### 4.3 Persistent Volumes

Docker Compose creates the named volumes automatically on first `up -d`.
You only need to pre-create or migrate them if you manage storage separately.

### 4.4 Build and Deploy

Recommended public production path:

1. Keep `API_LISTEN=127.0.0.1` (the default)
2. Start Vigilyx with Docker Compose
3. Terminate TLS on the host with Caddy in section 5.1
4. Use the Compose `tls` profile only when you intentionally want all-in-one TLS inside the Compose stack

```bash
cd deploy/docker

# First-time build (pulls images + compiles the selected topology, ~10-15 minutes)
docker compose --profile mirror build
# For an MTA-only host, use: docker compose --profile mta build

# Start the default passive-capture stack
docker compose --profile mirror up -d

# Optional profiles
docker compose --profile mirror --profile ai up -d   # if AI_ENABLED=true
docker compose --profile mirror --profile tls up -d  # all-in-one TLS: auto domain certs, internal CA, or file certs

# Inline MTA profile (does not stop an already-running mirror data plane).
# First place a PEM certificate/key at deploy/docker/certs/mta.crt and
# deploy/docker/certs/mta.key; keep the private key mode 600.
docker compose --profile mta up -d

# Experimental / isolated lab only (requires KVM/libvirt)
docker compose --profile sandbox up -d

# Verify all containers are healthy
docker compose ps
```

Compose profile commands select services but do not stop services from another profile or persist `VIGILYX_MODE`. Use `./deploy.sh --mta` to switch a running deployment; it updates the mode and stops the mirror sniffer/engine before starting MTA.

`./deploy.sh` without `--production` uses the developer `release-fast` path.
For existing installations, including component updates, schema changes,
maintenance windows, configuration preservation, and recovery, follow
[Updating](UPDATING.md). The deployment helper does not change host sysctl,
NIC, IRQ, or RPS settings.

If you terminate TLS with host-level Caddy or Nginx in section 5, keep the container bound to localhost and do not enable the Compose `tls` profile.
The profiles select the data plane explicitly: `mirror` starts `vigilyx-sniffer` plus the dedicated `vigilyx-engine-standalone`; `mta` starts `vigilyx-mta` with its embedded engine. The main `vigilyx` container is the API/frontend control plane in both modes.

Typical output (with `mirror` + `ai` enabled, without TLS):
```
NAME               STATUS                    PORTS
vigilyx            Up (healthy)              127.0.0.1:8088->8088/tcp
vigilyx-ai         Up (healthy)              127.0.0.1:8900->8900/tcp
vigilyx-engine-standalone Up (healthy)
vigilyx-postgres   Up (healthy)              127.0.0.1:5433->5432/tcp
vigilyx-redis      Up (healthy)              127.0.0.1:6379->6379/tcp
vigilyx-sniffer    Up
```

Container state alone is not a readiness check. Verify the public aggregate endpoint after startup:

```bash
curl -fsS http://127.0.0.1:8088/api/health/ready
# {"status":"ready"}
```

`deploy.sh` also compares the effective PostgreSQL memory/logging settings with
the resolved Compose configuration. In mirror mode it waits up to 120 seconds
for both consumer groups to have at most 100 undelivered entries on two consecutive
observations. In-flight pending work is reported separately. A stuck backlog
fails deployment verification even when the health endpoint returns ready.
These read-only checks can be rerun with `python3 scripts/verify-deployment.py --mode mirror`
from the remote deployment directory.

### 4.5 First Login

1. For production, enable TLS and open `https://<your-domain-or-server>`
2. Without TLS, the service binds to localhost by default; open `http://127.0.0.1:8088` on the server itself or use an SSH tunnel / reverse proxy
3. For a temporary non-TLS test from another machine, set both `API_LISTEN=0.0.0.0` and `API_SECURE_COOKIE=false`, then open `http://<server-ip>:8088`. Restore `API_SECURE_COOKIE=true` and `API_LISTEN=127.0.0.1` after testing, or enable TLS before normal use. Without this temporary cookie setting, browsers reject the Secure session cookie over HTTP and login will not persist.
4. On a brand-new database, log in with `<API_USERNAME, default admin>` / `<API_PASSWORD from .env>`
5. **Change your password immediately** via Settings page

After the first password change, the database-backed credential takes
precedence. Editing `API_PASSWORD` does not rotate an existing account.

The one-shot bootstrap also creates `AUDIT_USERNAME` with the independent
`AUDIT_BOOTSTRAP_PASSWORD` only when that account does not already exist. An
authorized operator should use it for the first audit login and change it
immediately. Subsequent bootstrap runs leave the existing account and password
unchanged; the value remaining in `.env` is not a password-rotation mechanism.

---

## 5. TLS / HTTPS Setup

> **Strongly recommended for production**. Without TLS, login credentials and JWT tokens are transmitted in cleartext.

### Recommended: Host-Level Caddy (Automatic HTTPS, simplest)

```bash
# Install Caddy
dnf install -y caddy   # or: apt install -y caddy

# Configure
cat > /etc/caddy/Caddyfile << 'EOF'
your-domain.com {
    reverse_proxy localhost:8088

    # WebSocket support
    @websocket {
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @websocket localhost:8088

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
    }
}
EOF

systemctl enable --now caddy
```

Keep the Vigilyx container bound to localhost:
```bash
# In deploy/docker/.env
API_LISTEN=127.0.0.1
API_PORT=8088
```

The default Compose configuration already trusts `localhost`, `host.docker.internal`,
`caddy`, and `vigilyx-caddy` as reverse proxies for `X-Forwarded-For`, so the
per-IP login rate limiter still keys on the real client IP in the recommended
host-level or bundled Caddy setup. If you add another proxy / load balancer /
WAF in front, extend `TRUSTED_PROXY_HOSTS` or `TRUSTED_PROXY_IPS` in
`deploy/docker/.env` instead of replacing the defaults.

This is the recommended Internet-facing production setup.

### Alternative: Nginx (Self-Signed Certificate)

```bash
# Generate self-signed certificate (valid 1 year)
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/vigilyx.key \
  -out /etc/nginx/ssl/vigilyx.crt \
  -subj "/CN=vigilyx/O=Security/C=CN"
chmod 600 /etc/nginx/ssl/vigilyx.key

# Install nginx
dnf install -y nginx   # or: apt install -y nginx

cat > /etc/nginx/conf.d/vigilyx.conf << 'EOF'
# conf.d files are included from the http context by the standard distro config.
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;

server {
    listen 443 ssl http2;
    server_name _;

    ssl_certificate /etc/nginx/ssl/vigilyx.crt;
    ssl_certificate_key /etc/nginx/ssl/vigilyx.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    # Request limits
    client_max_body_size 10m;

    # Rate limiting (zone declared above, at http scope)
    limit_req zone=api burst=50 nodelay;

    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
EOF

# Bind API to localhost only
# In deploy/docker/.env set:
# API_LISTEN=127.0.0.1

nginx -t && systemctl enable --now nginx
```

### Alternative: Bundled Compose Caddy (Automatic Domain Certs or Self-Signed)

Use this when you intentionally want TLS termination inside the Compose stack instead of on the host.

Supported modes:

```bash
# 1) Public domain: automatic ACME certificate
cd deploy/docker
cat >> .env << 'EOF'
VIGILYX_DOMAIN=mail.example.com
CADDY_ACME_EMAIL=ops@example.com
EOF
docker compose --profile tls up -d
```

```bash
# 2) IP address / localhost: automatic fallback to Caddy internal CA
cd deploy/docker
cat >> .env << 'EOF'
VIGILYX_DOMAIN=192.0.2.10
EOF
docker compose --profile tls up -d
```

```bash
# 3) File-based certificate mode (used by deploy.sh --tls)
cd deploy/docker
cat >> .env << 'EOF'
VIGILYX_DOMAIN=192.0.2.10
CADDY_TLS_MODE=files
VIGILYX_TLS_CERT_FILE=/data/vigilyx.crt
VIGILYX_TLS_KEY_FILE=/data/vigilyx.key
EOF
docker compose --profile tls up -d
```

```bash
# Convenience bootstrap for remote self-signed testing
./deploy.sh --tls
```

Notes:

- With a DNS hostname, the bundled Caddy profile can obtain certificates automatically
- With an IP address or `localhost`, Caddy falls back to its internal CA unless you force `CADDY_TLS_MODE=files`
- File mode expects readable certificate files at `VIGILYX_TLS_CERT_FILE` and `VIGILYX_TLS_KEY_FILE`
- For public production with a real domain, host-level Caddy is still the preferred path
- Keep `API_LISTEN=127.0.0.1` and `API_SECURE_COOKIE=true` for normal use. Temporary remote HTTP testing requires `API_LISTEN=0.0.0.0` and `API_SECURE_COOKIE=false`; restore both afterward.

---

## 6. Firewall Configuration

### firewalld (Rocky Linux / RHEL)

```bash
# Enable firewall
systemctl enable --now firewalld

# Add rules to the zone that owns the management interface.
FIREWALL_ZONE=$(firewall-cmd --get-default-zone)
firewall-cmd --permanent --zone="$FIREWALL_ZONE" --add-service=ssh
firewall-cmd --permanent --zone="$FIREWALL_ZONE" --add-service=http   # ACME + HTTPS redirect
firewall-cmd --permanent --zone="$FIREWALL_ZONE" --add-service=https

# Inline MTA only, after MTA_LISTEN is set to the intended public/interface IP:
# firewall-cmd --permanent --zone="$FIREWALL_ZONE" --add-service=smtp
# firewall-cmd --permanent --zone="$FIREWALL_ZONE" --add-service=smtps

# Apply
firewall-cmd --reload

# Verify
firewall-cmd --zone="$FIREWALL_ZONE" --list-all
```

Do not open `8088`, `5433`, `6379`, `8900`, `3310`, or `8000` publicly. The
Compose defaults bind those ports to loopback; production UI traffic should
enter through the TLS reverse proxy.

### UFW (Ubuntu / Debian)

```bash
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp     # ACME + HTTPS redirect
ufw allow 443/tcp
# Inline MTA only, after MTA_LISTEN is set intentionally:
# ufw allow 25/tcp
# ufw allow 465/tcp
ufw enable
ufw status verbose
```

Docker manages its own packet-filtering rules. Keep the Compose host bindings
at their secure defaults and verify the effective exposure with `ss -lntp` from
another host; do not rely on UFW alone to hide a Docker-published port.

### IP Whitelist (Restrict to Trusted Networks)

If you intentionally set `API_LISTEN=0.0.0.0` for direct, non-TLS testing,
restrict port 8088 to the exact management ranges instead of opening it
globally. This is not a substitute for HTTPS:

```bash
# Only allow specific IPs to access Vigilyx
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="8088" protocol="tcp" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/16" port port="8088" protocol="tcp" accept'
firewall-cmd --reload
```

---

## 7. Backup and Recovery

### 7.1 PostgreSQL Backup

```bash
# Create backup script
install -d -o vigilyx -g vigilyx -m 700 /home/vigilyx/backups
cat > /home/vigilyx/backup-db.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
umask 077
BACKUP_DIR="/home/vigilyx/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"
FINAL="$BACKUP_DIR/vigilyx_${DATE}.dump"
PARTIAL="${FINAL}.partial"
trap 'rm -f "$PARTIAL"' EXIT

# Dump with the owner identity already present in the PostgreSQL container.
# The cron user therefore does not need read access to the root-owned .env.
docker exec vigilyx-postgres sh -lc \
  'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --compress=zstd:3' \
  > "$PARTIAL"

# Do not publish a truncated dump under the final filename.
docker exec -i vigilyx-postgres pg_restore --list < "$PARTIAL" >/dev/null
mv "$PARTIAL" "$FINAL"
trap - EXIT

# Retain last 7 days
find "$BACKUP_DIR" -name "vigilyx_*.dump" -mtime +7 -delete

echo "[$(date)] Backup complete: $(basename "$FINAL") ($(du -h "$FINAL" | cut -f1))"
SCRIPT

chmod +x /home/vigilyx/backup-db.sh
```

### 7.2 Schedule Daily Backups

```bash
# Run as root: a separate cron.d file preserves existing schedules.
cat > /etc/cron.d/vigilyx-backup << 'CRON'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 3 * * * vigilyx /home/vigilyx/backup-db.sh >> /home/vigilyx/backups/backup.log 2>&1
CRON
chown root:root /etc/cron.d/vigilyx-backup
chmod 644 /etc/cron.d/vigilyx-backup
```

### 7.3 Restore from Backup

```bash
# Stop every process that can write application data. PostgreSQL stays up for restore.
cd /home/CCAB_VIGILYX/deploy/docker
docker compose --profile mirror --profile mta stop vigilyx engine sniffer mta

# Restore with the owner identity already present in the PostgreSQL container.
docker exec -i vigilyx-postgres sh -lc \
  'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  < /home/vigilyx/backups/vigilyx_YYYYMMDD_HHMMSS.dump

# Restart the active topology (use mta instead of mirror for MTA mode)
docker compose --profile mirror up -d
# Add optional --profile ai / --profile tls when configured.
# Do not add --profile mta alongside --profile mirror; choose one topology.
```

### 7.4 Volume Backup (Full Disaster Recovery)

```bash
# Stop all services
cd /home/CCAB_VIGILYX/deploy/docker
docker compose --profile '*' down

# Back up every persistent volume that exists. Optional-service volumes are
# skipped when that profile has never been started.
for vol in \
  vigilyx_vigilyx_pgdata \
  vigilyx_redis_data \
  vigilyx_vigilyx_data \
  vigilyx_http_temp_data \
  vigilyx_vigilyx_models \
  vigilyx_mta_certs \
  vigilyx_hf_cache \
  vigilyx_clamav_db \
  vigilyx_sandbox_data \
  vigilyx_caddy_data \
  vigilyx_caddy_config; do
  docker volume inspect "$vol" >/dev/null 2>&1 || continue
  docker run --rm -v "${vol}:/data:ro" -v /home/vigilyx/backups:/backup \
    alpine tar czf "/backup/${vol}_$(date +%Y%m%d).tar.gz" -C /data .
done

# Restart with the same profiles you use in production
docker compose --profile mirror up -d
# For MTA, replace --profile mirror with --profile mta.
# Add --profile ai / --profile tls as needed.
```

The Compose project has the fixed name `vigilyx`, so these volume names are deterministic. Test the restore process on a separate host; an unread backup is not a recovery plan.
`deploy.sh` excludes a top-level `backups/` directory from `rsync --delete`,
but storing backups outside the synchronized checkout is still recommended.

---

## 8. Monitoring and Maintenance

### 8.1 Health Check Script

```bash
cat > /home/vigilyx/healthcheck.sh << 'SCRIPT'
#!/bin/bash
API_URL="http://127.0.0.1:8088"
# Set this to "mta" for an MTA deployment. A Compose profile does not switch
# or stop the other data plane; use ./deploy.sh --mta for a topology switch.
COMPOSE_PROFILE="mirror"

# Check aggregate readiness (API process + PostgreSQL + Redis + engine heartbeat)
if ! curl -fsS "${API_URL}/api/health/ready" > /dev/null 2>&1; then
  echo "[ALERT] Vigilyx is not ready!" | mail -s "Vigilyx Alert" admin@example.com
  # Auto-restart (optional)
  cd /home/CCAB_VIGILYX/deploy/docker
  docker compose --profile "$COMPOSE_PROFILE" up -d
fi

# Check disk space (alert at 85%)
DISK_USAGE=$(df /var/lib/docker | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "[ALERT] Disk usage at ${DISK_USAGE}%!" | mail -s "Vigilyx Disk Alert" admin@example.com
fi
SCRIPT

chmod +x /home/vigilyx/healthcheck.sh

# Run as root: keep this independent of the backup schedule.
cat > /etc/cron.d/vigilyx-healthcheck << 'CRON'
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/5 * * * * vigilyx /home/vigilyx/healthcheck.sh >> /home/vigilyx/healthcheck.log 2>&1
CRON
chown root:root /etc/cron.d/vigilyx-healthcheck
chmod 644 /etc/cron.d/vigilyx-healthcheck
```

### 8.2 Log Management

Application logs go to stdout/stderr and are managed by Docker's log driver:

```bash
# Mirror deployment
docker compose logs -f vigilyx engine sniffer

# MTA deployment (the engine is embedded in the MTA process)
docker compose logs -f vigilyx mta

# Rotation is handled by each service's `local` log-driver settings in Compose;
# the daemon.json settings are only the host fallback.
```

### 8.3 Docker Image Updates

```bash
cd /home/CCAB_VIGILYX

# Pull latest code
git pull origin main

# Rebuild and redeploy the active topology
cd deploy/docker
docker compose --profile mirror build
docker compose --profile mirror up -d
# Add optional --profile ai / --profile tls when configured.
# For MTA, replace --profile mirror with --profile mta; never select both topologies.

# Clean up old images
docker image prune -f
```

### 8.4 PostgreSQL Maintenance

```bash
# Analyze tables for query optimizer
docker exec vigilyx-postgres sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "ANALYZE;"'

# Check database size
docker exec vigilyx-postgres sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT pg_size_pretty(pg_database_size(current_database()));"'

# Vacuum (reclaim space)
docker exec vigilyx-postgres sh -lc \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "VACUUM ANALYZE;"'
```

---

## 9. Security Checklist

Run through this checklist before going to production:

### Server Level

- [ ] OS fully updated (`dnf update` / `apt upgrade`)
- [ ] SSH: key-only auth, no root password login, MaxAuthTries=3
- [ ] fail2ban installed and enabled
- [ ] Firewall enabled; normally only SSH + 80/443 are public (plus 25/465 for an intentionally exposed MTA)
- [ ] Automatic security updates enabled
- [ ] Kernel security parameters applied (sysctl)
- [ ] Unnecessary services disabled
- [ ] Dedicated service user created (not running as root)

### Docker Level

- [ ] Docker Engine up to date
- [ ] Log rotation configured (daemon.json)
- [ ] `no-new-privileges` enabled
- [ ] Docker socket not exposed to containers
- [ ] Regular `docker image prune` scheduled

### Application Level

- [ ] `.env` file generated with strong random passwords (`generate-secrets.sh`)
- [ ] `.env` file has `chmod 600` permissions
- [ ] `.env` file is NOT committed to git
- [ ] Default admin password changed after first login
- [ ] Independent audit bootstrap password changed after first audit login
- [ ] `RUST_LOG` set to `info` (never `debug` in production)
- [ ] Internal services bound to `127.0.0.1` (Redis, PostgreSQL, AI)
- [ ] `SNIFFER_INTERFACE` set to correct capture interface

### Network Level

- [ ] TLS/HTTPS configured (Caddy or Nginx)
- [ ] API port behind reverse proxy (not directly exposed)
- [ ] HTTP redirected to HTTPS
- [ ] HSTS header enabled
- [ ] Access restricted to trusted IP ranges (if applicable)

### Backup Level

- [ ] Daily PostgreSQL backup scheduled
- [ ] Backup retention policy configured (7-30 days)
- [ ] Backup restore procedure tested
- [ ] Backup files stored on separate storage / off-site

---

## 10. Troubleshooting

### Container Won't Start

```bash
# Check container logs
docker compose logs <service-name>

# Check if ports are already in use
ss -tlnp | grep -E '8088|5433|6379'

# Check Docker volumes exist
docker volume ls | grep vigilyx
```

### Database Connection Failed

```bash
# Verify PostgreSQL is healthy
docker exec vigilyx-postgres pg_isready -U vigilyx

# Check password matches
source deploy/docker/.env
docker exec vigilyx-postgres psql -U vigilyx -d vigilyx -c "SELECT 1;"
```

### Sniffer Not Capturing

```bash
# Check interface exists
ip link show

# Check sniffer logs
docker logs vigilyx-sniffer --tail 50

# Verify capture interface in .env
grep SNIFFER_INTERFACE deploy/docker/.env

# Test with tcpdump
tcpdump -i <interface> -c 10 port 25
```

### AI Service Unavailable

```bash
# Check AI container
docker logs vigilyx-ai --tail 50

# Verify both switches
grep AI_ENABLED deploy/docker/.env           # Must be true
docker compose --profile ai ps               # AI container must be running

# First startup downloads ~550MB model (takes 5-10 min)
docker exec vigilyx-ai ls -la /app/.hf_cache/
```

### High CPU Usage

```bash
# Check if debug logging is enabled
docker exec vigilyx-sniffer env | grep RUST_LOG
# If it shows "debug" → change to "info" in .env and restart

# Check system load
docker stats --no-stream
```

### Forgot Admin Password

Use another active administrator account to reset the affected user in the platform user settings. Changing `API_PASSWORD` or deleting only the legacy `auth_password_hash` config row does **not** overwrite an existing `platform_users` password. If no administrator account remains accessible, restore a tested database backup or use the authenticated factory-reset workflow only when complete application-data loss is acceptable; there is currently no unauthenticated password-reset command.
