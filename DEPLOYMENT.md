# Vigilyx Production Deployment Guide

Complete guide for deploying Vigilyx on a remote Linux server with security hardening.

**Target audience**: System administrators deploying Vigilyx in enterprise environments.

---

## Table of Contents

- [1. Server Requirements](#1-server-requirements)
- [2. OS Security Baseline](#2-os-security-baseline)
- [3. Docker Installation](#3-docker-installation)
- [4. Vigilyx Deployment](#4-vigilyx-deployment)
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
  "userns-remap": "default",
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

> **Note on `userns-remap`**: This maps container root to an unprivileged host user. The **sniffer container** requires `NET_RAW`/`NET_ADMIN` capabilities which may conflict with user namespaces. If sniffer fails to start, either:
> - Remove `"userns-remap"` from daemon.json, or
> - Add `"userns-mode": "host"` to the sniffer service in docker-compose.yml

```bash
# Enable and start Docker
systemctl enable --now docker

# Verify
docker info | grep -E "Server Version|Security Options|Logging Driver"
```

### 3.3 Docker Log Rotation

The daemon.json above sets 50MB x 3 files per container. Verify:

```bash
# Check current log sizes
du -sh /var/lib/docker/containers/*/*-json.log 2>/dev/null | sort -rh | head -5
```

---

## 4. Vigilyx Deployment

### 4.1 Get the Source Code

> Publishing to GitHub is optional. You can deploy from a private Git server, an internal mirror, an offline tarball, or `rsync` from your workstation.

```bash
cd /home/vigilyx
git clone <your-git-remote-or-local-mirror> vigilyx
cd vigilyx

# Example without GitHub:
# rsync -av ./VIGILYX/ vigilyx@server:/home/vigilyx/vigilyx/
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
```

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

# First-time build (pulls images + compiles, ~10-15 minutes)
docker compose build

# Start the default passive-capture stack
docker compose --profile mirror up -d

# Optional profiles
docker compose --profile mirror --profile ai up -d   # if AI_ENABLED=true
docker compose --profile mirror --profile tls up -d  # all-in-one TLS: auto domain certs, internal CA, or file certs

# Inline MTA mode (adds vigilyx-mta instead of the mirror sniffer path)
docker compose --profile mta up -d

# Experimental / isolated lab only (requires KVM/libvirt)
docker compose --profile sandbox up -d

# Verify all containers are healthy
docker compose ps
```

If you deploy from a local checkout through the helper script, use the explicit production path:

```bash
./deploy.sh --production
./deploy.sh --production --backend
./deploy.sh --production --frontend
./deploy.sh --production --sniffer
```

`./deploy.sh` without `--production` remains the fast developer path (`release-fast` + `docker-compose.fast.yml`).

If you terminate TLS with host-level Caddy or Nginx in section 5, keep the container bound to localhost and do not enable the Compose `tls` profile.
In the current Compose defaults, `--profile mta` adds `vigilyx-mta`; it does not automatically disable the standalone engine inside `vigilyx`.

Typical output (with `mirror` + `ai` enabled, without TLS):
```
NAME               STATUS                    PORTS
vigilyx            Up (healthy)              127.0.0.1:8088->8088/tcp
vigilyx-ai         Up (healthy)              127.0.0.1:8900->8900/tcp
vigilyx-postgres   Up (healthy)              127.0.0.1:5433->5432/tcp
vigilyx-redis      Up (healthy)              127.0.0.1:6379->6379/tcp
vigilyx-sniffer    Up
```

### 4.5 First Login

1. For production, enable TLS and open `https://<your-domain-or-server>`
2. Without TLS, the service binds to localhost by default; open `http://127.0.0.1:8088` on the server itself or use an SSH tunnel / reverse proxy
3. Set `API_LISTEN=0.0.0.0` only for temporary non-TLS remote testing, then open `http://<server-ip>:8088`
4. Login with `admin` / `<API_PASSWORD from .env>`
5. **Change your password immediately** via Settings page

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

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
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
- Keep `API_LISTEN=127.0.0.1` unless you explicitly need temporary non-TLS remote testing

---

## 6. Firewall Configuration

### firewalld (Rocky Linux / RHEL)

```bash
# Enable firewall
systemctl enable --now firewalld

# Allow only necessary ports
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-port=443/tcp    # HTTPS (if using TLS proxy)
firewall-cmd --permanent --add-port=8088/tcp   # Vigilyx API (remove if behind proxy)

# Block everything else by default
firewall-cmd --permanent --set-default-zone=drop

# Apply
firewall-cmd --reload

# Verify
firewall-cmd --list-all
```

### iptables (Ubuntu / Debian)

```bash
# Install persistent rules
apt install -y iptables-persistent

# Create rules
cat > /etc/iptables/rules.v4 << 'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Loopback
-A INPUT -i lo -j ACCEPT

# Established connections
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT

# HTTPS (if using TLS proxy)
-A INPUT -p tcp --dport 443 -j ACCEPT

# Vigilyx API (remove if behind proxy)
-A INPUT -p tcp --dport 8088 -j ACCEPT

# ICMP (ping)
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT

COMMIT
EOF

iptables-restore < /etc/iptables/rules.v4
```

### IP Whitelist (Restrict to Trusted Networks)

For maximum security, restrict API access to known IP ranges:

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
cat > /home/vigilyx/backup-db.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
BACKUP_DIR="/home/vigilyx/backups"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

# Source the .env for credentials
source /home/vigilyx/vigilyx/deploy/docker/.env

# Dump database
docker exec vigilyx-postgres pg_dump \
  -U "${PG_USER:-vigilyx}" \
  -d "${PG_DB:-vigilyx}" \
  --format=custom \
  --compress=9 \
  > "$BACKUP_DIR/vigilyx_${DATE}.dump"

# Retain last 7 days
find "$BACKUP_DIR" -name "vigilyx_*.dump" -mtime +7 -delete

echo "[$(date)] Backup complete: vigilyx_${DATE}.dump ($(du -h "$BACKUP_DIR/vigilyx_${DATE}.dump" | cut -f1))"
SCRIPT

chmod +x /home/vigilyx/backup-db.sh
```

### 7.2 Schedule Daily Backups

```bash
# Run backup daily at 3 AM
echo "0 3 * * * /home/vigilyx/backup-db.sh >> /home/vigilyx/backups/backup.log 2>&1" | crontab -u vigilyx -
```

### 7.3 Restore from Backup

```bash
# Stop the application
cd /home/vigilyx/vigilyx/deploy/docker
docker compose stop vigilyx

# Restore
source .env
docker exec -i vigilyx-postgres pg_restore \
  -U "${PG_USER:-vigilyx}" \
  -d "${PG_DB:-vigilyx}" \
  --clean --if-exists \
  < /home/vigilyx/backups/vigilyx_YYYYMMDD_HHMMSS.dump

# Restart with the same profiles you use in production
docker compose --profile mirror up -d
# Add --profile ai / --profile tls / --profile mta as needed
```

### 7.4 Volume Backup (Full Disaster Recovery)

```bash
# Stop all services
cd /home/vigilyx/vigilyx/deploy/docker
docker compose down

# Backup all volumes
for vol in vigilyx_vigilyx_pgdata vigilyx_redis_data vigilyx_vigilyx_data vigilyx_hf_cache; do
  docker run --rm -v ${vol}:/data -v /home/vigilyx/backups:/backup \
    alpine tar czf /backup/${vol}_$(date +%Y%m%d).tar.gz -C /data .
done

# Restart with the same profiles you use in production
docker compose --profile mirror up -d
# Add --profile ai / --profile tls / --profile mta as needed
```

---

## 8. Monitoring and Maintenance

### 8.1 Health Check Script

```bash
cat > /home/vigilyx/healthcheck.sh << 'SCRIPT'
#!/bin/bash
API_URL="http://127.0.0.1:8088"

# Check API health
if ! curl -sf "${API_URL}/api/health" > /dev/null 2>&1; then
  echo "[ALERT] Vigilyx API is down!" | mail -s "Vigilyx Alert" admin@example.com
  # Auto-restart (optional)
  cd /home/vigilyx/vigilyx/deploy/docker
  docker compose --profile mirror up -d
fi

# Check disk space (alert at 85%)
DISK_USAGE=$(df /var/lib/docker | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "[ALERT] Disk usage at ${DISK_USAGE}%!" | mail -s "Vigilyx Disk Alert" admin@example.com
fi
SCRIPT

chmod +x /home/vigilyx/healthcheck.sh

# Run every 5 minutes
echo "*/5 * * * * /home/vigilyx/healthcheck.sh >> /home/vigilyx/healthcheck.log 2>&1" | crontab -u vigilyx -
```

### 8.2 Log Management

Application logs are inside the container:

```bash
# View real-time logs
docker exec vigilyx tail -f /app/logs/api.log
docker exec vigilyx tail -f /app/logs/engine.log
docker logs -f vigilyx-sniffer

# Log rotation (container logs handled by Docker daemon.json)
# Application logs: rotated by the Rust tracing layer (file-based)
```

### 8.3 Docker Image Updates

```bash
cd /home/vigilyx/vigilyx

# Pull latest code
git pull origin main

# Rebuild and redeploy
cd deploy/docker
docker compose build
docker compose --profile mirror up -d
# Add --profile ai / --profile tls / --profile mta as needed

# Clean up old images
docker image prune -f
```

### 8.4 PostgreSQL Maintenance

```bash
# Analyze tables for query optimizer
docker exec vigilyx-postgres psql -U vigilyx -d vigilyx -c "ANALYZE;"

# Check database size
docker exec vigilyx-postgres psql -U vigilyx -d vigilyx -c \
  "SELECT pg_size_pretty(pg_database_size('vigilyx'));"

# Vacuum (reclaim space)
docker exec vigilyx-postgres psql -U vigilyx -d vigilyx -c "VACUUM ANALYZE;"
```

---

## 9. Security Checklist

Run through this checklist before going to production:

### Server Level

- [ ] OS fully updated (`dnf update` / `apt upgrade`)
- [ ] SSH: key-only auth, no root password login, MaxAuthTries=3
- [ ] fail2ban installed and enabled
- [ ] Firewall enabled, only required ports open (SSH + 443/8088)
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

```bash
# Generate a new password hash and update in database
source deploy/docker/.env
NEW_PASS="your-new-password"

# The simplest way: delete the saved hash, restart, and it will use API_PASSWORD from .env
docker exec vigilyx-postgres psql -U vigilyx -d vigilyx \
  -c "DELETE FROM config WHERE key = 'auth_password_hash';"
docker restart vigilyx

# Login with API_PASSWORD from .env, then change via Settings page
```
