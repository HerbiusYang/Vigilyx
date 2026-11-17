---
title: Quick Start
description: Quick start instructions for running Vigilyx in mirror mode or inline MTA mode with Docker Compose.
---

# Quick Start

New server: [First deployment](/docs/deployment). Existing installation (for example, 0.9.3 → 0.9.4): [Updating and recovery](/docs/updating).

The repository supports two ways to launch Vigilyx:

- Recommended: the remote-first `deploy.sh` workflow
- Alternative: manual `docker compose` commands on the target host

## Recommended workflow: deploy.sh

This matches the repository's primary deployment flow.

```bash
# 1. Point deploy.sh at the target host
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf

# 2. Pre-pull the pinned Rust builder image on the target host
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"

# 3. One-time initialization
./deploy.sh --init

# 4. Review the remote runtime settings
ssh root@<server> "cd <repo-root> && vi deploy/docker/.env"
# Mirror mode: set SNIFFER_INTERFACE
# Optional: AI_ENABLED=true, HF_ENDPOINT=https://hf-mirror.com
# MTA mode: set MTA_DOWNSTREAM_HOST, MTA_DOWNSTREAM_PORT, and MTA_LOCAL_DOMAINS
# For SMTP clients on other hosts, set MTA_LISTEN to the intended host-interface IP (default: 127.0.0.1)
# MTA mode also requires remote deploy/docker/certs/mta.crt + mta.key (PEM)

# 5. Choose ONE complete initial deployment
./deploy.sh --production
# ./deploy.sh --production --mta  # install MTA TLS material first
# Add --tls for bundled HTTPS on a new host, or provision a host proxy.
```

For `./deploy.sh --mta`, install the certificate and key directly on the target at `<repo-root>/deploy/docker/certs/mta.crt` and `mta.key`; TLS material is deliberately excluded from source sync. The command stops the mirror data plane. To switch back, set `VIGILYX_MODE=mirror` in the remote `.env` and run `./deploy.sh`.

`./deploy.sh` is the recommended day-to-day path. It syncs the repo while preserving mtimes, runs clippy and workspace tests in the remote `vigilyx-rust-builder`, runs frontend tests plus the TypeScript/Vite build when applicable, packages the images, restarts the active topology, and checks `/api/health/ready`.

## Alternative: manual Docker Compose

## 1. Generate secrets

From the project root:

```bash
bash scripts/generate-secrets.sh
```

This creates `deploy/docker/.env` with random passwords and secrets.

## 2. Edit deployment settings

Open `deploy/docker/.env` and set the values that matter for your environment.

Common settings:

- `SNIFFER_INTERFACE` for mirror mode
- `AI_ENABLED=true` if you want the optional AI service
- `HF_ENDPOINT=https://hf-mirror.com` if you need a mainland China mirror
- `MTA_DOWNSTREAM_HOST` and `MTA_DOWNSTREAM_PORT` for inline MTA mode
- `MTA_LOCAL_DOMAINS` plus PEM files at `deploy/docker/certs/mta.crt` and `mta.key` for the secure-default MTA listener; keep the private key mode `600`
- `MTA_LISTEN` defaults to `127.0.0.1`; set it to the intended host-interface IP when SMTP clients connect from another host

## 3. Build the containers

```bash
cd deploy/docker
docker compose --profile mirror build
# For an MTA-only host, use: docker compose --profile mta build
```

## 4. Start the mode you need

Mirror mode:

```bash
docker compose --profile mirror up -d
```

Mirror mode with AI:

```bash
docker compose --profile mirror --profile ai up -d
```

Inline MTA mode:

```bash
# From the repository root, provision the certificate before the first start.
# For remote SMTP clients, set MTA_LISTEN=<host-interface-IP> in deploy/docker/.env first.
cd /path/to/Vigilyx
install -d -m 700 deploy/docker/certs
install -m 644 /path/to/fullchain.pem deploy/docker/certs/mta.crt
install -m 600 /path/to/private-key.pem deploy/docker/certs/mta.key
cd deploy/docker
docker compose --profile mta up -d
```

`docker compose up -d` without a profile starts the control-plane containers (`vigilyx`, `postgres`, `redis`) and runs one-shot PostgreSQL migration, role-initialization, and audit-bootstrap jobs. Use `--profile mirror` for passive capture or `--profile mta` for inline SMTP handling. Direct profile commands do not stop a data plane that was started under another profile; use the deploy helper for topology changes.

## 5. Open the UI

- HTTPS entry: `https://<server-or-domain>` after you configure a host reverse proxy or start the bundled `tls` profile
- Local API debug entry: `http://127.0.0.1:8088`

Bundled TLS example:

```bash
docker compose --profile mirror --profile tls up -d
```

Login with:

- On a brand-new database, username: `admin` unless overridden by `API_USERNAME`
- On a brand-new database, password: `API_PASSWORD` from `deploy/docker/.env`

Once that password is changed in the UI, the database-backed credential takes
precedence. Editing `API_PASSWORD` does not rotate an existing account.

The one-shot bootstrap also creates the independent `AUDIT_USERNAME` account if it is absent. Retrieve `AUDIT_BOOTSTRAP_PASSWORD` only through an authorized server session, use it for the first audit login, and change it immediately. Later bootstrap runs do not overwrite that account or rotate its password.

## Notes

- Keep `API_LISTEN=127.0.0.1` in production and terminate TLS with Caddy or Nginx.
- Do not assume default credentials. `API_PASSWORD` must be set explicitly.
- AI is optional. If it is disabled, the core detection pipeline still runs.
- Verify a traffic-processing deployment with `curl -fsS http://127.0.0.1:8088/api/health/ready`; `/health/ready` without the `/api` prefix is not the public route.

For deeper operational details, continue with [Deployment](/docs/deployment).
