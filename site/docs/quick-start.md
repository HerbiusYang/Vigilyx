---
title: Quick Start
description: Quick start instructions for running Vigilyx in mirror mode or inline MTA mode with Docker Compose.
---

# Quick Start

The repository supports two ways to launch Vigilyx:

- Recommended: the remote-first `deploy.sh` workflow
- Alternative: manual `docker compose` commands on the target host

## Recommended workflow: deploy.sh

This matches the repository's primary deployment flow.

```bash
# 1. Point deploy.sh at the target host
cp deploy.conf.example deploy.conf
$EDITOR deploy.conf

# 2. Pre-pull the pinned Rust builder image on the target host
ssh root@<server> "docker pull rust:1.95.0-bookworm"

# 3. One-time initialization
./deploy.sh --init

# 4. Review the remote runtime settings
ssh root@<server> "cd <repo-root> && vi deploy/docker/.env"
# Mirror mode: set SNIFFER_INTERFACE
# Optional: AI_ENABLED=true, HF_ENDPOINT=https://hf-mirror.com
# MTA mode: set MTA_DOWNSTREAM_HOST, MTA_DOWNSTREAM_PORT, and MTA_LOCAL_DOMAINS

# 5. Deploy the topology you want
./deploy.sh
./deploy.sh --backend
./deploy.sh --frontend
./deploy.sh --sniffer
./deploy.sh --mta

# 6. Release-grade packaging
./deploy.sh --production
./deploy.sh --production --mta
```

`./deploy.sh` is the recommended day-to-day path. It syncs the repo, runs clippy/tests in the remote `vigilyx-rust-builder`, builds `release-fast` artifacts, packages the images, and restarts the active topology.

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

## 3. Build the containers

```bash
cd deploy/docker
docker compose build
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
docker compose --profile mta up -d
```

`docker compose up -d` without a profile only starts the control-plane containers (`vigilyx`, `postgres`, `redis`). Use `--profile mirror` for passive capture or `--profile mta` for inline SMTP handling.

## 5. Open the UI

- HTTPS entry: `https://<server-or-domain>`
- Local API debug entry: `http://127.0.0.1:8088`

Login with:

- Username: `admin` unless overridden by `API_USERNAME`
- Password: `API_PASSWORD` from `deploy/docker/.env`

## Notes

- Keep `API_LISTEN=127.0.0.1` in production and terminate TLS with Caddy or Nginx.
- Do not assume default credentials. `API_PASSWORD` must be set explicitly.
- AI is optional. If it is disabled, the core detection pipeline still runs.

For deeper operational details, continue with [Deployment](/docs/deployment).
