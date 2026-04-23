---
title: Quick Start
description: Quick start instructions for running Vigilyx in mirror mode or inline MTA mode with Docker Compose.
---

# Quick Start

These steps are the fastest way to get Vigilyx running from the repository.

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
