---
title: Deployment
description: Deployment overview for Vigilyx, covering mirror mode, MTA mode, Docker Compose profiles, and production recommendations.
---

# Deployment

Vigilyx supports two main deployment patterns.

## Recommended workflow

The repository's primary deployment path is `deploy.sh`, not ad-hoc local `cargo` or manual image assembly.

Common commands:

```bash
./deploy.sh
./deploy.sh --backend
./deploy.sh --frontend
./deploy.sh --sniffer
./deploy.sh --mta
./deploy.sh --production
./deploy.sh --production --mta
```

This remote-first workflow syncs the repository, verifies Rust code inside the remote `vigilyx-rust-builder`, builds `release-fast` artifacts for day-to-day deployment, packages the images, and restarts the active topology. Manual `docker compose` remains available as a fallback or for direct single-host operation.

## Mirror mode

Use mirror mode when you want traffic visibility without changing the existing mail system.

Data flow:

```text
libpcap capture -> Redis Streams -> Engine -> PostgreSQL -> API/UI
```

Typical use cases:

- Retrospective analysis
- Alerting and audit
- Email traffic forensics
- Webmail and data-security monitoring

Recommended profile:

```bash
./deploy.sh
# or, on the target host:
docker compose --profile mirror up -d
```

## MTA proxy mode

Use MTA mode when you want inline SMTP decisions before delivery.

Data flow:

```text
SMTP client -> vigilyx-mta -> inline engine -> quarantine/reject/relay -> downstream MTA
```

Typical use cases:

- Quarantine before final delivery
- Reject clearly malicious mail inline
- Real-time gateway-style protection

Recommended profile:

```bash
./deploy.sh --mta
# or, on the target host:
docker compose --profile mta up -d
```

`docker compose up -d` without a profile only starts the control-plane services (`vigilyx`, `postgres`, `redis`). It does not enable passive capture or inline SMTP enforcement by itself.

## Current topology notes

- Mirror mode runs a dedicated `vigilyx-engine-standalone` container together with `vigilyx-sniffer`.
- MTA mode runs the engine embedded inside `vigilyx-mta`; the standalone mirror engine is not part of that path.
- The main `vigilyx` container is the API/frontend control plane in both topologies.

## Optional services

- `--profile ai`: optional NLP and semantic analysis
- `--profile tls`: bundled Caddy reverse proxy
- `--profile antivirus`: ClamAV integration
- `--profile sandbox`: experimental CAPEv2 detonation

## Production guidance

- Keep the API private behind TLS termination
- Set explicit secrets in `deploy/docker/.env`
- Use `mirror` and `mta` based on a clear network design, not at random
- Turn on only the optional services you actually operate
- Monitor Redis, PostgreSQL, and sniffer health together

## Release workflow

For formal releases, prefer the production deployment path documented in the repository:

- `./deploy.sh --production`
- `./deploy.sh --production --backend`
- `./deploy.sh --production --frontend`
- `./deploy.sh --production --sniffer`
- `./deploy.sh --production --mta`

For architecture details, see [Architecture](/docs/architecture).
