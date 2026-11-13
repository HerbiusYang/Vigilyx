---
title: First Deployment
description: Install Vigilyx on a new server, configure its mode and HTTPS entry point, and verify the installation.
---

# First Deployment

Use this page for a new server. For an installed environment, follow
[Updating and recovery](/docs/updating), retaining its configuration and data.

## Prerequisites

- Workstation: Bash, SSH, rsync, Python 3, and the complete release source with lockfiles.
- Target: Docker Engine 24+, Compose v2.20+, Bash, Python 3, rsync, and OpenSSL.
- Working SSH keys, Docker access, sufficient build disk space, and the intended capture interface.
- Target access to OCI registries, Rust/crate servers, npm, and Debian mirrors. Configure a required proxy on the target; a workstation proxy is not forwarded automatically over SSH.

Run helper commands from the workstation checkout. Builds and tests run remotely.

## Recommended workflow

The repository's primary deployment path is `deploy.sh`, not ad-hoc local `cargo` or manual image assembly.

Follow these steps in order:

```bash
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
# Set VIGILYX_SERVER and VIGILYX_REMOTE_DIR.

ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init

# Use the same remote directory as deploy.conf; review the generated .env.
ssh root@<server> "vi /home/CCAB_VIGILYX/deploy/docker/.env"
# Mirror: VIGILYX_MODE=mirror, SNIFFER_INTERFACE=<capture NIC>.
# Set AI_ENABLED=false when not using the optional Python AI service.

# Choose ONE complete initial deployment:
./deploy.sh --production
# ./deploy.sh --production --mta  # configure downstream and install TLS first
```

`--init` generates secrets only if `.env` is missing, prepares the builder, and warms its cache; it does not start the application. Edit the generated remote `.env` rather than generating secrets again. The first installation must deploy the complete topology; component commands are for subsequent updates.

`--production` uses full Dockerfiles and release builds. Omit it for incremental `release-fast` development builds. The helper syncs source, runs applicable checks, builds images, coordinates database/roles, starts the topology, and verifies readiness and queues. Direct Compose is an alternative described in the repository's `DEPLOYMENT.md`.

## HTTPS and first acceptance

Provision a host reverse proxy or add `--tls` to the first deployment, for example `./deploy.sh --production --tls`, to use bundled Caddy. Choose one to avoid port 80/443 conflicts. The default API binds only to `127.0.0.1:8088`; completing deployment does not enable public HTTPS by itself.

Run in the server's deployment directory:

```bash
docker compose -f deploy/docker/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:8088/api/health/ready
python3 scripts/verify-deployment.py --mode mirror
# Use --mode mta for MTA.
```

Require exit code 0, `{"status":"ready"}`, and the selected data plane running. Open the configured HTTPS entry point. On a new database, use `.env` values `API_USERNAME` (default `admin`) and `API_PASSWORD`, then change the password. Sign in separately as `AUDIT_USERNAME` using `AUDIT_BOOTSTRAP_PASSWORD` and change that password too. Existing accounts use their database-backed credentials.

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
./deploy.sh --production
# or, on the target host:
  docker compose -f deploy/docker/docker-compose.yml --profile mirror up -d
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
./deploy.sh --production --mta
# or, on the target host:
  docker compose -f deploy/docker/docker-compose.yml --profile mta up -d
```

The secure defaults require PEM files at `deploy/docker/certs/mta.crt` and `mta.key` (private key mode `600`) before either command starts the MTA. `./deploy.sh --mta` persists `VIGILYX_MODE=mta` and stops the mirror data plane. A direct Compose command only starts the selected profile; it does not stop containers from another profile or persist the deployment mode. For a topology switch, use the deploy helper or update the remote mode and stop the previous data-plane services explicitly.

Compose binds MTA ports to `127.0.0.1` by default. For SMTP clients on another host, set `MTA_LISTEN` in `deploy/docker/.env` to the intended host-interface IP before starting MTA; keep the listener on loopback for local-only use.

`./deploy.sh --sniffer` is mirror-only and fails if the remote environment is
pinned to MTA mode; change `VIGILYX_MODE` explicitly rather than using a
component command to switch traffic-processing topology.

`docker compose up -d` without a profile starts the control-plane services (`vigilyx`, `postgres`, `redis`) and runs one-shot PostgreSQL migration, role-initialization, and audit-bootstrap jobs. It does not enable passive capture or inline SMTP enforcement by itself.

## Current topology notes

- Mirror mode runs a dedicated `vigilyx-engine-standalone` container together with `vigilyx-sniffer`.
- MTA mode runs the engine embedded inside `vigilyx-mta`; the standalone mirror engine is not part of that path.
- The main `vigilyx` container is the API/frontend control plane in both topologies.

## Optional services

- `--profile ai`: optional NLP and semantic analysis
- `--profile tls`: bundled Caddy reverse proxy
- `--profile antivirus`: ClamAV integration
- `--profile sandbox`: experimental CAPEv2 detonation
- `--profile read-cache`: optional disposable Valkey cache for aggregate reads; set `READ_CACHE_ENABLED=true`, a separate `CACHE_REDIS_PASSWORD`, and at least one of `CACHE_SECURITY_STATS_ENABLED`, `CACHE_DELIVERY_STATS_ENABLED`, `CACHE_LOGIN_STATS_ENABLED`, or `CACHE_SESSION_COUNTS_ENABLED` to `true`. All dataset gates default to `false`. `deploy.sh` does not start this service; run `docker compose -f deploy/docker/docker-compose.yml --profile read-cache up -d cache` on the host after configuring `.env`.

With direct Compose commands, profiles start containers and their matching feature switches and credentials must also be configured. For example, AI requires `AI_ENABLED=true` and the `ai` profile. `deploy.sh` starts AI when enabled during backend or data-plane deployments; `--frontend` preserves the current AI service state. ClamAV starts during backend/data-plane deployments when enabled, or with `--antivirus`; `--frontend` preserves its current state. CAPEv2 submissions require a sandbox URL plus API token. URL/process sandbox analysis is opt-in and is not part of the default inline MTA decision path.

`--antivirus` adds ClamAV to the components selected for that deploy; used by itself, `deploy.sh` still selects its default full deployment. To start only ClamAV on a host whose API and active engine containers already have `CLAMAV_ENABLED=true`, run `docker compose -f deploy/docker/docker-compose.yml --profile antivirus up -d clamav`. If you just changed the setting from `false`, recreate the active engine-bearing service too, for example with `./deploy.sh --backend --antivirus`.

Every deployment run except initialization-only `deploy.sh --init` pauses running clients before reconciling PostgreSQL/Valkey and database roles, then restores their previous running state on success or failure. Packet capture pauses during this window. Schema migrations run only after building a new API binary (backend/full deployments or production frontend builds); fast frontend, sniffer-only, and config-only deployments preserve installed SQL functions. Use `--backend` or a full deployment for backend/schema changes. Deployment does not change host/network settings.

## Production guidance

- Keep the API private behind TLS termination
- Set explicit secrets in `deploy/docker/.env`
- Let `deploy.sh` reconcile PostgreSQL/Valkey, runtime roles, and the independent audit identity before targeted restarts; it runs schema migration when it has built a new API binary. Starting only a rebuilt API container can leave newly added runtime passwords unapplied
- Retrieve the generated `AUDIT_BOOTSTRAP_PASSWORD` only through an authorized server session, sign in as `AUDIT_USERNAME`, and replace it immediately; the helper keeps it only in the mode-`600` remote `.env`
- Avoid deploying schema changes during `pg_dump` or long database transactions; the migrator's 15-second lock-acquisition timeout makes deployment fail rather than queue DDL that blocks later application queries
- Deployment verification compares effective PostgreSQL settings with Compose and, in mirror mode, waits up to 120 seconds for undelivered lag to stay at most 100 on two consecutive observations for both Streams. Pending in-flight work is reported separately; health alone does not establish queue recovery
- Store backups outside the synchronized checkout when possible; `deploy.sh` also excludes a top-level `backups/` directory so `rsync --delete` cannot remove operational backup files
- Use `mirror` and `mta` based on a clear network design, not at random
- Turn on only the optional services you actually operate
- Monitor Redis, PostgreSQL, and sniffer health together
- Verify the aggregate after startup with `curl -fsS http://127.0.0.1:8088/api/health/ready`

## After installation

Use [Updating and recovery](/docs/updating) for subsequent version/component updates, backups, and rollback.

For architecture details, see [Architecture](/docs/architecture).
