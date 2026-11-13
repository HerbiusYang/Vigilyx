<p align="center">
  <h1 align="center">Vigilyx</h1>
  <p align="center">Real-time email threat detection platform</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Rust-1.98.0-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/React-19-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB.svg" alt="Python">
</p>

---

Two deployment modes: **Mirror** (passive network capture) and **MTA Proxy** (inline SMTP relay with accept/quarantine/reject decisions). Vigilyx combines a configurable multi-module analysis pipeline, evidence fusion, DLP, automated response, and a React dashboard in one Docker Compose project. Optional AI, antivirus, and sandbox integrations are disabled unless explicitly configured and started.

### Website

- Website: https://herbiusyang.github.io/Vigilyx/
- Docs: https://herbiusyang.github.io/Vigilyx/docs/
- Repository: https://github.com/HerbiusYang/Vigilyx

### Friendly Links

- [RelaySail](https://relaysail.com/?lang=zh-CN)

### Community

- Linux.do project post: https://linux.do/t/topic/2027260

### Architecture

```text
Core control plane (`docker compose up -d`)

                           optional integrations
                    +----------+----------+----------+
                    |    AI    |  ClamAV  | Sandbox  |
                    +----------+----------+----------+

┌──────────────────────────────────────────────────────────────┐
│ vigilyx                                                     │
│ API + frontend control plane                                │
│ - auth, REST, WebSocket, settings, SOAR                     │
│ - serves the React UI                                       │
│ - queries stored sessions/verdicts and manages config/auth  │
│ - normal analysis writes come from Engine/MTA; API imports  │
└───────────────┬──────────────────────────────────────┬───────┘
                │                                      │
                │ control topics / API auth            │ SQL
                │                                      │
┌───────────────▼───────────────┐        ┌─────────────▼─────────────┐
│ Valkey / Redis                │        │ PostgreSQL                │
│ Streams + Pub/Sub             │        │ sessions / verdicts       │
│ transport + control bus       │        │ config / audit / state    │
└───────────────────────────────┘        └───────────────────────────┘
```

```text
Mirror deployment (`docker compose --profile mirror up -d` or `./deploy.sh`)

                           optional integrations
                    +----------+----------+----------+
                    |    AI    |  ClamAV  | Sandbox  |
                    +-----+----+-----+----+-----+----+
                          \          |          /
                           \         |         /
                            v        v        v
┌──────────────────────────────────────────────────────────────┐
│ vigilyx-engine-standalone                                   │
│ Dedicated analysis engine                                   │
│ - consumes Redis Streams                                    │
│ - runs parsing, detection, fusion, DLP, and SOAR hooks      │
└───────────────┬──────────────────────────────────────┬───────┘
                │                                      │
                │ Streams + Pub/Sub                    │ SQL
                │                                      │
┌───────────────▼───────────────┐        ┌─────────────▼─────────────┐
│ Valkey / Redis                │        │ PostgreSQL                │
│ Streams + Pub/Sub             │        │ sessions / verdicts       │
│ transport + control bus       │        │ config / audit / state    │
└───────────────▲───────────────┘        └─────────────▲─────────────┘
                │                                      │
                │ mirror ingress only                  │
┌───────────────┴───────────────┐        ┌─────────────┴─────────────┐
│ vigilyx-sniffer               │        │ vigilyx                   │
│ libpcap capture               │        │ API + frontend control    │
│ -> Streams (sessions)         │        │ plane                     │
│ -> Pub/Sub (stats)            │        │                           │
└───────────────────────────────┘        └───────────────────────────┘
```

Email and HTTP sessions, and current rescan requests use Redis Streams. Pub/Sub carries sniffer statistics, engine verdicts, alerts, data-security incidents and status, plus reload/control commands; the engine also retains a legacy Pub/Sub rescan subscriber. AI content analysis uses the internal HTTP API rather than the declared but currently unused AI Redis channels.

```text
Inline MTA deployment (`--profile mta`)

Mail client / upstream MTA
            |
            v
┌──────────────────────────────────────────────────────────────┐
│ vigilyx-mta                                                 │
│ SMTP proxy + embedded Engine                                │
│ - accepts, rejects, or quarantines inline                   │
│ - reads config and stores verdict state via PostgreSQL      │
│ - uses Redis for shared transport / control paths           │
└──────────────────────────────────────────────────────────────┘
            |
            v
      downstream MTA
```

- `SOAR` is library logic executed inside the engine and API flows, not a standalone container.
- `AI`, `ClamAV`, and `Sandbox` are engine-side integrations used by the dedicated mirror-mode engine and the embedded MTA engine when enabled.
- `docker compose up -d` starts the control-plane containers (`vigilyx`, `postgres`, `redis`) and runs the one-shot PostgreSQL migration, role-initialization, and audit-bootstrap jobs. Add `--profile mirror` for passive capture or `--profile mta` for inline SMTP.
- `STANDALONE_ENGINE` remains only for backward compatibility. Current compose defaults and `deploy.sh` normalize it to `false`, so mirror mode uses the dedicated `engine` container and MTA mode uses the embedded engine inside `vigilyx-mta`.

### Features

- **Dual Mode**: passive mirror mode or inline MTA proxy mode
- **MTA Proxy**: inbound SMTP relay for local domains, TLS support, a configurable inline-decision timeout (8 seconds by default), and configurable fail-open or fail-closed behavior
- **Passive Capture**: libpcap-based SMTP reconstruction without mail-server integration; POP3/IMAP currently provide protocol metadata and coverage signals, not reconstructed mail-content analysis. In standard Compose, configure HTTP capture through the UI/API; the default Webmail server list is empty
- **Configurable Detection Pipeline**: the compiled default currently defines 29 configured entries, including the final `verdict` stage and entries that remain inert unless their optional service or explicit opt-in is available; runtime aggregation defaults to `clustered_ds_v2`, and historical D-S configuration names normalize to it
- **Threat Intel**: OTX, VirusTotal, and AbuseIPDB with a local IOC cache
- **DLP**: bounded sensitive-data scanning for HTTP/Webmail and separate SMTP outbound-email reviews; mirror auditing and MTA outbound policy enforcement on relay candidates
- **Privacy Access**: content masking by default, independent audit approval, and short-lived access leases bound to the requesting user, login session, resource, and scopes
- **YARA**: built-in and database-backed YARA rule scanning
- **Temporal Analysis**: CUSUM, EWMA, Hawkes process, and HMM-based attack-phase modeling
- **SOAR**: alert dispatch, email notifications, webhooks, and disposition rules
- **Real-Time Dashboard**: React SPA with WebSocket updates
- **Optional Integrations**: AI service, ClamAV, CAPEv2 sandbox, bundled or host-level TLS

### Quick Start

New server: [First deployment](DEPLOYMENT.md). Already installed:
[Updating, verification, and recovery](UPDATING.md).

Recommended remote-first workflow:

```bash
# 1. Point deploy.sh at your target host
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf

# 2. Pre-pull the pinned Rust builder image on the target host
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"

# 3. One-time initialization (sync source, generate remote .env if missing, create build container)
./deploy.sh --init

# 4. Review the remote runtime configuration
ssh root@<server> "cd <repo-root> && vi deploy/docker/.env"
# Mirror mode: set SNIFFER_INTERFACE
# Optional: AI_ENABLED=true, HF_ENDPOINT=https://hf-mirror.com
# MTA mode: set MTA_DOWNSTREAM_HOST, MTA_DOWNSTREAM_PORT, and MTA_LOCAL_DOMAINS
# For mail servers on another host, set MTA_LISTEN to the intended host-interface IP (default: 127.0.0.1)
# MTA mode also requires remote deploy/docker/certs/mta.crt + mta.key (PEM)

# 5. Choose ONE initial topology (release-grade packaging)
./deploy.sh --production            # mirror mode by default
# ./deploy.sh --production --mta    # MTA instead; requires its TLS files first
# Add --tls only when using the bundled HTTPS entry point.
```

For `./deploy.sh --mta`, install the certificate and private key directly on
the target as `<repo-root>/deploy/docker/certs/mta.crt` and `mta.key` before
running the command. TLS material is intentionally excluded from source sync.
To return to passive capture, set `VIGILYX_MODE=mirror` in the remote `.env`
and run a complete deployment. Day-to-day development can omit `--production`
to use `release-fast`. Component-only commands belong to the
[update workflow](UPDATING.md), after the first complete installation.

Manual Docker Compose on the target host is still supported:

```bash
# 1. Generate secrets from the project root
bash scripts/generate-secrets.sh

# 2. Edit configuration
vi deploy/docker/.env

# 3. Build and start
cd deploy/docker
docker compose --profile mirror build   # use --profile mta for an MTA-only build

# Mirror mode (control plane + standalone engine + sniffer)
docker compose --profile mirror up -d

# Mirror mode + AI
docker compose --profile mirror --profile ai up -d

# Mirror mode + bundled TLS
docker compose --profile mirror --profile tls up -d

# Inline MTA mode
# Requires deploy/docker/certs/mta.crt and mta.key (PEM; private key mode 600)
# Set MTA_LISTEN to the intended host-interface IP if SMTP clients connect from another host.
docker compose --profile mta up -d
```

Direct Compose profile commands start the selected services but do not stop a data plane already running under another profile or update VIGILYX_MODE. For a live topology switch, use the deploy helper; the --mta path updates the mode and stops the mirror services.

> `docker compose up -d` without a profile starts the control-plane containers and runs the one-shot PostgreSQL migration, role-initialization, and audit-bootstrap jobs. Use `--profile mirror` or `--profile mta` for an actual traffic-processing deployment.

> **Production**: keep `API_LISTEN=127.0.0.1` and terminate TLS on the host with Caddy or Nginx. See the [Deployment Guide](DEPLOYMENT.md).
>
> Without HTTPS, login credentials and JWT tokens are transmitted in cleartext.
>
> By default, the API binds to `127.0.0.1:8088`; set `API_LISTEN=0.0.0.0` only for temporary non-TLS testing. For remote HTTP tests, also set `API_SECURE_COOKIE=false` temporarily, then restore it to `true`; browsers do not send Secure cookies over remote HTTP.

After TLS is provisioned, open `https://<server-or-domain>`. Without TLS, access `http://127.0.0.1:8088` from the server itself or through an SSH tunnel.

On a brand-new database, log in as `API_USERNAME` (default `admin`) with
`API_PASSWORD` from `deploy/docker/.env`. After that password is changed in the
UI, the database-backed credential takes precedence; editing `API_PASSWORD`
does not rotate an existing account.

> **Important**: `API_PASSWORD` must be set explicitly in `.env`. Default fallback credentials are disabled.
>
> The one-shot bootstrap also creates the independent `AUDIT_USERNAME` account when it does not already exist. Retrieve `AUDIT_BOOTSTRAP_PASSWORD` only from the mode-`600` server `.env`, sign in once, and change it immediately. A later bootstrap never overwrites an existing audit account or its password.

### Services

| Container | Port | Profile | Purpose |
|-----------|------|---------|---------|
| `vigilyx` | 127.0.0.1:8088 by default (`API_LISTEN` can override) | default | API + frontend control plane |
| `vigilyx-engine-standalone` | - | `mirror` | Dedicated analysis engine for passive deployments |
| `vigilyx-sniffer` | host net | `mirror` | Packet capture for passive deployments |
| `vigilyx-mta` | 25 / 465 | `mta` | SMTP proxy relay with embedded engine |
| `vigilyx-postgres` | 5433 local | default | PostgreSQL persistence |
| `vigilyx-redis` | 6379 local | default | Streams + Pub/Sub message bus |
| `vigilyx-cache` | internal only | `read-cache` | Optional disposable Valkey read cache; separate from the message bus |
| `vigilyx-ai` | 8900 local | `ai` | Optional semantic/NLP and VT scrape service |
| `vigilyx-clamav` | 3310 local | `antivirus` | Antivirus scanning |
| `vigilyx-sandbox` | 8000 local | `sandbox` | Experimental CAPEv2 detonation |
| `vigilyx-caddy` | 80 / 443 | `tls` | Bundled TLS reverse proxy |

> `sandbox` is experimental and intended for isolated internal testing with KVM/libvirt. It is not required for standard deployment or public release.
>
> MTA host ports default to loopback (`127.0.0.1:25/465`). Set `MTA_LISTEN` to the intended interface IP for connections from other hosts; expose only the SMTP ports needed by your mail path.

ClamAV is enabled with `CLAMAV_ENABLED=true`. The deploy helper starts it during backend/data-plane deployments; `--antivirus` adds it to the components selected for that run, and a bare `./deploy.sh --antivirus` still performs the default full deployment. To start only ClamAV on a host whose API and active engine containers already have `CLAMAV_ENABLED=true`, run `docker compose -f deploy/docker/docker-compose.yml --profile antivirus up -d clamav`. If you just changed the setting from `false`, recreate the active engine-bearing service too, for example with `./deploy.sh --backend --antivirus`.

Every deployment run except initialization-only `deploy.sh --init`, including `--frontend`, pauses running clients before reconciling PostgreSQL/Valkey and database roles, then restores their prior running state on success or failure. Schema migrations run only with a newly built API binary (backend/full deployments and production frontend builds); fast frontend, sniffer-only, and config-only deployments preserve installed SQL functions. Packet capture and inline SMTP service pause during dependency reconciliation; plan a maintenance window even for targeted deployments.

Read-cache requires `READ_CACHE_ENABLED=true`, a separate `CACHE_REDIS_PASSWORD`, and at least one `CACHE_*_ENABLED=true` dataset gate. `deploy.sh` does not start it automatically; after configuring the remote `.env`, run `docker compose -f deploy/docker/docker-compose.yml --profile read-cache up -d cache` on the host.

### Detection Modules

**Core and built-in pipeline entries**:

| Module | Detection Target |
|--------|------------------|
| `header_scan` | Forged sender indicators, SPF/DMARC results, Received-chain IOC hits |
| `content_scan` | Urgency language, financial bait, keyword and phrase heuristics |
| `semantic_scan` | Local semantic rules, optional CPU ONNX intent ensemble, and optional Python NLP |
| `link_scan` | Short links, homoglyphs, IDN attacks, suspicious parameters |
| `link_reputation` | Domain, URL, and IP reputation via OTX, VT, and AbuseIPDB |
| `link_content` | DGA traits, brand impersonation, mixed-script domains |
| `landing_page_scan` | Bounded landing-page fetching and content-risk signals |
| `attach_scan` | Type-vs-extension mismatch via magic-byte detection |
| `attach_content` | Macros, scripts, and encrypted archive heuristics |
| `attach_qr_scan` | QR payload extraction from supported image/document carriers |
| `attach_hash` | SHA-256 matching against known malicious samples |
| `yara_scan` | Built-in and database-backed YARA rule matching for EML and attachments |
| `domain_verify` | Envelope and DKIM domain alignment, link-domain trust scoring, impersonation suppression |
| `identity_anomaly` | Sender inconsistency and first-contact detection |
| `html_scan` | Obfuscation, hidden elements, CSS cloaking, zero-width tricks |
| `html_pixel_art` | Pixel tracking, beacons, and invisible iframe patterns |
| `mime_scan` | MIME validation and header injection checks |
| `transaction_correlation` | Cross-session fraud and business-process correlation |
| `anomaly_detect` | Statistical feature anomalies |
| `aitm_detect` | AitM, OAuth redirect, MFA-bait, and device-code indicators |
| `rmm_detect` | Remote-management software lures and links |
| `prompt_injection_scan` | Prompt-injection-like instructions in message content |
| `toad_detect` | Telephone-oriented attack-delivery indicators |
| `url_sandbox_scan` | Deferred URL detonation result ingestion; opt-in and inert by default |
| `process_sandbox_scan` | Bounded observations in a separate worker; opt-in, no independent threat verdict, kernel isolation pending |

**Conditional integrations and final stage**:

- `av_eml_scan` and `av_attach_scan`: registered only when ClamAV is enabled and reachable
- `verdict`: final aggregation stage for all module output
- `sandbox_scan`: registered only when the CAPEv2 URL and API token are both configured

The compiled default order currently contains 29 entries. PostgreSQL stores the active pipeline configuration and can override code defaults; the engine backfills newly added default entries without silently enabling a missing external service. See `default_modules()` in `crates/vigilyx-engine/src/pipeline/config.rs` and the runtime registry in `crates/vigilyx-engine/src/modules/registry.rs` for the source of truth.

**Subsystems**: Data Security Engine (HTTP/Webmail DLP and SMTP outbound reviews), temporal analyzer (CUSUM/EWMA/Hawkes/HMM), and verdict fusion with circuit breakers.

### Semantic Model Modes

`semantic_scan` runs local Rust semantic rules without the Python AI service.
An optional bge/e5 ensemble runs inside the engine on CPU when
`SEMANTIC_INTENT_MODEL_DIR` and `ORT_DYLIB_PATH` identify valid model/runtime
artifacts. It runs in shadow mode by default, recording diagnostics without
changing the verdict. Setting a valid `SEMANTIC_INTENT_SCORE_THRESHOLD` switches
to scored mode and replaces the local semantic-rule path: a threshold hit
contributes a Low module score of 0.20 to fusion, rather than guaranteeing a
final verdict or action. The optional Python NLP/OCR service is a separate
integration. Current Compose intent-model wiring is on the mirror engine;
MTA model deployment requires separate configuration. See the
[semantic engine guide](crates/vigilyx-engine/src/semantic/README.md).

### Outbound Data Security and Privacy

SMTP outbound reviews are separate from HTTP incidents and email threat
verdicts. Mirror mode audits only inspectable payloads; MTA mode can alert,
quarantine, or block relay candidates under outbound DLP policy. Direction
requires trusted source, domain, and recipient evidence; a local-looking
`MAIL FROM` alone is insufficient. Encrypted traffic, incomplete inspection,
and failed checks remain explicit unknowns. Reviews are available through
`GET /api/data-security/email-reviews`, `/stats`, and `/{id}` beneath that path.

Privacy mode masks content by default while preserving security analysis. An
administrator requests access to a specific resource and scopes with a purpose
and their configured verification factor; an independent audit user approves
with a separate factor. The requester then obtains a lease bound to their user,
JWT session, resource, and scopes, valid for at most five minutes. Manage the
policy and requests in System Settings → Privacy; the API uses
`/api/config/privacy` and `/api/privacy/access-requests`. A missing or unreadable
policy defaults to masking. Credentials remain masked when privacy is disabled,
and already-redacted persisted review evidence cannot be reconstructed.

### Threat Levels

| Level | Score | Meaning |
|-------|-------|---------|
| Safe | `< 0.15` | Risk score is below the first alert band |
| Low | `0.15 - <0.40` | Low-scoring suspicious evidence |
| Medium | `0.40 - <0.65` | Review or policy action may be appropriate |
| High | `0.65 - <0.85` | Stronger combined risk evidence |
| Critical | `>= 0.85` | Highest risk band; the configured policy decides the action |

These are the compiled `ThreatLevel::from_score` boundaries. A risk level is a detector output, not proof that a message is malicious; active pipeline settings and optional integrations affect the evidence that reaches the final score.

### Project Structure

```text
crates/
├── vigilyx-core/       Shared types and security primitives
├── vigilyx-parser/     SMTP, MIME, and protocol parsing shared by sniffer and MTA
├── vigilyx-sniffer/    Packet capture and passive session publishing
├── vigilyx-db/         PostgreSQL and Redis abstractions
├── vigilyx-engine/     Detection modules, fusion, DLP, temporal analysis
├── vigilyx-api/        REST API, WebSocket push, auth, metrics
├── vigilyx-soar/       Alerts and disposition logic
└── vigilyx-mta/        SMTP proxy with embedded engine
frontend/               React SPA (Vite + TypeScript)
python/vigilyx_ai/      FastAPI AI / VT scrape service
site/                   VitePress project site and public docs
```

### Development

> Vigilyx uses a remote-first workflow: edit locally, and run compilation, tests, and builds on the remote host. Rust commands run in the `vigilyx-rust-builder` container; frontend checks run through `deploy.sh --frontend`.

```bash
# One-time setup
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init

# Day-to-day deployment
./deploy.sh
./deploy.sh --backend
./deploy.sh --frontend
./deploy.sh --sniffer
./deploy.sh --sniffer --config-only
./deploy.sh --mta

# Release-grade builds
./deploy.sh --production
./deploy.sh --production --backend
./deploy.sh --production --frontend
./deploy.sh --production --sniffer
./deploy.sh --production --mta

# Project site / docs preview (run these commands from the local repository root)
REMOTE_HOST="root@your-server"   # replace with the SSH target from deploy.conf
REMOTE_DIR="/path/to/VIGILYX"   # replace with the remote repository path
rsync -az --exclude='node_modules' --exclude='.vitepress/cache' --exclude='.vitepress/dist' \
  site/ "${REMOTE_HOST}:${REMOTE_DIR}/site/"
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/site' && npm ci && npm run dev -- --host 127.0.0.1"
# In a second local terminal, forward the remote preview port
REMOTE_HOST="root@your-server"   # set this again in the second terminal
ssh -L 5173:127.0.0.1:5173 "$REMOTE_HOST"
```

Repeat the `rsync` command after local site edits; VitePress watches the synchronized files on the remote host.

`./deploy.sh` defaults to the fast developer path (`release-fast` + `docker-compose.fast.yml`). `./deploy.sh --production` switches back to the full Dockerfiles and Docker-side `cargo --release` image builds. By default it deploys the mirror topology; if the remote deployment mode is pinned to `mta`, `deploy.sh` keeps the MTA image in sync automatically, and `./deploy.sh --mta` forces an inline-proxy rollout. For env/compose adjustments that do not need a rebuild, use `./deploy.sh --config-only` with the relevant component flag. Deployment verifies effective PostgreSQL settings and mirror Stream lag after API readiness; host/network tuning remains a separate manual task.

`./deploy.sh --sniffer` is mirror-only. If the remote `.env` pins
`VIGILYX_MODE=mta`, switch it back to `mirror` before deploying the sniffer;
the helper refuses to change the active topology implicitly.

The public project site lives in `site/` and is published through GitHub Pages with the workflow in `.github/workflows/pages.yml`. For GitHub-hosted Pages, the default URL is `https://herbiusyang.github.io/Vigilyx/`. For a custom domain, set `PAGES_CUSTOM_DOMAIN`, or override `PAGES_SITE_URL` and `PAGES_BASE_PATH` in repository variables.

Passive mirror deployments can also reuse the host-side capture tuning helper directly:

```bash
ssh <server> "cd <repo-root> && bash scripts/apply-capture-host-tuning.sh --env-file deploy/docker/.env"
```

Manual verification on the remote build host:

```bash
ssh <server> "docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings"
ssh <server> "docker exec vigilyx-rust-builder cargo fmt --check"

# Full tests take several minutes: detach them and poll the recorded exit code.
ssh <server> "rm -f /tmp/vigilyx_test_output.txt /tmp/vigilyx_test_status && \
  (nohup sh -c 'docker exec vigilyx-rust-builder cargo test --workspace -- --test-threads=8 \
    > /tmp/vigilyx_test_output.txt 2>&1; echo \$? > /tmp/vigilyx_test_status' \
    </dev/null >/dev/null 2>&1 &)"
test_status=""
while [[ ! "$test_status" =~ ^[0-9]+$ ]]; do
  test_status=$(ssh <server> "cat /tmp/vigilyx_test_status" 2>/dev/null || true)
  [[ "$test_status" =~ ^[0-9]+$ ]] || sleep 15
done
ssh <server> "tail -n 80 /tmp/vigilyx_test_output.txt"
test "$test_status" -eq 0
```

`deploy.sh` runs the full workspace test command as a remote background job, polls a status file, and checks the real exit code so an SSH interruption does not turn into an ambiguous result.

Frontend toolchain (installs, tests, and builds run on the remote host):

```bash
./deploy.sh --frontend
```

- Frontend development is pinned to `Node 24.19.0` via [`.nvmrc`](.nvmrc).
- Use `npm 12.0.2` for lockfile updates. The repo declares this in [frontend/package.json](frontend/package.json) and enforces it with [frontend/.npmrc](frontend/.npmrc).
- `deploy.sh --frontend` checks the pinned Node/npm pair and runs `npm ci`, `npm test`, and the TypeScript/Vite build on the remote host.
- `./deploy.sh --frontend` and the production [deploy/docker/Dockerfile.api](deploy/docker/Dockerfile.api) both build the frontend with the same pinned `Node 24.19.0 + npm 12.0.2` toolchain.
- When changing dependencies, update `frontend/package.json` and `package-lock.json` together, then verify with `./deploy.sh --frontend`.

Optional remote Vite HMR:

```bash
REMOTE_HOST="root@your-server"   # replace with the SSH target from deploy.conf
REMOTE_DIR="/path/to/VIGILYX"   # replace with the remote repository path
rsync -az --exclude='node_modules' --exclude='dist' --exclude='.env' --exclude='.env.*' \
  frontend/ "${REMOTE_HOST}:${REMOTE_DIR}/frontend/"
# On the remote host, install dependencies once, then start Vite
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/frontend' && npm ci && npm run dev -- --host 127.0.0.1"
# In a second local terminal, set the host again and forward the Vite port
REMOTE_HOST="root@your-server"
ssh -L 3000:127.0.0.1:3000 "$REMOTE_HOST"
```

Repeat the `rsync` command after local frontend edits; remote Vite watches the synchronized files.

Do not run frontend tests or builds on the local machine; use the remote workflow above.

### Configuration

Environment-level settings and deployment secrets live in `deploy/docker/.env`. Settings managed through the UI/API are persisted in PostgreSQL or the relevant runtime configuration store and may override code or environment defaults where the service supports it.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PG_PASSWORD` | Yes | -- | PostgreSQL schema-owner password, used only by one-shot setup/maintenance jobs |
| `PG_API_PASSWORD`, `PG_ENGINE_PASSWORD`, `PG_MTA_PASSWORD` | Yes | -- | Distinct non-owner PostgreSQL runtime-role passwords |
| `REDIS_PASSWORD` | Yes | -- | Valkey administrator password used to render the ACL file |
| `REDIS_API_PASSWORD`, `REDIS_ENGINE_PASSWORD`, `REDIS_SNIFFER_PASSWORD`, `REDIS_MTA_PASSWORD` | Yes | -- | Distinct Valkey service-user passwords |
| `API_JWT_SECRET` | Yes | -- | JWT signing key (minimum 32 chars) |
| `VIGILYX_CONFIG_ENCRYPTION_KEY` | Yes | -- | Independent key for encrypted integration credentials |
| `API_PASSWORD` | Yes | -- | First-login admin password and authenticated factory-reset seed; it does not overwrite an existing account |
| `AUDIT_USERNAME`, `AUDIT_BOOTSTRAP_PASSWORD` | Yes | `privacy-auditor` / -- | Independent audit identity and first-login password |
| `INTERNAL_API_TOKEN`, `SNIFFER_API_TOKEN`, `MTA_API_TOKEN` | Yes | -- | Distinct internal API tokens by trust boundary |
| `MQ_AUTH_TOKEN` | Yes | -- | Authenticates control and data-plane message envelopes |
| `AI_INTERNAL_TOKEN` | Yes | -- | AI-scoped token for API, mirror engine, and embedded MTA engine to AI |
| `READ_CACHE_ENABLED` | No | `false` | Enable optional aggregate read caching; also start the `read-cache` profile and set a distinct `CACHE_REDIS_PASSWORD` |
| `CACHE_SECURITY_STATS_ENABLED`, `CACHE_DELIVERY_STATS_ENABLED`, `CACHE_LOGIN_STATS_ENABLED`, `CACHE_SESSION_COUNTS_ENABLED` | No | `false` | Per-dataset gates; enable at least one in addition to `READ_CACHE_ENABLED=true` |
| `CACHE_REDIS_PASSWORD` | Read cache | -- | Dedicated cache password; keep distinct from all message-bus credentials |
| `SNIFFER_INTERFACE` | No | `eth0` | Capture network interface |
| `SNIFFER_WORKERS` | No | `16` | Sniffer worker thread count; mirrored email traffic usually does not need dozens of workers |
| `SNIFFER_WORKER_CPU_LIST` | No | empty | Optional CPU list for sniffer workers, e.g. `0-15`; host IRQ tuning reserves it |
| `SNIFFER_CAPTURE_CPU` | No | empty | Optional dedicated CPU for the libpcap capture reader; must be outside the worker list |
| `SNIFFER_HOST_TUNING` | No | `true` | Enable the manually invoked NIC/sysctl/RPS tuning helper; `deploy.sh` does not change host/network settings |
| `SNIFFER_HOST_IRQ_REBALANCE` | No | `true` | Rebalance capture NIC IRQs away from reserved sniffer worker CPUs |
| `SNIFFER_HOST_IRQ_CPU_LIST` | No | empty | Optional explicit CPU list for NIC IRQs, e.g. `16-23,32-39` |
| `AI_ENABLED` | No | `false` | Allow `vigilyx` and the active engine to call AI; `deploy.sh` starts AI on backend/data-plane deployments when enabled, while `--frontend` preserves its current state; direct Compose use also needs the `ai` profile |
| `VIGILYX_MODE` | No | empty | Lock the UI mode and select the active data-plane topology for `deploy.sh` (`mirror` or `mta`) |
| `MTA_LOCAL_DOMAINS` | MTA | -- | Comma-separated local recipient domains accepted by the MTA |
| `MTA_DOWNSTREAM_HOST` | MTA | `127.0.0.1` | Downstream MTA address; set the actual reachable relay host for deployment |
| `MTA_DOWNSTREAM_PORT` | MTA | `25` | Downstream MTA SMTP port |
| `MTA_INLINE_TIMEOUT_SECS` | MTA | `8` | Inline verdict timeout |
| `MTA_FAIL_OPEN` | MTA | `false` | Attempt relay after engine failure (`true`, still subject to outbound DLP) or return SMTP 451 (`false`) |
| `RUST_LOG` | No | `info` | Log level; never use `debug` in production |

Full variable list: see [`.env.example`](deploy/docker/.env.example).

### Security

- JWT auth (HS256 + Argon2) with forced password change on first login
- Per-IP and normalized-account login rate limiting
- Constant-time internal token comparison
- One-time WebSocket ticket flow with no JWT in the URL
- Redis and PostgreSQL bound to `127.0.0.1`
- CSP headers, SSRF protection, and masked error responses
- Non-root containers and request tracing via `X-Request-Id`
- Host-level or bundled TLS termination options

See the root [Deployment Guide](DEPLOYMENT.md) for production hardening.

### Tech Stack

| Layer | Stack |
|-------|-------|
| Backend | Rust 1.98.0, tokio, axum, sqlx, redis, pnet/pcap, yara-x, petgraph, dashmap, rayon, crossbeam, tracing |
| Frontend | React 19, TypeScript, Vite, React Router |
| AI | Python 3.12, FastAPI, Transformers, PyTorch |
| Infra | Docker Compose, PostgreSQL 17, Valkey/Redis 8, Caddy 2 |

## Donate

We are committed to giving back the vast majority of funds received to society. The target allocation is:

| Allocation | % | Details |
|:----------:|:-:|---------|
| Public welfare | 80% | Support vulnerable groups, rural education, students, and charitable organizations |
| Project development | 10% | AI training, GPU compute, infrastructure, CI/CD, and API operating costs |
| Team building | 10% | Security researcher recruitment, contributor bounties, and community operations |

> Fund usage details will be published on the `/community` page of the Vigilyx dashboard in a future release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[AGPL-3.0](LICENSE) -- if you deploy Vigilyx as a network service, you must make the source code available to your users.
