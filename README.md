<p align="center">
  <h1 align="center">Vigilyx</h1>
  <p align="center">Real-time email threat detection platform</p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Rust-1.95.0-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/React-18-61DAFB.svg" alt="React">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB.svg" alt="Python">
</p>

---

Two deployment modes: **Mirror** (passive network capture) and **MTA Proxy** (inline SMTP relay with block/quarantine). Vigilyx ships a default 20-entry mail-analysis pipeline, clustered Dempster-Shafer based evidence fusion, DLP, automated response, and a React dashboard in one Docker Compose deployment.

### Website

- Website: https://herbiusyang.github.io/Vigilyx/
- Docs: https://herbiusyang.github.io/Vigilyx/docs/
- Repository: https://github.com/HerbiusYang/Vigilyx

### Community

- Linux.do project post: https://linux.do/t/topic/2027260

### Architecture

```text
Default runtime (`docker compose up -d`)

                           optional integrations
                    +----------+----------+----------+
                    |    AI    |  ClamAV  | Sandbox  |
                    +-----+----+-----+----+-----+----+
                          \          |          /
                           \         |         /
                            v        v        v
┌──────────────────────────────────────────────────────────────┐
│ vigilyx                                                     │
│ API + frontend + standalone Engine                          │
│ - consumes session streams and engine control topics        │
│ - persists sessions, verdicts, stats, and config state      │
│ - pushes WebSocket updates                                  │
│ - executes SOAR / disposition flows                         │
└───────────────┬──────────────────────────────────────┬───────┘
                │                                      │
                │ SESSION_* / STATS_* / ENGINE_*       │ SQL
                │ Streams + Pub/Sub                    │
                │                                      │
┌───────────────▼───────────────┐        ┌─────────────▼─────────────┐
│ Valkey / Redis                │        │ PostgreSQL                │
│ Streams + Pub/Sub             │        │ sessions / verdicts       │
│ transport + control bus       │        │ config / audit / state    │
└───────────────▲───────────────┘        └───────────────────────────┘
                │
                │ mirror ingress only
                │
┌───────────────┴───────────────┐
│ vigilyx-sniffer               │
│ libpcap capture               │
│ -> Streams (primary)          │
│ -> Pub/Sub (shadow/control)   │
└───────────────────────────────┘
```

```text
Inline MTA add-on (`--profile mta`)

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
- `AI`, `ClamAV`, and `Sandbox` are engine-side integrations used by the standalone engine and the embedded MTA engine when enabled.
- In the current `docker-compose.yml` defaults, `docker compose --profile mta up -d` adds `vigilyx-mta`; it does not automatically disable the standalone engine inside `vigilyx`. The `STANDALONE_ENGINE` environment variable (default `true`) controls whether the main `vigilyx` container runs its embedded engine; set it to `false` when using the standalone `engine` profile (`deploy.sh --engine` does this automatically).

### Features

- **Dual Mode**: passive mirror mode or inline MTA proxy mode
- **MTA Proxy**: inbound SMTP relay for local domains, TLS support, sub-8 second inline verdicts, configurable fail-open or fail-closed behavior
- **Passive Capture**: libpcap-based SMTP/POP3/IMAP/HTTP sniffing with no mail server integration
- **20 Pipeline Entries by Default**: 17 always-registered analyzers, 2 conditional ClamAV analyzers, and a final `verdict` stage; runtime aggregation defaults to clustered D-S fusion (`clustered_ds_v1`, exposed as `ds_murphy` for backward compatibility), with `tbm_v5`, `noisy_or`, and `weighted_max` also available
- **Threat Intel**: OTX, VirusTotal, and AbuseIPDB with a local IOC cache
- **DLP**: 30 sensitive-data patterns, HTTP session analysis, draft box abuse, file transit, self-send, and chunked upload tracking
- **YARA**: built-in and database-backed YARA rule scanning
- **Temporal Analysis**: CUSUM, EWMA, Hawkes process, and HMM-based attack-phase modeling
- **SOAR**: alert dispatch, email notifications, webhooks, and disposition rules
- **Real-Time Dashboard**: React SPA with WebSocket updates
- **Optional Integrations**: AI service, ClamAV, CAPEv2 sandbox, bundled or host-level TLS

### Quick Start

```bash
# 1. Generate secrets from the project root
bash scripts/generate-secrets.sh
# -> creates deploy/docker/.env with random passwords (chmod 600)

# 2. Edit configuration
vi deploy/docker/.env
# Required: set SNIFFER_INTERFACE to your capture NIC (for mirror mode)
# Optional: set AI_ENABLED=true to let the engine call the AI service
#           Start the AI container separately with `--profile ai`
# Optional: set HF_ENDPOINT=https://hf-mirror.com for mainland China
# Optional: set CADDY_TLS_MODE=internal for IP-based HTTPS access
# Optional: set API_LISTEN=0.0.0.0 only for temporary non-TLS remote testing

# 3. Build and start
cd deploy/docker
docker compose build

# Mirror mode
docker compose --profile mirror up -d

# Mirror mode + AI
docker compose --profile mirror --profile ai up -d

# Mirror mode + bundled TLS
docker compose --profile mirror --profile tls up -d

# Mirror mode + AI + bundled TLS
docker compose --profile mirror --profile ai --profile tls up -d

# Inline MTA mode
# Set MTA_DOWNSTREAM_HOST, MTA_DOWNSTREAM_PORT, and MTA_LOCAL_DOMAINS in .env first
docker compose --profile mta up -d
```

> **Production**: keep `API_LISTEN=127.0.0.1` and terminate TLS on the host with Caddy or Nginx. See [Deployment Guide](docs/DEPLOYMENT.md).
>
> Without HTTPS, login credentials and JWT tokens are transmitted in cleartext.
>
> By default, the API binds to `127.0.0.1:8088`; set `API_LISTEN=0.0.0.0` only for temporary non-TLS testing.

After TLS is provisioned, open `https://<server-or-domain>`. Without TLS, access `http://127.0.0.1:8088` from the server itself or through an SSH tunnel.

Login as `admin` with `API_PASSWORD` from `deploy/docker/.env`.

> **Important**: `API_PASSWORD` must be set explicitly in `.env`. Default fallback credentials are disabled.

### Services

| Container | Port | Profile | Purpose |
|-----------|------|---------|---------|
| `vigilyx` | 8088 | default | API + frontend + standalone engine |
| `vigilyx-sniffer` | host net | `mirror` | Packet capture for passive deployments |
| `vigilyx-mta` | 25 / 465 | `mta` | SMTP proxy relay with embedded engine |
| `vigilyx-postgres` | 5433 local | default | PostgreSQL persistence |
| `vigilyx-redis` | 6379 local | default | Streams + Pub/Sub message bus |
| `vigilyx-ai` | 8900 local | `ai` | Optional semantic/NLP and VT scrape service |
| `vigilyx-clamav` | 3310 local | `antivirus` | Antivirus scanning |
| `vigilyx-sandbox` | 8000 local | `sandbox` | Experimental CAPEv2 detonation |
| `vigilyx-caddy` | 80 / 443 | `tls` | Bundled TLS reverse proxy |

> `sandbox` is experimental and intended for isolated internal testing with KVM/libvirt. It is not required for standard deployment or public release.

### Detection Modules

**17 always-registered analyzers in the default engine build**:

| Module | Detection Target |
|--------|------------------|
| `header_scan` | Forged sender indicators, SPF/DMARC results, Received-chain IOC hits |
| `content_scan` | Urgency language, financial bait, keyword and phrase heuristics |
| `semantic_scan` | AI-assisted semantic phishing analysis |
| `link_scan` | Short links, homoglyphs, IDN attacks, suspicious parameters |
| `link_reputation` | Domain, URL, and IP reputation via OTX, VT, and AbuseIPDB |
| `link_content` | DGA traits, brand impersonation, mixed-script domains |
| `attach_scan` | Type-vs-extension mismatch via magic-byte detection |
| `attach_content` | Macros, scripts, and encrypted archive heuristics |
| `attach_hash` | SHA-256 matching against known malicious samples |
| `yara_scan` | Built-in and database-backed YARA rule matching for EML and attachments |
| `domain_verify` | Envelope and DKIM domain alignment, link-domain trust scoring, impersonation suppression |
| `identity_anomaly` | Sender inconsistency and first-contact detection |
| `html_scan` | Obfuscation, hidden elements, CSS cloaking, zero-width tricks |
| `html_pixel_art` | Pixel tracking, beacons, and invisible iframe patterns |
| `mime_scan` | MIME validation and header injection checks |
| `transaction_correlation` | Cross-session fraud and business-process correlation |
| `anomaly_detect` | Statistical feature anomalies |

**Additional pipeline entries and optional integrations**:

- `av_eml_scan` and `av_attach_scan`: enabled by configuration, but only registered when ClamAV is reachable
- `verdict`: final aggregation stage for all module output
- `sandbox_scan`: extra optional analyzer when the CAPEv2 sandbox integration is configured

This yields the default 20-entry pipeline documented above: 17 always-registered analyzers + 2 conditional ClamAV analyzers + 1 final `verdict` stage. `sandbox_scan` is outside that baseline and remains an optional add-on.

**Subsystems**: Data Security Engine (HTTP DLP, 30 patterns), temporal analyzer (CUSUM/EWMA/Hawkes/HMM), and verdict fusion with circuit breakers.

### Threat Levels

| Level | Score | Meaning |
|-------|-------|---------|
| Safe | `< 0.15` | No meaningful threat indicators |
| Low | `0.15 - <0.40` | Minor suspicious signals |
| Medium | `0.40 - <0.65` | Multiple risk indicators, needs analyst review |
| High | `0.65 - <0.85` | Strong threat evidence |
| Critical | `>= 0.85` | Confirmed malicious, immediate action required |

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

> Vigilyx uses a remote-first workflow. Edit locally, but run Rust compilation and verification in the remote `vigilyx-rust-builder` container. Do not treat local `cargo` runs as the authoritative verification path.

```bash
# One-time setup
cp deploy.conf.example deploy.conf
$EDITOR deploy.conf
ssh root@<server> "docker pull rust:1.95.0-bookworm"
./deploy.sh --init

# Day-to-day deployment
./deploy.sh
./deploy.sh --backend
./deploy.sh --frontend
./deploy.sh --sniffer
./deploy.sh --sniffer --config-only

# Release-grade builds
./deploy.sh --production
./deploy.sh --production --backend
./deploy.sh --production --frontend
./deploy.sh --production --sniffer

# Project site / docs
cd site
npm ci
npm run dev
```

`./deploy.sh` defaults to the fast developer path (`release-fast` + `docker-compose.fast.yml`). `./deploy.sh --production` switches back to the full Dockerfiles and Docker-side `cargo --release` image builds. For env/compose/host-tuning adjustments that do not need a rebuild, use `./deploy.sh --config-only` with the relevant component flag.

The public project site lives in `site/` and is published through GitHub Pages with the workflow in `.github/workflows/pages.yml`. For GitHub-hosted Pages, the default URL is `https://herbiusyang.github.io/Vigilyx/`. For a custom domain, set `PAGES_CUSTOM_DOMAIN`, or override `PAGES_SITE_URL` and `PAGES_BASE_PATH` in repository variables.

Passive mirror deployments can also reuse the host-side capture tuning helper directly:

```bash
ssh <server> "cd <repo-root> && bash scripts/apply-capture-host-tuning.sh --env-file deploy/docker/.env"
```

Manual verification on the remote build host:

```bash
ssh <server> "docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings"
ssh <server> "docker exec vigilyx-rust-builder cargo test --workspace"
ssh <server> "docker exec vigilyx-rust-builder cargo fmt --check"
```

Frontend toolchain:

```bash
nvm use
bash scripts/check-frontend-toolchain.sh
cd frontend
npm ci
```

- Frontend development is pinned to `Node 24.15.0` via [`.nvmrc`](.nvmrc).
- Use `npm 11.12.1` for lockfile updates. The repo declares this in [frontend/package.json](frontend/package.json) and enforces it with [frontend/.npmrc](frontend/.npmrc).
- Run [scripts/check-frontend-toolchain.sh](scripts/check-frontend-toolchain.sh) before local or remote frontend work if you need to confirm the active Node/npm pair.
- `./deploy.sh --frontend` and the production [deploy/docker/Dockerfile.api](deploy/docker/Dockerfile.api) both build the frontend with the same pinned `Node 24.15.0 + npm 11.12.1` toolchain.
- For routine installs, use `npm ci`.
- When changing dependencies, run `npm install ...` in `frontend/` and commit the updated `package-lock.json` in the same change.

Optional local Vite HMR:

```bash
nvm use
ssh -L 8088:127.0.0.1:8088 <server>
cd frontend
npm ci
npm run dev
```

Containerized frontend override for local development only:

```bash
cd deploy/docker
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
nvm use
cd ../../frontend
npm ci
npm run build -- --watch
```

### Configuration

All runtime configuration lives in `deploy/docker/.env`.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PG_PASSWORD` | Yes | -- | PostgreSQL password |
| `REDIS_PASSWORD` | Yes | -- | Redis password |
| `API_JWT_SECRET` | Yes | -- | JWT signing key (minimum 32 chars) |
| `API_PASSWORD` | Yes | -- | Initial admin password |
| `INTERNAL_API_TOKEN` | Yes | -- | Internal token for sniffer and engine to API |
| `AI_INTERNAL_TOKEN` | Yes | -- | AI-scoped token for API and engine to AI |
| `SNIFFER_INTERFACE` | No | `eth0` | Capture network interface |
| `SNIFFER_WORKERS` | No | `16` | Sniffer worker thread count; mirrored email traffic usually does not need dozens of workers |
| `SNIFFER_HOST_TUNING` | No | `true` | Let `deploy.sh` apply host-side NIC/sysctl/RPS tuning for the capture interface |
| `SNIFFER_HOST_IRQ_REBALANCE` | No | `true` | Rebalance capture NIC IRQs away from reserved sniffer worker CPUs |
| `SNIFFER_HOST_IRQ_CPU_LIST` | No | empty | Optional explicit CPU list for NIC IRQs, e.g. `16-23,32-39` |
| `AI_ENABLED` | No | `false` | Allow `vigilyx` and the engine to call the AI service; still start `vigilyx-ai` with the `ai` profile |
| `VIGILYX_MODE` | No | empty | Lock frontend deployment mode to `mirror` or `mta` |
| `MTA_LOCAL_DOMAINS` | MTA | -- | Comma-separated local recipient domains accepted by the MTA |
| `MTA_DOWNSTREAM_HOST` | MTA | -- | Downstream MTA address |
| `MTA_DOWNSTREAM_PORT` | MTA | `25` | Downstream MTA SMTP port |
| `MTA_INLINE_TIMEOUT_SECS` | MTA | `8` | Inline verdict timeout |
| `MTA_FAIL_OPEN` | MTA | `false` | Relay on engine failure (`true`) or return SMTP 451 (`false`) |
| `RUST_LOG` | No | `info` | Log level; never use `debug` in production |

Full variable list: see [`.env.example`](deploy/docker/.env.example).

### Security

- JWT auth (HS256 + Argon2) with forced password change on first login
- Per-IP login rate limiting
- Constant-time internal token comparison
- One-time WebSocket ticket flow with no JWT in the URL
- Redis and PostgreSQL bound to `127.0.0.1`
- CSP headers, SSRF protection, and masked error responses
- Non-root containers and request tracing via `X-Request-Id`
- Host-level or bundled TLS termination options

See [Deployment Guide](docs/DEPLOYMENT.md) for production hardening.

### Tech Stack

| Layer | Stack |
|-------|-------|
| Backend | Rust 1.95.0, tokio, axum, sqlx, redis, pnet/pcap, yara-x, petgraph, dashmap, rayon, crossbeam, tracing |
| Frontend | React 18, TypeScript, Vite, React Router |
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

<p align="center">
  <img src="assets/donate.png" alt="WeChat Pay QR code" width="240">
</p>
<p align="center"><b>WeChat Pay</b></p>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[AGPL-3.0](LICENSE) -- if you deploy Vigilyx as a network service, you must make the source code available to your users.
