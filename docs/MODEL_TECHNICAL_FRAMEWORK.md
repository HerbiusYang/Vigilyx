# Vigilyx Technical Framework

This document describes the current implementation-level architecture of Vigilyx as of the `0.9.x` codebase.

Primary source files:

- `deploy/docker/docker-compose.yml`
- `deploy.sh`
- `crates/vigilyx-db/src/mq/mod.rs`
- `crates/vigilyx-engine/src/modules/registry.rs`
- `crates/vigilyx-engine/src/fusion/engine_map.rs`
- `crates/vigilyx-engine/src/pipeline/config.rs`
- `crates/vigilyx-engine/src/pipeline/verdict/`
- `crates/vigilyx-api/src/main.rs`
- `crates/vigilyx-mta/src/main.rs`

## 1. Runtime Modes

Vigilyx supports two traffic acquisition modes built on a shared detection stack.

### Mirror mode

Mirror mode is enabled with `docker compose --profile mirror up -d`.

```text
network traffic
  -> vigilyx-sniffer
  -> Redis Streams (data plane) + Redis Pub/Sub (shadow/control)
  -> standalone engine inside vigilyx
  -> PostgreSQL
  -> API + WebSocket
  -> frontend
```

Mirror mode is passive. It depends on libpcap capture and does not require integration with the upstream mail server.

### MTA mode

MTA mode is enabled with `docker compose --profile mta up -d`.

```text
upstream client or upstream MTA
  -> vigilyx-mta
  -> embedded engine
  -> accept / temporary fail / reject / quarantine
  -> downstream MTA
  -> PostgreSQL + Redis
```

Important current behavior:

- `--profile mta` adds `vigilyx-mta`
- it does not automatically disable the standalone engine inside `vigilyx`
- submission port 587 remains disabled until SMTP AUTH is implemented

## 2. Runtime Topology

The default Compose stack contains:

- `vigilyx`: API, frontend static assets, and the standalone engine
- `vigilyx-postgres`: PostgreSQL 17
- `vigilyx-redis`: Valkey / Redis

Optional services:

- `vigilyx-sniffer` with profile `mirror`
- `vigilyx-mta` with profile `mta`
- `vigilyx-ai` with profile `ai`
- `vigilyx-clamav` with profile `antivirus`
- `vigilyx-sandbox` with profile `sandbox`
- `vigilyx-caddy` with profile `tls`

The public API binds to port `8088` inside the container and defaults to `127.0.0.1:8088` on the host.

## 3. Message Transport

The Redis transport layer is split by purpose.

### Data plane

Redis Streams are used for at-least-once delivery:

- `vigilyx:stream:sessions`
- `vigilyx:stream:http_sessions`
- `vigilyx:stream:ai_tasks`

The engine uses the `vigilyx-engine` consumer group for stream consumption.

### Control and notification plane

Redis Pub/Sub is used for notifications and commands:

- `vigilyx:session:new`
- `vigilyx:session:update`
- `vigilyx:stats:update`
- `vigilyx:http_session:new`
- `vigilyx:engine:verdict`
- `vigilyx:engine:alert`
- `vigilyx:engine:ds_incident`
- `vigilyx:engine:status`
- `vigilyx:engine:cmd:rescan`
- `vigilyx:engine:cmd:reload`
- `vigilyx:sniffer:cmd:reload`

### API subscriptions

The API process subscribes directly to sniffer and engine topics. It is not merely a database reader. It:

- persists session and verdict state
- updates cached statistics
- broadcasts WebSocket messages to the frontend

## 4. Storage Model

PostgreSQL is the primary and only persistent system of record for the main application.

Persistent data includes:

- sessions and verdicts
- configuration rows
- IOC and whitelist data
- YARA rules
- data-security incidents
- authentication state and saved password hash

Redis is not the durable record. It is the transport and ephemeral coordination layer.

Earlier internal notes that described SQLite as the main persistence backend are no longer accurate for the current codebase.

## 5. Parsing and Session Construction

The shared parser layer lives in `vigilyx-parser`.

Protocols currently handled across the product:

- SMTP
- POP3
- IMAP
- HTTP

Mirror mode uses `vigilyx-sniffer` plus the shared parser crate. MTA mode uses `vigilyx-mta` plus the same parser primitives for SMTP and MIME handling.

Key session artifacts include:

- envelope sender and recipients
- parsed headers
- text and HTML bodies
- attachments with hashes and metadata
- extracted links
- authentication context when available

## 6. Detection Pipeline

The registry in `crates/vigilyx-engine/src/modules/registry.rs` currently builds:

- 17 built-in detection modules
- 3 external-service detection modules when their services are available
- 1 verdict sink module

### Built-in detection modules

- `content_scan`
- `html_scan`
- `html_pixel_art`
- `attach_scan`
- `attach_content`
- `attach_hash`
- `mime_scan`
- `header_scan`
- `link_scan`
- `link_reputation`
- `link_content`
- `anomaly_detect`
- `semantic_scan`
- `domain_verify`
- `identity_anomaly`
- `transaction_correlation`
- `yara_scan`

### External-service detection modules

- `av_eml_scan`
- `av_attach_scan`
- `sandbox_scan`

### Verdict sink

- `verdict`

## 7. Eight-Engine Fusion Layout

The D-S fusion layer groups most modules into eight conceptual engines.

| Engine | Label | Modules |
|--------|-------|---------|
| A | `sender_reputation` | `domain_verify` |
| B | `content_analysis` | `content_scan`, `html_scan`, `html_pixel_art`, `attach_scan`, `attach_content`, `attach_hash`, `yara_scan`, `av_eml_scan`, `av_attach_scan` |
| C | `behavior_baseline` | `anomaly_detect` |
| D | `url_analysis` | `link_scan`, `link_reputation`, `link_content` |
| E | `protocol_compliance` | `header_scan`, `mime_scan` |
| F | `semantic_intent` | `semantic_scan` |
| G | `identity_anomaly` | `identity_anomaly` |
| H | `transaction_correlation` | `transaction_correlation` |

Important nuance:

- `sandbox_scan` is currently **not** mapped into the A-H engine table in `module_to_engine()`
- it still participates in the broader module result set and can influence the final verdict path outside the grouped engine fusion map

## 8. MTA Inline Tiering

`vigilyx-mta` does not run every module on the inline critical path.

Tier 1 inline modules:

- `content_scan`
- `header_scan`
- `html_scan`
- `mime_scan`
- `link_scan`
- `attach_scan`
- `attach_hash`
- `domain_verify`
- `anomaly_detect`
- `identity_anomaly`
- `yara_scan`
- `av_eml_scan`
- `av_attach_scan`
- `html_pixel_art`
- `attach_content`

Tier 2 asynchronous modules:

- `semantic_scan`
- `link_content`
- `link_reputation`
- `transaction_correlation`
- `sandbox_scan`
- `verdict`

Current default MTA settings from `MtaConfig`:

- inline timeout: `8` seconds
- fail-open default: `false`
- reject threshold: `Critical`
- quarantine threshold: `Medium`

## 9. Verdict Semantics

### Threat levels

Threat levels come from `vigilyx-core`:

- `Safe` for scores `< 0.15`
- `Low` for scores `>= 0.15` and `< 0.40`
- `Medium` for scores `>= 0.40` and `< 0.65`
- `High` for scores `>= 0.65` and `< 0.85`
- `Critical` for scores `>= 0.85`

### BPA primitives

Important built-in BPA helpers:

- `Bpa::vacuous() = { b=0.0, d=0.0, u=1.0 }`
- `Bpa::safe_analyzed() = { b=0.0, d=0.15, u=0.85 }`

`safe_analyzed()` is intentionally weakly benign and high-uncertainty. It does not absorb threat evidence from other modules.

### Supported aggregation strategies

The current pipeline supports:

- `ds_murphy` (default)
- `tbm_v5`
- `noisy_or`
- `weighted_max`

### Current default verdict parameters

From `pipeline/config.rs`:

| Parameter | Default |
|-----------|---------|
| `aggregation` | `ds_murphy` |
| `eta` | `0.30` |
| `default_epsilon` | `0.01` |
| `alert_belief_threshold` | `0.20` |
| `alert_floor_factor` | `1.0` |
| `convergence_min_modules` | `2` |
| `convergence_base_floor` | `0.40` |
| `convergence_belief_threshold` | `0.10` |

The practical effect is:

- uncertainty contributes 30% of its mass to risk in the default D-S path
- a single strong module can force a floor through the circuit breaker
- two or more sufficiently aligned modules can force at least Medium severity through the convergence floor

## 10. Data Security Pipeline

The data-security subsystem focuses on HTTP webmail behavior and DLP.

It includes:

- 30 pattern families with JR/T 0197-2020 mappings
- draft-box abuse detection
- file-transit abuse detection
- self-send detection
- chunked upload reassembly and analysis

This subsystem is separate from the mail verdict modules but shares the same API, database, and alerting surfaces.

## 11. AI and External Integrations

### AI service

The Python AI service runs in `python/vigilyx_ai` and is typically exposed as `vigilyx-ai` on port `8900`.

It is used for:

- NLP phishing classification
- VirusTotal scrape requests when VT API access is not used directly

### Threat intel

Current intel sources in the engine layer:

- OTX AlienVault
- VirusTotal official API or VT scrape path
- AbuseIPDB

### Antivirus and sandbox

- ClamAV is used by `av_eml_scan` and `av_attach_scan`
- CAPEv2 is used by `sandbox_scan`

These are engine-side integrations, not API-side plugins.

## 12. API and Frontend

The API process is responsible for:

- authentication and JWT issuance
- REST endpoints
- WebSocket fan-out
- metrics
- dashboard cache refresh tasks
- Redis subscription handling
- persistence side effects triggered by transport events

The frontend is a React SPA served from the `vigilyx` container. In standard production builds the assets are baked into the image. The `docker-compose.dev.yml` override exists only for development-time frontend replacement.

## 13. Build and Deployment Paths

There are two supported build paths:

### Fast developer path

- driven by `./deploy.sh`
- uses `release-fast`
- uses `docker-compose.fast.yml`
- uses the persistent remote build container `vigilyx-rust-builder`

### Production path

- driven by `./deploy.sh --production` or direct `docker compose build`
- uses full Dockerfiles
- uses `cargo --release` in Docker multi-stage builds

## 14. Operational Caveats That Matter

- `VIGILYX_ALLOW_DEFAULT_CREDS` must be explicitly enabled before fallback credentials are allowed
- the API defaults to `127.0.0.1:8088`, so host-level TLS termination is the preferred public deployment pattern
- `--profile mta` does not disable the standalone engine automatically
- submission port 587 is still intentionally disabled
- older documents that mention SQLite persistence, Pub/Sub-only transport, or custom per-module BPA math for `domain_verify` are out of date

## 15. Bottom Line

The current Vigilyx architecture is best understood as:

- PostgreSQL-backed application state
- Redis Streams for at-least-once session delivery
- Redis Pub/Sub for notifications and control messages
- a standalone engine in the default `vigilyx` service
- an optional embedded engine inside `vigilyx-mta`
- 17 built-in detection modules, 3 external-service modules, and a verdict sink
- a React frontend and axum API running from the same primary service container
