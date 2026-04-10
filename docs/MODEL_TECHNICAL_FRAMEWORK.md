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

## 7. Default Verdict Path: Clustered Evidence Fusion

The default runtime verdict path is no longer the legacy A-H engine grouping.

The current default dispatcher treats `aggregation = "ds_murphy"` as a compatibility alias for
`clustered_ds_v1`. The old grouped engine map still exists, but it is only used when the
configuration explicitly selects `legacy_ds_murphy`.

### Normalization stage

Before fusion, raw `(module_id, category)` outputs are normalized into eight evidence clusters:

| Cluster | Meaning |
|---------|---------|
| `inherited_gateway_prior` | Upstream gateway banners or pre-classification labels |
| `delivery_integrity` | Header completeness, protocol anomalies, delivery-chain weaknesses |
| `sender_identity_authenticity` | Sender and display-name authenticity anomalies |
| `link_and_html_deception` | Credential links, redirects, URL tricks, deceptive HTML |
| `payload_malware` | Attachments, AV, YARA, sandbox, overt malicious payload signals |
| `external_reputation_ioc` | IOC and external-intel matches |
| `social_engineering_intent` | Phishing, BEC, coercion, and credential-theft language |
| `business_sensitivity` | DLP and transaction-sensitive content |

This clustered path is designed to stop correlated weak signals from being counted as if they were
independent engines.

### Scenario recognition

The normalizer also derives context tags used for caps, floors, and explainability:

- `gateway_banner_polluted`
- `notice_banner_polluted`
- `dsn_like_system_mail`
- `auto_reply_like`
- `semantic_nlp_only_signal`
- `transcript_like_structure`
- `sender_alignment_verified`
- `account_security_signal`
- `credential_link_signal`
- `malicious_ioc_signal`
- `payment_change_signal`

The phrase dictionaries behind `gateway_banner_polluted`, `notice_banner_polluted`,
`dsn_like_system_mail`, and `auto_reply_like` are no longer intended to be maintained in Rust
logic. They are sourced from `keyword_system_seed` / `keyword_overrides`, so operational tuning
goes through the keyword-management surface instead of hardcoded verdict-layer edits.

The parser and semantic layers also include a structural MIME-container safeguard:

- when the shared MIME parser receives a message whose top-level `Content-Type` is missing, but
  the body itself clearly starts with multipart boundaries and MIME-part headers, it attempts a
  multipart-body salvage instead of storing the raw container text as `body_text`
- the salvage path is not limited to a single clean multipart wrapper; it also reconstructs
  fragmented MIME bodies where text/html parts and attachment parts are split across broken or
  mismatched boundary fragments
- when a module still receives raw MIME container text (boundary lines, `Content-Type`,
  `Content-Transfer-Encoding`, long base64 payload lines), `semantic_scan` and
  `transaction_correlation` suppress that container text rather than treating it as human-readable
  mail body
- before `content_scan` runs keyword/BEC matching, it strips leading gateway or security-notice
  banner sections using the runtime keyword-management lists, and trims separator-delimited footer
  disclaimers so legal boilerplate is not double-counted as social-engineering content
- `content_scan` does not treat a lone single-token BEC keyword such as `immediately` or `asap`
  as BEC evidence by itself; single-token hits are weak hints and need co-occurrence, while
  multi-token phrases remain strong BEC signals
- `transaction_correlation` separates actionable payment signals (IBAN, SWIFT, bank account,
  wire instruction, payment-change request, crypto wallet) from reference-only business markers
  such as invoice or PO numbers; urgency escalation and multi-entity boosts require actionable
  payment context, not just invoice references
- `link_content` / `link_reputation` structurally suppress object-storage static assets
  (for example `*.oss-*.aliyuncs.com/...png`) so CDN bucket labels and provider parent domains
  do not inflate phishing scores on ordinary embedded images

This is intentionally structure-based. It is not a sender whitelist, a "file assistant" special
case, or a hardcoded keyword bypass.

### Low-noise suppression rules

`clustered_ds_v1` now includes explicit low-risk suppression for the most common false-positive
patterns seen in production:

- `notice_banner_polluted`
  Internal warning templates such as "unable to scan attachment", "please verify the sender",
  or "contact the security administrator" are treated as upstream notice text rather than threat
  body content. When no link, payload, identity, or IOC signal reinforces the email, the social
  cluster is heavily discounted and the final risk is capped to a `Safe`-equivalent floor.
- `gateway_banner_polluted`
  Upstream gateway headers and body banners can still be preserved as provenance, but if
  `gateway_pre_classified` is the only surviving signal and there is no local corroboration from
  link, payload, identity, IOC, delivery, or business-sensitivity clusters, the inherited prior
  is collapsed to `Safe`-equivalent noise instead of remaining as an analyst-facing `Low`.
- `auto_reply_like`
  Auto-replies, out-of-office messages, and DSN-like notices can still be fully analyzed, but
  weak semantic or sender-anomaly hits are suppressed when stronger threat clusters are absent.
- `semantic_nlp_only_signal`
  When the only flagged module is `semantic_scan`, and its categories are limited to weak NLP
  intent labels such as `nlp_phishing`, `nlp_scam`, `nlp_bec`, `nlp_spam`, or
  `nonsensical_spam`, the result is treated as low-confidence semantic noise instead of
  multi-source evidence.
- `transcript_like_structure`
  This is a structure-based semantic-only downgrading signal, not a sender, subject, or keyword
  whitelist. It is only set when the only flagged module is `semantic_scan` and the message body
  looks like a multi-turn transcript based on generic text-shape features such as repeated short
  lines, speaker-turn separators, or timestamp density. The goal is to reduce transcript-style
  false positives without trusting attacker-controlled labels such as "file assistant".
- benign interactive HTML wrappers in exported chat or office-sharing messages are also treated
  conservatively: a lone `onclick` attribute is no longer classified as XSS unless the handler
  actually performs redirect or script-execution behavior such as `window.location`, `eval`, or
  `fetch`

Current cap behavior:

- notice-banner / auto-reply / DSN-like semantic noise is capped to `risk <= 0.12`
- transcript-structure semantic-only noise is capped to `risk <= 0.18`
- generic semantic-only weak NLP noise is capped to `risk <= 0.24`
- these caps do not apply when `account_security_signal`, `credential_link_signal`, or
  `malicious_ioc_signal` is present
- a structural phishing triad of `credential_link_signal + malicious_ioc_signal + sender-identity anomaly`
  now forces at least `Medium`, even when the body text itself is weak, polluted by gateway banners,
  or intentionally disguised to avoid obvious phishing wording
- real phishing samples that combine link deception, account-security lures, and IOC evidence
  are therefore still expected to remain `High`

### Alignment handling

`domain_verify` does not contribute a threat cluster of its own in the default path.
Instead, its `alignment_score` is consumed as context.

Important current behavior:

- alignment can reduce weak structural noise
- alignment does **not** discount payload, link-deception, IOC, or social-engineering evidence
- aligned attacker-owned phishing domains are therefore still allowed to reach `High`
- the legacy `trust_score` field is retained in JSON details only for backward compatibility

### Legacy engine map

The older A-H grouped engine map still exists for `legacy_ds_murphy`:

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

- `ds_murphy` (default config name, dispatched to `clustered_ds_v1`)
- `clustered_ds_v1` (explicit name for the current default path)
- `legacy_ds_murphy`
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

Important current nuance:

- the persisted config still defaults to the string `ds_murphy`
- the runtime dispatcher maps that string to `clustered_ds_v1`
- selecting the old grouped-engine fusion now requires `legacy_ds_murphy`

The practical effect is:

- uncertainty still contributes 30% of its mass to risk
- clustered evidence, not raw module count, drives the default D-S path
- strong corroborated link/social/IOC combinations can reach `High` even when sender alignment exists
- weak gateway-banner or DSN-style noise is capped before it dominates the verdict

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

- `API_PASSWORD` and `API_JWT_SECRET` must always be set explicitly; fallback credentials are disabled
- the API defaults to `127.0.0.1:8088`, so host-level TLS termination is the preferred public deployment pattern
- `--profile mta` does not disable the standalone engine automatically
- submission port 587 is still intentionally disabled
- older documents that mention SQLite persistence, Pub/Sub-only transport, default A-H grouped engine fusion, or generalized `trust` semantics for `domain_verify` are out of date

## 15. Bottom Line

The current Vigilyx architecture is best understood as:

- PostgreSQL-backed application state
- Redis Streams for at-least-once session delivery
- Redis Pub/Sub for notifications and control messages
- a standalone engine in the default `vigilyx` service
- an optional embedded engine inside `vigilyx-mta`
- 17 built-in detection modules, 3 external-service modules, and a verdict sink
- a React frontend and axum API running from the same primary service container
