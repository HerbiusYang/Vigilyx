# Changelog

All notable changes to Vigilyx are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.3] - 2026-08-16

### Added

- **Alert center (P0–P3 pipeline now end-to-end)**: `security_alerts` records are finally exposed — new `GET /api/security/alerts` (with `acknowledged`/`alert_level` filters) and `POST /api/security/alerts/{id}/acknowledge` endpoints, the `Alert` WebSocket message is forwarded by the frontend, and a new Alert Center page (`/alerts`) lists, filters and acknowledges alerts. SOAR disposition `alert`/`log` actions now also persist into `security_alerts` instead of only logging a line
- **Verdict threshold UI**: the pipeline settings tab now edits the DS-fusion thresholds (`alert_floor_factor`, `convergence_base_floor`, `convergence_belief_threshold`, etc.) through the existing `PUT /api/security/pipeline` endpoint — the psql manual-edit workflow is no longer needed for these values
- **MTA verdict metrics**: `vigilyx-mta` now counts accepted/quarantined/rejected/timeout decisions and reports them to the API every 5 s (`POST /api/system/mta`, new `MTA_API_HOST`/`MTA_API_PORT` env vars); the deployment settings page shows the decision distribution instead of only online/connection state
- **LLM second opinion**: when the local NLP model's malicious probability falls in the uncertain band (0.3–0.7), the AI service optionally asks the configured Claude/OpenAI-compatible LLM for a second opinion (20 s hard timeout, fail-open to the local result); the security analysis view shows the LLM card alongside the NLP probability bars. The LLM provider/key/model configured in the AI settings tab are now actually consumed by the engine
- **NLP probability visualisation**: the reserved `.sa-nlp-*` styles are now backed by a real probability-bar component reading `details.nlp_details.probabilities`

### Removed

- NTP settings UI (was decorative — no backend consumer existed)
- Dead code on both sides of the AI boundary: Rust `analyze_attachment`/`analyze_link` client methods and the Python `update-base-model` endpoint (neither had callers)

### Changed

- Upgraded the Rust toolchain from 1.95.0 to 1.97.1 across `rust-toolchain.toml`, all Dockerfiles (digest-pinned `rust:1.97.1-bookworm`), the persistent builder container (`setup-builder.sh`), and CI

### Security

- **Engine crash via single crafted email (Critical)**: removed `panic = "abort"` from the release profiles and fixed 5 untrusted-string byte-slice panic sites (`link_scan` redirect/token evidence truncation, `link_content` URL truncation, `domain_verify` private RFC2047 decoder — the decoder was deleted in favour of `vigilyx_parser::mime::decode_rfc2047`); module execution in the pipeline orchestrator is now wrapped in `catch_unwind` so a panicking module produces a `MODULE_EXECUTION_FAILED` result instead of hanging the pipeline for 90 s or aborting the process
- **Sniffer silent-disable via malformed IMAP (High)**: `STATUS`/`FETCH` commands without arguments panicked the capture worker, permanently dropping every 5-tuple hashed to it; all catch_unwind sites in the capture path now log and `exit(1)` so Docker restarts the process instead of leaving it "alive but blind"
- **Unauthenticated memory DoS via Prometheus labels**: metrics middleware now labels by axum `MatchedPath` route template; unmatched paths are recorded as `:unmatched` instead of attacker-controlled path segments
- **Unauthenticated login lockout via spoofed `X-Forwarded-For`**: ambiguous XFF chains now resolve to the rightmost untrusted hop (the peer the trusted proxy actually saw), and the generated Caddyfile overwrites inbound XFF with `header_up X-Forwarded-For {remote_host}`
- **IOC false-positive amplification**: `auto_record_impersonation_domain` now requires a verdict of High or above before writing auto IOCs (domain/email/IP), matching the project's IOC gating rule
- **AI model tampering boundary**: AI model directory moved to a dedicated `vigilyx_models` volume instead of the shared `vigilyx_data` volume; base-model downloads support `HF_BASE_MODEL_REVISION` pinning; inference and VT-scrape concurrency are now bounded (`AI_MAX_CONCURRENCY`, `AI_VT_MAX_CONCURRENCY`); `/health` `last_error` output is path-sanitised and truncated
- **Kubernetes sandbox manifest**: pinned the third-party sandbox image by digest, removed the invalid `volumeClaimTemplates`, and added the missing `storage` volume
- **Zero-auth pcap stream**: `email-capture.sh` now refuses to bind a non-loopback address unless `ALLOW_REMOTE_CAPTURE=1` is set, with warnings recommending an SSH tunnel/stunnel for remote capture
- Redis password no longer appears on the container command line (generated `/tmp/valkey.conf` via `valkey-entrypoint.sh`); control-plane command tokens use constant-time comparison; MTA downstream error text is sanitised before being echoed into SMTP replies; `MTA_FAIL_OPEN` defaults are consistently fail-closed (`false`) across code, Dockerfiles, and compose
- Public readiness endpoint caches its DB/Redis fan-out for 3 s; gateway-wrapped URLs only skip structural checks when the inner target was successfully unwrapped; IDN homograph detection now covers pure-Cyrillic and fullwidth-Latin brand spoofs; YARA scanning enforces a per-email total time budget (15 s) in addition to the per-file timeout
- Supply chain: base images and service images pinned by digest (`rust`, `node`, `postgres`, `valkey`, `caddy`), `cargo-chef` pinned to 0.1.77, TLS self-signed certs reduced to 397 days, CI workflow granted `contents: read` only, frontend `react-router-dom` upgraded to 7.18.2 plus non-major `npm audit fix` (postcss/undici/@babel); the inline theme bootstrap script moved to an external file and `'unsafe-inline'` removed from the meta CSP

## [0.9.2] - 2026-04-29

### Added

- Multilingual phrase seed expansion: 77 lists / ~5300 entries across 10 languages (EN/ZH/JA/KO/RU/ES/PT/FR/DE/AR) for MFA bait, prompt injection, account-security phishing, subsidy fraud, AiTM lures, and related detectors
- High-throughput multi-pattern matcher (`vigilyx-engine::matcher`) backed by Aho-Corasick with a process-wide `OnceLock` cache and epoch-versioned hot reload; replaces naive `phrases.iter().any(contains)` scans on the security pipeline hot path (now `O(n + matches)` instead of `O(haystack × patterns × pattern_len)`)
- Unicode-aware brand keyword boundary detection in `aitm_detect` to prevent short brand names (`line`, `abc`, `box`, …) from substring-matching unrelated alphanumeric runs across ASCII, CJK, Cyrillic, Greek, and Arabic neighbours
- Comprehensive new test coverage (≈20 new tests across `matcher`, `aitm_detect`, and seed coverage gates) — full workspace now at **1993 passed / 0 failed / 6 ignored**

### Changed

- Refactored 7 detection modules (`prompt_injection_scan`, `aitm_detect`, `content_scan::detectors`, `transaction_correlation`, `rmm_detect`, `toad_detect`, `html_scan`, `link_content`) to route 18+ substring-scan call sites through the shared phrase matcher; removed redundant per-module `find_substring_match` / `first_pattern_hit` helpers
- Enabled `gzip` feature on `reqwest` so the URL fetcher enforces decoded-body size limits correctly when upstream responses are compressed
- Refreshed release metadata and UI version strings to `0.9.2`

### Fixed

- Brand-impersonation false positive where the LINE messenger brand `"line"` matched the substring inside `microsoftonline.com`
- URL fetcher decoded-response size enforcement test that silently passed because gzip decoding was not enabled
- Test isolation: `ModuleDataRegistry::replace_list_for_test` now allows hot-reload assertions without polluting parallel tests that depend on neighbouring registry lists

## [0.9.1] - 2026-04-21

### Changed

- Pinned the frontend toolchain to `Node 24.15.0` and `npm 11.12.1` across local development, CI, remote deploys, and production Docker builds
- Added frontend toolchain verification and containerized frontend builds in `deploy.sh` so remote deployments no longer depend on the host Node.js version
- Refreshed release metadata and UI version strings to `0.9.1`

## [0.9.0] - 2026-03-31

Initial open-source release.

### Core Platform

- Dual acquisition paths: passive mirror capture and inline MTA proxy mode
- Passive network capture for SMTP, POP3, IMAP, and HTTP traffic using libpcap
- Shared SMTP and MIME parsing in `vigilyx-parser` for both passive capture and MTA mode
- Event-driven DAG orchestration for detection modules
- PostgreSQL 17 persistence with migrations and operational indexes
- Valkey / Redis Streams plus Pub/Sub for transport, notifications, and control signals
- Docker Compose deployment with mirror, MTA, AI, antivirus, sandbox, and TLS profiles

### Detection Engine

- 20 detection modules in total
- 17 built-in detection modules: `header_scan`, `content_scan`, `semantic_scan`, `link_scan`, `link_reputation`, `link_content`, `attach_scan`, `attach_content`, `attach_hash`, `yara_scan`, `domain_verify`, `identity_anomaly`, `html_scan`, `html_pixel_art`, `mime_scan`, `transaction_correlation`, `anomaly_detect`
- 3 external-service modules: `av_attach_scan`, `av_eml_scan`, `sandbox_scan`
- Verdict fusion strategies: `ds_murphy`, `tbm_v5`, `noisy_or`, and `weighted_max`
- Circuit breakers and convergence boosting to prevent threat dilution
- Threat intel federation across OTX, VirusTotal, and AbuseIPDB with a local IOC cache
- Zero-shot NLP phishing detection with optional fine-tuned models
- Temporal anomaly analysis with CUSUM, EWMA, Hawkes process, and HMM-based modeling

### Data Security

- 30 DLP patterns including PII, financial, medical, and JR/T 0197-2020 mappings
- HTTP session analysis for webmail exfiltration detection
- Draft-box abuse, file transit abuse, self-send, and chunked upload handling

### API and Frontend

- REST API built on axum with JWT authentication and Prometheus metrics
- WebSocket real-time push with one-time ticket authentication
- React 18 SPA for dashboard, email security, data security, automation, knowledge, and settings
- Default `vigilyx` runtime packs API, frontend assets, and the standalone engine in one service

### SOAR

- Alert dispatch with configurable severity thresholds
- Email alert notifications over SMTP / STARTTLS
- Webhook integration
- Disposition rules and response workflows

### Security Hardening

- Argon2 password hashing with forced password change on first login
- Per-IP login rate limiting
- Constant-time internal service token comparison
- CSP headers and SSRF protection on connection-test endpoints
- Error masking that keeps internal details server-side only
- Non-root Docker containers
- Redis authentication with localhost-only binding
- Host-level or bundled TLS support via Caddy or Nginx

### Infrastructure

- `scripts/generate-secrets.sh` for automated secret generation
- Fast developer builds via the `release-fast` profile
- Explicit production release path via `./deploy.sh --production`
- Production image builds via the `release` profile and full Dockerfiles
- More than 1,400 automated tests with a zero-warning clippy policy
- GitHub Actions CI for Rust checks, frontend type-checking, and Vite production builds

### Documentation and Release Readiness

- Public-facing documentation aligned to the current runtime topology and deployment model
- Public markdown and `docs/` content standardized to English
- Deployment guidance updated to distinguish fast developer deploys from production release builds
- Architecture documentation corrected to reflect PostgreSQL persistence, Redis Streams plus Pub/Sub transport, and current module grouping
- GitHub issue templates and pull request template included for open-source release
