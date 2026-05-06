# Changelog

All notable changes to Vigilyx are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/).

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
