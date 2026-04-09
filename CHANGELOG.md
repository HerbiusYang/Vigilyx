# Changelog

All notable changes to Vigilyx are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the project follows [Semantic Versioning](https://semver.org/).

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
