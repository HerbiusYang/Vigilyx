---
title: Features
description: Vigilyx capabilities across passive capture, inline MTA inspection, detection, data security, response, and operations.
---

# Features

Vigilyx shares its training mail as [VIGILYX-Training-Data](https://github.com/HerbiusYang/VIGILYX-Training-Data) (MIT). The current `data/corpus.json` has 5,438 records (4,537 malicious, 901 benign). See [Training corpus](/docs/training-data).

Vigilyx combines mail-session capture, MIME parsing, analysis modules, evidence fusion, quarantine workflows, and deployment tooling in one open-source project. Operators can inspect and extend the rules, then choose passive mirror monitoring or inline SMTP inspection to fit their mail path.

## At a glance

| Capability | What Vigilyx does |
| --- | --- |
| Passive mirror monitoring | Uses libpcap in `vigilyx-sniffer` to capture SMTP, POP3, and IMAP without changing the existing mail path. HTTP/Webmail capture requires a non-empty Webmail list in the API response; the standard API default is empty, so configure it through the UI/API. |
| Inline MTA proxy | Runs `vigilyx-mta` as an SMTP relay, inspecting mail before delivery and relaying, quarantining, rejecting, or temporarily failing according to policy. |
| Shared analysis stack | Sniffer and MTA share `vigilyx-parser`, `vigilyx-engine`, and verdict logic. |
| Explainable verdicts | Modules produce threat level, confidence, category, and evidence for review and evidence fusion. |
| Data security | HTTP/Webmail DLP, draft-abuse and chunked-upload analysis, self-send/file-transit detection, JR/T 0197-2020 mapping, and separate SMTP outbound-email reviews. |
| Privacy access | Content masking, independent audit approval, and short-lived resource/scoped access leases. |
| Self-hosted deployment | Uses Docker Compose under AGPL-3.0-only; AI, ClamAV, and sandbox integrations are optional. |

## Deployment modes

### Passive mirror mode

Mirror mode observes traffic from a network mirror port or host interface, reconstructs mail and Webmail sessions, and sends them through Redis Streams to the dedicated engine.

- Does not require changes to the existing MX, MTA, or business mail-server configuration
- Captures SMTP, POP3, and IMAP traffic; HTTP/Webmail capture is disabled while the configured Webmail server list is empty
- SMTP content can be reconstructed when inspectable; POP3/IMAP currently provide protocol metadata and coverage signals, not reconstructed mail-content analysis. Encrypted or incomplete payloads remain coverage gaps.
- In the standard Compose deployment, use the UI/API to configure HTTP capture; the API returns saved settings or built-in defaults that override matching sniffer environment values, and the default Webmail list is empty
- Successfully published messages that remain in the Stream are processed by consumer groups with at-least-once semantics; exhausted publish retries and `MAXLEN` trimming can still lose messages
- Single, batch, and quarantine-release rescan requests use Streams; Pub/Sub carries reload commands and verdict/status notifications
- PostgreSQL stores sessions, verdicts, YARA rules, quarantine records, and data-security events

### Inline MTA proxy mode

MTA mode makes SMTP decisions before final delivery. On port 25, `vigilyx-mta` sends the SMTP greeting and EHLO response, then negotiates STARTTLS according to policy. Port 465 starts implicit TLS immediately after connection. The proxy parses MIME, runs the inline engine, and then relays, quarantines, rejects, or returns a temporary failure.

- Supports ports 25 and 465 and a configured local-domain list
- `MTA_INLINE_TIMEOUT_SECS` controls the inline verdict timeout; the compiled and Compose defaults are 8 seconds
- `MTA_FAIL_OPEN` controls whether an engine failure returns SMTP 451 or attempts relay; outbound DLP can still quarantine or block
- The current code defaults to quarantine from Medium and reject from Critical with `550 5.7.1`; these thresholds are not environment variables
- Only fully inspected Safe/Low messages are relayed by the default policy. A completed Safe/Low verdict with incomplete coverage is quarantined; blocking module failures/timeouts or unavailable required dependencies return 451 by default, with fail-open optionally attempting relay. Outbound DLP scans for audit, but enforcement applies only to messages whose delivery plan would relay; it can alert, quarantine, or block those relay candidates.
- Final actions also depend on the active DLP policy, engine availability, and persisted runtime configuration
- Quarantined messages retain the raw EML and can later be released, deleted, and audited through the console or API

## Parsing and session reconstruction

The parsing layer is shared by the sniffer, MTA, and engine.

- `vigilyx-parser` handles SMTP state, MIME, body, attachment, and header parsing
- `vigilyx-sniffer` manages TCP sessions and passive protocol identification
- `vigilyx-mta` uses the same parser to construct an `EmailSession` for pre-delivery checks
- The engine processes both `EmailSession` and `HttpSession`
- Attachments can enter type identification, content heuristics, hash, QR, and YARA modules; antivirus runs only when ClamAV is enabled and reachable
- HTML analysis includes hidden elements, CSS cloaking, pixel-art patterns, iframes, redirects, and landing-page analysis

Passive and inline mail use the shared `EmailSession` and mail `SecurityVerdict` models. Webmail HTTP uploads and downloads use separate `HttpSession` and `DataSecurityIncident` models and data-security tables; they do not write into the mail-verdict storage path.

## Detection pipeline

The compiled default order currently contains 29 pipeline entries, including the final `verdict` stage and entries that need an external service or explicit opt-in. PostgreSQL's active configuration can override code defaults; a configured entry does not mean its external service is available.

| Module | Focus |
| --- | --- |
| `header_scan` | Sender spoofing, SPF/DMARC/Received chains, and header IOCs |
| `content_scan` | Financial, password, urgency, phishing-language, and configurable keyword clues |
| `semantic_scan` | Local semantic rules, optional CPU ONNX intent ensemble, and optional Python NLP |
| `link_scan` | Shorteners, IDNs, homoglyphs, suspicious parameters, and URL structure |
| `link_reputation` | OTX, VirusTotal, AbuseIPDB, and the local IOC cache |
| `link_content` | DGA, brand impersonation, mixed-script domains, and login lures |
| `landing_page_scan` | Landing-page content, forms, credential prompts, and redirect risk |
| `url_sandbox_scan` | Deferred dynamic URL analysis; disabled by default and not used for inline MTA verdicts |
| `process_sandbox_scan` | Opt-in bounded observations in a separate worker; no independent threat verdict, kernel isolation pending |
| `aitm_detect` | Adversary-in-the-middle reverse-proxy phishing patterns, including Evilginx, Tycoon2FA, and EvilProxy |
| `rmm_detect` | Remote-management-tool language, links, and payload clues |
| `prompt_injection_scan` | Prompt-injection-style instructions in message content |
| `toad_detect` | Attack-delivery clues centered on callback phone numbers |
| `html_scan` | HTML obfuscation, hidden elements, zero-width characters, and CSS deception |
| `html_pixel_art` | QR-like HTML tables/pixel art, tracking pixels, and hidden iframes |
| `mime_scan` | MIME anomalies, header injection, boundaries, and content declarations |
| `attach_scan` | Extension and magic-byte mismatches and executable masquerading |
| `attach_content` | Macro, script, archive, and sensitive-content lures |
| `attach_qr_scan` | QR phishing entry points in attachments and images |
| `attach_hash` | Attachment SHA-256 matches against malicious samples and IOCs |
| `yara_scan` | Built-in and database-backed YARA rules over EML and attachments |
| `domain_verify` | Alignment across envelope, DKIM, link domains, and trusted domains |
| `identity_anomaly` | First contact, sender-identity drift, and communication-history anomalies |
| `transaction_correlation` | Cross-session business-process and fraud-chain correlation |
| `anomaly_detect` | Statistical anomalies |
| `verdict` | Combines module evidence into a final risk level and response recommendation |

ClamAV can register `av_eml_scan` and `av_attach_scan`. `sandbox_scan` is registered only when both the CAPEv2 URL and token are configured. With AI disabled, `semantic_scan` provides no remote NLP evidence while the other Rust detection modules can still run. The default order is in `crates/vigilyx-engine/src/pipeline/config.rs`; module registration is in `crates/vigilyx-engine/src/modules/registry.rs`.

### Semantic model modes

Local semantic rules run without the Python AI service. With valid
`SEMANTIC_INTENT_MODEL_DIR` and `ORT_DYLIB_PATH` artifacts, the engine can also
run a bge/e5 ONNX ensemble on CPU. It records `semantic_intent_model` diagnostics
in shadow mode by default. A valid `SEMANTIC_INTENT_SCORE_THRESHOLD` explicitly
switches to scored mode, replacing the local semantic-rule and later Python
NLP/OCR path. A threshold hit is a review signal in fusion, not a final verdict or action. Model load failures disable the model
with a warning; incomplete checks remain coverage gaps. Current Compose model
wiring is on the mirror engine and requires separate setup for MTA.

## Evidence fusion and temporal analysis

A verdict retains module evidence and causal provenance through fusion, risk constraints, and the final mode-dependent disposition.

- The default runtime strategy is `clustered_ds_v2`; historical `ds_murphy`, `clustered_ds_v1`, and `legacy_ds_murphy` configuration names normalize to it
- Explicit alternative strategies are TBM (`tbm_v5`), Noisy-OR, and Weighted Max
- Evidence, category, confidence, and match reasons are retained for analyst review
- Runtime evidence preserves causal keys so repeated views of the same artifact can be deduplicated
- Temporal analysis includes CUSUM, EWMA, Hawkes self-excitation, HMM attack-phase modeling, and communication-graph features

Learned D-S parameters have a separate candidate, acceptance, install, and rollback workflow; feedback or training does not automatically activate a model. A risk level is detector output, not proof that a message is malicious. Validate local samples, thresholds, and response policy before relying on it operationally.

## AiTM, HTML, and YARA analysis

- The AiTM module produces evidence from clues such as hosted-platform domains, authentication paths, OAuth redirects, MFA/CAPTCHA language, and brand homoglyphs
- HTML modules analyze hidden forms, CSS hiding, zero-width characters, suspicious iframes, and tracking pixels
- `html_pixel_art` analyzes graphical patterns built from HTML tables or pixels; `attach_qr_scan` handles QR codes in attachments and embedded images
- YARA loads built-in rules, administrator-managed database rules, and explicitly configured governed rule packs; rule counts vary by version and runtime configuration
- YARA scans raw EML, body excerpts, and attachment bytes; a single match should be reviewed alongside rule provenance and other evidence

## DLP and data security

Data security covers HTTP/Webmail incidents and separate SMTP outbound-email reviews. Both remain separate from email threat verdict labels.

- Auditable pattern families cover general sensitive data and JR/T 0197-2020 mappings; their exact count depends on the source and seed data
- Scanning uses a 512 KiB window, 256-byte overlap, a 50 MiB total-input cap, and a 10-second budget, with UTF-8 boundary handling
- Webmail form extraction includes support for Coremail
- `chunked_upload` reassembles chunks using composeId, attachmentId, and offset
- `draft_detect` identifies sensitive-data staging through draft folders
- `self_send_detect` identifies self-send patterns that can bypass outbound auditing
- `file_transit_detect` identifies data-transit paths involving attachments, downloads, and forwarding
- `jrt_compliance` counts cumulative C3/C4 sensitive-data triggers per user/IP over 24 hours

HTTP capture requires a non-empty Webmail server list in the API response. At startup, the sniffer loads the saved PostgreSQL configuration or API defaults; returned fields override matching environment values (a non-empty API port list replaces the environment port list).

### SMTP outbound reviews

Mirror mode audits inspectable mail and cannot block or quarantine it. MTA
outbound DLP can alert, quarantine, or block messages whose delivery plan would
otherwise relay. Direction uses trusted source/domain/recipient evidence; a
local-looking `MAIL FROM` alone does not establish an outbound message.
Encrypted traffic, unknown direction, incomplete payloads, and failed checks
remain explicit unknowns. List, statistics, and detail routes are
`GET /api/data-security/email-reviews`, `GET /api/data-security/email-reviews/stats`,
and `GET /api/data-security/email-reviews/{id}`.

## Privacy and temporary content access

Privacy mode masks content by default while leaving security analysis visible.
An administrator requests a resource, scopes, and purpose using their configured
verification factor. An independent audit user approves or rejects with a
separate factor. The requester then obtains a lease bound to their user, JWT
session, exact resource, and scopes. Requested lifetimes are bounded to 60–300
seconds; a lease lasts at most five minutes.

Use System Settings → Privacy to manage the policy and access requests. The
policy API is `GET/PUT /api/config/privacy`; requests use
`GET/POST /api/privacy/access-requests` with per-request approve, reject, revoke,
and lease routes. Missing or unreadable policy defaults to masking. Credentials
remain masked even with privacy disabled, and previously redacted persisted
review evidence cannot be reconstructed by changing the policy.

## Quarantine, SOAR, and audit

Response paths combine automated actions and analyst review.

- Risk levels range from Safe, Low, Medium, High, to Critical; they are risk bands, not proof of maliciousness
- MTA mode quarantines or rejects according to active policy; verify persisted configuration before deployment
- Quarantine supports listing, statistics, release, deletion, and raw EML retention
- Before release, the API rescans the exact stored raw EML through the engine; a High or Critical verdict blocks release
- If the engine, rescan channel, parsing, or timeout prevents a fresh verdict, release fails closed and the entry returns to quarantine; delivery failures also roll back the release state
- SOAR supports alert dispatch, email notifications, webhooks, and disposition rules
- The API and WebSocket provide the console with live verdicts, session details, and system status

## Operations and engineering workflow

The project uses a remote-first workflow and can run as a full stack on Rocky Linux or as profile-selected services.

- `./deploy.sh` uses `release-fast` and the persistent `vigilyx-rust-builder` for incremental day-to-day builds
- `./deploy.sh --production` uses the full Dockerfiles and `cargo --release`
- `--frontend`, `--backend`, `--sniffer`, and `--mta` update selected components
- The React SPA is packaged in the `vigilyx` image so each image tag contains a known frontend version
- The API binds to `127.0.0.1:8088` by default; terminate TLS with Caddy or Nginx in production
- AI, ClamAV, sandbox, and TLS reverse proxy are enabled through Compose profiles and matching configuration
- Core services do not require a network license; external intelligence feeds and AI can be disabled per environment

Compose profiles do not automatically stop services started under another profile. Use the deployment helper when changing topology on a running host.

Every deployment except initialization-only `--init`, including `--frontend`,
briefly stops running API, engine, sniffer, and MTA services before dependency
and database-role reconciliation, then restores their running state even on failure. Plan a
maintenance window for packet capture and inline SMTP interruption.
Schema migration requires a newly built API binary: backend/full deployments
or production frontend builds. Fast frontend, sniffer-only, and config-only
deployments preserve installed SQL functions. Verification also checks effective
PostgreSQL settings and mirror consumer lag; deployment does not tune host/network settings.

## Code locations

| Capability | Main source paths |
| --- | --- |
| SMTP/MIME parsing | `crates/vigilyx-parser/` |
| Passive capture and session management | `crates/vigilyx-sniffer/src/capture/`, `crates/vigilyx-sniffer/src/session/` |
| Detection module registry | `crates/vigilyx-engine/src/modules/registry.rs` |
| Inline verdict path | `crates/vigilyx-engine/src/pipeline/engine.rs` |
| MTA proxy | `crates/vigilyx-mta/src/server/`, `crates/vigilyx-mta/src/relay/` |
| AiTM detection | `crates/vigilyx-engine/src/modules/aitm_detect.rs` |
| HTML pixel-art detection | `crates/vigilyx-engine/src/modules/html_pixel_art.rs` |
| YARA engine and rules | `crates/vigilyx-engine/src/yara/`, `crates/vigilyx-db/src/security/yara.rs` |
| DLP and data security | `crates/vigilyx-engine/src/data_security/` |
| Quarantine API | `crates/vigilyx-api/src/handlers/security/quarantine.rs` |
| Security tables and indexes | `crates/vigilyx-db/src/security/migrate.rs` |

## Related pages

- [Quick Start](/docs/quick-start)
- [Deployment](/docs/deployment)
- [Architecture](/docs/architecture)
- [Email Threat Knowledge](/docs/knowledge/)
