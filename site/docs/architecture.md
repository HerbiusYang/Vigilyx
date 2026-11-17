---
title: Architecture
description: High-level architecture of Vigilyx, including sniffer, engine, database, API, frontend, SOAR, and the inline MTA path.
---

# Architecture

Mail enters on one of two paths. Detection is the same engine either way. Mirror watches. Inline decides before delivery. Verdicts, evidence, and audit land in one console.

<ArchitectureFlow locale="en" />

Read the diagram downward. The two top lanes are the entrances. They meet in one engine. Below that are storage, the console, and the four dispositions.

## Two entrances

**Mirror.** `vigilyx-sniffer` captures traffic and rebuilds the SMTP session. The session goes onto Redis Streams, and `vigilyx-engine-standalone` takes it from there. Delivery has already happened. This path sees, alerts, and audits.

**Inline.** `vigilyx-mta` accepts SMTP itself. Parsing and detection run inside the proxy, without a queue. Only then does the proxy relay, quarantine, reject, or fail temporarily. Only a relay is sent to the downstream server.

Both paths use the same parser and the same modules. Changing the deployment does not change the verdict logic.

| | Processes | Role |
| --- | --- | --- |
| Control plane | `vigilyx`, PostgreSQL, Valkey/Redis | API, UI, results, queue |
| Mirror plane | `vigilyx-sniffer`, `vigilyx-engine-standalone` | Capture and async detection |
| Inline plane | `vigilyx-mta` | Receive, detect, dispose |

## Inside the engine

The default pipeline has 29 entries in `default_modules`. Twenty-eight produce evidence. `verdict` fuses them.

| Module | What it sees |
| --- | --- |
| `content_scan` | Body rules: urgency, payment, credentials, reply-to lures |
| `html_scan` | HTML structure, hidden content, and external links |
| `html_pixel_art` | QR codes drawn as HTML tables or pixels |
| `attach_scan` | Attachment type, extension, and dangerous files |
| `attach_content` | Text inside attachments |
| `attach_qr_scan` | QR codes inside attachment images |
| `attach_hash` | Attachment hashes against known samples |
| `mime_scan` | Abnormal MIME structure |
| `header_scan` | Headers, and whether From matches Reply-To |
| `link_scan` | Shorteners, IDN, homoglyphs, suspicious parameters |
| `link_reputation` | Link-domain reputation and randomness |
| `link_content` | Lookalike hosts, DGA, and sender-domain nesting |
| `landing_page_scan` | The page behind the link |
| `anomaly_detect` | Whether this message is abnormal for the relationship |
| `aitm_detect` | Sign-in proxies that steal the session |
| `rmm_detect` | Remote-tool lures |
| `prompt_injection_scan` | Prompt injection hidden in the mail |
| `toad_detect` | Callback scams |
| `semantic_scan` | Intent. The model stays in shadow mode unless scoring is turned on |
| `domain_verify` | Whether the sender domain holds up |
| `identity_anomaly` | First contact, identity drift, tenant mailbox domains |
| `transaction_correlation` | Whether the mail fits the surrounding business thread |
| `yara_scan` | YARA rules |

Those 23 run by default. Five more are on the list and produce a result only with a predecessor or an external component:

| Module | When it runs |
| --- | --- |
| `url_sandbox_scan` | After the landing-page module |
| `process_sandbox_scan` | After the landing-page module |
| `av_eml_scan` | ClamAV is configured; scans the whole message |
| `av_attach_scan` | ClamAV is configured; scans attachments |
| `sandbox_scan` | After the attachment module, and only with CAPEv2 |

With antivirus and sandbox idle, a live verdict summary usually shows a denominator of 25. The compiled list is still 29, including `verdict` and those optional entries.

`verdict` fuses with `clustered_ds_v2`. Repeated evidence from the same source counts once, and the verdict names which check saw it.

## After the verdict

Results go to PostgreSQL. The API and WebSocket push them to the React console. SOAR sends mail or WeCom alerts when a notification is due.

Inline disposition follows the level. A completed Safe verdict is relayed, and Low is relayed only when coverage is complete. Medium starts quarantine. Critical is rejected and is not forwarded. If the engine cannot return a verdict, the default is a temporary failure, not a relay. Response codes are on the [releases](/docs/releases) page.

## Outbound data security

This is not one of the 29 threat checks. It looks for sensitive data that should not leave, such as ID numbers and bank card numbers.

The scanner lives in `vigilyx-engine`'s `data_security` module. `vigilyx-mta` runs it at disposition time. It runs only when the threat verdict would already relay the message, and the direction is outbound. It is on by default. A hit at level 3 or above is quarantined. The action can instead block the message, or allow it and raise an alert.

Mirror mode can audit mail it can already inspect. It cannot hold the message before delivery. This check does not change the threat level above.

## Where the code lives

| Crate | Role |
| --- | --- |
| `vigilyx-core` | Shared mail, level, and disposition types |
| `vigilyx-parser` | SMTP and MIME |
| `vigilyx-sniffer` | Mirror capture |
| `vigilyx-engine` | Modules, fusion, DLP, temporal analysis |
| `vigilyx-mta` | SMTP proxy and the embedded engine |
| `vigilyx-db` | PostgreSQL and Redis |
| `vigilyx-api` | REST, login, WebSocket |
| `vigilyx-soar` | Alerts |

The UI is React. Python is optional NLP and is not on the main path.

## Related documents

- [Overview](/docs/)
- [Quick Start](/docs/quick-start)
- [Deployment](/docs/deployment)
- [Releases](/docs/releases)
