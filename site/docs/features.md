---
title: Features
description: Core product capabilities of Vigilyx across mirror deployments, inline MTA inspection, detection, response, and operator workflows.
---

# Features

Vigilyx is built as an engineering-oriented email security platform. The feature set is organized around deployment flexibility, explainable detection, operational response, and long-term maintainability.

## Deployment shapes

- **Mirror mode**: passively capture SMTP, POP3, IMAP, and webmail traffic without changing the existing mail path
- **Inline MTA proxy mode**: accept, quarantine, relay, or reject mail before delivery
- **Shared detection stack**: the same parsing, detection, and verdict logic can run behind both topologies
- **Optional AI sidecar**: NLP enrichment is available, but the Rust core still works when AI is disabled

## Parsing and session analysis

- SMTP and MIME parsing
- Passive mail-session reconstruction from captured traffic
- Attachment extraction and metadata normalization
- Header, HTML, link, and attachment context building
- Reusable parsing logic shared by the sniffer and the MTA proxy

## Detection pipeline

- Multi-module threat analysis pipeline
- Header, content, semantic, link, reputation, MIME, HTML, and anomaly modules
- Attachment heuristics and hash-based detection
- YARA scanning for messages and attachments
- DLP checks for sensitive data and data-security workflows
- Verdict fusion with explainable, reviewable scoring

## Response and enforcement

- Risk levels from safe to critical
- Inline accept / quarantine / reject behavior in MTA mode
- Quarantine management and release workflows
- Alerting, webhooks, and automated response hooks
- Audit-oriented session and verdict history for analysts

## Operations and product surface

- Real-time React dashboard
- REST API and WebSocket updates
- Docker Compose deployment for mirror and MTA topologies
- Remote-first `deploy.sh` workflow for fast developer packaging and production releases
- Bilingual public docs and GitHub Pages project site

## Design priorities

- Explainable verdicts instead of black-box-only scoring
- Clear separation between control plane and traffic-processing data planes
- Practical deployment on CPU-only infrastructure
- Rules, IOCs, and fusion behavior that can be iterated over time

## Related pages

- [Overview](/docs/)
- [Quick Start](/docs/quick-start)
- [Deployment](/docs/deployment)
- [Architecture](/docs/architecture)
