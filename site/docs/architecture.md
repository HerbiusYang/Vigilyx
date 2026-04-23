---
title: Architecture
description: High-level architecture of Vigilyx, including sniffer, engine, database, API, frontend, SOAR, and the inline MTA path.
---

# Architecture

## Main components

```text
Sniffer -> Redis Streams -> Engine -> PostgreSQL -> API/WebSocket -> Frontend
```

The project is split into focused Rust crates plus a React frontend and optional Python AI service.

## Core crates

- `vigilyx-core`: shared models, error types, security primitives
- `vigilyx-parser`: SMTP, MIME, and protocol parsing
- `vigilyx-sniffer`: packet capture and passive session publishing
- `vigilyx-db`: PostgreSQL and Redis abstractions
- `vigilyx-engine`: detection modules, verdict fusion, DLP, temporal analysis
- `vigilyx-api`: REST API, auth, metrics, WebSocket updates
- `vigilyx-soar`: alerting and response automation
- `vigilyx-mta`: SMTP proxy with embedded inline engine

## Mirror path

In mirror mode, the sniffer captures network traffic and reconstructs sessions. Those sessions move through Redis Streams into the engine, which persists results to PostgreSQL and exposes them through the API and dashboard.

## Inline path

In MTA mode, the SMTP proxy accepts mail, parses the message, runs inline inspection, and then decides whether to relay, quarantine, or reject.

## Design principles

- Engineering-first, not AI-first
- Explainable verdicts
- Replayable and auditable workflows
- Clear separation between capture, analysis, storage, and UI
- Shared parsing and detection logic across mirror and MTA paths

## Related documents

- [Overview](/docs/)
- [Quick Start](/docs/quick-start)
- [Deployment](/docs/deployment)
