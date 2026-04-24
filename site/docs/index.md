---
title: Overview
description: Product overview for Vigilyx, including mirror mode, MTA proxy mode, and the core detection pipeline.
---

# Overview

Vigilyx is a Rust-powered email security gateway and analysis platform. It supports two operating modes:

- **Mirror mode**: passive traffic capture, analysis, alerting, and audit after delivery
- **MTA proxy mode**: inline SMTP relay with accept, quarantine, and reject decisions before delivery

The project is designed as an engineering-oriented security system:

- Verdicts should be explainable
- Rules and fusion logic should be easy to iterate
- False positives and misses should be traceable
- The system should still work when AI is disabled

## Core capabilities

- SMTP and MIME parsing
- Passive session reconstruction
- Inline MTA inspection
- Multi-module threat detection
- DLP and YARA
- Attachment and link analysis
- Automated response and alerting
- Web dashboard and audit workflow

## Source code

- Repository: [HerbiusYang/Vigilyx](https://github.com/HerbiusYang/Vigilyx)
- License: `AGPL-3.0-only`

## Next pages

- [Features](/docs/features)
- [Quick Start](/docs/quick-start)
- [Deployment](/docs/deployment)
- [Architecture](/docs/architecture)
