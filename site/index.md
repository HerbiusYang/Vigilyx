---
layout: home

title: Vigilyx
titleTemplate: Rust-Powered Email Security Gateway
description: Rust-powered email security gateway and analysis platform for passive mirror monitoring, inline MTA inspection, threat detection, and audit workflows.

hero:
  name: Vigilyx
  text: Rust-powered email security gateway and analysis platform
  tagline: Built for passive mirror traffic monitoring and inline SMTP inspection. Useful if you are looking for an email security gateway, SMTP proxy, or 邮件安全分析平台 in one stack.
  actions:
    - theme: brand
      text: Quick Start
      link: /docs/quick-start
    - theme: alt
      text: Deployment Modes
      link: /docs/deployment
    - theme: alt
      text: GitHub
      link: https://github.com/HerbiusYang/Vigilyx

features:
  - title: Mirror mode
    details: Capture SMTP, POP3, IMAP, and webmail traffic without changing the existing mail system. Analyze sessions after delivery for detection, alerting, and audit.
  - title: Inline MTA mode
    details: Run as an SMTP relay before final delivery. Accept, quarantine, or reject mail with sub-8 second inline verdict paths and configurable fail-open behavior.
  - title: Engineering-first security
    details: Multi-module detection pipeline, evidence fusion, DLP, YARA, automation, and explainable verdict flows. AI is optional, not a hard dependency.
  - title: Rust core
    details: Packet capture, parsing, detection, API, and MTA logic are built around a Rust-first codebase designed for operational safety and performance.
---

## Why Vigilyx

Vigilyx is an open source email security platform for teams that want a controllable and auditable detection stack instead of a black-box gateway. It supports both passive analysis and inline SMTP relay workflows in the same project.

## Who it is for

- Security engineers building an internal email security gateway
- Analysts doing email traffic analysis or forensic review
- SOC teams that want alerting, quarantine, and audit workflows
- Rust developers interested in building real-world security systems

## What ships today

- SMTP and MIME parsing
- Session capture and reconstruction
- Multi-module threat detection pipeline
- Evidence fusion and verdicting
- Attachment, link, and content analysis
- YARA and DLP scanning
- React dashboard and audit workflows
- Inline MTA quarantine and rejection paths
