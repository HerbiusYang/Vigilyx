---
layout: home

title: Vigilyx
titleTemplate: Rust-Powered Email Security Gateway
description: Rust-powered email security gateway and analysis platform built to financial-industry security standards — passive mirror monitoring, inline MTA inspection, threat detection, and audit workflows.

hero:
  name: Vigilyx
  text: Email security gateway built to financial-industry security standards.
  tagline: Open source, Rust-powered, explainable. Engineered against banking-grade security requirements — observe traffic in mirror mode, then move to inline SMTP decisions without swapping out the detection stack or trusting a black box.
  actions:
    - theme: brand
      text: Quick Start
      link: /docs/quick-start
    - theme: alt
      text: Architecture
      link: /docs/architecture
    - theme: alt
      text: Deployment Modes
      link: /docs/deployment

features:
  - title: Passive mirror monitoring
    details: Capture SMTP, POP3, IMAP, and webmail traffic without changing the existing mail system. Analyze sessions after delivery for detection, alerting, and audit.
  - title: Inline MTA verdicts
    details: Run as an SMTP relay before final delivery. Accept, quarantine, or reject mail with sub-8 second inline verdict paths and configurable fail-open behavior.
  - title: Explainable detection stack
    details: Multi-module detection pipeline, evidence fusion, DLP, YARA, automation, and verdict flows that are designed to be replayed and tuned over time.
  - title: Rust-first operations
    details: Packet capture, parsing, detection, API, and MTA logic are built around a Rust core optimized for operational safety, performance, and deployability.
---

<HomeLanding locale="en" />
