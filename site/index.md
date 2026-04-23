---
layout: home

title: Vigilyx
titleTemplate: Rust-Powered Email Security Gateway
description: Rust-powered email security platform built to financial-industry security standards. Ships as two independent deployment shapes — passive mirror monitoring for visibility, or inline MTA proxy for enforcement — on the same explainable detection stack.

hero:
  name: Vigilyx
  text: Email security gateway built to financial-industry security standards.
  tagline: Open source, Rust-powered, explainable. Pick the deployment that fits the environment — observe traffic passively in mirror mode, or run as an inline SMTP proxy that accepts, quarantines, or rejects mail before delivery. Same detection stack, two independent paths, no black box.
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
  - title: Mirror deployment — passive analysis
    details: A zero-touch monitoring deployment. Vigilyx sits next to the mail system and captures SMTP, POP3, IMAP, and webmail traffic from a mirror port. Verdicts arrive after delivery, so the detection stack never blocks mail flow. Best fit for audit, forensics, tuning, and environments where the mail path cannot be touched.
  - title: MTA deployment — inline enforcement
    details: A separate deployment shape. Vigilyx runs as an SMTP relay in front of the final mail server and decides accept / quarantine / reject before delivery, with sub-2 second inline verdicts and configurable fail-open behavior. Best fit when the mail path can be reshaped and real blocking is required.
  - title: One detection stack, two deployment shapes
    details: The same multi-module pipeline (parsing, headers, content, links, attachments, YARA, DLP, identity, verdict fusion, SOAR) runs behind both deployments. Tuning, rules, IOCs, and audit trails carry over — the only thing that changes is whether verdicts are advisory (mirror) or enforcing (MTA).
  - title: Rust-first operations
    details: Packet capture, parsing, detection, API, and MTA logic are built around a Rust core optimized for operational safety, performance, and deployability.
---

<HomeLanding locale="en" />
