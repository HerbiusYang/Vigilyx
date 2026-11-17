---
title: Releases
description: Release notes for Vigilyx 0.9.4.
---

# Releases

Product pages describe what Vigilyx does. Behavior that belongs to 0.9.4 is on this page.

## 0.9.4 — 2026-11-13

- `clustered_ds_v2` is the default fusion strategy. The historical names `ds_murphy`, `clustered_ds_v1`, and `legacy_ds_murphy` normalize to it. Noisy-OR, Weighted Max, and TBM stay explicit alternatives.
- `semantic_scan` can run an optional CPU ONNX intent ensemble. It records shadow diagnostics unless `SEMANTIC_INTENT_SCORE_THRESHOLD` is set. A scored hit contributes a review-level Medium score of 0.40 to fusion. That score is not a final verdict and does not by itself choose an action.
- A tenant label under a hosted mailbox platform is an assigned identifier, not a random domain. The configured platforms include `wecom.work`, `onmicrosoft.com`, `onmschina.cn`, Outlook protection hosts, and the Tencent, NetEase, and Alibaba enterprise-mail hosts.
- The same brand on `.com` and `.com.cn` is not treated as the sender domain nested in an unrelated host. `lenovo.com` linking to `shop.lenovo.com.cn` is the China site. A brand string inside a different registrable domain, such as `lenovo.com.attacker.example`, still is.
- Random-domain checks use the registrable label. A short label that still contains a vowel is not marked DGA from a consonant run alone. A vowel-less short label that is not a pinyin-initial abbreviation still is.
- A public announcement on a Chinese institutional suffix, and a download that stays on the sender's own organization, is not an external action-link lure. A password or account request on that link still is.
- A running verdict summary counts the modules that actually ran. With antivirus and sandbox entries idle, that denominator is commonly 25. The compiled pipeline list still has 29 entries, including `verdict` and those optional integrations.
- MTA defaults: a completed Safe verdict is relayed, and Low is relayed only when coverage is complete. Medium and above, and Safe or Low with incomplete coverage, are quarantined. Critical is rejected with `550 5.7.1` and is not forwarded. Only a relay is sent downstream. `MTA_FAIL_OPEN` defaults to false, so an unavailable inline verdict returns `451 4.7.1`.
- SMTP outbound data-security review is separate from the threat verdict. Mirror mode audits inspectable mail. The MTA can enforce outbound DLP on messages that would otherwise be relayed.
- Privacy mode, short access leases, and an independent audit account are part of this release. Learned D-S parameters have an explicit install and rollback path. Training does not turn a candidate model on.
- The Rust toolchain for this release is 1.98.0. Upgrade and recovery steps are on [Updating and recovery](/docs/updating).
