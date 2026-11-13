---
title: Email Threat Knowledge
description: Short, source-attributed summaries of email and identity attack patterns.
---

# Email Threat Knowledge

These entries summarize the threat patterns described by the site's knowledge cards. The source names, dates, and severity labels below come from those cards; they are pointers for further review, not a formal bibliography or a guarantee of Vigilyx detection coverage.

<KnowledgeGrid />

<a id="clickfix"></a>
## 01 · ClickFix / Fake CAPTCHA

A fake human-verification page prompts a recipient to copy and run an attacker-provided command, moving execution outside ordinary attachment handling.

- Sources listed by the card: Proofpoint, CISA, Microsoft
- Date range: 2024–2025
- Card severity: High

<a id="device-code-phishing"></a>
## 02 · Storm-2372 device-code phishing

A phishing flow abuses OAuth device authorization: the victim enters an attacker-provided code on a legitimate sign-in page, which can grant the attacker access.

- Source listed by the card: Microsoft Threat Intelligence
- Date label: February 2025
- Card severity: Critical

<a id="quishing"></a>
## 03 · Quishing / QR-code phishing

A QR image carries the phishing URL, so the destination may not be visible to controls that inspect only text links.

- Sources listed by the card: Cisco Talos, Sophos
- Date range: 2024–2025
- Card severity: High

<a id="html-text-cloaking"></a>
## 04 · HTML text cloaking and homoglyph evasion

HTML and Unicode tricks can make the rendered text differ from the text exposed to simple keyword scanning. The card highlights zero-width characters, entities, hidden elements, and lookalike characters.

- Sources listed by the card: Microsoft, Cofense, Sophos
- Date range: 2024–2025
- Card severity: High

<a id="html-smuggling"></a>
## 05 · HTML smuggling

An HTML attachment can use browser-side JavaScript and Blob URLs to reconstruct or download a payload, shifting part of delivery into the browser.

- Sources listed by the card: Microsoft, Mandiant, HP Wolf
- Date range: 2024–2025
- Card severity: Critical

<a id="aitm-phishing"></a>
## 06 · Tycoon 2FA / EvilProxy AiTM phishing

An adversary-in-the-middle proxy relays a sign-in and MFA exchange and may capture session cookies after authentication.

- Sources listed by the card: Proofpoint, Mandiant, Sekoia
- Date range: 2024–2025
- Card severity: Critical

<a id="vendor-email-compromise"></a>
## 07 · Vendor email compromise

A compromised vendor mailbox can be used to continue a real invoice conversation and request payment to a changed account. A valid sender identity alone does not establish that a payment request is legitimate.

- Sources listed by the card: FBI IC3, Abnormal Security
- Date range: 2024–2025
- Card severity: High

<a id="toad-callback-phishing"></a>
## 08 · TOAD callback phishing

A plain-text email asks the recipient to call a fake support number. The follow-up call may pressure them to install remote-management software or provide an OAuth device code.

- Sources listed by the card: Proofpoint, Cisco Talos, CISA
- Date range: 2024–2025
- Card severity: High

## Scope

These summaries describe attack patterns, not verified incidents or detection results. Review original references and validate the active deployment configuration before using any detection or response capability operationally.
