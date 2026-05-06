---
title: TOAD callback phishing (Telephone-Oriented Attack Delivery)
description: A pure-text email lures the victim into calling a fake "support" hotline; the call-centre operator then walks them through installing RMM software or reading out an OAuth device code — no attachments, no links, sandbox-proof.
---

# Case 08 — TOAD callback phishing (Telephone-Oriented Attack Delivery)

> **Public sources**: Proofpoint *Human Factor Report 2024* and ongoing 2025 tracking, Cisco Talos *Callback phishing playbooks* (2024), CISA Alert AA24-241A, Microsoft Threat Intelligence *Storm-1811 ransomware preludes* (2024-2025)

## Background

TOAD (Telephone-Oriented Attack Delivery, also called **callback phishing**) is one of the fastest-growing email attack patterns of 2024-2025. Its viciousness comes from **inverting the direction of contact**: the email itself is just a plain-text notification — the only suspicious thing is a toll-free customer-service number. **The victim places the call themselves.** From that moment on, the attacker is in full control.

The "agent" on the other end follows a tight script (many gangs operate call centres in Southeast Asia or Eastern Europe at scale). Their goal is usually one of:

- **Remote takeover** — walk the victim through installing ScreenConnect / AnyDesk / TeamViewer to get screen + input control.
- **OAuth device-code theft** — have the victim open `microsoft.com/devicelogin` and read out the 9-digit code (the now-popular device-code phishing flow).
- **Direct bank transfer** — pose as a bank agent and guide the victim through "reversing an erroneous charge" via real online banking.
- **Ransomware staging** — Microsoft tracks Storm-1811, which uses TOAD as the initial-access stepping stone for Black Basta ransomware deployments.

Why do traditional email gateways collapse against TOAD? Because the email **carries no technical malicious indicators**:

- No attachment, so sandboxes have nothing to detonate.
- No link, so URL sandboxes have no landing page to fetch.
- DMARC/SPF/DKIM all typically pass — attackers send from compliant SendGrid/Mailgun/Amazon SES tenants.
- The body is a plain "subscription renewal" notice; keyword classifiers are reluctant to flag it because it looks like ordinary marketing.

The only "malicious payload" is **the toll-free phone number sitting in the body text**.

## Kill chain

```
Attacker rents SendGrid/Mailgun → sends "Geek Squad / Norton / McAfee renewal" email
  ↓ DMARC pass, plain text, no attachment, no link (only a toll-free number)
Email lands in inbox (gateway lets it through)
  ↓
Victim sees "$499.99 will auto-renew within 24h, call 1-855-XXX-XXXX to cancel"
  ↓ panicked dial — this is the TOAD essence: the victim initiates the call
Attacker call centre answers (scripted agent, employee ID, polished greeting)
  ↓ pretends to verify the order, asks the victim to open a browser
Branch A: Remote takeover
  → walks victim through installing ScreenConnect.ClientSetup.exe
  → screen sharing + input control
  → attacker logs straight into the victim's online bank / mailbox / SaaS
Branch B: OAuth device code
  → opens microsoft.com/devicelogin, reads out the 9-digit code
  → attacker receives a long-lived access_token + refresh_token
  ↓
Account takeover complete; email evidence wiped
```

## Email signals

| Dimension | Signal |
| --- | --- |
| Subject | "Your subscription will auto-renew for $499.99", "Order #XX-XXXXXX confirmation", "Geek Squad Protection Plan renewal" |
| Impersonated brands | Geek Squad, Norton, McAfee, PayPal, Amazon, Microsoft, Best Buy (consumer brands users feel familiar with) |
| Urgency phrasing | "within 24 hours", "to cancel call immediately", "before midnight today" |
| Callback verbs | "call now", "call to cancel", "please dial", "contact our support team" |
| Phone numbers | US toll-free (1-855/1-866/1-877/1-888-XXX-XXXX), UK 0800, Chinese 400 hotlines |
| Sender domain | **Completely unrelated** to the brand (attacker-owned domain or shared SendGrid sub-domain) — yet SPF/DKIM all pass |
| Attachment | Usually none; some variants include a static branded PDF invoice (no macros) |

### Animation

<TOADTimeline />

## ✅ How Vigilyx detects this

> **Verdict**: TOAD is a blind spot for sandbox-centric gateways but exactly the comfort zone of Vigilyx's content-semantic analysis. Vigilyx ships a dedicated `toad_detect` module in `vigilyx-engine` that uses a three-factor model: **callback verb + phone number + (urgency OR brand impersonation)**.

| Capability | Vigilyx implementation | Code location |
| --- | --- | --- |
| Callback verb detection | Data-driven phrase matcher (call now / dial / 立即拨打 / 致电…) — single hit adds +0.35 | `crates/vigilyx-engine/src/modules/toad_detect.rs` + `matcher::toad_callback_verbs` |
| Phone-number detection | Four parallel regexes: US toll-free (1-8XX), international E.164, Chinese 400/800 hotlines, Chinese 11-digit mobile | `crates/vigilyx-engine/src/modules/toad_detect.rs` line 110-140 |
| Urgency phrase detection | "within 24h", "cancel immediately", "立即处理"… short list adds +0.20 | `matcher::toad_urgency_phrases` |
| Brand impersonation | Body mentions Geek Squad/Norton/PayPal but sender domain does **not** contain the brand token — adds +0.15 | `toad_detect.rs` line 270-310 |
| Core combo gate | callback_verb + phone_present + (urgency OR brand_impersonation) — only the full combo escalates to High | `toad_detect.rs` line 374-380 (false-positive gate) |
| RMM weaponization | If the body links to ScreenConnect/AnyDesk/TeamViewer installers, `rmm_detect` adds +0.45 | `crates/vigilyx-engine/src/modules/rmm_detect.rs` line 208-209 |
| Device-code interplay | Phone + device-code combo additionally fires `device_code_phishing_scan` | `crates/vigilyx-engine/src/modules/device_code_phishing_scan.rs` |
| Module convergence | toad_detect alone usually stops at Medium; combined hits with content_scan urgency, intel domain-age anomaly and header_scan SPF-align failure trigger DS-Murphy's convergence breaker → High+ | `crates/vigilyx-engine/src/pipeline/verdict.rs` Step 6.6 |

**Operational note**: `toad_detect`'s anti-false-positive gate is the key design choice — without a callback verb, a plain phone number in the body (e.g. a legitimate company hotline in a signature block) **does not** contribute to the risk score. The constraint is hard-coded in the core-combo evaluator: callback verb **and** phone must both be present before any further escalation.

## Why traditional gateways fail

| Gateway type | Reason for failure |
| --- | --- |
| Sandbox / CDR | No attachment, no link → nothing to detonate or reconstruct |
| URL reputation | No URL → module is skipped entirely |
| DMARC/SPF/DKIM | Attackers use compliant SendGrid/Mailgun → all pass |
| Generic phishing-keyword classifier | "Subscription renewal" appears in countless legitimate marketing emails → false-positive cost is too high to enable |
| Domain blacklist | Attackers rotate sender domains weekly → blacklists are always behind |

**Vigilyx's angle**: Stop chasing "which domain is malicious" — that race is unwinnable. Instead, place semantic constraints directly on the **body structure**. The four ingredients of a TOAD email — callback verb + phone + urgency + brand impersonation — are *necessary* conditions of the attack pattern. Necessary conditions cannot be obfuscated away.

## Mitigation

**User training first** — TOAD's whole house of cards relies on the victim being willing to dial. Any email that asks you to "call to cancel within 24 hours":

1. **Do not call the number in the email.**
2. Log into the brand's website or app directly and check whether the order actually exists.
3. Or call the official number printed on the back of the card / website footer to verify.

**Gateway side**:

- Keep `toad_detect` enabled (it ships enabled by default with `vigilyx-engine`).
- Make sure `content_scan` keyword sets include combo phrases like "subscription auto-renew / cancel within 24 hours".
- Treat "body contains toll-free number AND sender domain does not contain the brand token" as an automatic Medium baseline.

**MFA layer**: Lock down the OAuth device-code authorization flow with the Conditional-Access policy described in the [device-code phishing case](./device-code-phishing.md) — this kills the second branch of TOAD outright.

**RMM blocking**: Have endpoint EDR block unauthorized installations of ScreenConnect / AnyDesk / TeamViewer (see CISA Alert AA24-241A for the canonical RMM tool list).

## Cheat sheet for end-users

- ✅ Got a "subscription auto-renewal — call now to cancel" email? **Never dial the number in the email.**
- ✅ Any agent asks you to "open microsoft.com/devicelogin and read 9 digits"? Hang up immediately — that is OAuth device-code theft.
- ✅ Any agent asks you to "install AnyDesk / ScreenConnect to process the refund"? Hang up immediately.
- ✅ The only correct way to verify an order: log into the official site or app — never via the number provided in the email.

## References

- Proofpoint, "Human Factor Report" — ongoing TOAD/callback phishing tracking, 2024 through 2025
- Cisco Talos, "Callback phishing playbooks", 2024
- CISA, "Alert AA24-241A — Threat actors increasingly using RMM tools", 2024
- Microsoft Threat Intelligence, "Storm-1811 ransomware preludes via callback phishing", 2024-2025
- Vigilyx source: `crates/vigilyx-engine/src/modules/toad_detect.rs`
