---
title: Storm-2372 OAuth Device-Code Phishing
description: Storm-2372 (Microsoft TI, 2025-02) tricks victims into entering an attacker-generated device code on the real microsoft.com login page, hijacking OAuth tokens with full MFA passed.
---

# Case 02 — Storm-2372 OAuth Device-Code Phishing

Sources: Microsoft Threat Intelligence (2025-02-13), Volexity (2025-02-13), CISA.

## Background

Storm-2372 is a state-aligned threat actor tracked by Microsoft. Since August 2024 the group has run OAuth device-code phishing campaigns against defense, IT, telecom, government, and NGO targets across North America, Europe, the Middle East, and Africa.

The attacker does not impersonate a login page. Instead, they send the victim to the real `https://microsoft.com/devicelogin` and ask them to enter an attacker-generated 8-character code. After the victim completes MFA, the issued OAuth tokens (access + refresh) are bound to a "device" the attacker controls. The attacker then keeps full Microsoft Graph access to mail, OneDrive, SharePoint, and Teams without ever needing MFA again.

Device codes expire after 15 minutes, so attackers usually generate the code and send the email or chat message simultaneously, with strong urgency framing.

## Email indicators

- **Sender mailbox is often a real, already-compromised partner mailbox** — SPF, DKIM, and DMARC all pass
- Subject is highly relevant to the victim's real work area
- The only external link is `microsoft.com/devicelogin` — a genuine, legitimate URL
- Body contains the device code, "sign in to join", "federation policy", and an explicit 15-minute deadline

This is the hardest variant to detect: no malicious domain, no malicious attachment, no suspicious link.

## Animated walkthrough

<AttackSimulation
  title="Storm-2372 device-code flow"
  :interval="2500"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "调用 OAuth /devicecode 端点", en: "Call OAuth /devicecode endpoint" },
      detail: { zh: "拿到合法的 8 位码，有效期 15 分钟", en: "Get legitimate 8-char code, valid 15 min" }
    },
    {
      actor: "attacker",
      title: { zh: "从被攻陷邮箱发出会议邀请", en: "Send invite from a compromised mailbox" },
      payload: "Open https://microsoft.com/devicelogin and enter HXDF-7K9P (valid 15 min)"
    },
    {
      actor: "victim",
      title: { zh: "受害者打开真实 microsoft.com", en: "Victim opens the real microsoft.com URL" }
    },
    {
      actor: "victim",
      title: { zh: "输入码 + 完成 MFA", en: "Enter code, complete MFA" }
    },
    {
      actor: "attacker",
      title: { zh: "轮询 /token 端点取得令牌", en: "Poll /token to receive tokens" }
    },
    {
      actor: "attacker",
      title: { zh: "持续访问邮件 / OneDrive / Teams", en: "Persist access to mail / OneDrive / Teams" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在投递阶段就拦下", en: "Vigilyx blocks at delivery time" },
      detection: { zh: "content_scan 专项规则 + identity_anomaly 首次通信 + behavior_baseline 首次提及 OAuth + AI 语义模型，融合后判 High", en: "content_scan dedicated rule, identity_anomaly first-contact flag, behavior_baseline OAuth-novelty signal, optional NLP semantic model; fused to High" }
    }
  ]'
/>

## Vigilyx detection coverage

Vigilyx is hardened specifically for OAuth device-code phishing. Even when the sender is a fully compromised legitimate mailbox passing all authentication, the engine still detects the attempt via semantic and contextual signals:

- **Dedicated device-code rule** — `content_scan` looks for `microsoft.com/devicelogin`, `aka.ms/devicelogin`, `device code`, or `one-time code` co-occurring with urgency words (`crates/vigilyx-engine/src/modules/content_scan/detectors.rs`)
- **First-contact detection** — `identity_anomaly` queries the historical session table to flag the first time this sender ever contacts the victim (`crates/vigilyx-engine/src/modules/identity_anomaly.rs`)
- **Behavior baseline** — `behavior_baseline` flags the first time this contact ever discusses OAuth or meeting-invite topics (`crates/vigilyx-engine/src/modules/behavior_baseline.rs`)
- **AI semantic model (optional)** — when the AI sidecar is enabled, the fine-tuned NLP model is highly accurate at the OAuth-plus-urgency combination (`crates/vigilyx-engine/src/modules/semantic_scan.rs`, `python/vigilyx_ai/nlp_phishing.py`)
- **Convergence floor** — even when every signal is individually weak, DS-Murphy still raises the verdict to Medium through `convergence_base_floor=0.40`

Traditional gateways uniformly miss this attack (no malicious domain, all auth passing). Vigilyx catches it through the multi-signal fusion of dedicated rules, first-contact detection, and urgency-language analysis.

## Defense

- **Identity layer (most important)** — disable device-code grant in Entra ID Conditional Access by default; allow only for explicitly approved users and apps. Alert on every `urn:ietf:params:oauth:grant-type:device_code` sign-in.
- **Gateway** — flag any email containing `microsoft.com/devicelogin` or `aka.ms/devicelogin` as OAuth-risk and require manual review for external senders.
- **Training** — Microsoft never asks you to open `devicelogin` in an email. Joining a Teams meeting is always done by clicking the meeting link, not entering a numeric code.
- **IR** — on suspected compromise, immediately revoke all refresh tokens with `Revoke-AzureADUserAllRefreshToken` and audit Sign-in logs for `authenticationProtocol = deviceCode`.
