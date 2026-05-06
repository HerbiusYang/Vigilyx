---
title: VEC Vendor Email Compromise
description: After taking over a real vendor mailbox, attackers reply inside legitimate threads and request a bank-account change. Every traditional signal passes; Vigilyx detects the anomaly via behavior baselines and banking-change rules.
---

# Case 07 — VEC Vendor Email Compromise

Sources: FBI IC3 Internet Crime Report 2024, Abnormal Security VEC report (2024), Microsoft Digital Defense Report 2024.

## Background

VEC is the highest-loss variant of BEC. The FBI IC3 2024 report places BEC at 38% of all cybercrime losses; within BEC, VEC averages over $120K per incident — far higher than CEO-impersonation BEC.

The flow: attacker compromises a vendor mailbox via phishing or AiTM, lurks for 1-3 months observing the email pattern, and then **replies inside an existing payment thread** with a "we changed banks" message. Sender, SPF, DKIM, DMARC, signature, and full thread history are all genuine.

## Email indicators

- Sender mailbox is real and previously communicated with the victim
- All authentication passes
- The thread history is real (the prior `RE:` chain genuinely exists)
- Signature format matches the contact's historical mail
- Attachments (W-9, bank letter) are convincingly forged
- The new ACH account routes to a money-mule chain

This is the hardest BEC variant to detect. There is no malicious domain, no malicious attachment, and no traditional anomaly to trigger.

## Animated walkthrough

<AttackSimulation
  title="VEC vendor account takeover invoice fraud"
  :interval="2600"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "钓鱼接管供应商邮箱", en: "Compromise vendor mailbox via phishing or AiTM" }
    },
    {
      actor: "attacker",
      title: { zh: "潜伏 30-90 天，建立 inbox 规则隐藏告警", en: "Lurk 30-90 days, hide alerts via inbox rules" }
    },
    {
      actor: "attacker",
      title: { zh: "学习审批流程、识别金额阈值与对接人", en: "Learn the approval workflow, amount thresholds, contacts" }
    },
    {
      actor: "attacker",
      title: { zh: "在真实邮件线程中回复修改银行账户", en: "Reply inside a real thread, requesting bank-account change" }
    },
    {
      actor: "victim",
      title: { zh: "财务相信这是 Sarah", en: "AP trusts: this is Sarah" }
    },
    {
      actor: "victim",
      title: { zh: "向攻击者账户发起 ACH/电汇", en: "Wire/ACH to attacker-controlled account" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 通过行为基线识别异常", en: "Vigilyx flags via behavior baselines" },
      detection: { zh: "behavior_baseline 识别该联系人首次提及银行账户变更 + content_scan 命中 banking_change 专项检测 + identity_anomaly 标记 reply 链虽真但首次涉及付款变更 + attach_content 检测 W-9 附件 PDF metadata 异常，融合后判 High，AP 在付款前看到告警", en: "behavior_baseline notices the contact has never discussed bank changes before, content_scan triggers the banking_change rule, identity_anomaly flags first-time payment-change content in an otherwise real thread, attach_content detects newly-created PDF metadata in the W-9; DS-Murphy fuses to High and AP sees the alert before paying" }
    }
  ]'
/>

## Vigilyx detection coverage

VEC is the email-security blind spot every traditional gateway shares. Vigilyx covers it through behavior baselines, semantic dedicated rules, and attachment metadata analysis:

- **Banking-change rule** — `content_scan` dedicated rule: `routing` plus `ACH` or `wire` plus `change` / `update` / `new` co-occurring → Medium baseline (`crates/vigilyx-engine/src/modules/content_scan/detectors.rs`)
- **Behavior baseline** — `behavior_baseline` checks the historical session table and raises risk when this contact discusses payment-change topics for the first time (`crates/vigilyx-engine/src/modules/behavior_baseline.rs`)
- **Identity anomaly** — `identity_anomaly` flags real reply chains that suddenly introduce payment-change or urgency language (`crates/vigilyx-engine/src/modules/identity_anomaly.rs`)
- **Attachment metadata analysis** — `attach_content` examines PDF/Office creation timestamps, authors, and revision history; freshly-created "official" documents are suspicious (`crates/vigilyx-engine/src/modules/attach_content.rs`)
- **Historical conversation queries** — DB indexes support fast queries over the sender/recipient relationship's topic history and frequency (`crates/vigilyx-db/src/infra/session.rs::count_sender_domain_history`)
- **Cross-organization reply-chain inspection** — `header_scan` parses References and In-Reply-To to distinguish "real thread injection" from forged replies (`crates/vigilyx-engine/src/modules/header_scan.rs`)

Traditional gateways are blind to VEC (every authentication signal passes, domain reputation is clean). Vigilyx flags it via "this real contact has never discussed bank-account changes before" — the kind of baseline judgment that has successfully alerted finance teams in multiple 2025 replay cases.

## Defense

- **Process layer (most important)** — any bank-account change must be confirmed by **calling back a known phone number** (not the number in the email signature). This is the only reliable defense against VEC.
- **Identity layer** — require all vendors to enable FIDO2 / passkey MFA on their mailboxes, reducing the upstream compromise rate.
- **Gateway** — keep banking_change and behavior_baseline modules enabled and require manual review for any routing/ACH/wire change request.

## End-user training

- "We changed banks" requires a callback to a known number — never reply by email
- Urgency words ("please process today", "sorry for the late notice") plus account change is extremely high risk
- A W-9 PDF created in the last few hours is suspicious
