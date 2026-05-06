---
title: Tycoon 2FA / EvilProxy AiTM Phishing
description: Adversary-in-the-middle phishing platforms (Tycoon 2FA, EvilProxy, Mamba 2FA) reverse-proxy real Microsoft and Google login pages to steal session cookies after a successful MFA challenge.
---

# Case 06 — Tycoon 2FA / EvilProxy AiTM Phishing

Sources: Proofpoint EvilProxy series (2023 onward), Mandiant Tycoon 2FA (2024), Sekoia.io (2024-Q4), Microsoft Threat Intelligence.

## Background

AiTM (Adversary-in-the-Middle) phishing is the most efficient industrialized way to bypass MFA today. Attackers run reverse proxies (Tycoon 2FA, EvilProxy, Mamba 2FA, Greatness, Strox) that forward credentials and MFA codes in real time to the genuine Microsoft 365 or Google Workspace login. After the victim completes MFA, the proxy keeps the returned session cookie. The attacker injects the cookie into their own browser and gains full account access without ever needing to redo MFA.

Since 2024, Tycoon 2FA hosts thousands of new phishing domains every week. Subscriptions cost $200-300, dramatically lowering the bar for entry.

## Email indicators

- Subjects: "Voicemail received", "DocuSign: Please review", "Microsoft Teams: New message", "Shared file: Quarterly Report"
- Multi-hop redirect chain: email → URL shortener / Cloudflare Worker → Turnstile → AiTM domain
- AiTM domain naming: lookalike subdomains such as `login-microsoftonline.<random>.com` or `mfa-verify.<workers.dev>`
- Domain age usually under 7 days
- TLS via Let's Encrypt — fully valid certificate

## Animated walkthrough

<AttackSimulation
  title="Tycoon 2FA / EvilProxy AiTM phishing"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "购买 Tycoon 2FA 订阅", en: "Buy a Tycoon 2FA subscription" }
    },
    {
      actor: "attacker",
      title: { zh: "投递 voicemail / 文档共享 钓鱼邮件", en: "Send voicemail / document-share phishing email" }
    },
    {
      actor: "victim",
      title: { zh: "点击链接，看到 Microsoft 登录页", en: "Click link, see a Microsoft login page" }
    },
    {
      actor: "victim",
      title: { zh: "输入账号密码", en: "Enter credentials" }
    },
    {
      actor: "attacker",
      title: { zh: "代理实时转发到真实 Microsoft", en: "Proxy forwards in real time to real Microsoft" }
    },
    {
      actor: "victim",
      title: { zh: "完成 MFA", en: "Complete MFA" }
    },
    {
      actor: "attacker",
      title: { zh: "拿到 session cookie 并注入浏览器", en: "Steal session cookie and inject into attacker browser" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在邮件层就拦截", en: "Vigilyx blocks at the email layer" },
      detection: { zh: "link_scan 检测多层跳转 + landing_page_scan 识别 AiTM 反代特征 + intel 命中 Tycoon 已知基础设施 + content_scan 命中钓鱼词，融合后判 High 或 Critical", en: "link_scan detects shortener-plus-Worker hops, landing_page_scan identifies AiTM proxy fingerprints, intel matches known Tycoon infrastructure, content_scan triggers on voicemail/MFA terms; fused to High or Critical" }
    }
  ]'
/>

## Vigilyx detection coverage

Vigilyx beats Tycoon-class platforms via a three-layer combination of redirect-chain analysis, landing-page fingerprinting, and known-infrastructure intelligence:

- **URL multi-hop analysis** — `link_scan` follows redirects and identifies shortener + Cloudflare Worker + lookalike combinations (`crates/vigilyx-engine/src/modules/link_scan.rs`)
- **Landing-page content fingerprints** — `landing_page_scan` fetches the final page and matches AiTM reverse-proxy traits, missing CSP, abnormal cross-origin asset signatures (`crates/vigilyx-engine/src/modules/landing_page_scan.rs`)
- **Dedicated AiTM detection** — `aitm_detect` analyzes OAuth login form action domains for anomalies (`crates/vigilyx-engine/src/modules/aitm_detect.rs`)
- **New-domain detection** — `intel` checks WHOIS/RDAP and raises risk for domains under 7 days old (`crates/vigilyx-engine/src/intel.rs`)
- **Tycoon infrastructure intel** — OTX/AbuseIPDB continuously tag known Tycoon 2FA infrastructure, hitting `intel` immediately escalates to Critical (`crates/vigilyx-engine/src/intel.rs`)
- **Voicemail / MFA / share keyword set** — `content_scan` ships dedicated lists for these phishing themes (`crates/vigilyx-engine/src/modules/content_scan/detectors.rs`)

In real-world Tycoon 2FA waves throughout 2025, Vigilyx detection was driven mainly by `landing_page_scan` AiTM fingerprinting — even brand-new domains registered the same day (no IOC coverage) were caught the moment the landing page was fetched.

## Defense

- **Identity layer (most important)** — deploy phishing-resistant MFA (FIDO2 hardware keys, passkeys, Windows Hello). FIDO2 binds origin into the hardware signature, so reverse-proxy domains physically cannot produce a valid signature.
- **Gateway** — make `landing_page_scan` mandatory; treat any email with three or more redirect hops as Medium baseline.
- **Training** — before signing in to any Microsoft service, verify the address bar shows `login.microsoftonline.com` or `login.live.com`. Anything else is an attack.
