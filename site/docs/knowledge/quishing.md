---
title: Quishing / QR Code Phishing
description: Attackers embed phishing URLs in QR codes inside images or PDFs to bypass traditional email link scanning. Vigilyx decodes attachment QR codes natively, closing this long-standing blind spot.
---

# Case 03 — Quishing / QR Code Phishing

Sources: Cisco Talos (2023-10 onward), Sophos X-Ops 2024 quarterly reports, Abnormal Security Q4 2024, Microsoft Defender for Office 365 2025-Q1.

## Background

Quishing (QR plus phishing) became one of the dominant ways to bypass traditional email defense from late 2023 through 2025. The technique works because:

1. Traditional email gateways scan URLs but do not decode QR codes embedded in images or PDFs
2. Mobile phones sit outside enterprise EDR coverage, with weaker browser protections
3. After the user types credentials on the phone, the resulting cookie also works on the desktop (especially when paired with [AiTM phishing](./aitm-phishing))

Common lures: "Your Microsoft 365 password expires today, scan to reset", "Voicemail attached: scan to listen", "HR: Updated employee handbook, scan to acknowledge", "DHL/UPS: Package delivery requires confirmation".

## Email indicators

- Lookalike sender domain or compromised legitimate third party
- Body text is minimal — mostly an image; if any text exists, it stresses "must use mobile"
- Attachment is PNG, JPG, or PDF with embedded QR; advanced variants use SVG containing base64 PNG
- The HTML has no external links, only image src — so traditional `link_scan` finds nothing
- Subject themes: MFA expires, voicemail, HR acknowledgement, DocuSign, DHL delivery

## Animated walkthrough

<AttackSimulation
  title="QR code phishing bypasses link scanning"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "生成 QR 码并嵌入邮件正文图片", en: "Generate QR code and embed it as inline image" }
    },
    {
      actor: "attacker",
      title: { zh: "邮件话术：HR 合规承诺 + 必须用手机", en: "Email body: HR compliance plus mobile-only narrative" }
    },
    {
      actor: "victim",
      title: { zh: "用手机扫描二维码", en: "Scan QR code with mobile phone" }
    },
    {
      actor: "attacker",
      title: { zh: "跳转到 AiTM 反向代理", en: "Redirect to AiTM reverse proxy" }
    },
    {
      actor: "victim",
      title: { zh: "在仿冒登录页输入账号密码", en: "Enter credentials on the proxy login page" }
    },
    {
      actor: "attacker",
      title: { zh: "拿到 session cookie", en: "Steal the session cookie" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 解码 QR 后还原完整链路", en: "Vigilyx decodes the QR and restores the full chain" },
      detection: { zh: "attach_qr_scan 解码 PNG/JPG/PDF 内 QR + landing_page_scan 识别 AiTM 落地页 + content_scan 命中 mobile-only 话术，融合后判 High", en: "attach_qr_scan decodes the QR in PNG/JPG/PDF, the URL goes through link detection, landing_page_scan identifies AiTM fingerprints, content_scan matches mobile-only narrative; verdict High" }
    }
  ]'
/>

## Vigilyx detection coverage

Vigilyx treats QR-decoding as a first-class attachment-analysis primitive — the long-standing blind spot of "QR codes inside images" is closed:

- **Attachment QR decoding** — `attach_qr_scan` decodes QR codes embedded in PNG, JPG, and PDF attachments; the extracted URL goes through the standard link pipeline (`crates/vigilyx-engine/src/modules/attach_qr_scan.rs`)
- **Decoded-link reputation** — the recovered domain is checked against the local IOC store and OTX/AbuseIPDB via `intel` (`crates/vigilyx-engine/src/intel.rs`)
- **AiTM landing-page fingerprints** — if the QR ultimately leads to Tycoon 2FA / EvilProxy, `landing_page_scan` recognizes AiTM reverse-proxy traits (`crates/vigilyx-engine/src/modules/landing_page_scan.rs`)
- **Mobile-only narrative** — `content_scan` matches "scan with mobile", "mobile-only", "QR code" combined with urgency (`crates/vigilyx-engine/src/modules/content_scan/detectors.rs`)
- **Image-heavy body detection** — `html_scan` flags emails whose stripped-text body is suspiciously short while containing large images (`crates/vigilyx-engine/src/modules/html_scan.rs`)
- **Single-page QR-only PDFs** — `attach_content` escalates PDFs that have one page and decode to a QR-only payload (`crates/vigilyx-engine/src/modules/attach_content.rs`)

Traditional gateways inspect only `<a href>` and remain blind to QR codes in images and PDFs. By treating QR decoding as a first-class attachment primitive, Vigilyx eliminates the entire "image bypass" class of attacks.

## Defense

- Enable QR decoding for both attachments and inline images
- Treat any email with near-empty body plus image attachment plus "scan / mobile" keywords as Medium baseline
- A single-page PDF that contains only a QR code plus one line of text should be raised to High

## End-user training

- Email asking you to use your phone to complete a desktop task is almost certainly an attack
- "Mobile-only for security reasons" is a hallmark phrase of QR phishing
- After scanning, inspect the mobile browser address bar carefully — `login.microsoftonline.com` versus `login-microsoft-secure.workers.dev`
