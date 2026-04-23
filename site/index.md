---
layout: home

title: Vigilyx
titleTemplate: Rust-Powered Email Security Gateway
description: Rust-powered email security platform built to financial-industry security standards. D-S + Murphy evidence fusion, 5-state HMM BEC phase tracking, Hawkes self-exciting time series, AitM MFA-bypass detection, HTML-pixel-art QR decoding, and JR/T 0197-2020 financial DLP — shipped as two independent deployment shapes on the same explainable detection stack.

hero:
  name: Vigilyx
  text: Email security that is actually different under the hood.
  tagline: Open source, Rust-powered, explainable. D-S + Murphy evidence fusion instead of weighted-sum scoring. A full temporal layer (CUSUM, dual-EWMA, Hawkes, 5-state HMM, comm graph) on top of per-email verdicts. Detection for AitM MFA-bypass kits, HTML-pixel-art QR codes, and JR/T 0197-2020 financial-DLP compliance. Pick mirror (passive) or MTA (inline) — same stack, two deployment shapes, no black box.
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
  - title: Murphy-corrected D-S evidence fusion
    details: Not weighted-sum, not a black-box classifier. Proper Dempster–Shafer with Murphy weighted-average correction and Copula discount for correlated engines, so same-family signals do not amplify each other and every verdict is explainable per-engine. Implemented in Rust, not inherited from a vendor library.
  - title: Full temporal layer on top of per-email verdicts
    details: CUSUM shift detection, dual-speed EWMA baseline drift, marked Hawkes self-exciting process for attack-campaign momentum, a 5-state HMM inferring BEC / ATO phases (recon → trust-build → execute → exfil), plus a directed communication graph. Most email-security products judge each message in isolation — this one does not.
  - title: AitM reverse-proxy phishing detection
    details: Fingerprints the MFA-bypass kits actually used in 2024+ (Tycoon2FA, EvilProxy, Evilginx3) — Cloudflare Workers / Pages DGA hosting, OAuth redirect_uri mismatch, Turnstile CAPTCHA toolkit indicators, and Latin-Cyrillic homograph brand impersonation. This class of phishing bypasses traditional link-reputation and attachment scanning entirely.
  - title: HTML pixel-art & QR-in-table detection
    details: Attackers draw QR codes using <table> bgcolor cells and smuggle phishing text via floated <div>s with background-color — specifically to bypass OCR and sandbox image scanning. Vigilyx reconstructs the rendered bitmap from DOM structure and decodes it with rqrr. Pure-text ASCII block-char QR codes are decoded the same way.
  - title: JR/T 0197-2020 financial DLP with real checksums
    details: Tracks cumulative sensitive-data counts per user / per IP against the People's Bank of China data-classification standard (C3 ≥ 500 / 24h → High, C4 ≥ 50 / 24h → Critical). Chinese ID / mobile / bank-card regexes are boundary-aware (`(?-u:\b)`), bank cards are Luhn-checked, IBAN mod-97 validated, 18-digit social-credit codes exclude I / O / Z / S / V — details most Western vendors and regex-only DLP products miss.
---

<HomeLanding locale="en" />
