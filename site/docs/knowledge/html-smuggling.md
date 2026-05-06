---
title: HTML Smuggling Delivers Ransomware Loaders
description: Attackers embed payloads as base64 blobs inside HTML attachments. The browser assembles the file locally, bypassing email attachment scanning and URL reputation.
---

# Case 05 — HTML Smuggling Delivers Ransomware Loaders

Sources: Microsoft Threat Intelligence (2021 onward), Mandiant M-Trends, HP Wolf Security Q1 2025.

## Background

HTML smuggling abuses HTML5 Blob and `<a download>` to embed an executable as a base64 string inside an HTML attachment. When the victim opens the attachment in a browser, JavaScript decodes the string locally, builds a Blob, and triggers a download. The transfer never crosses the network, the email contains no executable attachment, and traditional attachment scanning sees no PE header.

Active families in 2024-2025: Pikabot, SquidLoader, revived QakBot variants, IcedID, Bumblebee. Common lures: invoices, shipping notices, fax delivery, HR documents.

## Email indicators

- Attachment types: `.html`, `.htm`, occasionally `.svg`, or `.iso` containing `.html`
- Attachment size: 5-50 KB (much larger than plain HTML because of the base64 string)
- HTML content: long contiguous base64 strings (over 1KB) plus `atob()`, `Uint8Array`, `Blob`, `createObjectURL`
- Body: minimal, subject matches attachment name (invoice, shipment, fax)
- Sender: lookalike domain or compromised legitimate third party

## Animated walkthrough

<AttackSimulation
  title="HTML smuggling delivers a ransomware loader"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "把 ISO/LNK 加载器编码为 base64", en: "Encode ISO/LNK loader as base64" }
    },
    {
      actor: "attacker",
      title: { zh: "嵌入到 .html 附件并加上发票样式", en: "Embed in .html attachment with invoice-style UI" }
    },
    {
      actor: "victim",
      title: { zh: "收到逾期发票邮件并打开附件", en: "Receive past-due invoice email and open attachment" }
    },
    {
      actor: "system",
      title: { zh: "Invoice.zip 落到本地 — 没有任何网络下载", en: "Invoice.zip lands locally with zero network download" }
    },
    {
      actor: "victim",
      title: { zh: "解压 → ISO 自动挂载 → LNK 执行加载器", en: "Unzip, ISO auto-mounts, LNK executes loader" }
    },
    {
      actor: "attacker",
      title: { zh: "投递 Pikabot / IcedID / BlackCat", en: "Deliver Pikabot / IcedID / BlackCat" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在邮件投递时直接拦截", en: "Vigilyx blocks at delivery time" },
      detection: { zh: "attach_content 把 HTML 附件解析为文本，正则识别长 base64 字符串 + atob/Blob/createObjectURL 三件套指纹，融合后判 High，邮件进入隔离区", en: "attach_content parses the HTML, regex matches large base64 strings plus the atob/Blob/createObjectURL triplet, DS-Murphy fuses to High, mail quarantined" }
    }
  ]'
/>

## Vigilyx detection coverage

Vigilyx treats HTML smuggling as a first-class attachment problem rather than skipping `.html` files:

- **HTML attachment text parsing** — `attach_content` extracts text and JavaScript content from `.html` and `.htm` attachments (`crates/vigilyx-engine/src/modules/attach_content.rs`)
- **Large base64 string detection** — regex matches contiguous base64 over 512 bytes plus a Shannon-entropy check (`attach_content.rs`)
- **Smuggling fingerprint** — co-occurrence of `atob` + `Blob` + `createObjectURL` or `<a download>` triggers the `html_smuggling` category (`attach_content.rs`)
- **Recursive container parsing** — LNK / VBS / JS files inside ZIP / ISO / IMG attachments are also parsed by `attach_content` (`crates/vigilyx-parser/src/mime.rs`, `attach_content.rs`)
- **YARA rule integration** — built-in rules match Pikabot, IcedID, Bumblebee loader signatures (`crates/vigilyx-engine/src/modules/yara_scan.rs` plus `rules/`)
- **MIME-type spoofing** — magic-byte analysis detects attachments claiming `.pdf` while actually being HTML (`crates/vigilyx-engine/src/modules/mime_scan.rs`)

Traditional AV is largely useless against HTML attachments (no PE header to scan). Vigilyx detects this attack via the behavioral fingerprint — embedded base64 plus the JavaScript triplet — without depending on specific payload hashes, so new families are caught without signature updates.

## Defense

- Beyond Vigilyx defaults, **block `.html` and `.htm` attachments outright** at the corporate mail policy — there is almost no legitimate business case for HTML attachments
- Disable double-click auto-mount of `.iso` and `.img` files via Windows GPO (supported on Win10+) to break the post-smuggling chain
- Train staff: "Why is this invoice an .html file?" — be highly suspicious of any HTML, ISO, or IMG attachment
