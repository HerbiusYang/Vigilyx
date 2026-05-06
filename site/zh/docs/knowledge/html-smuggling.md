---
title: HTML 走私投递勒索软件加载器
description: 攻击者把恶意载荷以 base64 / blob 形式嵌入 HTML 附件，浏览器在本地组装并触发下载，绕过传统附件扫描。
---

# 案例 05 — HTML 走私（HTML Smuggling）投递勒索软件加载器

> **公开来源**：Microsoft Threat Intelligence《HTML smuggling surges》(2021 起持续追踪)，Mandiant M-Trends 报告，HP Wolf Security《Threat Insights Q1 2025》

## 背景

HTML 走私利用 HTML5 的 Blob / `<a download>` 能力，把恶意可执行文件以 base64 字符串嵌入 HTML 附件。受害者用浏览器打开附件后，JavaScript 在**本地**把字符串解码成 Blob 并触发下载——整个传输过程没有任何外部网络请求，邮件中也没有可执行附件，传统附件扫描完全看不到 PE 头。

2024-2025 年活跃使用 HTML 走私的家族：Pikabot、SquidLoader、QakBot 复活变种、IcedID、Bumblebee。常用诱饵：发票、运单、传真、HR 文档。

## 攻击链

```
邮件 + .html 附件（看似无害）
  → 用户双击 → 浏览器打开
    → JavaScript 把内嵌 base64 字符串解码为 Uint8Array
      → new Blob([bytes], {type: 'application/octet-stream'})
        → URL.createObjectURL + <a download> 触发自动下载
          → 用户得到 invoice.zip / shipment.iso
            → 解压 → 双击 → ISO 自动挂载 → LNK / VBS 执行加载器
              → Pikabot / IcedID / Bumblebee 落地
                → 后续投递 BlackCat / LockBit 勒索软件
```

## 邮件样本（脱敏）

```
From: Accounts Receivable <ar@partner-billing.example>
Subject: Invoice INV-2025-04812 (Past Due)

Please find your past-due invoice attached. Payment is required
within 5 business days to avoid service interruption.

Attachment: Invoice_2025-04812.html  (8.4 KB)
```

附件 HTML 内含 base64 字符串和约 30 行 JavaScript 解码逻辑。打开后浏览器立即弹出「Save As」下载 `Invoice_2025-04812.zip`。

## 邮件特征

| 维度 | 信号 |
| --- | --- |
| 附件类型 | `.html`、`.htm`、`.svg`（少见）、`.iso` 内含 `.html` |
| 附件大小 | 通常 5-50 KB，远大于纯文本 HTML（因 base64 字符串） |
| HTML 内容 | 含大段连续 base64 字符串（>1KB）+ `atob()` / `Uint8Array` / `Blob` / `createObjectURL` |
| 邮件正文 | 极简，主题与附件名匹配（invoice / shipment / fax） |
| 发件人 | 常用同形域名或被攻陷的真实第三方 |

### 动画演示

<AttackSimulation
  title="HTML Smuggling 投递勒索软件加载器"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "把 ISO/LNK 加载器编码为 base64", en: "Encode ISO/LNK loader as base64" },
      detail: { zh: "几十 KB 的 PE 加载器变成约 50KB 的 base64 字符串", en: "A few-tens-KB loader becomes a ~50KB base64 string" }
    },
    {
      actor: "attacker",
      title: { zh: "嵌入到 .html 附件并加上发票样式", en: "Embed in .html attachment with invoice-style UI" },
      payload: "<script>const data = atob(\"TVqQAAMA...\"); const blob = new Blob([bytes], {type: \"application/octet-stream\"}); const a = document.createElement(\"a\"); a.href = URL.createObjectURL(blob); a.download = \"Invoice.zip\"; a.click();</script>"
    },
    {
      actor: "victim",
      title: { zh: "收到「逾期发票」邮件并打开附件", en: "Receive past-due invoice email and open attachment" },
      detail: { zh: "浏览器渲染发票页面，同时 JS 自动触发下载", en: "Browser renders the invoice page; JS auto-triggers download" }
    },
    {
      actor: "system",
      title: { zh: "Invoice.zip 落到本地——没有任何网络下载", en: "Invoice.zip lands locally — zero network download" },
      detail: { zh: "整个过程不发任何外部请求，URL 信誉、HTTPS 检查、Web 网关全部失效", en: "No external request occurs — URL reputation, HTTPS inspection, web gateway all bypassed" }
    },
    {
      actor: "victim",
      title: { zh: "解压 → ISO 自动挂载 → LNK 执行加载器", en: "Unzip → ISO auto-mounts → LNK executes loader" }
    },
    {
      actor: "attacker",
      title: { zh: "投递 Pikabot / IcedID / BlackCat", en: "Deliver Pikabot / IcedID / BlackCat" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在邮件投递时直接拦截", en: "Vigilyx blocks at delivery time" },
      detection: { zh: "attach_content 把 HTML 附件解析为文本，正则识别长 base64 字符串 + atob/Blob/createObjectURL 三件套指纹 → 直接打 attachment_html_smuggling 类别 → DS-Murphy 融合判 High，邮件进入隔离区", en: "attach_content parses the HTML, regex matches large base64 strings + atob/Blob/createObjectURL triplet → tags attachment_html_smuggling → DS-Murphy fuses to High, mail quarantined" }
    }
  ]'
/>

## ✅ Vigilyx 对该攻击的检测能力

> **结论：Vigilyx 把 HTML 走私当作「附件第一公民」处理——不是简单跳过 .html 附件，而是把 HTML 解析后扫描内嵌 JavaScript 的特征模式。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| HTML 附件文本解析 | `attach_content` 模块对 .html/.htm 附件提取文本 + JS 内容 | `crates/vigilyx-engine/src/modules/attach_content.rs` |
| Base64 大字符串识别 | 正则匹配连续 >512 字节 base64 字符串 + Shannon 熵检查 | `attach_content.rs` |
| HTML 走私指纹 | 同时出现 `atob` + `Blob` + `createObjectURL` / `<a download>` 时打 `html_smuggling` 标签 | `attach_content.rs` |
| 容器附件递归解析 | ZIP / ISO / IMG 内的 LNK / VBS / JS 同样进入 `attach_content` 检测 | `crates/vigilyx-parser/src/mime.rs` + `attach_content.rs` |
| YARA 规则联动 | 内置 YARA 规则集匹配 Pikabot/IcedID/Bumblebee 加载器特征 | `crates/vigilyx-engine/src/modules/yara_scan.rs` + `rules/` |
| 文件类型欺骗检测 | 通过 magic byte 识别声称 .pdf 实为 .html 的附件 | `crates/vigilyx-engine/src/modules/mime_scan.rs` |

**实战表现**：传统 AV 对 HTML 附件几乎无能为力（没有 PE 头可扫）；Vigilyx 通过「内嵌 base64 + JS 三件套」的行为指纹，**不依赖具体载荷哈希**就能识别这类走私。新家族出现时无需更新签名即可拦截。

## 防御建议

**网关侧**：在 Vigilyx 默认能力之外，建议在企业邮件策略中**直接阻断 .html / .htm 附件**——业务上几乎没有发送 HTML 附件的合法场景。

**端点侧**：Windows 通过 GPO 取消 .iso / .img 文件的双击自动挂载（Win10+ 支持），可以阻断走私后的 ISO 落地链路。

**用户培训**：「财务发票为什么是 .html 文件？」——对任何 HTML / ISO / IMG 附件保持高度警惕。

## 员工识别要点

✅ 任何以 .html / .htm / .iso / .img 作为附件的邮件都是高风险
✅ 发票、运单、传真这类业务邮件正常应该是 PDF / Excel / Word，**不是网页文件**
✅ 打开附件后浏览器立刻自动下载东西 → 关掉浏览器并报告 IT

## 参考资料

- Microsoft Threat Intelligence, "HTML smuggling surges", 2021 至今
- Mandiant M-Trends 2024
- HP Wolf Security, "Threat Insights Report Q1 2025", 2025-04
- CISA, ALERT (AA22-216A) 引用 HTML smuggling
