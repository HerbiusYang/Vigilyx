---
title: Quishing / QR 码钓鱼
description: 2024-2025 年大规模流行的 QR 码钓鱼复盘——攻击者将钓鱼链接编码进二维码（图片或 PDF），绕过传统邮件链接扫描，诱导受害者用手机扫码完成认证或支付。
---

# 案例 03 — Quishing / QR 码钓鱼

> **公开来源**：Cisco Talos《Quishing: A new phishing technique》(2023-10) 持续追踪，Sophos X-Ops 2024 季度报告，Abnormal Security《QR Code Phishing Trends》(2024-Q4)，Microsoft Defender for Office 365 团队 2025-Q1 趋势分析

## 背景

Quishing（QR + Phishing）从 2023 年底开始流行，2024-2025 年成为绕过传统邮件防护的主流手段之一。攻击核心：

1. **传统邮件网关扫描 URL，不解码图片中的 QR 码**
2. **手机不在企业 EDR 覆盖范围**，浏览器保护和域名信誉检查弱
3. 用户在手机上输入凭据后，攻击者拿到的 cookie 在桌面端也能用（特别是配合 [AiTM 钓鱼](./aitm-phishing)）

常见诱饵：
- "Your Microsoft 365 password expires today, scan to reset"
- "Voicemail attached: scan to listen"
- "HR: Updated employee handbook, scan to acknowledge"
- "DHL/UPS: Package delivery requires confirmation"

## 攻击链

```
邮件（含 PNG/JPG 图片或 PDF 附件，QR 码嵌入）
  → 用户用手机扫描
    → 跳转到 Cloudflare Turnstile / reCAPTCHA 仿冒页（过滤沙箱扫描）
      → 跳转到 AiTM 反向代理（如 Tycoon 2FA / EvilProxy）
        → 用户输入 Microsoft 365 凭据 + MFA
          → 攻击者代理转发到真实 login.microsoftonline.com
            → 受害者完成登录，攻击者拿到 session cookie
              → 邮箱接管 → 内部钓鱼 / 财务欺诈
```

## 邮件样本（脱敏）

```
From: HR Department <hr-noreply@victim-corp[.]com>  ← 仿冒同形域名
To: employee@victim.example
Subject: Action Required: Annual Compliance Acknowledgement

Dear Employee,

As part of our annual compliance program, all employees must
acknowledge receipt of the updated Code of Conduct by Friday.

Please scan the QR code below using your mobile device to access
the secure acknowledgement portal:

  [QR CODE IMAGE]

This portal is mobile-only for security reasons and cannot be
accessed from a desktop browser.

HR Compliance Team
```

「mobile-only for security reasons」是经典话术，目的是**阻止用户在桌面端检查链接**。

### 动画演示

<AttackSimulation
  title="QR 码钓鱼绕过链接扫描"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "生成 QR 码并嵌入邮件正文图片", en: "Generate QR code and embed it as inline image" },
      detail: { zh: "PNG / JPG / PDF / SVG 都可以，传统网关只扫 <a href>，对图片中的 QR 码完全无视", en: "PNG / JPG / PDF / SVG — traditional gateways only scan <a href>, ignoring QR codes in images" }
    },
    {
      actor: "attacker",
      title: { zh: "邮件话术：HR 合规承诺 + 必须用手机", en: "Email body: HR compliance + mobile-only narrative" },
      payload: "Subject: Annual Compliance Acknowledgement\nThis portal is mobile-only for security reasons."
    },
    {
      actor: "victim",
      title: { zh: "用手机扫描二维码", en: "Scan QR code with mobile phone" },
      detail: { zh: "手机不在企业 EDR 覆盖范围，浏览器保护和域名信誉检查弱", en: "Phone is outside enterprise EDR coverage, browser protections weaker" }
    },
    {
      actor: "attacker",
      title: { zh: "跳转到 AiTM 反向代理", en: "Redirect to AiTM reverse proxy" },
      detail: { zh: "Tycoon 2FA / EvilProxy 实时转发凭据 + MFA 验证码", en: "Tycoon 2FA / EvilProxy proxies credentials and MFA codes in real time" }
    },
    {
      actor: "victim",
      title: { zh: "在仿冒登录页输入账号密码", en: "Enter credentials on the proxy login page" }
    },
    {
      actor: "attacker",
      title: { zh: "拿到 session cookie", en: "Steal the session cookie" },
      detail: { zh: "Cookie 在桌面端也能复用，绕过 MFA", en: "Cookie works on desktop too, completely bypassing MFA" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 解码 QR 后还原完整链路", en: "Vigilyx decodes the QR and restores the full chain" },
      detection: { zh: "attach_qr_scan 解码 PNG/JPG/PDF 内 QR 码 → 解码出的 URL 进入 link 检测 + landing_page_scan 识别 AiTM 落地页指纹 + content_scan 命中「mobile-only / scan with mobile」话术 → 判 High，邮件隔离", en: "attach_qr_scan decodes the QR in PNG/JPG/PDF; the URL goes through link detection, landing_page_scan identifies AiTM fingerprints, content_scan matches mobile-only narrative — verdict High, mail quarantined" }
    }
  ]'
/>

## 邮件特征

| 维度 | 信号 |
| --- | --- |
| 发件域名 | 同形域名 / 相似域名 / 也可能是被攻陷的合法第三方邮箱 |
| 正文 | **正文文字极少**，主要是图片；若有文字，强调"必须用手机扫描" |
| 附件 | PNG/JPG/PDF 内嵌 QR 码；高级变种用 SVG 嵌入 base64 PNG |
| 链接 | 邮件 HTML 中无外链或仅有图片 src — **传统 link_scan 模块无东西可看** |
| 主题 | "MFA expires"、"voicemail"、"HR acknowledgement"、"DocuSign"、"DHL delivery" |

## Vigilyx 检测要点

针对 Quishing，Vigilyx 必须**对附件和正文图片做 QR 解码**：

| 模块 | 期望命中 | 说明 |
| --- | --- | --- |
| `attachment_scan` | 高 | 检测附件中的 QR 码并解码 URL，再走标准 link 检测流程 |
| `html_scan` | 中 | 邮件正文 `<img>` 嵌入 QR 时同样解码 |
| `content_scan` | 中 | 关键词 `scan with your mobile`、`mobile-only`、`QR code` 与紧迫感词组合 |
| `link_content` | 中-高 | 解码出的 URL 落地页若含登录页或 AiTM 指纹 → 直接 High |
| `intel` | 视情况 | 解码出的域名命中 OTX/AbuseIPDB 时直接 critical |
| **D-S 融合** | **High** | QR 解码命中 + 内容关键词同时存在时大概率 Medium-High |

**实施提示**：Vigilyx 的 `attachment_scan` 模块可集成 `rqrr` (Rust QR decoder) 处理 PNG/JPG，对 PDF 先用 `pdfium-render` 渲染再解码。SVG 内嵌 base64 图片需先解码 `data:image/png;base64,` 段。

> 当前版本默认未启用 QR 解码（依赖较重），如需开启请见 [features](../features) 中 `attachment_qr_scan` 配置项；启用前评估邮件附件吞吐量。

## 防御建议

**网关侧**：
- 启用附件/正文图片 QR 解码，把解码出的 URL 加入正常 link 检测流程
- 对**正文几乎为空 + 含图片附件 + 关键词 "scan / mobile"** 的邮件直接 Medium 起步
- PDF 内只有一页且仅含 QR 码 + 一行文字，规则升级到 High

**用户培训**：
- **企业内部不会要求扫码完成桌面端任务**——HR 表单、合规承诺、密码重置都应在桌面浏览器完成
- 扫描可疑 QR 码后，**仔细看手机浏览器地址栏**：是 `login.microsoftonline.com` 还是 `login-microsoft-secure.workers.dev`？
- 任何"必须用手机"、"桌面无法访问"是红旗

**IR 处置**：
- 受害者扫码并输入凭据后：立即重置密码 + 撤销所有 session（参考 [AiTM 钓鱼](./aitm-phishing) 的处置流程）
- 检查 Microsoft 365 邮箱规则、转发设置、新增 MFA 设备

## 员工识别要点

✅ 邮件让你「用手机扫码」完成桌面端工作 → 99% 是攻击
✅ "Mobile-only for security reasons" 是攻击者的标志性话术
✅ 扫码后看到 Microsoft 登录页前先核对地址栏域名

## ✅ Vigilyx 对该攻击的检测能力

> **结论：Vigilyx 内置 QR 码解码模块，把二维码绕过这个长期盲区直接补上——附件 / 内嵌图片中的 QR 码会被解码，得到的 URL 进入完整的 link 检测链路。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| **附件 QR 码解码** | `attach_qr_scan` 模块对 PNG/JPG/PDF 内嵌 QR 码自动解码，提取出的 URL 进入 link 检测流程 | `crates/vigilyx-engine/src/modules/attach_qr_scan.rs` |
| 解码后链接信誉检查 | 解码出的域名走 `intel` 模块查询本地 IOC + OTX/AbuseIPDB | `crates/vigilyx-engine/src/intel.rs` |
| AiTM 落地页指纹 | 若 QR 跳转最终落地到 Tycoon 2FA / EvilProxy，`landing_page_scan` 可识别 AiTM 反代特征 | `crates/vigilyx-engine/src/modules/landing_page_scan.rs` |
| 「mobile-only」话术识别 | `content_scan` 命中 `scan with mobile`、`mobile-only`、`QR code` + 紧迫感词组合 | `crates/vigilyx-engine/src/modules/content_scan/detectors.rs` |
| 正文文字稀少 + 图片为主 | `html_scan` 检测正文文字长度异常低（剥离 HTML 标签后 < 阈值）但含大图片 → 图片钓鱼信号 | `crates/vigilyx-engine/src/modules/html_scan.rs` |
| PDF 单页仅 QR 检测 | `attach_content` 对 PDF 解析后页数 = 1 且解码出 QR 时直接升级 | `crates/vigilyx-engine/src/modules/attach_content.rs` |

**实战表现**：传统邮件网关只扫描 HTML 中的 `<a href>`，对图片/PDF 中的 QR 码完全无视；Vigilyx 把 QR 解码作为附件分析的一等公民，**让攻击者用图片绕过链接扫描的整个攻击思路失效**。

## 参考资料

- Cisco Talos, "Quishing: A new phishing technique", 2023-10
- Sophos X-Ops, "QR code phishing campaigns 2024 in review", 2024-12
- Abnormal Security, "QR Code Phishing Trends Q4 2024", 2024-12
- Microsoft Defender for Office 365 Blog, "Stopping QR code phishing at scale", 2025-03
