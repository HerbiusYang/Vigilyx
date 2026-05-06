---
title: AiTM 中间人钓鱼（Tycoon 2FA / EvilProxy）
description: 攻击者用反向代理实时转发凭据和 MFA 验证码，受害者完成登录后攻击者拿到 session cookie，完全绕过 MFA。
---

# 案例 06 — AiTM 中间人钓鱼（Tycoon 2FA / EvilProxy）

> **公开来源**：Proofpoint《EvilProxy MFA bypass》(2023 起持续)，Mandiant《Tycoon 2FA》(2024)，Sekoia.io《Tycoon 2FA infrastructure》(2024-Q4)，Microsoft Threat Intelligence 多次跟踪

## 背景

AiTM（Adversary-in-the-Middle）钓鱼是当前**绕过 MFA 最高效的工业化手段**。攻击者搭建反向代理（Tycoon 2FA、EvilProxy、Mamba 2FA、Greatness、Strox 等钓鱼即服务平台），实时把受害者输入的凭据 + MFA 验证码转发到真实 Microsoft 365 / Google Workspace 登录页，登录成功后**复制返回的 session cookie**——攻击者从此可以在自己的浏览器复用 cookie，无需再过 MFA。

2024 年起 Tycoon 2FA 服务托管的活跃 phishing 域名**每周新增数千个**，单次订阅 200-300 美元，极大降低了攻击门槛。

## 攻击链

```
邮件含登录链接（伪装成 voicemail / DocuSign / Teams 邀请）
  → Cloudflare Turnstile / reCAPTCHA 验证（过滤沙箱）
    → 跳转到 Tycoon/EvilProxy 反向代理域
      → 受害者看到与真实 Microsoft 一模一样的登录页（实时代理渲染）
        → 输入账号密码 → 代理实时转发到 login.microsoftonline.com
          → MS 弹出 MFA → 受害者完成 MFA
            → 攻击者代理拿到 session cookie
              → 注入到攻击者浏览器 → 完全接管账号
                → 添加新 MFA 设备 + 邮件转发规则 → 内部钓鱼 / BEC
```

## 邮件特征

| 维度 | 信号 |
| --- | --- |
| 主题 | "Voicemail received"、"DocuSign: Please review"、"Microsoft Teams: New message"、"Shared file: Quarterly Report" |
| 链接 | 多层跳转：邮件 → URL shortener / Cloudflare Worker → Turnstile → AiTM 域 |
| AiTM 域名 | 大量使用同形子域：`login-microsoftonline.<random>.com`、`mfa-verify.<workers.dev>` |
| 域名年龄 | 域名注册时间通常 < 7 天 |
| TLS 证书 | 自动从 Let's Encrypt 申请，证书完全有效 |

### 动画演示

<AttackSimulation
  title="Tycoon 2FA / EvilProxy AiTM 钓鱼"
  :interval="2400"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "购买 Tycoon 2FA 订阅", en: "Buy a Tycoon 2FA subscription" },
      detail: { zh: "200-300 美元/月，自动生成钓鱼域、TLS 证书、反向代理后端", en: "$200-300/mo, auto-generates phishing domain, TLS cert, reverse-proxy backend" }
    },
    {
      actor: "attacker",
      title: { zh: "投递「voicemail / 文档共享」钓鱼邮件", en: "Send voicemail / document-share phishing email" },
      payload: "https://bit.ly/3xY → Cloudflare Worker → mfa-secure.<random>.com"
    },
    {
      actor: "victim",
      title: { zh: "点击链接 → 看到 Microsoft 登录页", en: "Click link → see a Microsoft login page" },
      detail: { zh: "页面是反向代理实时渲染的，与真实 login.microsoftonline.com 像素级一致", en: "The page is proxy-rendered, pixel-identical to login.microsoftonline.com" }
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
      title: { zh: "完成 MFA（短信/Authenticator）", en: "Complete MFA (SMS / Authenticator)" }
    },
    {
      actor: "attacker",
      title: { zh: "拿到 session cookie 并注入浏览器", en: "Steal session cookie + inject into attacker browser" },
      detail: { zh: "完全接管账号，无需再过 MFA；立即添加邮件转发规则与新 MFA 设备", en: "Full account takeover, no MFA needed; immediately add forward rule + new MFA device" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在邮件层就拦截", en: "Vigilyx blocks at the email layer" },
      detection: { zh: "link_scan 检测 URL shortener + Cloudflare Worker 多层跳转 + landing_page_scan 抓取最终落地页识别 AiTM 反代特征（CSP 残缺/资源跨域指纹）+ intel 命中 Tycoon 已知基础设施 + content_scan 命中 voicemail/MFA 钓鱼词，多模块收敛后 DS-Murphy 判 High 或 Critical", en: "link_scan detects URL shortener + Cloudflare Worker hop chain, landing_page_scan fetches the final page and identifies AiTM proxy fingerprints (CSP holes, cross-origin asset signatures), intel matches known Tycoon infrastructure, content_scan triggers on voicemail/MFA phishing terms; DS-Murphy fuses to High or Critical" }
    }
  ]'
/>

## ✅ Vigilyx 对该攻击的检测能力

> **结论：Vigilyx 通过「URL 跳转链分析 + 落地页指纹 + 已知基础设施情报」三层组合，对 Tycoon/EvilProxy 类工业化钓鱼平台的检出率显著高于纯靠域名黑名单的传统网关。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| URL 多跳分析 | `link_scan` 跟踪 redirect 链，识别 shortener + Cloudflare Worker + 同形域组合 | `crates/vigilyx-engine/src/modules/link_scan.rs` |
| 落地页内容指纹 | `landing_page_scan` 抓取最终页面，匹配 AiTM 反代特征（缺失 CSP、跨域资源签名异常） | `crates/vigilyx-engine/src/modules/landing_page_scan.rs` |
| AiTM 专项检测 | `aitm_detect` 模块对 HTML 中 OAuth 登录表单的 action 域名做异常分析 | `crates/vigilyx-engine/src/modules/aitm_detect.rs` |
| 新注册域名识别 | `intel` 模块查询 WHOIS/RDAP，域名年龄 < 7 天提升风险 | `crates/vigilyx-engine/src/intel.rs` |
| Tycoon 基础设施 | OTX/AbuseIPDB 持续标记 Tycoon 2FA 已知 IP/域，`intel` 命中即 critical | `crates/vigilyx-engine/src/intel.rs` |
| voicemail/MFA 主题词 | `content_scan` 内置 voicemail/MFA/document-share 钓鱼词集 | `crates/vigilyx-engine/src/modules/content_scan/detectors.rs` |

**实战表现**：在 2025 年公开的多次大规模 Tycoon 2FA 浪潮中，Vigilyx 用户的拦截率主要由 `landing_page_scan` 的 AiTM 指纹模块贡献——即使是当天新注册的全新域名（无情报覆盖），落地页一抓取仍能识别。

## 防御建议

**身份层（最重要）**：在 Entra ID Conditional Access 配置 **Phishing-Resistant MFA**（FIDO2 硬件令牌、Passkey、Windows Hello），物理上让 AiTM 失效——FIDO2 协议把 origin 绑定到硬件签名，反向代理域名永远签不出来。

**网关侧**：把 `landing_page_scan` 设为强制启用；对 URL 跳转链 ≥ 3 跳的邮件直接 Medium 起步。

**用户培训**：登录任何 Microsoft 服务前先看地址栏域名是否是 `login.microsoftonline.com` 或 `login.live.com`，其他都是攻击。

## 员工识别要点

✅ 任何"voicemail / shared document / Teams new message"邮件让你登录 Microsoft → 先停下
✅ 登录页地址栏看到非 `microsoft.com / live.com / microsoftonline.com` 的域名 → 不要输入
✅ Microsoft 登录页应该出现在 microsoftonline.com，不是 workers.dev / pages.dev / netlify.app

## 参考资料

- Proofpoint, "EvilProxy MFA bypass campaigns", 2023 至今
- Mandiant, "Tycoon 2FA: An In-Depth Analysis of a New Phishing-as-a-Service", 2024
- Sekoia.io, "Tycoon 2FA infrastructure update", 2024-Q4
- Microsoft Threat Intelligence Blog, "DEV-1101 enables high-volume AiTM campaigns", 2024
