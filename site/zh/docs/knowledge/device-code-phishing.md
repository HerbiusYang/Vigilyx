---
title: Storm-2372 Device Code 钓鱼
description: 2025 年 2 月 Microsoft Threat Intelligence 披露的 Storm-2372 攻击复盘——攻击者通过 Microsoft Teams / 邮件冒充身份，诱导受害者在合法 microsoft.com 设备登录页输入攻击者生成的设备码，从而劫持 OAuth 令牌。
---

# 案例 02 — Storm-2372 Device Code 钓鱼

> **公开来源**：Microsoft Threat Intelligence《Storm-2372 conducts device code phishing campaign》(2025-02-13)，CISA 后续转载，Volexity 跟进分析

## 背景

Storm-2372 是 Microsoft 跟踪的一个高度活跃的国家级威胁组织，自 2024 年 8 月起对国防、IT、电信、政府、NGO 行业（北美、欧洲、中东、非洲）发动**OAuth 设备码钓鱼**。

不同于传统钓鱼站点，攻击者**不仿冒登录页**——他们让受害者去**真实的 `https://microsoft.com/devicelogin`** 输入一个由攻击者预生成的 8 位设备码。一旦受害者完成 MFA，OAuth 访问令牌+刷新令牌被绑定到攻击者持有的"设备"，攻击者从此可以访问 Microsoft Graph、邮件、OneDrive、Teams 而无需再过 MFA。

## 攻击链

```
攻击者调用 OAuth /devicecode 端点
  → 拿到 user_code (8位) + device_code (机器用)
    → 通过 Teams / 邮件冒充 IT / 大使馆 / Defense 同事
      联系受害者，发送：
      "Please join the secure meeting:
       1. Open https://microsoft.com/devicelogin
       2. Enter code: ABC-DEF-GH"
    → 受害者在真实 microsoft.com 输入码 + 完成 MFA
      → 攻击者轮询 /token 端点拿到 access_token + refresh_token
        → 绑定到攻击者控制的"设备"
          → 持续访问邮件、OneDrive、SharePoint、Teams
            → 横向钓鱼内部联系人
```

设备码默认有效期 **15 分钟**，所以攻击者通常在生成码的同时立刻发出邮件/IM，并营造紧迫感。

### 动画演示

<AttackSimulation
  title="Storm-2372 设备码钓鱼全过程"
  :interval="2500"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "调用 OAuth /devicecode 端点", en: "Call OAuth /devicecode endpoint" },
      detail: { zh: "从 Microsoft 拿到合法的 8 位 user_code 和 device_code，有效期 15 分钟", en: "Microsoft returns a legitimate 8-char user_code + device_code, valid for 15 minutes" },
      payload: "POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode\n→ user_code: HXDF-7K9P"
    },
    {
      actor: "attacker",
      title: { zh: "从被攻陷邮箱发出会议邀请", en: "Send meeting invite from a compromised mailbox" },
      detail: { zh: "发件人是真实合作方邮箱，SPF/DKIM/DMARC 全通过，主题与受害者业务高度相关", en: "Sender is a real partner mailbox, SPF/DKIM/DMARC all pass, subject highly relevant to the victim" },
      payload: "Open https://microsoft.com/devicelogin\nEnter code: HXDF-7K9P\n(valid 15 min — meeting starts in 10)"
    },
    {
      actor: "victim",
      title: { zh: "受害者打开真实 microsoft.com", en: "Victim opens the real microsoft.com URL" },
      detail: { zh: "地址栏完全合法，证书合法，无任何浏览器警告", en: "Address bar is genuinely Microsoft, valid cert, zero browser warnings" }
    },
    {
      actor: "victim",
      title: { zh: "输入码 + 完成 MFA", en: "Enter code + complete MFA" },
      detail: { zh: "受害者完成多因素认证，认为只是加入了一个会议", en: "Victim completes MFA, believing they are joining a meeting" }
    },
    {
      actor: "attacker",
      title: { zh: "轮询 /token 端点取得令牌", en: "Poll /token endpoint to get tokens" },
      detail: { zh: "拿到 access_token + refresh_token，绑定到攻击者的「设备」", en: "Receives access_token + refresh_token, bound to attacker-controlled device" }
    },
    {
      actor: "attacker",
      title: { zh: "持续访问邮件 / OneDrive / Teams", en: "Persist access to mail / OneDrive / Teams" },
      detail: { zh: "通过 Microsoft Graph 长期访问，刷新令牌可续命数月，无需再过 MFA", en: "Long-term Graph API access; refresh token lasts months, no further MFA prompts" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 在投递阶段就拦下", en: "Vigilyx blocks at delivery time" },
      detection: { zh: "content_scan 命中专项规则（microsoft.com/devicelogin + device code + 紧迫感词同现）+ identity_anomaly 标记首次通信 + behavior_baseline 检测「该联系人首次提及 OAuth」+ DS-Murphy 多模块收敛 → 判 High", en: "content_scan triggers a dedicated rule (microsoft.com/devicelogin + device code + urgency together), identity_anomaly flags first-time communication, behavior_baseline notes the contact has never discussed OAuth before; DS-Murphy fuses these into a High verdict" }
    }
  ]'
/>

## 邮件样本（脱敏）

```
From: <真实被攻陷的同行/合作方邮箱>
To: target@victim.example
Subject: Joint working group session — please confirm attendance

Hi Bob,

We're starting a working session for the joint NATO advisory group in
about 10 minutes. Microsoft Teams requires a one-time device sign-in
because of the new federation policy.

Please:

  1. Open https://microsoft.com/devicelogin
  2. Enter the code:  HXDF-7K9P
  3. Sign in with your usual work account.

The code is valid for 15 minutes only. Let me know once you're in.

Best,
Sarah Chen
Policy Coordination, [真实组织名]
```

## 邮件特征

| 维度 | 信号 |
| --- | --- |
| 发件邮箱 | **常常是真实被攻陷的合法邮箱**（前一名受害者），SPF/DKIM/DMARC 全通过 |
| 主题 | 与受害者实际工作领域强相关（NATO、援助、防务、电信招标） |
| 正文链接 | **唯一外链就是 `microsoft.com/devicelogin`** —— 这是真实合法 URL |
| 关键词 | "device code"、"one-time code"、"sign in to join"、"federation policy" |
| 紧迫感 | 强调 15 分钟内必须完成、会议即将开始 |

> 这是该攻击最难检测的地方：**没有恶意域名，没有恶意附件，没有可疑链接**。

## Vigilyx 检测要点

针对 Storm-2372，Vigilyx 需要依赖**语义 + 上下文**而非传统 IOC：

| 模块 | 期望命中 | 说明 |
| --- | --- | --- |
| `content_scan` | 中 | 主题/正文同时含 `device code` + `microsoft.com/devicelogin` + 时间紧迫词 |
| `link_scan` | 低 | 链接本身合法，无法直接命中 |
| `identity_anomaly` | 中-高 | 历史首次通信 + 未来日期 + 未与发件人有过会议邀请 |
| `behavior_baseline` | 中 | 该联系人首次提及 device code / OAuth 类话题 |
| `nlp_phishing` (AI 启用时) | 高 | 微调模型对「OAuth 设备码 + 紧迫感」组合识别度高 |
| **D-S 融合** | **Medium-High** | 单独看每个信号都不强，需要多模块收敛 |

**关键规则建议**：在 `content_scan.rs` 里加一条**专项检测**——
邮件中同时出现以下两类关键词时直接升级到 High：
- 类 A: `microsoft.com/devicelogin`、`aka.ms/devicelogin`、`device code`、`one-time code`
- 类 B: 紧迫感词汇（`15 minutes`、`expires`、`right now`、`meeting starts`）

任何**让用户输入 OAuth 设备码**的邮件都应被视为高风险，无论发件人是谁。

## 防御建议

**身份层（最重要）**：
- 在 Entra ID Conditional Access 中**默认禁用设备码登录流**，仅对明确需要的用户/应用开白名单
- 配置告警：任何 `urn:ietf:params:oauth:grant-type:device_code` 类型的登录都触发 SOC 告警

**网关侧**：
- 邮件正文含 `microsoft.com/devicelogin` 或 `aka.ms/devicelogin` 时打标"OAuth 风险"，要求二次确认
- 对来自外部组织 + 主题含会议邀请 + 仅一条 microsoft.com 链接的邮件，提升到 Medium

**用户培训**：
- **微软不会**通过邮件让你打开 `devicelogin` 页面输入会议邀请码
- 加入 Teams 会议**永远是点击会议链接**，不是输入数字码

**IR 处置**：
- 一旦怀疑令牌被劫持：立即在 Entra ID 撤销该用户所有 refresh token (`Revoke-AzureADUserAllRefreshToken`)
- 检查最近 24 小时内 `Sign-in logs` 中 `authenticationProtocol = deviceCode` 的所有登录
- 检查 Microsoft Graph 审计日志中的 `Add app role assignment` / `Add OAuth2PermissionGrant`

## 员工识别要点

✅ 任何让你「打开 microsoft.com/devicelogin 输入码」的邮件都是攻击
✅ 真实 Teams 会议邀请永远是 `https://teams.microsoft.com/l/meetup-join/...` 链接
✅ "15 分钟内必须完成"是设备码钓鱼的天然紧迫感——感到被催促时立刻停下

## ✅ Vigilyx 对该攻击的检测能力

> **结论：Vigilyx 已针对 OAuth 设备码钓鱼专项加固，即使发件人是被攻陷的合法邮箱（SPF/DKIM/DMARC 全过），仍能通过语义 + 上下文识别。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| 设备码关键词专项规则 | `content_scan` 检测 `microsoft.com/devicelogin`、`aka.ms/devicelogin`、`device code`、`one-time code` 与紧迫感词同现 | `crates/vigilyx-engine/src/modules/content_scan/detectors.rs` |
| 首次通信检测 | `identity_anomaly` 查询历史会话表，发件人首次与受害者通信即提升风险 | `crates/vigilyx-engine/src/modules/identity_anomaly.rs` |
| 行为基线偏离 | `behavior_baseline` 检测发件人首次提及 OAuth/会议邀请类话题 | `crates/vigilyx-engine/src/modules/behavior_baseline.rs` |
| AI 语义理解（可选） | 启用 AI sidecar 后 `nlp_phishing` 模型对「OAuth + 紧迫感」组合识别度高 | `crates/vigilyx-engine/src/modules/semantic_scan.rs` + `python/vigilyx_ai/nlp_phishing.py` |
| 紧迫感语言模式 | `content_scan` 内置时间紧迫感模式（`15 minutes`、`expires`、`right now`） | `crates/vigilyx-engine/src/modules/content_scan/mod.rs` |
| 多模块收敛 | DS-Murphy 融合在所有信号都偏弱时仍能通过 `convergence_base_floor=0.40` 触发 Medium | `crates/vigilyx-engine/src/pipeline/verdict.rs` |

**实战表现**：传统网关因「无恶意域名 + SPF/DKIM 全通过」全部漏报；Vigilyx 通过**关键词专项规则 + 首次通信检测 + 紧迫感语言**的多信号融合，可稳定识别这类零信誉攻击。

## 参考资料

- Microsoft Threat Intelligence, "Storm-2372 conducts device code phishing campaign", 2025-02-13
- Volexity, "Multiple Russian Threat Actors Targeting Microsoft Device Code Authentication", 2025-02-13
- CISA, 引用 Microsoft 报告并加入 Known Exploited Techniques 跟踪
