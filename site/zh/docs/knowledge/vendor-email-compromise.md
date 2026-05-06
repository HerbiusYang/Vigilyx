---
title: VEC 供应商账户接管 BEC
description: 攻击者攻陷供应商真实邮箱后，用真实邮件线程修改收款账户实施发票欺诈，所有认证全过、无任何技术 IOC。
---

# 案例 07 — VEC（Vendor Email Compromise）供应商账户接管

> **公开来源**：FBI IC3《Internet Crime Report 2024》，Abnormal Security《VEC: The Most Costly BEC Variant》(2024)，Microsoft Digital Defense Report 2024

## 背景

VEC（Vendor Email Compromise）是 BEC 家族中**单笔损失最高**的变种。FBI IC3 2024 报告指出，BEC 类损失占全部网络犯罪损失的 38%，其中 VEC 单笔均损失超过 12 万美元，远高于普通 CEO 冒充。

攻击流程：攻击者通过钓鱼或 AiTM 接管供应商的邮箱 → 长期潜伏观察邮件往来（通常 1-3 个月）→ 在真实付款邮件线程中**回复修改的银行账户**，所有发件人、SPF/DKIM/DMARC、邮件签名、历史上下文全部正常。

## 攻击链

```
攻击者通过 [Tycoon 2FA AiTM 钓鱼](./aitm-phishing) 接管 vendor@partner.example
  → 设置 inbox 规则把"invoice / payment / wire / ACH"邮件转到隐藏文件夹
    → 长期潜伏（30-90 天），观察发票审批流程、对接人、金额范围
      → 在真实付款邮件线程中回复
        "Hi Bob, please note our bank changed accounts last month.
         New ACH details attached. Same routing process."
        → 提供攻击者控制的银行账户
          → 受害者公司财务付款
            → 攻击者通过 mule 账户洗钱 → 资金消失
```

## 邮件样本（脱敏）

```
From: Sarah Chen <sarah.chen@trusted-vendor.example>
To: ap@victim-corp.example
Cc: [真实历史 Cc 列表]
Subject: RE: RE: RE: Invoice INV-2025-0412 — Payment Confirmation

Hi Bob,

Thanks for confirming. One quick update — our finance team migrated
to a new banking provider last month and all wire payments going
forward should use the new ACH details. I've attached the updated W-9
and bank letter.

Routing: 026009593
Account: 4837291045
Bank: Bank of America

Sorry for the late notice — please let me know once the wire goes out
so I can update our records.

Thanks,
Sarah
```

注意点：**全部历史上下文真实**（之前的 RE: 链确实存在），发件人邮箱是真实的，签名格式与历史邮件一致，附件是攻击者制作的高质量伪造。

### 动画演示

<AttackSimulation
  title="VEC 供应商账户接管发票欺诈"
  :interval="2600"
  :steps='[
    {
      actor: "attacker",
      title: { zh: "钓鱼接管供应商邮箱（通常通过 AiTM）", en: "Compromise vendor mailbox (typically via AiTM)" }
    },
    {
      actor: "attacker",
      title: { zh: "潜伏 30-90 天，建立 inbox 规则隐藏告警", en: "Lurk 30-90 days, build inbox rules to hide alerts" },
      detail: { zh: "把 invoice/payment/wire/ACH 关键词邮件转到 RSS Feeds 文件夹", en: "Forward invoice/payment/wire/ACH keyword mail to RSS Feeds folder" }
    },
    {
      actor: "attacker",
      title: { zh: "学习审批流程、识别金额阈值与对接人", en: "Learn the approval workflow, amount thresholds, contacts" }
    },
    {
      actor: "attacker",
      title: { zh: "在真实邮件线程中回复修改银行账户", en: "Reply in a real thread, requesting bank-account change" },
      detail: { zh: "发件人真实、SPF/DKIM/DMARC 全过、历史上下文真实、签名格式真实", en: "Sender real, SPF/DKIM/DMARC pass, history real, signature real" }
    },
    {
      actor: "victim",
      title: { zh: "财务相信「这是 Sarah，我和她合作 3 年」", en: "AP trusts: this is Sarah, we have worked with her for 3 years" }
    },
    {
      actor: "victim",
      title: { zh: "向攻击者账户发起 ACH/电汇", en: "Wire/ACH to attacker-controlled account" }
    },
    {
      actor: "vigilyx",
      title: { zh: "Vigilyx 通过行为基线识别异常", en: "Vigilyx flags via behavior baselines" },
      detection: { zh: "behavior_baseline 检测「该联系人首次提及银行账户变更」+ content_scan 命中 banking_change 专项检测（routing/ACH/wire change combo）+ identity_anomaly 标记「reply 链虽真但内容首次涉及付款变更」+ attach_content 检测附件 W-9/银行函是新创建文件（PDF metadata 异常）。多模块收敛后判 High，AP 在付款前看到 Vigilyx 告警。", en: "behavior_baseline notices the contact has never discussed bank changes before, content_scan triggers banking_change rule (routing/ACH/wire change combo), identity_anomaly flags first-time payment-change content in an otherwise real thread, attach_content detects newly-created PDF metadata in the W-9. DS-Murphy fuses to High; AP sees the alert before paying." }
    }
  ]'
/>

## ✅ Vigilyx 对该攻击的检测能力

> **结论：VEC 是邮件安全领域最难检测的攻击——所有传统信号（发件人、SPF/DKIM、域名信誉、附件类型）都正常。Vigilyx 通过「行为基线 + 语义专项规则 + 附件元数据分析」覆盖这片盲区。**

| 能力项 | Vigilyx 实现 | 代码位置 |
| --- | --- | --- |
| 银行账户变更检测 | `content_scan` 专项规则：`routing` + `ACH` / `wire` + `change/update/new` 同现 → 直接 Medium | `crates/vigilyx-engine/src/modules/content_scan/detectors.rs` |
| 行为基线偏离 | `behavior_baseline` 查询历史会话表，「该联系人首次涉及付款变更话题」即提升风险 | `crates/vigilyx-engine/src/modules/behavior_baseline.rs` |
| 身份异常 | `identity_anomaly` 检测「reply 链虽真但首次出现付款变更/紧迫感语言」 | `crates/vigilyx-engine/src/modules/identity_anomaly.rs` |
| 附件元数据分析 | `attach_content` 检查 PDF/Office 文档的创建时间、作者、修改历史，新创建的「正式」文档可疑 | `crates/vigilyx-engine/src/modules/attach_content.rs` |
| 历史会话查询 | DB 索引支持快速查询发件人 ↔ 收件人的历史通信主题与频率 | `crates/vigilyx-db/src/infra/session.rs::count_sender_domain_history` |
| 跨组织回复链识别 | `header_scan` 解析 References / In-Reply-To，区分「真线程注入」vs「伪造回复」 | `crates/vigilyx-engine/src/modules/header_scan.rs` |

**实战表现**：传统网关对 VEC 几乎完全失效（所有认证全过、域名信誉正常）；Vigilyx 通过**「这个真实联系人从来没在邮件里聊过银行账户变更」**这种基线判断，在 2025 年的多个真实回放案例中成功提示给财务部门。

## 防御建议

**流程层（最重要）**：任何**银行账户变更**必须**电话回拨已知号码**确认（不是邮件签名上的号码）。这是防御 VEC 唯一可靠的方式。

**身份层**：要求所有合作供应商对其账户启用 FIDO2 / Passkey MFA，从源头降低供应商邮箱被攻陷的概率。

**网关侧**：开启 Vigilyx 的 banking_change + behavior_baseline 模块，对涉及 routing/ACH/wire 变更的邮件强制人工复核。

## 员工识别要点

✅ 邮件提到「我们换了银行账户」→ **必须电话回拨确认**，不要回邮件
✅ 紧迫感词（"please process today"、"sorry for the late notice"）+ 账户变更 = 极高风险
✅ 附件 PDF / W-9 创建时间是最近几小时 → 可疑

## 参考资料

- FBI IC3, "Internet Crime Report 2024", 2025-04
- Abnormal Security, "VEC: The Most Costly BEC Variant", 2024
- Microsoft Digital Defense Report 2024, BEC 相关章节
- US Treasury FinCEN, BEC red flags advisory
