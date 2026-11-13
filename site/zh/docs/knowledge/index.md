---
title: 邮件威胁知识库
description: 邮件与身份攻击模式的简要摘要及来源标注。
---

# 邮件威胁知识库

本页汇总站点知识卡描述的威胁模式。下列来源名称、时间和严重度来自知识卡元数据，可作为进一步查阅的线索；它们不是正式参考文献，也不代表 Vigilyx 对相关攻击的检测效果保证。

<KnowledgeGrid />

<a id="clickfix"></a>
## 01 · ClickFix / Fake CAPTCHA

伪造的人机验证页面诱导收件人复制并运行攻击者提供的命令，使执行过程脱离常规附件处理链路。

- 卡片列出的来源：Proofpoint、CISA、Microsoft
- 时间范围：2024–2025
- 卡片严重度：高

<a id="device-code-phishing"></a>
## 02 · Storm-2372 设备码钓鱼

攻击流程滥用 OAuth 设备授权：受害者在合法登录页面输入攻击者提供的设备码，可能由此授予攻击者访问权限。

- 卡片列出的来源：Microsoft Threat Intelligence
- 时间标签：2025 年 2 月
- 卡片严重度：严重

<a id="quishing"></a>
## 03 · Quishing / QR 码钓鱼

钓鱼 URL 放在二维码图片中；只检查文本链接的控制措施可能无法直接看到目标地址。

- 卡片列出的来源：Cisco Talos、Sophos
- 时间范围：2024–2025
- 卡片严重度：高

<a id="html-text-cloaking"></a>
## 04 · HTML 拼凑文字与同形字符混淆

HTML 和 Unicode 技巧可能让页面渲染内容与简单关键词扫描看到的文本不同。卡片列出的手法包括零宽字符、字符实体、隐藏元素和外形相似的字符。

- 卡片列出的来源：Microsoft、Cofense、Sophos
- 时间范围：2024–2025
- 卡片严重度：高

<a id="html-smuggling"></a>
## 05 · HTML Smuggling 走私

HTML 附件可以通过浏览器端 JavaScript 和 Blob URL 重建载荷或触发下载，使部分投递过程发生在浏览器中。

- 卡片列出的来源：Microsoft、Mandiant、HP Wolf
- 时间范围：2024–2025
- 卡片严重度：严重

<a id="aitm-phishing"></a>
## 06 · Tycoon 2FA / EvilProxy AiTM 钓鱼

攻击者中间人代理转发登录和 MFA 交互，并可能在认证后窃取会话 Cookie。

- 卡片列出的来源：Proofpoint、Mandiant、Sekoia
- 时间范围：2024–2025
- 卡片严重度：严重

<a id="vendor-email-compromise"></a>
## 07 · VEC 供应商邮箱入侵

被控制的供应商邮箱可用于接续真实发票邮件往来，并要求将款项支付到变更后的账户。发件人身份有效本身不能证明付款请求可信。

- 卡片列出的来源：FBI IC3、Abnormal Security
- 时间范围：2024–2025
- 卡片严重度：高

<a id="toad-callback-phishing"></a>
## 08 · TOAD 回拨电话钓鱼

纯文本邮件要求收件人拨打假客服号码。后续电话沟通可能施压诱导其安装远程管理软件或提供 OAuth 设备码。

- 卡片列出的来源：Proofpoint、Cisco Talos、CISA
- 时间范围：2024–2025
- 卡片严重度：高

## 内容范围

本页摘要描述攻击模式，不是已核实的事件记录或检测结果。运维使用检测或响应能力前，应查阅原始资料并验证当前部署配置。
