---
layout: home

title: Vigilyx
titleTemplate: Rust 驱动的邮件安全网关
description: 按金融行业安全标准打造的 Rust 邮件安全平台。D-S + Murphy 证据融合、5 状态 HMM 做 BEC 阶段推断、Hawkes 自激过程时序建模、AitM MFA 绕过工具检测、HTML 像素艺术二维码解码、JR/T 0197-2020 金融 DLP——两种独立部署形态共用同一套可解释的检测栈。

hero:
  name: Vigilyx
  text: 在核心实现层面真正不一样的邮件安全网关
  tagline: 开源、Rust 驱动、可解释。不是加权求和，而是 D-S + Murphy 证据融合。单邮件判定之上再叠一整层跨时间窗（CUSUM、双速 EWMA、Hawkes、5 状态 HMM、通信图）。专门检测 AitM MFA 绕过工具、HTML 像素艺术二维码、以及 JR/T 0197-2020 金融数据安全分级合规。旁路镜像（被动）或 MTA 代理（Inline）二选一，同一套检测栈，不交给黑盒。
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/docs/quick-start
    - theme: alt
      text: 架构说明
      link: /zh/docs/architecture
    - theme: alt
      text: 部署方式
      link: /zh/docs/deployment

features:
  - title: Murphy 修正的 D-S 证据融合
    details: 不是加权求和，不是黑盒分类器。一套正经的 Dempster–Shafer 实现，配合 Murphy 权重平均修正和针对相关检测器的 Copula 折扣——同源同族的信号不会互相放大，每个 verdict 都能按引擎单独解释。用 Rust 自研，不是继承某个商用库。
  - title: 在单邮件判定之上的完整时序层
    details: CUSUM 累计漂移检测、双速 EWMA 基线漂移、带 mark 的 Hawkes 自激过程建模攻击期节奏、5 状态 HMM 推断 BEC / ATO 阶段（侦察 → 建信 → 执行 → 收割），还叠了一张有向通信图。多数邮件安全产品按"单封邮件"孤立判定——这套不是。
  - title: AitM 反向代理钓鱼检测
    details: 专门针对 2024 年起实战里真在用的 MFA 绕过工具（Tycoon2FA、EvilProxy、Evilginx3）做指纹——Cloudflare Workers / Pages 上的 DGA 托管、OAuth redirect_uri 不一致、Turnstile 验证码工具包指纹、Latin-Cyrillic 同形异义做品牌冒充。这一类钓鱼会完全绕过传统链接信誉库和附件扫描。
  - title: HTML 像素艺术与表格二维码检测
    details: 攻击者用 <table> 的 bgcolor 单元格"画"二维码、用浮动 <div> 配 background-color 拼出钓鱼文字——就是为了绕开 OCR 和沙箱图片扫描。Vigilyx 从 DOM 结构重建位图并用 rqrr 解码。正文里用 Unicode 方块字符拼出来的 ASCII-art 二维码用同一套流程解出来。
  - title: JR/T 0197-2020 金融 DLP，带真正的校验
    details: 按人民银行《金融数据安全分级指南》做 per-user / per-IP 累计追踪（C3 级 24h 内 ≥ 500 → High、C4 级 24h 内 ≥ 50 → Critical）。中国身份证 / 手机号 / 银行卡用边界感知的正则 `(?-u:\b)`，银行卡 Luhn 校验，IBAN 走 mod-97，18 位统一社会信用代码严格排除 I / O / Z / S / V——海外厂商和纯正则 DLP 多数漏掉的细节这里都有。
---

<HomeLanding locale="zh" />
