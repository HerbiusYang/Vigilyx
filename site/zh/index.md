---
layout: home

title: Vigilyx
titleTemplate: Rust 驱动的邮件安全网关
description: 按金融行业安全标准打造的 Rust 邮件安全平台。提供两种独立的部署形态——旁路镜像做可见性分析，或 Inline MTA 代理做实时拦截，两者共用同一套可解释的检测栈。

hero:
  name: Vigilyx
  text: 按金融行业安全标准打造的邮件安全网关
  tagline: 开源、Rust 驱动、可解释。根据环境选择合适的部署形态——可以做旁路镜像被动观察流量，也可以作为 Inline SMTP 代理在投递前接受、隔离或拒收邮件。同一套检测栈，两条独立路径，不交给黑盒。
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
  - title: 旁路镜像部署 — 被动分析
    details: 零侵入的监控形态。Vigilyx 部署在邮件系统旁边，从镜像口抓取 SMTP、POP3、IMAP、Webmail 流量，在邮件投递完成后产出判定，不阻塞邮件收发。适合做审计、取证、规则迭代，或者暂时不便改动主链路的环境。
  - title: MTA 代理部署 — 实时拦截
    details: 独立的部署形态。Vigilyx 作为 SMTP 中继放在最终邮件服务器之前，在投递前做 accept / quarantine / reject 决策，Inline 判定典型耗时 <2s，支持可配置的 fail-open 策略。适合可以接管邮件路径、且需要真正阻断的场景。
  - title: 同一检测栈，两种部署形态
    details: 两种部署共用同一套多模块检测流水线（解析、头部、内容、链接、附件、YARA、DLP、身份、证据融合、SOAR）。规则、IOC、调参与审计链都可以通用——唯一的区别是判定结果是"事后参考"（旁路）还是"投递前拦截"（MTA）。
  - title: Rust 核心运行时
    details: 抓包、解析、检测、API 与 MTA 逻辑围绕同一套 Rust 栈构建，更适合做稳定的安全工程系统。
---

<HomeLanding locale="zh" />
