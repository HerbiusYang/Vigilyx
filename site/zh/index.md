---
layout: home

title: Vigilyx
titleTemplate: Rust 驱动的邮件安全网关
description: Rust 驱动的邮件安全网关与邮件安全分析平台，支持旁路镜像分析、Inline MTA 检测、威胁发现与审计处置。

hero:
  name: Vigilyx
  text: 面向旁路分析与 Inline SMTP 决策的邮件安全网关
  tagline: 开源、Rust 驱动，并且按工程系统去构建，而不是按黑盒 appliance 去包装。可以先旁路观察，再逐步走向 Inline 决策，检测逻辑保持同一套。
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
  - title: 旁路镜像分析
    details: 抓取 SMTP、POP3、IMAP 与 Webmail 流量，不改现有邮件系统，做事后检测、告警与审计。
  - title: Inline MTA 决策
    details: 作为 SMTP 中继放在投递前链路，支持接受、隔离、拒收等实时判定路径。
  - title: 可解释检测栈
    details: 检测模块、证据融合、DLP、YARA、自动化响应与 verdict 逻辑都可以追踪、复盘与持续调优。
  - title: Rust 核心运行时
    details: 抓包、解析、检测、API 与 MTA 逻辑围绕同一套 Rust 栈构建，更适合做稳定的安全工程系统。
---

<HomeLanding locale="zh" />
