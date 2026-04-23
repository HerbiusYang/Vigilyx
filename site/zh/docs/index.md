---
title: 概览
description: Vigilyx 产品概览，包含旁路镜像模式、MTA 代理模式以及核心检测流水线说明。
---

# 概览

Vigilyx 是一个 Rust 驱动的邮件安全网关与邮件安全分析平台，支持两种运行方式：

- **旁路镜像模式**：在投递后做流量分析、告警与审计
- **MTA 代理模式**：在最终投递前做 Inline SMTP 决策

这个项目更偏工程化安全系统，而不是单纯的“AI 一把梭”：

- 判定结果应当可解释
- 误报和漏报应当能持续回归
- 规则与融合逻辑应当方便迭代
- 即使关闭 AI，核心检测链也要能稳定运行

## 核心能力

- SMTP 与 MIME 解析
- 旁路会话重组
- Inline MTA 检测
- 多模块威胁检测
- DLP 与 YARA
- 附件与链接分析
- 自动化响应与告警
- Web 控制台与审计流

## 源码

- 仓库： [HerbiusYang/Vigilyx](https://github.com/HerbiusYang/Vigilyx)
- 许可：`AGPL-3.0-only`

## 继续阅读

- [快速开始](/zh/docs/quick-start)
- [部署说明](/zh/docs/deployment)
- [架构说明](/zh/docs/architecture)
