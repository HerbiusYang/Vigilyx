---
title: 架构说明
description: Vigilyx 高层架构说明，覆盖 sniffer、engine、database、API、frontend、SOAR 与 inline MTA 路径。
---

# 架构说明

## 主链路

```text
Sniffer -> Redis Streams -> Engine -> PostgreSQL -> API/WebSocket -> Frontend
```

运行时拓扑可以拆成控制面加一个活动数据面：

- 控制面：`vigilyx` + PostgreSQL + Valkey/Redis
- 旁路数据面：`vigilyx-sniffer` + `vigilyx-engine-standalone`
- MTA 数据面：内嵌 inline engine 的 `vigilyx-mta`

整个项目由多个 Rust crate、一个 React 前端以及可选 Python AI 服务组成。

## 核心 crate

- `vigilyx-core`：共享模型、错误类型、安全基础类型
- `vigilyx-parser`：SMTP、MIME 与协议解析
- `vigilyx-sniffer`：抓包与旁路会话投递
- `vigilyx-db`：PostgreSQL 与 Redis 抽象
- `vigilyx-engine`：检测模块、verdict fusion、DLP、时序分析
- `vigilyx-api`：REST API、认证、指标与 WebSocket
- `vigilyx-soar`：告警与响应自动化
- `vigilyx-mta`：带内嵌引擎的 SMTP 代理

## 旁路路径

在 mirror 模式下，sniffer 负责抓流量并重组会话，再通过 Redis Streams 进入独立的 `vigilyx-engine-standalone` 容器。engine 把结果写入 PostgreSQL，最后由 API 与前端展示。

## Inline 路径

在 MTA 模式下，SMTP 代理在 `vigilyx-mta` 内接收邮件、解析消息、执行 Inline 检测，并决定是转发、隔离还是拒收。

## 设计原则

- 工程优先，而不是 AI 优先
- 判定要可解释
- 处置流与审计流可回放
- 抓包、检测、存储、展示边界清晰
- mirror 与 MTA 路径共享解析与检测逻辑

## 相关页面

- [概览](/zh/docs/)
- [快速开始](/zh/docs/quick-start)
- [部署说明](/zh/docs/deployment)
