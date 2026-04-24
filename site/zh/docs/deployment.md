---
title: 部署说明
description: Vigilyx 部署说明，覆盖旁路镜像模式、MTA 模式、Docker Compose profiles 以及生产建议。
---

# 部署说明

Vigilyx 支持两种主要部署形态。

## 推荐工作流

仓库当前的主部署路径是 `deploy.sh`，不是在本地随手跑 `cargo` 或手工拼装镜像。

常用命令：

```bash
./deploy.sh
./deploy.sh --backend
./deploy.sh --frontend
./deploy.sh --sniffer
./deploy.sh --mta
./deploy.sh --production
./deploy.sh --production --mta
```

这条远程优先工作流会同步仓库、在远端 `vigilyx-rust-builder` 中验证 Rust 代码、日常用 `release-fast` 增量构建、打包镜像，并重启当前拓扑。手工 `docker compose` 仍然可以作为补充路径，或用于直接在单机目标主机上部署。

## 旁路镜像模式

如果你想先获得邮件流量可视化与分析能力，而不改现有邮件系统，使用旁路模式。

数据流：

```text
libpcap capture -> Redis Streams -> Engine -> PostgreSQL -> API/UI
```

适合：

- 事后分析
- 告警与审计
- 邮件流量取证
- Webmail 与数据安全检测

推荐 profile：

```bash
./deploy.sh
# 或者在目标主机上直接执行：
docker compose --profile mirror up -d
```

## MTA 代理模式

如果你希望在最终投递前做 SMTP 决策，使用 MTA 模式。

数据流：

```text
SMTP client -> vigilyx-mta -> inline engine -> quarantine/reject/relay -> downstream MTA
```

适合：

- 在最终投递前隔离邮件
- 对明确恶意邮件做 inline 拒收
- 做更接近网关形态的实时检测

推荐 profile：

```bash
./deploy.sh --mta
# 或者在目标主机上直接执行：
docker compose --profile mta up -d
```

如果只执行 `docker compose up -d`，只会启动控制面服务（`vigilyx`、`postgres`、`redis`），不会自动启用旁路抓包或 Inline SMTP 决策。

## 当前拓扑说明

- 旁路模式会启动独立的 `vigilyx-engine-standalone` 容器，并与 `vigilyx-sniffer` 组成数据面。
- MTA 模式把引擎内嵌在 `vigilyx-mta` 中，不再走旁路模式的独立 engine 容器。
- 主 `vigilyx` 容器在两种拓扑里都承担 API / 前端控制面角色。

## 可选服务

- `--profile ai`：可选 NLP / 语义分析
- `--profile tls`：内置 Caddy 反向代理
- `--profile antivirus`：ClamAV 集成
- `--profile sandbox`：实验性 CAPEv2 沙箱

## 生产建议

- API 尽量放在 TLS 反代后面，不直接裸露
- `deploy/docker/.env` 中所有密钥都显式设置
- 根据明确的网络设计选择 `mirror` 或 `mta`
- 只开启真正需要运维的可选服务
- Redis、PostgreSQL 和 sniffer 的健康状态要一起监控

## 正式发布路径

仓库里推荐的正式发布路径：

- `./deploy.sh --production`
- `./deploy.sh --production --backend`
- `./deploy.sh --production --frontend`
- `./deploy.sh --production --sniffer`
- `./deploy.sh --production --mta`

更多内部结构见 [架构说明](/zh/docs/architecture)。
