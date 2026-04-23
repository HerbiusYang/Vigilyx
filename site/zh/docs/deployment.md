---
title: 部署说明
description: Vigilyx 部署说明，覆盖旁路镜像模式、MTA 模式、Docker Compose profiles 以及生产建议。
---

# 部署说明

Vigilyx 支持两种主要部署形态。

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
docker compose --profile mta up -d
```

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
