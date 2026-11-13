---
title: 首次部署
description: 在新服务器上首次安装 Vigilyx：准备环境、初始化、选择运行模式、开启 HTTPS 与验收。
---

# 首次部署

本页用于新服务器。已有环境请按 [更新与回退](/zh/docs/updating) 操作，保留现有配置和数据。

## 准备环境

- 操作端：Bash、SSH、rsync、Python 3，以及完整版本源码和 lockfile。
- 目标服务器：Docker Engine 24+、Compose v2.20+、Bash、Python 3、rsync、OpenSSL。
- 配置 SSH 密钥登录和 Docker 操作权限，确认构建磁盘空间及抓包网卡。
- 目标服务器需要访问 OCI、Rust/crates、npm、Debian 软件源；需要代理时在服务器配置，操作端代理不会自动通过 SSH 传过去。

以下 `deploy.sh` 命令均在操作端仓库根目录执行，编译和测试在远程运行。

## 推荐工作流

仓库当前的主部署路径是 `deploy.sh`，不是在本地随手跑 `cargo` 或手工拼装镜像。

按顺序执行：

```bash
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
# 填写 VIGILYX_SERVER 和 VIGILYX_REMOTE_DIR。

ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init

# 路径必须与 deploy.conf 一致；检查远程生成的 .env。
ssh root@<server> "vi /home/CCAB_VIGILYX/deploy/docker/.env"
# 旁路：VIGILYX_MODE=mirror、SNIFFER_INTERFACE=<抓包网卡>。
# 当前不使用 Python AI 时设置 AI_ENABLED=false。

# 首次完整部署，二选一：
./deploy.sh --production
# ./deploy.sh --production --mta  # MTA 需先配置下游和安装证书
```

`--init` 只在 `.env` 不存在时生成密钥，准备构建容器并预编译，不启动应用。初始化后直接编辑远程 `.env`，不要再生成一遍密钥。首次必须完整部署，组件命令用于后续更新。

正式部署使用 `--production` 的完整 Dockerfile/release 构建；日常开发去掉它可用 `release-fast` 增量构建。脚本同步源码、运行相应测试、构建、协调数据库及角色、启动所选拓扑，并验收 readiness 与队列。手工 Compose 是另一条可选路径，详见仓库 `DEPLOYMENT.md`。

## HTTPS 与首次验收

新环境需要配置宿主机反向代理，或在首次命令中加 `--tls` 使用内置 Caddy，例如 `./deploy.sh --production --tls`。两者选一个，避免争用 80/443。默认 API 仅绑定 `127.0.0.1:8088`；部署完成不代表外网 HTTPS 已开通。

在服务器部署目录执行：

```bash
docker compose -f deploy/docker/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:8088/api/health/ready
python3 scripts/verify-deployment.py --mode mirror
# MTA 改用 --mode mta。
```

要求命令退出码为 0、readiness 返回 `{"status":"ready"}`、所选数据面运行。随后访问配置好的 HTTPS 入口。全新数据库使用 `.env` 中的 `API_USERNAME`（默认 `admin`）与 `API_PASSWORD` 登录并改密；独立审计账户使用 `AUDIT_USERNAME` 与 `AUDIT_BOOTSTRAP_PASSWORD` 首次登录后改密。现有账户密码以数据库为准。

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
./deploy.sh --production
# 或者在目标主机上直接执行：
  docker compose -f deploy/docker/docker-compose.yml --profile mirror up -d
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
./deploy.sh --production --mta
# 或者在目标主机上直接执行：
  docker compose -f deploy/docker/docker-compose.yml --profile mta up -d
```

MTA 的安全默认值要求先放置 `deploy/docker/certs/mta.crt` 与 `mta.key` PEM 文件（私钥权限 `600`）。`./deploy.sh --mta` 会持久化 `VIGILYX_MODE=mta` 并停止旁路数据面。直接执行 Compose 命令只会启动所选 profile，不会停止另一 profile 的容器，也不会持久化部署模式。切换拓扑时请使用部署脚本，或手动更新远程模式并明确停止旧数据面服务。

Compose 默认把 MTA 端口绑定到 `127.0.0.1`。如果 SMTP 客户端在其他主机，启动 MTA 前应在 `deploy/docker/.env` 中将 `MTA_LISTEN` 设为目标宿主机网卡 IP；仅本机使用时保留 loopback。

`./deploy.sh --sniffer` 只适用于旁路模式。如果远程环境已固定为 MTA 模式，脚本会报错；请显式修改 `VIGILYX_MODE`，不要借组件命令隐式切换流量处理拓扑。

如果只执行 `docker compose up -d`，会启动控制面服务（`vigilyx`、`postgres`、`redis`），并运行一次性的 PostgreSQL 迁移、角色初始化和审计账户初始化任务；不会自动启用旁路抓包或 Inline SMTP 决策。

## 当前拓扑说明

- 旁路模式会启动独立的 `vigilyx-engine-standalone` 容器，并与 `vigilyx-sniffer` 组成数据面。
- MTA 模式把引擎内嵌在 `vigilyx-mta` 中，不再走旁路模式的独立 engine 容器。
- 主 `vigilyx` 容器在两种拓扑里都承担 API / 前端控制面角色。

## 可选服务

- `--profile ai`：可选 NLP / 语义分析
- `--profile tls`：内置 Caddy 反向代理
- `--profile antivirus`：ClamAV 集成
- `--profile sandbox`：实验性 CAPEv2 沙箱
- `--profile read-cache`：可选的聚合查询临时 Valkey 缓存；需设置 `READ_CACHE_ENABLED=true`、独立的 `CACHE_REDIS_PASSWORD`，并至少将 `CACHE_SECURITY_STATS_ENABLED`、`CACHE_DELIVERY_STATS_ENABLED`、`CACHE_LOGIN_STATS_ENABLED`、`CACHE_SESSION_COUNTS_ENABLED` 之一设为 `true`。这些数据集开关默认均为 `false`。`deploy.sh` 不会自动启动此服务；在主机配置好 `.env` 后，运行 `docker compose -f deploy/docker/docker-compose.yml --profile read-cache up -d cache` 启动缓存。

直接使用 Compose 时，profile 负责启动容器，对应能力开关和凭据也必须配置。例如 AI 同时需要 `AI_ENABLED=true` 与 `ai` profile。使用 `deploy.sh` 做后端或数据面部署时，启用 AI 会启动 AI 服务；`--frontend` 保留 AI 服务当前运行状态。启用 ClamAV 时，后端/数据面部署会启动它，也可显式使用 `--antivirus`；`--frontend` 保留 ClamAV 当前运行状态。CAPEv2 提交需要同时配置沙箱 URL 和 API token。URL/进程沙箱分析为显式 opt-in，不属于默认 Inline MTA 判定路径。

`--antivirus` 会在本次部署所选组件之外追加 ClamAV；单独运行该参数时，`deploy.sh` 仍按默认值部署完整拓扑。若要单独启动 ClamAV，要求 API 和当前引擎容器已经带有 `CLAMAV_ENABLED=true`，然后运行 `docker compose -f deploy/docker/docker-compose.yml --profile antivirus up -d clamav`。如果刚把开关从 `false` 改为 `true`，还需重建当前引擎服务，例如运行 `./deploy.sh --backend --antivirus`。

除仅执行初始化的 `deploy.sh --init` 外，每次部署都会先暂停运行中的 API、engine、sniffer、MTA，再协调 PostgreSQL/Valkey 和数据库角色，成功或失败都会尝试恢复原运行状态；期间抓包会暂停。仅本次生成新 API 二进制时执行 schema 迁移（后端/完整部署及生产模式的前端构建）；快速前端、仅 sniffer 和配置部署保留已安装的 SQL 函数。后端/schema 变更请使用 `--backend` 或完整部署。部署不自动调整宿主机/网络设置。

## 生产建议

- API 尽量放在 TLS 反代后面，不直接裸露
- `deploy/docker/.env` 中所有密钥都显式设置
- 使用 `deploy.sh` 时保留其 PostgreSQL/Valkey、运行角色及独立审计身份协调步骤；本次生成新 API 二进制时才执行 schema 迁移。只启动新 API 容器会让新增的运行时密码未应用
- 仅通过授权的服务器会话读取自动生成的 `AUDIT_BOOTSTRAP_PASSWORD`，用 `AUDIT_USERNAME` 登录后立即更换；脚本只将它保留在权限为 `600` 的远程 `.env`
- 不要在 `pg_dump` 或长事务期间部署 schema 变更；迁移容器默认只等待 15 秒获取锁，宁可让部署失败，也不让排队的 DDL 堵住后续业务查询
- 部署验收会核对 PostgreSQL 生效参数；旁路模式还会等待最多 120 秒，要求邮件和 HTTP 两条队列的未消费积压连续两次不超过 100。在途 pending 单独报告，不能仅凭健康接口正常判断队列恢复
- 备份尽量存在同步代码目录之外；`deploy.sh` 也会排除顶层 `backups/`，防止 `rsync --delete` 删除运维备份
- 根据明确的网络设计选择 `mirror` 或 `mta`
- 只开启真正需要运维的可选服务
- Redis、PostgreSQL 和 sniffer 的健康状态要一起监控
- 启动后执行 `curl -fsS http://127.0.0.1:8088/api/health/ready` 验证整体 readiness

## 安装完成后

后续版本升级、定向组件更新、备份与回退均使用 [更新与回退](/zh/docs/updating)。

更多内部结构见 [架构说明](/zh/docs/architecture)。
