---
title: 快速开始
description: 使用 Docker Compose 快速启动 Vigilyx 的旁路镜像模式或 Inline MTA 模式。
---

# 快速开始

新服务器按 [首次部署](/zh/docs/deployment) 操作；已有环境（例如 0.9.3 → 0.9.4）使用 [更新与回退](/zh/docs/updating)。

仓库目前支持两套启动方式：

- 推荐：远程优先的 `deploy.sh` 工作流
- 备选：直接在目标主机上手工执行 `docker compose`

## 推荐工作流：deploy.sh

这条路径与仓库当前的主部署流程一致。

```bash
# 1. 让 deploy.sh 知道目标主机
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf

# 2. 在目标主机预拉取固定的 Rust builder 镜像
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"

# 3. 一次性初始化
./deploy.sh --init

# 4. 检查远端运行配置
ssh root@<server> "cd <repo-root> && vi deploy/docker/.env"
# 旁路模式：设置 SNIFFER_INTERFACE
# 可选：AI_ENABLED=true、HF_ENDPOINT=https://hf-mirror.com
# MTA 模式：设置 MTA_DOWNSTREAM_HOST、MTA_DOWNSTREAM_PORT、MTA_LOCAL_DOMAINS
# 如果 SMTP 客户端在其他主机，将 MTA_LISTEN 设为目标宿主机网卡 IP（默认 127.0.0.1）
# MTA 模式还需要远程 deploy/docker/certs/mta.crt + mta.key（PEM）

# 5. 首次完整部署，二选一
./deploy.sh --production
# ./deploy.sh --production --mta  # 需先安装 MTA TLS 文件
# 新环境使用内置 HTTPS 时加 --tls；否则配置宿主机反代。
```

使用 `./deploy.sh --mta` 时，必须先在目标服务器的 `<repo-root>/deploy/docker/certs/mta.crt` 与 `mta.key` 放好证书和私钥；TLS 材料会被源码同步故意排除。该命令会停止旁路数据面。如需切回旁路模式，在远程 `.env` 中设置 `VIGILYX_MODE=mirror`，再执行 `./deploy.sh`。

`./deploy.sh` 是推荐的日常路径。它会保留文件时间戳地同步仓库，在远端 `vigilyx-rust-builder` 里执行 clippy 和 workspace 测试；涉及前端时还会执行前端测试及 TypeScript/Vite 构建，随后打包镜像、重启当前拓扑，并检查 `/api/health/ready`。

## 备选：手工 Docker Compose

## 1. 生成密钥和密码

在项目根目录执行：

```bash
bash scripts/generate-secrets.sh
```

这会生成 `deploy/docker/.env`，里面包含随机密码和密钥。

## 2. 修改部署配置

打开 `deploy/docker/.env`，按你的环境调整配置。

常见项：

- `SNIFFER_INTERFACE`：旁路模式抓包网卡
- `AI_ENABLED=true`：启用可选 AI 服务
- `HF_ENDPOINT=https://hf-mirror.com`：中国大陆环境的 HuggingFace 镜像
- `MTA_DOWNSTREAM_HOST` 与 `MTA_DOWNSTREAM_PORT`：Inline MTA 下游地址
- `MTA_LOCAL_DOMAINS` 以及 `deploy/docker/certs/mta.crt` / `mta.key` PEM 文件：MTA 的安全默认值要求 TLS，私钥权限应保持为 `600`
- `MTA_LISTEN` 默认是 `127.0.0.1`；其他主机要连接 SMTP 时，将它设为目标宿主机网卡 IP

## 3. 构建容器

```bash
cd deploy/docker
docker compose --profile mirror build
# 如果只部署 MTA，改用：docker compose --profile mta build
```

## 4. 启动需要的模式

旁路镜像模式：

```bash
docker compose --profile mirror up -d
```

旁路镜像模式 + AI：

```bash
docker compose --profile mirror --profile ai up -d
```

Inline MTA 模式：

```bash
# 首次启动前在仓库根目录放置证书。
# 如果 SMTP 客户端来自其他主机，先在 deploy/docker/.env 中设置 MTA_LISTEN=<宿主机网卡IP>。
cd /path/to/Vigilyx
install -d -m 700 deploy/docker/certs
install -m 644 /path/to/fullchain.pem deploy/docker/certs/mta.crt
install -m 600 /path/to/private-key.pem deploy/docker/certs/mta.key
cd deploy/docker
docker compose --profile mta up -d
```

如果只执行 `docker compose up -d`，会启动控制面容器（`vigilyx`、`postgres`、`redis`），并运行一次性的 PostgreSQL 迁移、角色初始化和审计账户初始化任务。要处理真实流量，必须显式加 `--profile mirror` 或 `--profile mta`。直接执行 profile 命令不会停止已由另一 profile 启动的数据面；切换拓扑时请用部署脚本。

## 5. 打开界面

- HTTPS 入口：配置宿主机反向代理或启动内置 `tls` profile 后访问 `https://<server-or-domain>`
- 本机 API 调试入口：`http://127.0.0.1:8088`

内置 TLS 示例：

```bash
docker compose --profile mirror --profile tls up -d
```

登录信息：

- 全新数据库首次登录用户名：默认 `admin`，除非 `.env` 中设置了 `API_USERNAME`
- 全新数据库首次登录密码：`deploy/docker/.env` 里的 `API_PASSWORD`

一旦在界面中修改过密码，数据库中的凭据会优先生效；只修改 `API_PASSWORD`
不会轮换已存在账户的密码。

一次性初始化还会在审计账户不存在时创建独立的 `AUDIT_USERNAME` 账户。只应通过授权的服务器会话读取 `AUDIT_BOOTSTRAP_PASSWORD`，用它完成首次审计登录后立即更换。后续初始化不会覆盖已有账户，也不会轮换其密码。

## 说明

- 生产环境建议保持 `API_LISTEN=127.0.0.1`，然后在前面接 Caddy 或 Nginx 做 TLS。
- 不要假设有默认密码，`API_PASSWORD` 必须显式设置。
- AI 是可选增强项，不开启 AI 时核心检测链依然可运行。
- 用 `curl -fsS http://127.0.0.1:8088/api/health/ready` 验证处理流量的部署；公开路由必须带 `/api` 前缀，不能写成 `/health/ready`。

如果你需要更详细的部署说明，继续看 [部署说明](/zh/docs/deployment)。
