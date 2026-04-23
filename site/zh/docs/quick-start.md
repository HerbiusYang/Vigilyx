---
title: 快速开始
description: 使用 Docker Compose 快速启动 Vigilyx 的旁路镜像模式或 Inline MTA 模式。
---

# 快速开始

下面是从仓库启动 Vigilyx 的最快路径。

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

## 3. 构建容器

```bash
cd deploy/docker
docker compose build
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
docker compose --profile mta up -d
```

## 5. 打开界面

- HTTPS 入口：`https://<server-or-domain>`
- 本机 API 调试入口：`http://127.0.0.1:8088`

登录信息：

- 用户名：默认 `admin`，除非 `.env` 中设置了 `API_USERNAME`
- 密码：`deploy/docker/.env` 里的 `API_PASSWORD`

## 说明

- 生产环境建议保持 `API_LISTEN=127.0.0.1`，然后在前面接 Caddy 或 Nginx 做 TLS。
- 不要假设有默认密码，`API_PASSWORD` 必须显式设置。
- AI 是可选增强项，不开启 AI 时核心检测链依然可运行。

如果你需要更详细的部署说明，继续看 [部署说明](/zh/docs/deployment)。
