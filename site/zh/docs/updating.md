---
title: 更新与回退
description: 已有 Vigilyx 环境的版本更新：备份、保留配置、构建迁移、验收与失败回退。
---

# 更新与回退

本页用于已安装的环境。新服务器请从 [首次部署](/zh/docs/deployment) 开始。

## 示例：0.9.3 升级到 0.9.4

正式发布后，在操作端获取最终发布源码：

```bash
git clone --branch v0.9.4 --single-branch \
  https://github.com/HerbiusYang/Vigilyx.git Vigilyx-0.9.4
cd Vigilyx-0.9.4
git rev-parse HEAD
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
${EDITOR:-vi} deploy.conf
```

填入**原服务器、原部署目录**并核对发布 commit。0.9.3 示例目录是 `/home/vigilyx`，新示例是 `/home/CCAB_VIGILYX`，更新时必须保留实际旧路径。然后按下方第 1 步完成备份。

0.9.3 的 Rust 为 1.97.1，0.9.4 为 1.98.0，因此这次需要更新构建容器。在操作端执行：

```bash
ssh root@<server> \
  "docker pull rust:1.98.0-bookworm@sha256:e70e2eec3d495fd5c8e0be74adda86507dfac7f51a724fbf9813ff59b2b247c7"
./deploy.sh --init
# 保留并检查远程原 .env，再执行完整更新：
./deploy.sh --production
```

脚本会补齐新增 PostgreSQL/Redis 角色凭据、独立配置加密密钥和审计初始化账户，再协调角色、执行 schema 迁移。这次不能只执行 `--frontend` 或 `--config-only`。两个版本均使用 PostgreSQL 17，保留数据库卷，无需 SQLite 转换，也不要执行 `down -v`。

**旧集成密钥需要单独处理**：0.9.3 的 SMTP/AI 等配置可能使用 JWT 派生的旧 `ENC:` 密文，新 worker 需要独立密钥的 `ENC:v2:`。部署脚本不会自动转换。升级前准备原集成凭据并保留原 `API_JWT_SECRET`；更新后在对应设置中重新输入真实凭据并保存，再按批准的流程测试集成。仅保留掩码或空白字段不会转换旧密文。缺少原凭据时，应先解决这一项再升级依赖该集成的环境。

最后按第 4 步验收，使用原账户登录；新增独立审计账户首次登录后改密。失败时使用源码包 `UPDATING.md` 中专门的 **Recover 0.9.3** 流程：旧版会在启动时初始化数据库，且使用旧 Redis 认证，因此要恢复到新的空库并恢复配套 Redis 配置，不能只回退应用镜像。

## 1. 准备版本与备份

获取完整的新版本源码，记录发布 commit 或源码包校验值。操作端的 `deploy.conf` 应指向原服务器、原部署目录；不要把新版本部署到另一个空目录。所有编译、测试仍在远端执行。

在服务器上按仓库 [`UPDATING.md` 的第 2 步](https://github.com/HerbiusYang/Vigilyx/blob/main/UPDATING.md#2-record-and-back-up-the-existing-deployment--server) 保存当前配置、确切镜像 ID 和逻辑数据库备份。该文件也随源码包提供，不需要依赖 GitHub 执行。确认备份完成，再进入部署窗口；大库备份可能耗时很长。

保留远程 `.env`、密码、加密密钥、运行模式、抓包网卡、TLS 文件、模型卷和数据库参数。对照新 `deploy/docker/.env.example` 检查新增配置，**不要覆盖 `.env`，不要重新生成密钥**。脚本只会补齐缺少的运行角色/审计初始化密钥，保留已有值。已有账户的密码以数据库为准。

## 2. 检查构建环境

在操作端执行：

```bash
ssh root@<server> "docker exec vigilyx-rust-builder rustc --version"
```

与新版本的 `rust-toolchain.toml` 比较。只有构建容器缺失或固定工具链升级时，才按 `setup-builder.sh` 中的精确镜像先拉取镜像，再执行 `./deploy.sh --init`。它会保留已有 `.env` 和 Cargo 缓存。普通更新不需要初始化。

## 3. 执行更新

在操作端新版本仓库根目录执行：

```bash
./deploy.sh --production
```

这是完整版本更新入口，沿用远程模式，已有 MTA 环境会连同内嵌引擎一起更新。`--mta` 用于显式选择或切换 MTA，不是所有更新都要加。已有 HTTPS 反代继续沿用；只有需要新建内置 TLS 入口时才添加 `--tls`。

后续小范围改动可使用：

| 改动 | 命令 | Schema 迁移 |
|---|---|---|
| API / 引擎 / 数据库 | `./deploy.sh --production --backend` | 执行 |
| 前端 | `./deploy.sh --production --frontend` | 执行；生产 API 镜像也会编译 Rust |
| 旁路 sniffer | `./deploy.sh --production --sniffer` | 不执行 |
| 仅运行配置 | `./deploy.sh --config-only` | 不执行，复用现有镜像 |

不加 `--production` 是开发用的 `release-fast` 路径；快速前端更新会复用 API 二进制并跳过迁移。新版本发布采用完整更新。

部署会暂停当前 API/数据面，协调 PostgreSQL、Valkey 和运行角色，再恢复服务。因此定向更新也应安排维护窗口。迁移锁默认等待 15 秒；备份或长事务占锁时应等待其完成后重试。不要跳过失败的检查。

## 4. 验收

在服务器部署目录执行：

```bash
docker compose -f deploy/docker/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:8088/api/health/ready
python3 scripts/verify-deployment.py --mode mirror
# MTA 环境改用 --mode mta。
```

要求退出码为 0、readiness 为 `ready`、所选数据面运行且没有异常重启。旁路验收会核对数据库生效参数，并在最多 120 秒内确认邮件和 HTTP 队列积压连续两次不超过 100；pending 另行报告。

访问现有 HTTPS 页面，用原账户登录。有新 SMTP 流量时确认新记录持续进入；没有流量时将这一项记为待验证。MTA 环境另查 TLS 监听及经批准的正常邮件下游投递。记录本次镜像 ID 和最终退出码。

## 5. 失败恢复

迁移失败后脚本会尝试恢复原先运行的服务，这不等于自动回滚镜像或数据库。保留失败日志。确认旧应用兼容当前 schema 与认证方式、不会执行旧初始化逻辑且凭据没有轮换后，按源码包 [`UPDATING.md` 第 6 步](https://github.com/HerbiusYang/Vigilyx/blob/main/UPDATING.md#6-recover-a-failed-update--server) 使用已保存的配置与精确镜像 ID 回退应用。**0.9.3 不适用仅回退镜像的流程**，必须使用该文件中的专用恢复步骤。

Schema 不兼容或凭据已变更时，需要协调恢复数据库、配置与应用。先在独立主机验证备份恢复，评估备份后新增记录，再安排恢复。不要用旧版迁移器反向迁移，也不要通过删除数据卷尝试修复。
