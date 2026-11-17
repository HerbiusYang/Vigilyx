---
title: 项目站点
description: Vigilyx 公共站点如何通过 GitHub Pages 构建和发布，包括默认 URL 与自定义域名变量说明。
---

# 项目站点

Vigilyx 的公共官网与文档存放在 `site/`，使用 VitePress 构建。

## 仓库中提交的内容

仓库里只保存站点源码：

- `site/index.md` 和 `site/zh/index.md`
- `site/docs/` 和 `site/zh/docs/`
- `site/.vitepress/`
- `site/public/`
- `site/package.json`、`site/package-lock.json`、`site/scripts/postbuild.mjs`

构建产物，比如 `site/.vitepress/dist`，已经被忽略，不会提交到仓库。

## 发布方式

GitHub Pages 通过 `.github/workflows/pages.yml` 发布。

这条 workflow 会：

1. 安装 `site/` 的依赖
2. 构建 VitePress 产物
3. 把构建结果上传给 GitHub Pages
4. 发布站点，但不把 `dist` 回写进仓库

这样既保持主分支干净，也能让站点源码和产品代码保持同版本管理。

## 默认 URL

如果不绑定自定义域名，站点默认发布在仓库路径下：

```text
https://herbiusyang.github.io/Vigilyx/
```

英文文档入口：

```text
https://herbiusyang.github.io/Vigilyx/docs/
```

中文站点入口：

```text
https://herbiusyang.github.io/Vigilyx/zh/
```

中文文档入口：

```text
https://herbiusyang.github.io/Vigilyx/zh/docs/
```

## 自定义域名变量

workflow 支持三个仓库变量。

### `PAGES_CUSTOM_DOMAIN`

如果你希望站点直接发布在域名根路径，比如：

```text
vigilyx.example.com
```

设置这个变量后，workflow 会自动写入 `CNAME`，并把站点 base path 设为 `/`。

### `PAGES_SITE_URL`

如果你想显式覆盖最终 canonical URL，可以设置：

```text
https://docs.vigilyx.example.com/
```

### `PAGES_BASE_PATH`

如果站点需要发布在某个路径前缀下，可以设置：

```text
/Vigilyx/
```

## 远程预览

远程主机使用仓库 `.nvmrc` 固定的 Node.js `24.19.0` 和 `site/package.json` 要求的 npm `12.0.2`。

先把本地站点改动同步到远程构建主机，再从本机通过 SSH 隧道访问：

```bash
# 在本地仓库根目录执行；将目标替换为部署使用的 SSH 地址和远程仓库路径
REMOTE_HOST="root@your-server"
REMOTE_DIR="/path/to/VIGILYX"
rsync -az --exclude='node_modules' --exclude='.vitepress/cache' --exclude='.vitepress/dist' \
  site/ "${REMOTE_HOST}:${REMOTE_DIR}/site/"

# 从本地工作站通过 SSH 在远程主机启动预览
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/site' && npm ci && npm run dev -- --host 127.0.0.1"

# 在本机另一个终端
REMOTE_HOST="root@your-server"  # 在此终端重新设置相同的 SSH 地址
ssh -L 5173:127.0.0.1:5173 "$REMOTE_HOST"
```

本地每次修改站点后重新执行 `rsync`；远程 VitePress 会监听同步后的文件。

在远程主机构建：

```bash
REMOTE_HOST="root@your-server"
REMOTE_DIR="/path/to/VIGILYX"
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/site' && npm ci && npm run build"
```
