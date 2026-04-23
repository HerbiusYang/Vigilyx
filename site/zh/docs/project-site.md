---
title: 项目站点
description: Vigilyx 公共站点如何通过 GitHub Pages 构建和发布，包括默认 URL 与自定义域名变量说明。
---

# 项目站点

Vigilyx 的公共官网与文档存放在 `site/`，使用 VitePress 构建。

## 仓库中提交的内容

仓库里只保存站点源码：

- `site/index.md`
- `site/docs/*.md`
- `site/.vitepress/*`
- `site/public/*`

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

## 本地预览

从仓库根目录执行：

```bash
cd site
npm ci
npm run dev
```

本地构建：

```bash
cd site
npm run build
```
