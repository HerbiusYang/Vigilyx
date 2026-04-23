---
title: Project Site
description: How the Vigilyx public site is built and deployed with GitHub Pages, including default URLs and custom domain variables.
---

# Project Site

The public Vigilyx website and docs live in `site/` and are built with VitePress.

## What gets committed

This repository stores only the site source:

- `site/index.md`
- `site/docs/*.md`
- `site/.vitepress/*`
- `site/public/*`

Generated output such as `site/.vitepress/dist` is ignored and is not committed to the repository.

## How publishing works

GitHub Pages is deployed through the workflow at `.github/workflows/pages.yml`.

The workflow:

1. Installs the `site/` dependencies
2. Builds the VitePress output
3. Uploads the built artifact to GitHub Pages
4. Deploys without committing `dist` back into the repository

This keeps the main branch clean while still letting the site source stay versioned with the product code.

## Default URL

Without a custom domain, the site is published under the repository path:

```text
https://herbiusyang.github.io/Vigilyx/
```

The docs root is:

```text
https://herbiusyang.github.io/Vigilyx/docs/
```

The Simplified Chinese site is:

```text
https://herbiusyang.github.io/Vigilyx/zh/
```

## Custom domain variables

The workflow supports three repository variables.

### `PAGES_CUSTOM_DOMAIN`

Use this when you want the site to publish at the domain root, for example:

```text
vigilyx.example.com
```

If this variable is set, the workflow writes `CNAME` automatically and uses `/` as the site base path.

### `PAGES_SITE_URL`

Use this when you want to override the final canonical URL explicitly.

Example:

```text
https://docs.vigilyx.example.com/
```

### `PAGES_BASE_PATH`

Use this only when the published site should live under a path prefix.

Example:

```text
/Vigilyx/
```

## Local preview

Run the site locally from the repository root:

```bash
cd site
npm ci
npm run dev
```

To build it locally:

```bash
cd site
npm run build
```
