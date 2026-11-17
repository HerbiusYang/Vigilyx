---
title: Project Site
description: How the Vigilyx public site is built and deployed with GitHub Pages, including default URLs and custom domain variables.
---

# Project Site

The public Vigilyx website and docs live in `site/` and are built with VitePress.

## What gets committed

This repository stores only the site source:

- `site/index.md` and `site/zh/index.md`
- `site/docs/` and `site/zh/docs/`
- `site/.vitepress/`
- `site/public/`
- `site/package.json`, `site/package-lock.json`, and `site/scripts/postbuild.mjs`

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

The Simplified Chinese docs are:

```text
https://herbiusyang.github.io/Vigilyx/zh/docs/
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

## Remote preview

Use Node.js `24.19.0` and npm `12.0.2`, as pinned by the repository's `.nvmrc` and `site/package.json`.

Sync local site edits to the remote build host, then run the site there and use an SSH tunnel from the local machine:

```bash
# On the local workstation, from the repository root; replace these values
# with the SSH target and repository path used by your deployment.
REMOTE_HOST="root@your-server"
REMOTE_DIR="/path/to/VIGILYX"
rsync -az --exclude='node_modules' --exclude='.vitepress/cache' --exclude='.vitepress/dist' \
  site/ "${REMOTE_HOST}:${REMOTE_DIR}/site/"

# From the local workstation, start the preview on the remote host
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/site' && npm ci && npm run dev -- --host 127.0.0.1"

# In a second local terminal
REMOTE_HOST="root@your-server"  # set the same SSH target again in this terminal
ssh -L 5173:127.0.0.1:5173 "$REMOTE_HOST"
```

Repeat the `rsync` command after local edits; the remote VitePress server watches the synchronized files.

Build it on the remote host:

```bash
REMOTE_HOST="root@your-server"
REMOTE_DIR="/path/to/VIGILYX"
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/site' && npm ci && npm run build"
```
