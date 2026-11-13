# Contributing to Vigilyx

Thank you for your interest in contributing to Vigilyx.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Commit Message Conventions](#commit-message-conventions)
- [Pull Request Process](#pull-request-process)
- [Architecture Overview](#architecture-overview)
- [Where to Ask Questions](#where-to-ask-questions)

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:

```bash
git clone https://github.com/<your-username>/Vigilyx.git
cd Vigilyx
```

3. Create a branch for your changes:

```bash
git checkout -b feat/your-feature-name
```

Vigilyx uses a remote-first workflow: edit code locally, but run compilation, tests, and builds on the remote Linux host. Rust commands use the persistent `vigilyx-rust-builder` container created by `./deploy.sh --init`; frontend checks use `./deploy.sh --frontend`.

## Development Environment

### Prerequisites

| Environment | Tool | Purpose |
|-------------|------|---------|
| Local machine | SSH + rsync | Sync source code to the remote build host |
| Remote host | Node.js 24.19.0 + npm 12.0.2 | Frontend dependency install, tests, and build |
| Remote host | Docker and Docker Compose | Build container, runtime services, and containerized frontend builds |
| Remote host | Passwordless SSH access | Required by `deploy.sh` |

### Backend

The project is a Cargo workspace with eight crates:

```text
crates/
  vigilyx-core/      # Shared types and security primitives
  vigilyx-parser/    # SMTP/MIME parsing shared by sniffer and MTA
  vigilyx-sniffer/   # Network capture and protocol parsing
  vigilyx-db/        # PostgreSQL + Redis integration
  vigilyx-engine/    # Threat detection engine and fusion pipeline
  vigilyx-api/       # REST API + WebSocket (axum)
  vigilyx-soar/      # Alerting and disposition logic
  vigilyx-mta/       # Inline SMTP proxy / relay mode
```

Supported setup and verification flow:

```bash
cp deploy.conf.example deploy.conf
chmod 600 deploy.conf
$EDITOR deploy.conf
./deploy.sh --init

# Replace <server> with your SSH target if you want to run checks manually
ssh <server> "docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings"
ssh <server> "docker exec vigilyx-rust-builder cargo fmt --check"

# Run the long workspace suite in the background and preserve its real status.
ssh <server> "rm -f /tmp/vigilyx_test_output.txt /tmp/vigilyx_test_status && \
  (nohup sh -c 'docker exec vigilyx-rust-builder cargo test --workspace -- --test-threads=8 \
    > /tmp/vigilyx_test_output.txt 2>&1; echo \$? > /tmp/vigilyx_test_status' \
    </dev/null >/dev/null 2>&1 &)"
test_status=""
while [[ ! "$test_status" =~ ^[0-9]+$ ]]; do
  test_status=$(ssh <server> "cat /tmp/vigilyx_test_status" 2>/dev/null || true)
  [[ "$test_status" =~ ^[0-9]+$ ]] || sleep 15
done
ssh <server> "tail -n 80 /tmp/vigilyx_test_output.txt"
test "$test_status" -eq 0
```

Do not run compilation, tests, or builds locally. For a full deployment, `deploy.sh` starts the workspace tests as a remote background job and records the real exit status so a dropped SSH connection cannot be mistaken for a pass.

### Frontend

Update and deployment path:

```bash
./deploy.sh --frontend
```

For checks without deployment, synchronize the frontend into an isolated remote
working copy and run the pinned Node/npm toolchain there:

```bash
ssh <server> "cd <isolated-checkout>/frontend && npm ci && npm test && npm run build"
```

`deploy.sh --frontend` is a deployment, including a brief API/data-plane pause
for database role/schema reconciliation. Do not use it as a check-only command
against a live installation.

Optional remote Vite HMR (after source is synchronized and dependencies are installed on the remote host):

```bash
REMOTE_HOST="root@your-server"   # replace with the SSH target from deploy.conf
REMOTE_DIR="/path/to/VIGILYX"   # replace with the remote repository path
rsync -az --exclude='node_modules' --exclude='dist' --exclude='.env' --exclude='.env.*' \
  frontend/ "${REMOTE_HOST}:${REMOTE_DIR}/frontend/"

# Terminal 1: start Vite on the remote host
ssh "$REMOTE_HOST" "cd '${REMOTE_DIR}/frontend' && npm ci && npm run dev -- --host 127.0.0.1"

# Terminal 2: set the host again and forward the Vite port to the local browser
REMOTE_HOST="root@your-server"
ssh -L 3000:127.0.0.1:3000 "$REMOTE_HOST"
```

Repeat the `rsync` command after local frontend edits; remote Vite watches the synchronized files.

Toolchain rules:

- Frontend development on the remote build host is pinned to `Node 24.19.0` via [`.nvmrc`](.nvmrc).
- `frontend/package.json` declares `engines` and `packageManager`, and [frontend/.npmrc](frontend/.npmrc) enforces `engine-strict=true`.
- `./deploy.sh --frontend` and the production Docker build both use the same pinned `Node 24.19.0 + npm 12.0.2` frontend toolchain.
- Frontend installs, tests, and builds run on the remote host via `./deploy.sh --frontend`.
- When changing dependencies, update `frontend/package.json` and the matching `package-lock.json`, then verify through the remote workflow.

### Docker Deployment

See the [Deployment Guide](DEPLOYMENT.md) for full deployment instructions.

```bash
# One-time remote bootstrap
./deploy.sh --init

# Full stack
./deploy.sh

# Backend only
./deploy.sh --backend

# Frontend only
./deploy.sh --frontend

# Sniffer only
./deploy.sh --sniffer

# Release / production build
./deploy.sh --production
./deploy.sh --production --backend
./deploy.sh --production --frontend
./deploy.sh --production --sniffer
```

`./deploy.sh` defaults to the fast developer path (`release-fast` + `docker-compose.fast.yml`). Use `./deploy.sh --production` for release-grade images built from the full Dockerfiles.

## Code Style

### Rust

- Formatter: `cargo fmt`
- Linter: `cargo clippy -- -D warnings`
- Follow idiomatic Rust patterns.
- Use `thiserror` for library error types and `anyhow` for application-level errors.
- Use `tracing` for structured logging.
- Prefer `?` for error propagation.
- No `unwrap()` or `expect()` in production code unless accompanied by a `// SAFETY:` comment.
- Prefer newtype wrappers for domain identifiers such as `SessionId(Uuid)`.

### TypeScript / React

- Formatter: Prettier
- Functional components with hooks
- No `console.log` in production code
- Use TypeScript strict mode

### General

- Follow tool defaults for line width.
- Keep comments and documentation in English.
- Document public APIs with doc comments (`///` in Rust, JSDoc in TypeScript).

## Testing Requirements

Every PR must pass the supported remote verification sequence before merge:

```bash
ssh <server> "docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings"
ssh <server> "docker exec vigilyx-rust-builder cargo fmt --check"

ssh <server> "rm -f /tmp/vigilyx_test_output.txt /tmp/vigilyx_test_status && \
  (nohup sh -c 'docker exec vigilyx-rust-builder cargo test --workspace -- --test-threads=8 \
    > /tmp/vigilyx_test_output.txt 2>&1; echo \$? > /tmp/vigilyx_test_status' \
    </dev/null >/dev/null 2>&1 &)"
test_status=""
while [[ ! "$test_status" =~ ^[0-9]+$ ]]; do
  test_status=$(ssh <server> "cat /tmp/vigilyx_test_status" 2>/dev/null || true)
  [[ "$test_status" =~ ^[0-9]+$ ]] || sleep 15
done
ssh <server> "tail -n 80 /tmp/vigilyx_test_output.txt"
test "$test_status" -eq 0

ssh <server> "cd <isolated-checkout>/frontend && npm ci && npm test && npm run build"
```

This validates the frontend on the remote host without packaging or restarting live services. Use the deployment helper only when deployment is intended.

### Test Writing Guidelines

- New public functions (`pub fn`) must include unit tests.
- Bug fixes must include a regression test that reproduces the bug.
- Use names like `test_<feature>_<scenario>_<expected_result>`.
- Cover boundary conditions: empty input, maximum values, and `None` / `Err` paths.
- Keep each test focused on one behavior.
- Tests must be independent and not rely on execution order.

### What to Test First

1. Business-critical correctness such as detection and verdict generation.
2. Security boundaries such as authentication, authorization, and input validation.
3. Error handling paths.
4. Serialization and deserialization round-trips.
5. Edge cases and boundary values.

## Commit Message Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `perf` | Performance improvement |
| `security` | Security fix or hardening |
| `chore` | Build process, CI, dependency updates |

### Scopes

Use the crate or component name: `core`, `parser`, `sniffer`, `db`, `engine`, `api`, `soar`, `mta`, `frontend`, `deploy`, `ai`.

### Examples

```text
feat(engine): add YARA rule hot-reload support
fix(sniffer): resolve TCP session reassembly race condition
docs(api): document WebSocket ticket authentication flow
security(api): add SSRF protection to test endpoints
refactor(db): migrate IOC queries to batch operations
test(engine): add DS-Murphy fusion boundary tests
```

## Pull Request Process

1. Fork and branch from `main`.
2. Make your changes in small, reviewable commits.
3. Run the full verification sequence in the remote build container.
4. Push to your fork.
5. Open a PR against `main` with:
   - A clear title following the commit convention
   - A description of what changed and why
   - A test plan
   - Screenshots for UI changes
6. Address review feedback.
7. Maintainers will merge after approval.

### PR Checklist

- [ ] `cargo clippy --workspace -- -D warnings` passes in `vigilyx-rust-builder`
- [ ] `cargo fmt --check` passes in `vigilyx-rust-builder`
- [ ] `cargo test --workspace` passes in `vigilyx-rust-builder`
- [ ] Remote frontend `npm ci`, `npm test`, and `npm run build` pass in an isolated working copy
- [ ] New public functions have tests
- [ ] No hardcoded secrets or credentials
- [ ] No `unwrap()` or `expect()` without a `// SAFETY:` comment
- [ ] Logs do not expose sensitive data such as PII or credentials
- [ ] Error responses do not leak internal details

## Architecture Overview

Use the current `deploy/docker/docker-compose.yml` runtime topology as the source of truth:

```text
Default stack:
  vigilyx (API + frontend control plane)
    <-> PostgreSQL
    <-> Redis / Valkey (Streams + Pub/Sub)
    -> API-side SOAR / disposition and optional service configuration

Mirror path (`--profile mirror`):
  sniffer -> Redis Streams (session data)
          -> dedicated engine consumes sessions, runs detection/SOAR, persists results
          -> API exposes PostgreSQL state and pushes WebSocket updates

MTA path (`--profile mta`):
  vigilyx-mta (SMTP proxy + embedded engine)
    -> accept / reject / quarantine -> downstream MTA
    -> PostgreSQL / Redis for config, state, and verdicts
```

Key design decisions:

- Dual-mode deployment: passive mirror mode or inline MTA proxy mode
- Redis Streams consumer groups process messages at least once after successful publication while entries remain in the stream; exhausted publish retries and approximate MAXLEN trimming can lose messages, and poison messages can be moved to a dead-letter stream. Pub/Sub carries control signals and notifications.
- Evidence fusion: Dempster-Shafer, Murphy, TBM, and Noisy-OR aggregation strategies
- Circuit breakers: prevent majority-of-silent-modules from diluting genuine threat signals
- IOC management: automatic IOC recording from verdicts with anti-amplification safeguards
- Remote-first builds: Rust compilation happens in a persistent remote build container for repeatable incremental builds
- SOAR placement: alerting and disposition logic runs inside engine and API flows, not as a standalone container
- Engine-side integrations: AI, ClamAV, and Sandbox are called by the engine layer, not by the frontend
- Compose profiles select services but do not stop services from another profile or persist `VIGILYX_MODE`. Use `deploy.sh --mta` or explicitly stop the old data plane when changing topology. The `mirror` profile starts the dedicated engine and sniffer; `mta` starts `vigilyx-mta` with its embedded engine. The main `vigilyx` service is API/frontend only.

## Where to Ask Questions

- GitHub Issues: bug reports and feature requests
- GitHub Discussions: general questions, ideas, and community discussion
- PR comments: code-specific questions during review

When filing an issue, include:

- Vigilyx version or commit hash
- Steps to reproduce
- Expected vs. actual behavior
- Relevant stdout logs, for example `docker compose -f deploy/docker/docker-compose.yml logs --tail 50 vigilyx engine sniffer` (use `mta` instead of `engine sniffer` for inline deployments)
