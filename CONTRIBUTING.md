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

Vigilyx uses a remote-first workflow: edit code locally, but run Rust compilation and verification on a Linux host over SSH using the persistent `vigilyx-rust-builder` container created by `./deploy.sh --init`.

## Development Environment

### Prerequisites

| Environment | Tool | Purpose |
|-------------|------|---------|
| Local machine | SSH + rsync | Sync source code to the remote build host |
| Local machine | Node.js 18+ | Optional frontend tooling and local Vite HMR |
| Remote host | Docker and Docker Compose | Build container and runtime services |
| Remote host | Node.js 18+ / `npx` | Frontend build during `./deploy.sh --frontend` |
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
$EDITOR deploy.conf
./deploy.sh --init

# Replace <server> with your SSH target if you want to run checks manually
ssh <server> "docker exec vigilyx-rust-builder cargo clippy --workspace -- -D warnings"
ssh <server> "docker exec vigilyx-rust-builder cargo test --workspace"
ssh <server> "docker exec vigilyx-rust-builder cargo fmt --check"
```

Do not rely on local `cargo` runs as the authoritative verification path.

### Frontend

Preferred update path:

```bash
./deploy.sh --frontend
```

Optional local HMR:

```bash
ssh -L 8088:127.0.0.1:8088 <server>
cd frontend
npm install
npm run dev
```

### Docker Deployment

See [Deployment Guide](docs/DEPLOYMENT.md) for full deployment instructions.

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
ssh <server> "docker exec vigilyx-rust-builder cargo test --workspace"
```

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
- [ ] New public functions have tests
- [ ] No hardcoded secrets or credentials
- [ ] No `unwrap()` or `expect()` without a `// SAFETY:` comment
- [ ] Logs do not expose sensitive data such as PII or credentials
- [ ] Error responses do not leak internal details

## Architecture Overview

Use the current `deploy/docker/docker-compose.yml` runtime topology as the source of truth:

```text
Default stack:
  vigilyx (API + frontend + DB workers + standalone engine)
    <-> PostgreSQL
    <-> Redis / Valkey (Streams + Pub/Sub)
    -> optional AI / ClamAV / Sandbox
    -> SOAR / disposition logic

Mirror path (`--profile mirror`):
  sniffer -> Redis Streams (primary) + Pub/Sub (shadow/control)
          -> API subscribes sniffer + engine topics, writes PostgreSQL state, and pushes WebSocket updates
          -> engine consumes Streams and publishes verdict / status

MTA path (`--profile mta`):
  vigilyx-mta (SMTP proxy + embedded engine)
    -> accept / reject / quarantine -> downstream MTA
    -> PostgreSQL / Redis for config, state, and verdicts
```

Key design decisions:

- Dual-mode deployment: passive mirror mode or inline MTA proxy mode
- At-least-once delivery: Redis Streams with consumer groups for session data; Pub/Sub for control signals and notifications
- Evidence fusion: Dempster-Shafer, Murphy, TBM, and Noisy-OR aggregation strategies
- Circuit breakers: prevent majority-of-silent-modules from diluting genuine threat signals
- IOC management: automatic IOC recording from verdicts with anti-amplification safeguards
- Remote-first builds: Rust compilation happens in a persistent remote build container for repeatable incremental builds
- SOAR placement: alerting and disposition logic runs inside engine and API flows, not as a standalone container
- Engine-side integrations: AI, ClamAV, and Sandbox are called by the engine layer, not by the frontend
- Current Compose default: `--profile mta` adds `vigilyx-mta`, but it does not automatically disable the standalone engine inside `vigilyx`

## Where to Ask Questions

- GitHub Issues: bug reports and feature requests
- GitHub Discussions: general questions, ideas, and community discussion
- PR comments: code-specific questions during review

When filing an issue, include:

- Vigilyx version or commit hash
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs such as `docker exec vigilyx tail -50 /app/logs/api.log`, `docker exec vigilyx tail -50 /app/logs/engine.log`, and `docker logs vigilyx-sniffer --tail 50`
