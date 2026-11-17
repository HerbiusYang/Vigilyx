# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Vigilyx, report it privately. Do not open a public GitHub issue for undisclosed security bugs.

### How to Report

Use a private reporting channel. Preferred order:

1. GitHub private vulnerability reporting for this repository, if it is enabled.
2. A private maintainer contact channel published in the repository profile or organization profile.

Include:

- A description of the vulnerability
- Steps to reproduce
- Affected version or commit range
- Potential impact
- A suggested fix, if you have one

### Response Targets

These are best-effort open-source maintenance targets, not a contractual SLA:

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix release | Within 30 days for critical issues, within 90 days for other issues |

### Disclosure Policy

Vigilyx follows coordinated disclosure:

1. The reporter submits the vulnerability privately.
2. We confirm the issue and assess severity.
3. We develop and test a fix.
4. We release the fix together with a security advisory when appropriate.
5. We credit the reporter unless anonymity is requested.

### Supported Versions

| Version | Supported |
|---------|-----------|
| `0.9.x` | Yes |
| `< 0.9` | No |

### Scope

In scope:

- Rust backend crates
- Python AI service
- React frontend
- Docker deployment configuration
- Authentication and authorization flows
- A vulnerable dependency or supply-chain configuration when it is reachable in a supported Vigilyx deployment

Out of scope:

- Upstream CVE reports with no demonstrated impact on a supported Vigilyx version
- Social engineering attacks
- Capacity exhaustion that requires ordinary expected high-volume traffic; low-volume crafted-input resource exhaustion remains in scope

### Recognition

Responsible reporters may be credited in the changelog and, if desired, on the project website.
