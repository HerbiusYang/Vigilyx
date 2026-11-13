# Process-level external URL analysis sandbox

- Status: Accepted for phased implementation; worker contract and runtime seam implemented, kernel-isolation stage pending
- Date: 2026-08-28
- Owners: Vigilyx security platform
- Scope: external URL fetching, offline HTML rendering, visual/OCR observations,
  process isolation, resource limits, and coverage semantics
- Related implementation: `crates/vigilyx-engine/src/external/process_sandbox.rs`,
  `crates/vigilyx-engine/src/external/fetcher.rs`, and
  `crates/vigilyx-engine/src/modules/process_sandbox_scan.rs`

## Context

Vigilyx currently has two different external-content paths:

1. `UrlFetcher` performs a bounded, non-JavaScript HTTP fetch and HTML parse.
2. The optional CAPEv2 integration submits selected URLs to a Docker-packaged
   CAPE service, which controls a KVM/libvirt analysis guest.

The first path is fast and useful for static content, but it cannot observe
JavaScript-rendered text, canvas, CSS-generated text, or image-only landing
pages. The second path provides stronger isolation, but is expensive, requires
KVM and a prepared guest, and is not appropriate for every ordinary external
link. Neither path currently defines a Vigilyx-owned process-level contract
for a short-lived renderer.

The security objective is not merely to “open a link”. It is to obtain bounded
additional observations while preventing an untrusted page from using the
analysis worker to reach the Vigilyx host, internal services, credentials,
ambient cookies, or arbitrary filesystem state. A renderer result must also
remain distinguishable from verified link ownership and from a clean verdict.

## Decision

Vigilyx will add a self-owned process-level external-content path in phases.
The Rust engine owns the orchestration and the evidence contract. The Linux
kernel remains the isolation primitive; the project does not implement a new
kernel sandbox or browser engine.

The target topology is:

```text
engine
  -> URL policy/fetch broker
       (DNS pinning, SSRF policy, redirects, size/time limits, no ambient proxy)
  -> short-lived renderer worker
       (non-root, namespaces, seccomp/no_new_privs, cgroups, read-only FS)
  -> screenshot/OCR/DOM observations
```

### Boundary responsibilities

The fetch broker is the only component allowed to access the external network.
It must validate every redirect hop, resolve and pin the approved destination,
reject loopback/private/link-local/metadata targets, enforce body/time/redirect
limits, and disable ambient `HTTP_PROXY`/`HTTPS_PROXY` inheritance unless an
explicitly configured egress proxy is part of the policy. A fetch failure is a
coverage result, never a clean result.

The renderer receives a bounded, sanitized snapshot or explicitly approved
resource set. Its default network namespace is unavailable. It runs one job per
process and is killed and reaped on timeout, output overflow, protocol error,
or parent cancellation. Renderer output is observation-only until a separately
evaluated scenario policy promotes it.

The first implementation may use a small host helper or a mature launcher such
as `bubblewrap`/`nsjail` for the kernel setup. A Rust coordinator is owned by
Vigilyx; writing namespace, seccomp, cgroup, and browser isolation primitives
from scratch is out of scope for stage 1. If a helper is unavailable, the
feature must report `sandbox_unavailable` and remain non-actionable.

### Required process boundary

Every renderer job must have all of the following properties before it can be
called process-isolated:

- dedicated non-root UID/GID and no inherited credentials or cookies;
- private PID and mount namespaces, with a read-only application root and a
  bounded writable `tmpfs` workspace;
- `no_new_privs`, dropped Linux capabilities, and an allowlisted seccomp policy;
- a private network namespace with no route by default;
- cgroup v2 CPU, memory, process-count, file-size, and wall-clock budgets;
- bounded stdin/stdout/stderr and an explicit length-delimited worker protocol;
- parent-side timeout, kill, reap, and cleanup on every exit path;
- no host Docker socket, `/proc` host view, SSH material, service tokens, or
  application data volume.

Chromium, if used, must run as a non-root user with its own browser sandbox
enabled. `--no-sandbox` is not an acceptable production renderer setting.

### Failure and evidence semantics

The process sandbox is an inspection and coverage component. It must never:

- convert an unavailable, timed-out, blocked, or partial render into `Safe`;
- treat a rendered page as proof that a domain is owned by the claimed brand;
- replace independent native payload, authentication, or semantic evidence;
- promote an observation directly into threat fusion without a named,
  provenance-qualified scenario policy.

The worker contract uses explicit states: `not_attempted`, `submitted`,
`completed`, `partial`, `timeout`, `blocked`, `failed`, and `unavailable`.
Output records retain the original URL, effective URL/redirect chain, policy
version, worker profile, resource limits, provenance, and bounded failure
reason. If the worker cannot prove what it saw, the result is `unknown` or
coverage-incomplete.

### Relationship to CAPEv2

CAPE remains the high-assurance dynamic-analysis option for selected high-risk
URLs, attachments, and full guest detonation. The process-level path is a
lower-cost complement for bounded visual and HTML analysis. Both paths share
the same URL policy and coverage semantics; neither is enabled in MTA inline
verdicts during the initial rollout.

## Alternatives considered

| Alternative | Decision | Reason |
| --- | --- | --- |
| Keep only static `UrlFetcher` | Rejected as complete solution | Cannot observe JS/canvas/image-rendered content |
| Use CAPEv2/KVM for every URL | Rejected as default | High latency and operational cost; requires KVM/guest capacity |
| Use an ordinary Docker browser container | Rejected as sole boundary | Container defaults alone do not provide sufficient browser/process policy or egress control |
| Run a browser process directly in the engine | Rejected | Expands the engine blast radius and makes cleanup/resource ownership ambiguous |
| Self-written Rust coordinator plus kernel isolation | Accepted | Gives Vigilyx explicit policy, lifecycle, and evidence ownership |
| Implement namespace/seccomp/browser isolation entirely from scratch | Rejected | Too much security-critical code and insufficient benefit for stage 1 |

## Staged implementation

| Stage | Change | Threat/disposition effect | Gate |
| --- | --- | --- | --- |
| 1 | Worker contract, profile validation, process lifecycle, bounded protocol, unavailable/timeout semantics | none; observation/coverage only | unit + integration failure-path tests |
| 2 | Linux launcher with namespaces, no_new_privs, capability drop, seccomp, cgroup/resource limits | none; still shadow-only | executable remote Rocky Linux smoke test and escape/limit tests |
| 3 | Fetch broker snapshot handoff and offline renderer/OCR | observation/coverage only | SSRF, redirect, DNS-rebind, body/time, browser-network-deny tests |
| 4 | Red-team-derived visual/dynamic scenarios | separately flagged shadow evidence | capability-preservation replay and paired benign neighbors |
| 5 | Production rollout or CAPE fallback policy | only after release gates | v2 shadow plan, holdout, rollback, disposition review |

The current code implements stage 1, parent-side Linux `no_new_privs` plus
`RLIMIT_AS`/`RLIMIT_CPU` guardrails, and the stage-2 launcher/profile gate. It
does not yet claim the full stage-2 boundary: the reviewed launcher must still
provide the namespace, capability-drop, seccomp, and cgroup policy, and the
remote Rocky Linux smoke test is still pending. It must not change global
thresholds, floors, fusion, MTA disposition, or the existing CAPE default-off
behavior. A profile that is not a reviewed bubblewrap configuration is
rejected as unavailable coverage.

## Compatibility and rollout

- Existing `UrlFetcher` and CAPEv2 paths remain unchanged and independently
  selectable.
- The new worker is disabled unless `PROCESS_SANDBOX_ENABLED=true` and an
  explicit worker executable/profile is configured.
- Configuration errors and missing helpers fail closed for the worker but do
  not fail the whole email pipeline; they emit coverage evidence.
- No external page content is stored without the existing privacy/retention
  policy. Real email bodies, screenshots, and HTML remain outside Git.
- The MTA inline pipeline does not call the worker in stages 1–3.

## Verification contract

Before the feature can affect threat fusion, the test bank must cover:

- direct request versus quoted/forwarded/anti-action visual content;
- empty DOM with image/CSS/canvas text and ordinary benign image controls;
- SSRF, redirects, DNS rebinding, private IP, proxy, timeout, body-limit, and
  partial-content failures;
- worker missing, malformed output, output overflow, crash, timeout, and kill;
- network-denied renderer and no-cookie/no-token invariants;
- resource exhaustion and process cleanup;
- CAPE fallback and process-sandbox unavailable states;
- complete frozen capability-manifest replay before any release claim.

The implementation milestone is `implemented` only after focused code and
failure-path tests pass. It is not `shadow_validated` or `release_ready` until
the governance evaluation and capability-preservation gates are complete.
