# Engine A: Sender Reputation

This document describes the current implementation of Engine A in Vigilyx.

Source of truth:

- `crates/vigilyx-engine/src/modules/domain_verify.rs`
- `crates/vigilyx-engine/src/fusion/engine_map.rs`
- `crates/vigilyx-core/src/security/mod.rs`

## Summary

| Field | Value |
|------|-------|
| Engine label | `sender_reputation` (`EngineId::A`) |
| Current module set | `domain_verify` |
| Module metadata name | `Domain Verification` |
| Pillar | `Package` |
| Timeout | `3000 ms` |
| CPU-bound | Yes |
| Remote call | No |
| AI dependency | No |

Engine A produces a **trust-oriented signal**. It does not try to prove that a message is malicious. Instead, it contributes benign evidence when sender-domain alignment looks consistent.

## Position in the Current Fusion Model

The eight conceptual engines are defined in `fusion/engine_map.rs`.

Engine A is the sender-reputation engine:

```text
A  sender_reputation       -> domain_verify
B  content_analysis        -> content_scan, html_scan, html_pixel_art, attach_scan,
                              attach_content, attach_hash, yara_scan, av_eml_scan, av_attach_scan
C  behavior_baseline       -> anomaly_detect
D  url_analysis            -> link_scan, link_reputation, link_content
E  protocol_compliance     -> header_scan, mime_scan
F  semantic_intent         -> semantic_scan
G  identity_anomaly        -> identity_anomaly
H  transaction_correlation -> transaction_correlation
```

Default cross-engine correlation with Engine A:

| Engine | Correlation |
|--------|-------------|
| B | `0.10` |
| C | `0.05` |
| D | `0.05` |
| E | `0.15` |
| F | `0.05` |
| G | `0.10` |
| H | `0.05` |

Engine E has the highest default correlation with Engine A because both rely on sender and header alignment signals.

## What `domain_verify` Actually Checks

The module is intentionally lightweight and local. It does **not** perform live DNS lookups, SPF evaluation, DMARC validation, or external reputation queries by itself.

Current checks:

1. Received-host alignment
   - Extracts the hostname from `Received` headers with `from\s+...`
   - Grants `+0.40` trust when the hostname equals the sender domain or is its subdomain

2. DKIM signing-domain alignment
   - Extracts the `d=` domain from `DKIM-Signature`
   - Grants `+0.35` trust when the DKIM domain matches the sender domain or is its parent domain

3. Link-domain consistency
   - Extracts domains from parsed links in the message body
   - Grants `+0.25` trust when at least 80% of link domains align with the sender domain

4. Envelope mismatch suppression
   - Compares the `From` header domain with the SMTP `MAIL FROM` domain
   - If they differ, the module resets the accumulated trust score to `0.0`

5. Display-name brand impersonation suppression
   - Extracts the human-readable display name from the `From` header
   - Applies a trust penalty when the display name claims to be a known brand but the sender domain does not match expected brand-domain fragments

Known built-in brand checks include examples such as Amazon, Microsoft, Apple, Google, PayPal, DHL, FedEx, UPS, Japan Post, Sagawa, and Yamato.

## Inputs

| Source | Field |
|--------|-------|
| Envelope sender | `ctx.session.mail_from` |
| Message headers | `ctx.session.content.headers` |
| Parsed links | `ctx.session.content.links` |

## Output Behavior

`domain_verify` always returns `ThreatLevel::Safe`. Its job is to contribute safe evidence or remain weakly informative, not to emit a threat verdict on its own.

There are two important cases:

### No sender domain available

If `MAIL FROM` is missing or cannot be parsed:

- `confidence = 0.0`
- `verified = false`
- `trust_score = 0.0`
- `bpa = Bpa::vacuous()`

This means Engine A contributes no information.

### Sender domain available

If a sender domain exists:

- `confidence = 0.90` when verification succeeds
- `confidence = 0.50` when verification does not succeed
- `bpa = Bpa::safe_analyzed()`

`Bpa::safe_analyzed()` is defined in `vigilyx-core` as:

```text
{ b = 0.0, d = 0.15, u = 0.85, epsilon = 0.0 }
```

That is a weak benign signal with high uncertainty. It is intentionally non-absorbing: strong threat evidence from other modules still survives Dempster-style combination.

## Summary Strings

Current summary behavior:

- Sender missing: `"No sender domain available, unable to verify"`
- Mismatch case: `"Domain verification anomaly: From header (...) does not match envelope sender domain (...)"`
- Verified case: `"Domain verification passed (trust score X.XX), sender domain: ..."`
- Unverified case: `"Domain verification failed, sender domain: ..."`

## Important Constraints

- This module does not execute DNS, SPF, or DMARC resolution.
- It does not query OTX, VirusTotal, AbuseIPDB, or any other external service.
- It does not create a custom BPA from `trust_score`; it uses the standard `safe_analyzed()` and `vacuous()` helpers.
- It is mapped into Engine A for fusion purposes even though its own `ModuleResult` leaves `engine_id` unset; the aggregation layer resolves that through `module_to_engine("domain_verify")`.

## Why This Matters

Older documentation often described `domain_verify` as a generalized sender-authentication engine. That is no longer accurate. In the current codebase, it is a narrow sender-alignment and trust-suppression module whose main purpose is:

- reward obvious sender-domain consistency
- suppress trust when header and envelope domains diverge
- suppress trust when the display name impersonates a major brand

That behavior is materially different from full SPF, DKIM, or DMARC enforcement and should be documented separately from `header_scan`.
