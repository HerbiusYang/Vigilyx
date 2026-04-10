# `domain_verify`: Sender Alignment Context

This document describes the current implementation role of `domain_verify` in Vigilyx.

Source of truth:

- `crates/vigilyx-engine/src/modules/domain_verify.rs`
- `crates/vigilyx-engine/src/pipeline/verdict/evidence_clusters.rs`
- `crates/vigilyx-engine/src/pipeline/verdict/clustered_ds_v1.rs`
- `crates/vigilyx-engine/src/pipeline/verdict/noisy_or.rs`
- `crates/vigilyx-core/src/security/mod.rs`

## Summary

| Field | Value |
|------|-------|
| Module id | `domain_verify` |
| Module metadata name | `Domain Verification` |
| Pillar | `Package` |
| Timeout | `3000 ms` |
| CPU-bound | Yes |
| Remote call | No |
| AI dependency | No |
| Default verdict role | alignment context, not a threat cluster |
| Legacy grouped-engine role | `sender_reputation` (`Engine A`) in `legacy_ds_murphy` only |

`domain_verify` emits an **alignment signal**, not a benignity verdict. A sender domain can be
perfectly self-consistent and still be malicious.

## Position in the Current Fusion Model

In the current default verdict path, `domain_verify` is **not** treated as an independent threat
engine. Instead:

- the module still returns `ThreatLevel::Safe`
- its `alignment_score` is extracted by the verdict normalizer
- the normalizer adds context such as `sender_alignment_verified`
- that context can reduce weak structural noise
- it cannot suppress corroborated phishing, IOC, malicious-link, or payload evidence

The old A-H engine table is still relevant only for `legacy_ds_murphy`, where `domain_verify`
remains mapped to `Engine A / sender_reputation`.

## What `domain_verify` Actually Checks

The module is intentionally lightweight and local. It does **not** perform live DNS lookups, SPF
evaluation, DMARC validation, or external reputation queries by itself.

Current checks:

1. Received-host alignment
   - extracts a hostname from `Received` headers
   - adds alignment when that hostname matches the sender domain or its subdomain

2. DKIM signing-domain alignment
   - extracts the `d=` domain from `DKIM-Signature`
   - adds alignment when the DKIM domain matches the sender domain or its parent domain

3. Envelope mismatch suppression
   - compares the `From` header domain with the SMTP `MAIL FROM` domain
   - if they differ, the module suppresses the accumulated alignment score back to `0.0`

4. Display-name brand impersonation penalty
   - extracts the human-readable display name from the `From` header
   - reduces the alignment score when the display name claims a major brand but the sender domain
     does not match the expected brand family

Important current behavior:

- link-domain consistency is **no longer** used as a positive trust signal
- attacker-controlled domains therefore do not gain extra benign weight merely because their
  embedded links point back to the same domain

Known built-in brand checks include examples such as Amazon, Microsoft, Apple, Google, PayPal,
DHL, FedEx, UPS, Japan Post, Sagawa, and Yamato.

## Inputs

| Source | Field |
|--------|-------|
| Envelope sender | `ctx.session.mail_from` |
| Message headers | `ctx.session.content.headers` |

## Output Behavior

`domain_verify` always returns `ThreatLevel::Safe`. Its job is to expose sender-alignment context,
not to declare a message benign or malicious on its own.

There are two important cases:

### No sender domain available

If `MAIL FROM` is missing or cannot be parsed:

- `confidence = 0.0`
- `verified = false`
- `alignment_score = 0.0`
- `bpa = Bpa::vacuous()`

This means the module contributes no information.

### Sender domain available

If a sender domain exists:

- `confidence = 0.90` when alignment is established
- `confidence = 0.50` when alignment is not established
- `bpa = Bpa::safe_analyzed()`

`Bpa::safe_analyzed()` is defined in `vigilyx-core` as:

```text
{ b = 0.0, d = 0.15, u = 0.85, epsilon = 0.0 }
```

That is a weak benign-style signal with high uncertainty. It is intentionally non-absorbing.
Strong threat evidence from other modules survives Dempster-style combination.

## JSON Details

Current `details` fields include:

- `verified`
- `alignment_score`
- `trust_score`
- `sender_domain`

Important nuance:

- `trust_score` is retained only as a compatibility mirror of `alignment_score`
- callers should interpret it as alignment metadata, not as proof of benignity

## How the Default Clustered Path Uses Alignment

In `clustered_ds_v1` and the updated fallback aggregators:

- alignment may reduce weak structural clusters such as delivery-integrity noise
- alignment may reduce inherited gateway prior weight
- alignment may reduce business-sensitivity-only inflation
- alignment does **not** reduce:
  - `link_and_html_deception`
  - `external_reputation_ioc`
  - `social_engineering_intent`
  - `payload_malware`

This is deliberate. A self-consistent attacker domain should not be able to hide a credential
phishing campaign simply by aligning its own headers and DKIM.

## Summary Strings

Current summary behavior:

- sender missing: `"No sender domain available, unable to verify"`
- mismatch case: `"Domain verification anomaly: From header (...) does not match envelope sender domain (...)"`
- verified case: `"Sender alignment verified (alignment score X.XX), sender domain: ..."`
- unverified case: `"Sender alignment not established, sender domain: ..."`

## Important Constraints

- this module does not execute DNS, SPF, or DMARC resolution
- it does not query OTX, VirusTotal, AbuseIPDB, or any other external service
- it does not create a custom BPA from `alignment_score`
- in the default path it is consumed as context, not as a standalone threat cluster
- in `legacy_ds_murphy`, it is still part of the old `sender_reputation` engine map

## Why This Matters

Older documentation described `domain_verify` as a generalized sender-reputation or trust engine.
That is no longer accurate.

In the current codebase, its role is narrower:

- measure sender-side alignment from locally available headers
- suppress weak structural noise when alignment is good
- penalize header-envelope mismatch and display-name brand impersonation
- avoid granting attacker-controlled link alignment any extra benign weight

That behavior is materially different from full SPF, DKIM, or DMARC enforcement and should be
understood as verdict context, not as standalone sender reputation.
