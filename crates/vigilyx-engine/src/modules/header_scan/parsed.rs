//! Header data extraction — "Step 0" of header analysis.
//! Collects all relevant header fields into a single struct for downstream checks.

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

use crate::module::Evidence;
use crate::modules::common::extract_domain_from_email;

static RE_IP_ADDR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap());

/// Check whether IP is private/reserved (RFC 1918 + loopback + link-local)
fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("127.")
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("0.")
        || ip.starts_with("169.254.")
    // link-local
    {
        return true;
    }
    // 172.16.0.0/12 = 172.16.x.x ~ 172.31.x.x
    if ip.starts_with("172.")
        && let Some(second) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok())
        && (16..=31).contains(&second)
    {
        return true;
    }
    false
}

/// Alias kept for readability - delegates to the shared helper.
pub(super) fn extract_domain(addr: &str) -> Option<String> {
    extract_domain_from_email(addr)
}

/// Protected internal domains - spoofing these in From header is a strong signal
pub(super) const PROTECTED_DOMAINS: &[&str] = &["corp-internal.com"];

/// All header data extracted in a single pass over the raw headers.
pub(super) struct ParsedHeaders {
    pub from_value: Option<String>,
    pub reply_to_value: Option<String>,
    pub date_value: Option<String>,
    pub message_id_found: bool,
    pub x_mailer_value: Option<String>,
    pub received_count: usize,
    /// Public IPs found in Received headers (private/loopback filtered out).
    pub received_ips: Vec<String>,
    /// Raw header list reference is needed for auth-results parsing, but we
    /// extract the injection evidence inline during the gather pass so we
    /// don't need to keep the full header list.
    pub injection_score: f64,
    pub injection_evidence: Vec<Evidence>,
    pub injection_categories: Vec<String>,
    /// Pre-computed flags reused by several checks.
    pub is_internal: bool,
    pub sender_is_internal_domain: bool,
    /// Authentication-Results raw data — collected during gather pass so
    /// checks.rs doesn't need the full header list.
    pub auth_results: Vec<AuthResult>,
    pub auth_results_found: bool,
    /// An AR-family header was present, but its authserv-id was not trusted.
    /// Its claims are intentionally excluded from `auth_results`.
    pub untrusted_auth_results: bool,
    /// A DKIM-Signature header is present.  This is used only together with
    /// the narrow Microsoft EOP internal-notification guard in auth checks.
    pub has_dkim_signature: bool,
    /// Exchange Online marked the cross-tenant hop as internal.
    pub microsoft_cross_tenant_internal: bool,
    /// Whether the email content is complete (has all headers).
    pub is_complete: bool,
    pub has_headers: bool,
}

/// Minimal representation of an Authentication-Results header value.
pub(super) struct AuthResult {
    pub spf_fail: bool,
    pub dmarc_fail: bool,
    /// DKIM=fail or DKIM=none (no signature). DKIM=pass leaves this false.
    pub dkim_fail: bool,
    /// DKIM=pass was explicitly reported by a trusted authentication hop.
    pub dkim_pass: bool,
    /// `arc=pass` indicates an upstream MTA already authenticated this hop.
    /// Used to suppress Direct Send false positives on legitimate forwarders.
    pub arc_pass: bool,
    /// True if any Authentication-Results header was emitted by an
    /// `*.protection.outlook.com` (Exchange Online) host. Strong signal that
    /// the recipient tenant is on M365 / EOP.
    pub from_eop: bool,
}

/// Maximum number of distinct public Received-chain IPs fed into IOC/intel
/// lookups. A single email with dozens of forged Received headers would
/// otherwise exhaust the global per-minute external intel budget.
pub(super) const MAX_RECEIVED_IPS: usize = 5;

impl ParsedHeaders {
    /// Compatibility wrapper for unit tests that explicitly model a message
    /// after it has passed through a trusted MTA. Production code must call
    /// `extract_for_session` with the actual session trust boundary.
    #[cfg(test)]
    pub(super) fn extract(
        headers: &[(String, String)],
        client_ip: &str,
        mail_from: Option<&str>,
        is_complete: bool,
        is_internal_domain_fn: &dyn Fn(&str) -> bool,
    ) -> Self {
        Self::extract_for_session(
            headers,
            client_ip,
            mail_from,
            is_complete,
            is_internal_domain_fn,
            true,
        )
    }

    /// Single-pass extraction over raw headers.
    ///
    /// Corresponds to the "gather key headers" phase (lines 119-163 in old code)
    /// plus auth-results collection and injection detection.
    pub(super) fn extract_for_session(
        headers: &[(String, String)],
        client_ip: &str,
        mail_from: Option<&str>,
        is_complete: bool,
        is_internal_domain_fn: &dyn Fn(&str) -> bool,
        trust_mta_generated_auth_results: bool,
    ) -> Self {
        let mut from_value: Option<String> = None;
        let mut reply_to_value: Option<String> = None;
        let mut date_value: Option<String> = None;
        let mut message_id_found = false;
        let mut x_mailer_value: Option<String> = None;
        let mut received_count = 0usize;
        let mut received_ips: Vec<String> = Vec::new();

        let mut injection_score: f64 = 0.0;
        let mut injection_evidence: Vec<Evidence> = Vec::new();
        let mut injection_categories: Vec<String> = Vec::new();

        let mut auth_results: Vec<AuthResult> = Vec::new();
        let mut auth_results_found = false;
        let mut untrusted_auth_results = false;
        let mut has_dkim_signature = false;
        let mut microsoft_cross_tenant_internal = false;
        let mut first_ar_seen = false;
        // Header position and internal-domain suffixes are not trust
        // boundaries. The first result is trusted only when the session came
        // through our MTA; passive-mode trust requires an exact configured
        // authserv-id allowlist.
        let mut trusted_ar_authserv: Option<String> = None;

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            match name_lower.as_str() {
                "from" => from_value = Some(value.clone()),
                "reply-to" => reply_to_value = Some(value.clone()),
                "date" => date_value = Some(value.clone()),
                "message-id" => message_id_found = true,
                "dkim-signature" => has_dkim_signature = true,
                "x-mailer" => x_mailer_value = Some(value.clone()),
                "x-ms-exchange-crosstenant-authas" => {
                    microsoft_cross_tenant_internal = value
                        .to_ascii_lowercase()
                        .contains("internal");
                }
                "received" => {
                    received_count += 1;
                    // Extract IPs from Received headers (octets validated:
                    // the regex alone would accept e.g. 999.1.1.1)
                    for cap in RE_IP_ADDR.captures_iter(value) {
                        if let Some(m) = cap.get(1) {
                            let ip = m.as_str();
                            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                                continue;
                            }
                            // Skip private/loopback/link-local
                            if !is_private_ip(ip) {
                                received_ips.push(ip.to_string());
                            }
                        }
                    }
                }
                "authentication-results"
                | "arc-authentication-results"
                | "x-ms-exchange-authentication-results" => {
                    let authserv_id = normalize_authserv_id(value);
                    let allowlisted = !authserv_id.is_empty()
                        && configured_trusted_authserv_ids().contains(&authserv_id);
                    let trusted = !authserv_id.is_empty()
                        && ((trust_mta_generated_auth_results && !first_ar_seen) || allowlisted);
                    first_ar_seen = true;
                    if trusted {
                        if trusted_ar_authserv.is_none() {
                            trusted_ar_authserv = Some(authserv_id.clone());
                        }
                        auth_results_found = true;

                        // Parse method/result tokens exactly. Substrings such
                        // as `x-spf=pass` or `arc=passive` are not evidence.
                        let spf_fail = has_auth_result(value, "spf", "fail")
                            || has_auth_result(value, "spf", "softfail")
                            || has_auth_result(value, "spf", "none")
                            || has_auth_result(value, "spf", "temperror")
                            || has_auth_result(value, "spf", "permerror");

                        let dmarc_fail = has_auth_result(value, "dmarc", "fail")
                            || has_auth_result(value, "dmarc", "none")
                            || has_auth_result(value, "dmarc", "temperror")
                            || has_auth_result(value, "dmarc", "permerror");

                        let dkim_pass = has_auth_result(value, "dkim", "pass");
                        let dkim_fail = (has_auth_result(value, "dkim", "fail")
                            || has_auth_result(value, "dkim", "none")
                            || has_auth_result(value, "dkim", "neutral")
                            || has_auth_result(value, "dkim", "permerror"))
                            && !dkim_pass;

                        // ARC chain validation — when the upstream MTA has already
                        // authenticated and forwarded the message we treat it as
                        // a trusted hop. Only `arc=pass` clears.
                        let arc_pass = has_auth_result(value, "arc", "pass");

                        // Detect Exchange Online / EOP origin. The header value
                        // typically begins with the receiving host, e.g.
                        // `Authentication-Results: contoso-com.mail.protection.outlook.com; ...`
                        let from_eop = authserv_id == "protection.outlook.com"
                            || authserv_id.ends_with(".protection.outlook.com");

                        auth_results.push(AuthResult {
                            spf_fail,
                            dmarc_fail,
                            dkim_fail,
                            dkim_pass,
                            arc_pass,
                            from_eop,
                        });
                    } else {
                        untrusted_auth_results = true;
                    }
                }
                _ => {}
            }

            // --- Header injection detection ---
            if value.contains("\r\n") || value.contains('\r') || value.contains('\n') {
                injection_score += 0.40;
                injection_categories.push("header_injection".to_string());
                injection_evidence.push(Evidence {
                    description: format!(
                        "Header injection: {} contains line break characters",
                        name
                    ),
                    location: Some(format!("headers:{}", name)),
                    snippet: Some(value.chars().take(100).collect()),
                });
            }
        }

        // Pre-compute internal sender flags (reused by no_auth_results + no_received).
        // Covers all RFC1918/loopback/link-local ranges, including 172.16.0.0/12.
        let is_internal = is_private_ip(client_ip);
        let sender_is_internal_domain = mail_from
            .and_then(extract_domain)
            .is_some_and(|d| is_internal_domain_fn(&d));

        // Deduplicate (preserving top-to-bottom order: the topmost Received is
        // the gateway-stamped hop and therefore the most trustworthy) and cap
        // the IP count so a flood of forged Received headers cannot exhaust the
        // global external-intel rate budget.
        let mut seen_ips = std::collections::HashSet::new();
        received_ips.retain(|ip| seen_ips.insert(ip.clone()));
        received_ips.truncate(MAX_RECEIVED_IPS);

        ParsedHeaders {
            from_value,
            reply_to_value,
            date_value,
            message_id_found,
            x_mailer_value,
            received_count,
            received_ips,
            injection_score,
            injection_evidence,
            injection_categories,
            is_internal,
            sender_is_internal_domain,
            auth_results,
            auth_results_found,
            untrusted_auth_results,
            has_dkim_signature,
            microsoft_cross_tenant_internal,
            is_complete,
            has_headers: !headers.is_empty(),
        }
    }
}

fn normalize_authserv_id(value: &str) -> String {
    value
        .split(';')
        .next()
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default()
}

fn configured_trusted_authserv_ids() -> HashSet<String> {
    std::env::var("VIGILYX_TRUSTED_AUTH_SERV_IDS")
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn has_auth_result(value: &str, method: &str, result: &str) -> bool {
    value
        .split(|ch: char| ch == ';' || ch.is_ascii_whitespace())
        .filter_map(|token| token.split_once('='))
        .any(|(name, outcome)| {
            name.eq_ignore_ascii_case(method) && outcome.eq_ignore_ascii_case(result)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(headers: &[(&str, &str)]) -> ParsedHeaders {
        ParsedHeaders::extract(
            &headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>(),
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
        )
    }

    // ------------------------------------------------------------------
    // Item: forged Received flood / invalid IP literals
    // ------------------------------------------------------------------

    #[test]
    fn received_ips_deduped_and_capped_at_five() {
        // 20 forged Received headers with distinct public IPs — the intel
        // budget must not be exhausted by a single email.
        let mut headers: Vec<(String, String)> = vec![(
            "Received".to_string(),
            "from gw.local by mx.example with ESMTPS id abc".to_string(),
        )];
        for i in 0..20u8 {
            headers.push((
                "Received".to_string(),
                format!("from forged-{} ([198.51.100.{}]) by fake-{}.tld", i, i + 1, i),
            ));
        }
        let parsed = ParsedHeaders::extract(
            &headers,
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
        );
        assert_eq!(parsed.received_count, 21);
        assert!(
            parsed.received_ips.len() <= MAX_RECEIVED_IPS,
            "received_ips must be capped, got {:?}",
            parsed.received_ips
        );
    }

    #[test]
    fn received_ips_reject_invalid_octets() {
        let parsed = extract(&[
            ("Received", "from bad ([999.10.20.30]) by mx.example"),
            ("Received", "from also-bad ([256.1.2.3]) by mx.example"),
            ("Received", "from ok ([198.51.100.23]) by mx.example"),
        ]);
        assert_eq!(parsed.received_ips, vec!["198.51.100.23".to_string()]);
    }

    #[test]
    fn is_internal_covers_172_16_12_and_loopback() {
        for (ip, expect_internal) in [
            ("172.16.0.5", true),
            ("172.31.255.200", true),
            ("172.32.0.1", false),
            ("127.0.0.1", true),
            ("10.1.2.3", true),
            ("192.168.1.1", true),
            ("169.254.1.1", true),
            ("203.0.113.9", false),
        ] {
            let parsed = ParsedHeaders::extract(&[], ip, None, true, &|_| false);
            assert_eq!(
                parsed.is_internal, expect_internal,
                "is_internal mismatch for {}",
                ip
            );
        }
    }

    // ------------------------------------------------------------------
    // Item: forged Authentication-Results must not influence verdicts
    // ------------------------------------------------------------------

    #[test]
    fn forged_deep_ar_does_not_clear_trusted_spf_fail() {
        // Topmost AR (gateway hop) reports spf=fail; attacker injected a
        // deeper AR claiming spf=pass/dmarc=pass. The forged one must be
        // ignored.
        let parsed = extract(&[
            (
                "Authentication-Results",
                "mx.example.org; spf=fail smtp.mailfrom=evil.tld; dkim=none; dmarc=fail",
            ),
            (
                "Authentication-Results",
                "forged.attacker.tld; spf=pass; dkim=pass; dmarc=pass",
            ),
        ]);
        assert_eq!(parsed.auth_results.len(), 1, "forged AR must be dropped");
        assert!(parsed.auth_results[0].spf_fail);
        assert!(parsed.auth_results[0].dmarc_fail);
    }

    #[test]
    fn forged_deep_arc_pass_is_ignored() {
        let parsed = extract(&[
            (
                "Authentication-Results",
                "contoso-com.mail.protection.outlook.com; spf=none; dkim=none; dmarc=none",
            ),
            (
                "Authentication-Results",
                "forged.attacker.tld; arc=pass; spf=pass",
            ),
        ]);
        assert_eq!(parsed.auth_results.len(), 1);
        assert!(!parsed.auth_results[0].arc_pass);
    }

    #[test]
    fn forged_deep_eop_ar_is_ignored() {
        // Microsoft-exemption evidence (from_eop) must come from the trusted
        // hop only.
        let parsed = extract(&[
            (
                "Authentication-Results",
                "mx.example.org; spf=fail; dkim=none; dmarc=fail",
            ),
            (
                "Authentication-Results",
                "contoso-com.mail.protection.outlook.com; spf=pass; dkim=pass; dmarc=pass",
            ),
        ]);
        assert_eq!(parsed.auth_results.len(), 1);
        assert!(!parsed.auth_results[0].from_eop);
    }

    #[test]
    fn ar_from_internal_authserv_is_trusted_anywhere() {
        // Internal-domain suffixes are not a trust boundary. Only the first
        // synthetic gateway result is accepted by the compatibility wrapper.
        let parsed = ParsedHeaders::extract(
            &[
                (
                    "Authentication-Results".to_string(),
                    "mx.example.org; spf=none".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "mail.corp.example; spf=fail; dmarc=fail".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|d| d == "corp.example",
        );
        assert_eq!(parsed.auth_results.len(), 1);
        assert!(parsed.untrusted_auth_results);
    }

    #[test]
    fn forged_ar_dropped_while_topmost_kept() {
        // The compatibility wrapper models a result already stamped by our
        // gateway; deeper attacker-controlled ARs are dropped.
        let parsed = ParsedHeaders::extract(
            &[
                (
                    "Authentication-Results".to_string(),
                    "mx.example.org; spf=pass".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "forged.attacker.tld; spf=pass; dmarc=pass".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
        );
        assert!(parsed.auth_results_found);
        assert_eq!(parsed.auth_results.len(), 1);
    }

    #[test]
    fn direct_session_does_not_trust_attacker_authentication_results() {
        let parsed = ParsedHeaders::extract_for_session(
            &[(
                "Authentication-Results".to_string(),
                "mx.attacker.example; spf=pass; dkim=pass; dmarc=pass".to_string(),
            )],
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
            false,
        );
        assert!(!parsed.auth_results_found);
        assert!(parsed.auth_results.is_empty());
        assert!(parsed.untrusted_auth_results);
    }

    #[test]
    fn auth_tokens_and_eop_identity_are_exact() {
        let parsed = ParsedHeaders::extract_for_session(
            &[(
                "Authentication-Results".to_string(),
                "evilprotection.outlook.com.attacker; arc=passive; x-arc=pass; dkim=pass"
                    .to_string(),
            )],
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
            true,
        );
        assert_eq!(parsed.auth_results.len(), 1);
        assert!(!parsed.auth_results[0].arc_pass);
        assert!(!parsed.auth_results[0].from_eop);
        assert!(parsed.auth_results[0].dkim_pass);
    }
}
