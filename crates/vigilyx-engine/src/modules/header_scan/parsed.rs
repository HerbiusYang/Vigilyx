//! Header data extraction — "Step 0" of header analysis.
//! Collects all relevant header fields into a single struct for downstream checks.

use regex::Regex;
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
    /// Whether the email content is complete (has all headers).
    pub is_complete: bool,
    pub has_headers: bool,
}

/// Minimal representation of an Authentication-Results header value.
pub(super) struct AuthResult {
    pub spf_fail: bool,
    pub dmarc_fail: bool,
}

impl ParsedHeaders {
    /// Single-pass extraction over raw headers.
    ///
    /// Corresponds to the "gather key headers" phase (lines 119-163 in old code)
    /// plus auth-results collection and injection detection.
    pub(super) fn extract(
        headers: &[(String, String)],
        client_ip: &str,
        mail_from: Option<&str>,
        is_complete: bool,
        is_internal_domain_fn: &dyn Fn(&str) -> bool,
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

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

            match name_lower.as_str() {
                "from" => from_value = Some(value.clone()),
                "reply-to" => reply_to_value = Some(value.clone()),
                "date" => date_value = Some(value.clone()),
                "message-id" => message_id_found = true,
                "x-mailer" => x_mailer_value = Some(value.clone()),
                "received" => {
                    received_count += 1;
                    // Extract IPs from Received headers
                    for cap in RE_IP_ADDR.captures_iter(value) {
                        if let Some(m) = cap.get(1) {
                            let ip = m.as_str().to_string();
                            // Skip private/loopback/link-local
                            if !is_private_ip(&ip) {
                                received_ips.push(ip);
                            }
                        }
                    }
                }
                "authentication-results"
                | "arc-authentication-results"
                | "x-ms-exchange-authentication-results" => {
                    auth_results_found = true;
                    let val_lower = value.to_lowercase();

                    // SPF: fail / softfail / none are all failures
                    let spf_fail = val_lower.contains("spf=fail")
                        || val_lower.contains("spf=softfail")
                        || val_lower.contains("spf=none");

                    // DMARC: fail / none are failures
                    let dmarc_fail =
                        val_lower.contains("dmarc=fail") || val_lower.contains("dmarc=none");

                    auth_results.push(AuthResult {
                        spf_fail,
                        dmarc_fail,
                    });
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

        // Pre-compute internal sender flags (reused by no_auth_results + no_received)
        let is_internal = client_ip.starts_with("10.") || client_ip.starts_with("192.168.");
        let sender_is_internal_domain = mail_from
            .and_then(extract_domain)
            .is_some_and(|d| is_internal_domain_fn(&d));

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
            is_complete,
            has_headers: !headers.is_empty(),
        }
    }
}
