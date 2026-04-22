//! Synchronous header check functions.
//! Each function takes `&ParsedHeaders` plus shared mutable accumulators.

use std::collections::HashSet;

use crate::context::SecurityContext;
use crate::module::Evidence;

use super::parsed::{PROTECTED_DOMAINS, ParsedHeaders, extract_domain};
use crate::module_data::module_data;

// ---------------------------------------------------------------------------
// 1. From / Reply-To domain mismatch
// ---------------------------------------------------------------------------

pub(super) fn check_domain_mismatch(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if let (Some(from), Some(reply_to)) = (&parsed.from_value, &parsed.reply_to_value) {
        let from_domain = extract_domain(from);
        let reply_domain = extract_domain(reply_to);
        if let (Some(fd), Some(rd)) = (from_domain, reply_domain)
            && fd != rd
        {
            // Domain mismatch detected
            *total_score += 0.25;
            categories.push("domain_mismatch".to_string());
            evidence.push(Evidence {
                description: format!(
                    "From domain ({}) does not match Reply-To domain ({})",
                    fd, rd
                ),
                location: Some("headers:From,Reply-To".to_string()),
                snippet: Some(format!("From: {} | Reply-To: {}", from, reply_to)),
            });

            // Check if From uses a brand domain but Reply-To points to a free email provider
            // (e.g. From=id.apple.com, Reply-To=xxx@139.com) — classic brand spoofing pattern
            let known_brand_domains: &[&str] = &[
                "apple.com",
                "id.apple.com",
                "microsoft.com",
                "google.com",
                "amazon.com",
                "paypal.com",
                "netflix.com",
                "facebook.com",
                "instagram.com",
                "linkedin.com",
                "twitter.com",
                "icloud.com",
                "outlook.com",
                "live.com",
            ];
            let free_email_domains: &[&str] = &[
                "139.com",
                "qq.com",
                "163.com",
                "126.com",
                "yeah.net",
                "sina.com",
                "sina.cn",
                "foxmail.com",
                "189.cn",
                "gmail.com",
                "hotmail.com",
                "yahoo.com",
                "outlook.com",
            ];
            let from_is_brand = known_brand_domains
                .iter()
                .any(|&b| fd == b || fd.ends_with(&format!(".{}", b)));
            let reply_is_free = free_email_domains
                .iter()
                .any(|&f| rd == f || rd.ends_with(&format!(".{}", f)));

            if from_is_brand && reply_is_free {
                *total_score += 0.35;
                categories.push("brand_spoof_reply_to".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Brand domain ({}) Reply-To points to free email ({}) — classic brand spoofing phishing",
                        fd, rd
                    ),
                    location: Some("headers:From,Reply-To".to_string()),
                    snippet: Some(format!("From: {} → Reply-To: {}", from, reply_to)),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1b. From header domain vs MAIL_FROM (envelope) domain mismatch
// ---------------------------------------------------------------------------

pub(super) fn check_envelope_spoofing(
    parsed: &ParsedHeaders,
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // This catches spoofing where the display From differs from the SMTP envelope sender
    if let Some(ref from) = parsed.from_value {
        let from_domain = extract_domain(from);
        let envelope_domain = ctx.session.mail_from.as_deref().and_then(extract_domain);
        if let (Some(fd), Some(ed)) = (&from_domain, &envelope_domain)
            && fd != ed
        {
            // Base score for any envelope mismatch
            *total_score += 0.30;
            categories.push("envelope_spoofing".to_string());
            evidence.push(Evidence {
                description: format!(
                    "From header domain ({}) does not match envelope sender domain ({}) — possible sender spoofing",
                    fd, ed
                ),
                location: Some("headers:From vs MAIL_FROM".to_string()),
                snippet: Some(format!("From: {} | MAIL FROM domain: {}", from, ed)),
            });

            // Extra penalty if From claims an internal/protected domain
            if ctx.is_internal_domain(fd) || PROTECTED_DOMAINS.iter().any(|&pd| fd == pd) {
                *total_score += 0.20;
                categories.push("protected_domain_spoof".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "From header spoofs protected domain {} (actually sent from {})",
                        fd, ed
                    ),
                    location: Some("headers:From".to_string()),
                    snippet: None,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1c. SPF/DKIM/DMARC Authentication-Results Parse
// ---------------------------------------------------------------------------

pub(super) fn check_auth_results(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // Parse Authentication-Results / ARC-Authentication-Results headers (Exchange, Postfix, etc.)
    // spf=fail/none or dmarc=fail/none are strong spoofing signals.
    // Detects "legitimate-looking phishing" even when IPs appear clean, if SPF/DMARC fail.
    let mut spf_fail = false;
    let mut dmarc_fail = false;

    for ar in &parsed.auth_results {
        if ar.spf_fail {
            spf_fail = true;
        }
        if ar.dmarc_fail {
            dmarc_fail = true;
        }
    }

    if spf_fail && dmarc_fail {
        // Both authentication mechanisms failed: strong spoofing signal
        *total_score += 0.35;
        categories.push("auth_spf_dmarc_fail".to_string());
        evidence.push(Evidence {
            description: "SPF and DMARC both failed — sender identity cannot be verified, highly suspicious of spoofing"
                .to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    } else if spf_fail {
        *total_score += 0.20;
        categories.push("auth_spf_fail".to_string());
        evidence.push(Evidence {
            description: "SPF failed (fail/softfail/none) — sending IP not authorized by domain"
                .to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    } else if dmarc_fail {
        *total_score += 0.20;
        categories.push("auth_dmarc_fail".to_string());
        evidence.push(Evidence {
            description: "DMARC failed — domain policy verification failed".to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    }

    // Missing Authentication-Results on external email -> suspicious
    if !parsed.auth_results_found
        && parsed.has_headers
        && !parsed.is_internal
        && !parsed.sender_is_internal_domain
        && parsed.is_complete
    {
        *total_score += 0.10;
        categories.push("no_auth_results".to_string());
        evidence.push(Evidence {
            description:
                "Missing Authentication-Results header — cannot verify sender authentication status"
                    .to_string(),
            location: Some("headers".to_string()),
            snippet: None,
        });
    }
}

// ---------------------------------------------------------------------------
// 2. Date anomaly
// ---------------------------------------------------------------------------

pub(super) fn check_date_anomaly(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if let Some(ref date_str) = parsed.date_value {
        // Try to parse RFC 2822 date
        if let Ok(parsed_dt) = chrono::DateTime::parse_from_rfc2822(date_str) {
            let now = chrono::Utc::now();
            let diff = now.signed_duration_since(parsed_dt.with_timezone(&chrono::Utc));

            if diff.num_seconds() < -3600 {
                // Date is>1 hour in the future (tolerates clock skew up to 1h)
                *total_score += 0.20;
                categories.push("future_date".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Date header has future timestamp: {} (offset {} seconds)",
                        date_str,
                        -diff.num_seconds()
                    ),
                    location: Some("headers:Date".to_string()),
                    snippet: Some(date_str.clone()),
                });
            } else if diff.num_days() > 7 {
                // Date is more than 7 days old
                *total_score += 0.15;
                categories.push("stale_date".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Date header is stale: {} ({} days old)",
                        date_str,
                        diff.num_days()
                    ),
                    location: Some("headers:Date".to_string()),
                    snippet: Some(date_str.clone()),
                });
            }
        }
    } else if parsed.is_complete && parsed.has_headers {
        // Only flag missing Date when we have a complete email with headers
        *total_score += 0.10;
        categories.push("missing_date".to_string());
        evidence.push(Evidence {
            description: "Missing Date header".to_string(),
            location: Some("headers".to_string()),
            snippet: None,
        });
    }

    // --- 3. Missing Message-ID (only flag for complete emails with headers) ---
    if !parsed.message_id_found && parsed.is_complete && parsed.has_headers {
        *total_score += 0.10;
        categories.push("missing_message_id".to_string());
        evidence.push(Evidence {
            description: "Missing Message-ID header".to_string(),
            location: Some("headers".to_string()),
            snippet: None,
        });
    }
}

// ---------------------------------------------------------------------------
// 4. Suspicious X-Mailer
// ---------------------------------------------------------------------------

pub(super) fn check_suspicious_mailer(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if let Some(ref mailer) = parsed.x_mailer_value {
        let mailer_lower = mailer.to_lowercase();
        for pattern in module_data().get_list("suspicious_mailers") {
            if mailer_lower.contains(pattern.as_str()) {
                *total_score += 0.15;
                categories.push("suspicious_mailer".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Suspicious email client: {} (matches {})",
                        mailer, pattern
                    ),
                    location: Some("headers:X-Mailer".to_string()),
                    snippet: Some(mailer.clone()),
                });
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Received chain analysis
// ---------------------------------------------------------------------------

pub(super) fn check_received_chain(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if parsed.received_count == 0
        && parsed.has_headers
        && !parsed.is_internal
        && !parsed.sender_is_internal_domain
    {
        *total_score += 0.10;
        categories.push("no_received".to_string());
        evidence.push(Evidence {
            description: "Email missing Received header (possible direct injection)".to_string(),
            location: Some("headers".to_string()),
            snippet: None,
        });
    } else if parsed.received_count > 15 {
        *total_score += 0.10;
        categories.push("excessive_hops".to_string());
        evidence.push(Evidence {
            description: format!(
                "Received chain too long: {} hops (normally < 10)",
                parsed.received_count
            ),
            location: Some("headers:Received".to_string()),
            snippet: None,
        });
    }
}

// ---------------------------------------------------------------------------
// 6. Real-time domain impersonation detection (homoglyph + TLD swap)
// ---------------------------------------------------------------------------

/// Lightweight homoglyph normalization for the real-time path.
///
/// Only maps the most impactful Cyrillic look-alikes and digit substitutions.
/// The full version (with Greek, extended digit mapping, and `rn→m` collapse)
/// lives in `threat_scene.rs` and runs in the 5-minute batch scan.
fn normalize_homoglyph_simple(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // Cyrillic visually identical to Latin
            '\u{0430}' => 'a', // а → a
            '\u{0435}' => 'e', // е → e
            '\u{043E}' => 'o', // о → o
            '\u{0441}' => 'c', // с → c
            '\u{0440}' => 'p', // р → p
            '\u{0443}' => 'y', // у → y
            '\u{0445}' => 'x', // х → x
            '\u{0456}' => 'i', // і → i
            // Digit substitutions
            '0' => 'o',
            '1' => 'l',
            _ => c,
        })
        .collect()
}

/// Split domain into (base_name, tld), handling multi-part TLDs.
///
/// This is a local copy kept intentionally separate from `threat_scene.rs`
/// to avoid coupling two independently-evolved modules.
fn split_domain_parts(domain: &str) -> (String, String) {
    let domain = domain.to_lowercase();
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        return (domain, String::new());
    }

    // Known multi-part TLDs (kept in sync with threat_scene.rs)
    static MULTI_TLDS: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "com.cn", "org.cn", "net.cn", "gov.cn", "com.hk", "org.hk",
        "com.au", "org.au", "com.br", "co.jp", "or.jp", "co.kr", "or.kr", "com.tw", "org.tw",
        "co.nz", "com.sg", "edu.cn",
    ];

    if parts.len() >= 3 {
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        if MULTI_TLDS.contains(&last_two.as_str()) {
            let base = parts[..parts.len() - 2].join(".");
            return (base, last_two);
        }
    }

    let base = parts[..parts.len() - 1].join(".");
    let tld = parts[parts.len() - 1].to_string();
    (base, tld)
}

/// Result of a domain impersonation check.
pub(super) struct ImpersonationHit {
    /// Type of similarity: `"homoglyph"` or `"tld_swap"`.
    pub(super) similarity_type: &'static str,
    /// Risk score contribution (0.0–1.0).
    pub(super) score: f64,
    /// The internal domain that was impersonated.
    pub(super) target_domain: String,
    /// The sender domain that triggered the hit.
    pub(super) sender_domain: String,
}

/// Fast impersonation check: compare `sender_domain` against every known
/// internal domain using only O(n) algorithms (homoglyph normalization and
/// string equality).
///
/// Returns the **first** (highest-priority) hit, or `None`.
fn check_impersonation_quick(
    sender_domain: &str,
    internal_domains: &HashSet<String>,
) -> Option<ImpersonationHit> {
    let sender_lower = sender_domain.to_lowercase();
    let (sender_base, sender_tld) = split_domain_parts(&sender_lower);

    // Skip very short base names — too many false positives
    if sender_base.len() < 3 {
        return None;
    }

    for internal in internal_domains {
        let (int_base, int_tld) = split_domain_parts(internal);
        if int_base.len() < 3 {
            continue;
        }

        // Skip exact match — that's legitimate traffic, not impersonation
        if sender_lower == *internal {
            continue;
        }

        // 1. Homoglyph: same visual appearance, different codepoints
        //    Only fires when base names differ in raw form but match after normalization.
        if sender_base != int_base {
            let norm_sender = normalize_homoglyph_simple(&sender_base);
            let norm_internal = normalize_homoglyph_simple(&int_base);
            if norm_sender == norm_internal {
                return Some(ImpersonationHit {
                    similarity_type: "homoglyph",
                    score: 0.45,
                    target_domain: internal.clone(),
                    sender_domain: sender_lower.clone(),
                });
            }

            // Also check `rn → m` collapse (e.g. "exarnple.com" vs "example.com")
            let collapsed_sender = sender_base.replace("rn", "m");
            let collapsed_internal = int_base.replace("rn", "m");
            if collapsed_sender == collapsed_internal {
                return Some(ImpersonationHit {
                    similarity_type: "homoglyph",
                    score: 0.45,
                    target_domain: internal.clone(),
                    sender_domain: sender_lower.clone(),
                });
            }
        }

        // 2. TLD swap: identical base name, different TLD
        //    e.g. ccabchina.net vs ccabchina.com
        if sender_base == int_base && sender_tld != int_tld {
            return Some(ImpersonationHit {
                similarity_type: "tld_swap",
                score: 0.35,
                target_domain: internal.clone(),
                sender_domain: sender_lower.clone(),
            });
        }
    }

    None
}

/// Real-time domain impersonation detection.
///
/// Called for every inbound email in the header_scan pipeline.
/// Compares the sender's domain against the organization's internal domain
/// list using only fast, high-confidence algorithms (homoglyph normalization
/// and TLD swap). Deliberately skips Levenshtein-based typosquatting and
/// subdomain-prefix checks to avoid O(n²) cost and false positives — those
/// are handled by the 5-minute batch `threat_scene` scan.
pub(super) fn check_domain_impersonation(
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) -> Option<ImpersonationHit> {
    // Extract sender domain from MAIL FROM
    let sender_domain = ctx.session.mail_from.as_deref().and_then(extract_domain)?;

    // Skip if sender IS an internal domain (legitimate traffic)
    if ctx.is_internal_domain(&sender_domain) {
        return None;
    }

    // Skip if internal domain list is empty (nothing to compare against)
    if ctx.internal_domains.is_empty() {
        return None;
    }

    if let Some(hit) = check_impersonation_quick(&sender_domain, &ctx.internal_domains) {
        let category = format!("domain_impersonation_{}", hit.similarity_type);
        *total_score += hit.score;
        categories.push(category.clone());
        evidence.push(Evidence {
            description: format!(
                "Sender domain '{}' impersonates internal domain '{}' via {} (score {:.2})",
                hit.sender_domain, hit.target_domain, hit.similarity_type, hit.score
            ),
            location: Some("headers:MAIL_FROM".to_string()),
            snippet: Some(format!(
                "sender={} target={} type={}",
                hit.sender_domain, hit.target_domain, hit.similarity_type
            )),
        });
        return Some(hit);
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_homoglyph_simple_cyrillic() {
        // Cyrillic а (U+0430) should map to Latin a
        assert_eq!(normalize_homoglyph_simple("\u{0430}bc"), "abc");
        // Cyrillic е (U+0435) → e
        assert_eq!(normalize_homoglyph_simple("t\u{0435}st"), "test");
        // Mixed Cyrillic: а, е, о (U+043E), с (U+0441)
        assert_eq!(
            normalize_homoglyph_simple("\u{0430}\u{0441}\u{0435}"),
            "ace"
        );
    }

    #[test]
    fn test_normalize_homoglyph_simple_digits() {
        assert_eq!(normalize_homoglyph_simple("g00gle"), "google");
        assert_eq!(normalize_homoglyph_simple("1ogin"), "login");
    }

    #[test]
    fn test_split_domain_parts_simple() {
        let (base, tld) = split_domain_parts("example.com");
        assert_eq!(base, "example");
        assert_eq!(tld, "com");
    }

    #[test]
    fn test_split_domain_parts_multi_tld() {
        let (base, tld) = split_domain_parts("example.com.cn");
        assert_eq!(base, "example");
        assert_eq!(tld, "com.cn");
    }

    #[test]
    fn test_split_domain_parts_subdomain() {
        let (base, tld) = split_domain_parts("mail.example.com");
        assert_eq!(base, "mail.example");
        assert_eq!(tld, "com");
    }

    #[test]
    fn test_impersonation_homoglyph_cyrillic() {
        let mut internals = HashSet::new();
        internals.insert("ccabchina.com".to_string());

        // Replace 'a' with Cyrillic а (U+0430)
        let fake = "cc\u{0430}bchina.com";
        let hit = check_impersonation_quick(fake, &internals);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.similarity_type, "homoglyph");
        assert!((hit.score - 0.45).abs() < f64::EPSILON);
        assert_eq!(hit.target_domain, "ccabchina.com");
        assert_eq!(hit.sender_domain, fake.to_lowercase());
    }

    #[test]
    fn test_impersonation_homoglyph_rn_to_m() {
        let mut internals = HashSet::new();
        internals.insert("example.com".to_string());

        // "exarnple.com" — rn looks like m
        let hit = check_impersonation_quick("exarnple.com", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "homoglyph");
    }

    #[test]
    fn test_impersonation_tld_swap() {
        let mut internals = HashSet::new();
        internals.insert("ccabchina.com".to_string());

        let hit = check_impersonation_quick("ccabchina.net", &internals);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.similarity_type, "tld_swap");
        assert!((hit.score - 0.35).abs() < f64::EPSILON);
    }

    #[test]
    fn test_impersonation_tld_swap_multi_tld() {
        let mut internals = HashSet::new();
        internals.insert("ccabchina.com.cn".to_string());

        let hit = check_impersonation_quick("ccabchina.org.cn", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "tld_swap");
    }

    #[test]
    fn test_impersonation_exact_match_skipped() {
        let mut internals = HashSet::new();
        internals.insert("ccabchina.com".to_string());

        // Exact match should NOT trigger
        let hit = check_impersonation_quick("ccabchina.com", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn test_impersonation_unrelated_domain() {
        let mut internals = HashSet::new();
        internals.insert("ccabchina.com".to_string());

        let hit = check_impersonation_quick("google.com", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn test_impersonation_short_base_skipped() {
        let mut internals = HashSet::new();
        internals.insert("ab.com".to_string());

        // Base "ab" is < 3 chars, should skip
        let hit = check_impersonation_quick("ab.net", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn test_impersonation_empty_internals() {
        let internals = HashSet::new();
        let hit = check_impersonation_quick("evil.com", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn test_impersonation_digit_substitution() {
        let mut internals = HashSet::new();
        internals.insert("google.com".to_string());

        // "g00gle.com" — 0→o substitution
        let hit = check_impersonation_quick("g00gle.com", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "homoglyph");
    }
}
