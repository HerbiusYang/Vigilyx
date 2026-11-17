//! Synchronous header check functions.
//! Each function takes `&ParsedHeaders` plus shared mutable accumulators.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::context::SecurityContext;
use crate::module::Evidence;
use crate::module_data::module_data;
use crate::modules::common::{
    domains_share_organizational_domain, domains_share_sender_organization,
};
use vigilyx_parser::mime::decode_rfc2047;

use super::parsed::{PROTECTED_DOMAINS, ParsedHeaders, extract_domain};

// ---------------------------------------------------------------------------
// 1. From / Reply-To domain mismatch
// ---------------------------------------------------------------------------

pub(super) fn check_domain_mismatch(
    parsed: &ParsedHeaders,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
    ds_learning_items: &mut Vec<serde_json::Value>,
) {
    if let (Some(from), Some(reply_to)) = (&parsed.from_value, &parsed.reply_to_value) {
        let from_domain = extract_domain(from);
        let reply_domain = extract_domain(reply_to);
        if let (Some(fd), Some(rd)) = (from_domain, reply_domain)
            && !domains_share_sender_organization(&fd, &rd)
        {
            // Domain mismatch detected
            *total_score += 0.25;
            categories.push("domain_mismatch".to_string());
            // Learning-only item provenance. The bootstrap module score and
            // evidence contract remain unchanged, including separate brand and
            // envelope findings; their contributions must never enter this item.
            let identity = format!(
                "{}\0{}",
                fd.trim_end_matches('.').to_ascii_lowercase(),
                rd.trim_end_matches('.').to_ascii_lowercase(),
            );
            ds_learning_items.push(serde_json::json!({
                "categories": ["domain_mismatch"],
                "score": 0.25,
                "confidence": 0.80,
                "causal_key": format!("header_from_reply_to:sha256:{}", hex::encode(Sha256::digest(identity.as_bytes()))),
            }));
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
            && !domains_share_organizational_domain(fd, ed)
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

fn display_contains_domain_token(display: &str, domain: &str) -> bool {
    let display = display.to_lowercase();
    let domain = domain.trim_end_matches('.').to_lowercase();
    if domain.is_empty() {
        return false;
    }

    display.match_indices(&domain).any(|(start, matched)| {
        let end = start + matched.len();
        let before_is_boundary = display[..start]
            .chars()
            .next_back()
            .is_none_or(|ch| !ch.is_alphanumeric() && ch != '.');
        let after_is_boundary = display[end..]
            .chars()
            .next()
            .is_none_or(|ch| !ch.is_alphanumeric() && ch != '.');
        before_is_boundary && after_is_boundary
    })
}

/// Detect an external sender that places an exact configured internal domain
/// in the RFC 5322 display name. The bare identity contradiction contributes
/// only a weak `display_name_spoof` fact. A bounded recipient-facing account
/// action upgrades the same fact to the existing authority-lure category,
/// which is already governed by the named inline floor.
pub(super) fn check_internal_domain_display_name(
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(from_value) = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .map(|(_, value)| value)
    else {
        return;
    };
    let Some(from_domain) = extract_domain(from_value) else {
        return;
    };
    let envelope_domain = ctx
        .session
        .mail_from
        .as_deref()
        .and_then(extract_domain)
        .unwrap_or_else(|| from_domain.clone());
    if ctx.is_internal_domain(&from_domain) || ctx.is_internal_domain(&envelope_domain) {
        return;
    }

    let Some(display_end) = from_value.rfind('<') else {
        return;
    };
    let display = decode_rfc2047(from_value[..display_end].trim().trim_matches('"'));
    let Some(internal_domain) = ctx
        .internal_domains
        .iter()
        .find(|domain| display_contains_domain_token(&display, domain))
        .cloned()
    else {
        return;
    };

    *total_score += 0.24;
    categories.push("display_name_spoof".to_string());
    evidence.push(Evidence {
        description: format!(
            "External sender domain '{}' embeds configured internal domain '{}' in the display name",
            from_domain, internal_domain
        ),
        location: Some("headers:From display-name".to_string()),
        snippet: Some(display.clone()),
    });

    let action_text = format!(
        "{} {} {}",
        ctx.session.subject.as_deref().unwrap_or_default(),
        ctx.session.content.body_text.as_deref().unwrap_or_default(),
        ctx.session.content.body_html.as_deref().unwrap_or_default(),
    )
    .to_lowercase();
    let has_account_action = module_data()
        .get_list("internal_domain_display_action_terms")
        .iter()
        .any(|term| action_text.contains(&term.to_lowercase()));
    if has_account_action {
        *total_score += 0.16;
        categories.push("authority_display_name_lure".to_string());
        evidence.push(Evidence {
            description:
                "Internal-domain display-name claim is paired with a recipient-facing account/IT action"
                    .to_string(),
            location: Some("headers:From display-name + subject/body".to_string()),
            snippet: Some(display),
        });
    }
}

/// Detect a recipient-facing lure that uses an internal authority identity in
/// either the display name or the sender local-part. This stays in the inline
/// header module so the MTA does not depend on the database-backed identity
/// behavior module for a purely lexical identity fact.
pub(super) fn check_authority_identity_lure(
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(mail_from) = ctx.session.mail_from.as_deref() else {
        return;
    };
    let Some(sender_domain) = mail_from.rsplit('@').next() else {
        return;
    };
    if ctx.is_internal_domain(sender_domain)
        || PROTECTED_DOMAINS
            .iter()
            .any(|domain| sender_domain.eq_ignore_ascii_case(domain))
    {
        return;
    }

    let body = format!(
        "{} {}",
        ctx.session.content.body_text.as_deref().unwrap_or_default(),
        ctx.session.content.body_html.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    let lure_markers = [
        "在吗", "回复", "确认", "事务", "帮忙", "加急", "紧急", "reply", "confirm", "urgent",
        "need you",
    ];
    let lure_hits = lure_markers
        .iter()
        .filter(|marker| body.contains(*marker))
        .count();
    if lure_hits < 2 {
        return;
    }

    let authority_from = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .and_then(|(_, value)| value.rfind('<').map(|index| (value, index)))
        .and_then(|(value, index)| {
            let display = decode_rfc2047(value[..index].trim().trim_matches('"'))
                .trim()
                .to_lowercase();
            (!display.is_empty()).then_some(display)
        });

    let registry = module_data();
    let display_authority_hit = authority_from.as_deref().is_some_and(|display| {
        registry
            .get_list("display_name_impersonation_targets")
            .iter()
            .chain(
                registry
                    .get_list("corporate_authority_display_terms")
                    .iter(),
            )
            .any(|phrase| {
                let phrase = phrase.to_ascii_lowercase();
                phrase.len() > 1 && display.contains(&phrase)
            })
    });
    if display_authority_hit {
        *total_score += 0.30;
        categories.push("authority_display_name_lure".to_string());
        evidence.push(Evidence {
            description:
                "External sender display name claims an internal authority role in a reply/confirmation lure"
                    .to_string(),
            location: Some("headers:From + body".to_string()),
            snippet: authority_from,
        });
    }

    let header_address = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .and_then(|(_, value)| value.rsplit_once('<'))
        .map(|(_, value)| value.trim_matches(['<', '>']))
        .filter(|value| value.contains('@'));
    let identity_address = header_address.unwrap_or(mail_from);
    let local_part = identity_address
        .split('@')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let normalized_local = normalize_homoglyph_simple(&local_part);
    // Generic operational aliases such as `admin@` and `sysadmin@` are
    // routinely used by vendor support and fund-administration mailboxes.
    // Executive aliases remain actionable when paired with the existing
    // recipient-facing authority lure checks.
    let local_authority_hit = ["ceo", "cfo", "coo", "老板"]
        .iter()
        .any(|target| normalized_local == *target);
    if local_authority_hit {
        *total_score += 0.30;
        categories.push("authority_localpart_lure".to_string());
        evidence.push(Evidence {
            description:
                "External sender local-part uses a confusable internal authority identifier in a reply/confirmation lure"
                    .to_string(),
            location: Some("envelope:MAIL_FROM + body".to_string()),
            snippet: Some(mail_from.to_string()),
        });
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
    // Only explicit fail results from the trusted authentication boundary are
    // corroborating spoofing signals. none/neutral/errors are unknown states.
    // Detects "legitimate-looking phishing" even when IPs appear clean, if SPF/DMARC fail.
    let mut spf_fail = false;
    let mut dmarc_fail = false;
    // Microsoft account-security notifications can carry an ARC result from
    // an earlier hop that reports SPF/DMARC=fail while the message itself is
    // DKIM-signed and traversed Exchange Online as an internal notification.
    // Keep this exception narrow to the exact Microsoft notification domain
    // and require all three independent header signals. The EOP signal must
    // come from a trusted Authentication-Results authserv-id; a Received
    // header or a deep AR header mentioning protection.outlook.com is not
    // enough.
    let microsoft_internal_notification = parsed
        .from_value
        .as_deref()
        .and_then(extract_domain)
        .is_some_and(|domain| domain == "accountprotection.microsoft.com")
        && parsed.auth_results.iter().any(|ar| ar.from_eop)
        && parsed.auth_results.iter().any(|ar| ar.dkim_pass)
        && parsed.microsoft_cross_tenant_internal;

    for ar in &parsed.auth_results {
        if ar.spf_fail {
            spf_fail = true;
        }
        if ar.dmarc_fail {
            dmarc_fail = true;
        }
    }

    if spf_fail && dmarc_fail && !microsoft_internal_notification {
        // Both authentication mechanisms failed: strong spoofing signal
        *total_score += 0.35;
        categories.push("auth_spf_dmarc_fail".to_string());
        evidence.push(Evidence {
            description: "SPF and DMARC both failed — sender identity cannot be verified, highly suspicious of spoofing"
                .to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    } else if spf_fail && !microsoft_internal_notification {
        *total_score += 0.20;
        categories.push("auth_spf_fail".to_string());
        evidence.push(Evidence {
            description: "SPF explicitly failed at a trusted authentication boundary — sending IP not authorized by domain"
                .to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    } else if dmarc_fail && !microsoft_internal_notification {
        *total_score += 0.20;
        categories.push("auth_dmarc_fail".to_string());
        evidence.push(Evidence {
            description: "DMARC failed — domain policy verification failed".to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    }

    if parsed.untrusted_auth_results {
        // An untrusted authserv-id means the claim cannot be consumed; it is
        // an inspection diagnostic, not evidence that authentication failed.
        categories.push("untrusted_auth_results".to_string());
        evidence.push(Evidence {
            description: "Authentication-Results present without a trusted authserv-id; upstream claims were ignored"
                .to_string(),
            location: Some("headers:Authentication-Results".to_string()),
            snippet: None,
        });
    }

    if parsed.has_dkim_signature && !parsed.auth_results.iter().any(|ar| ar.dkim_pass) {
        // Presence of a DKIM signature without a locally trusted pass is
        // unknown verification state. Explicit dkim/spf/dmarc failures above
        // remain actionable.
        categories.push("dkim_unverified".to_string());
        evidence.push(Evidence {
            description:
                "DKIM-Signature header is present, but no trusted cryptographic DKIM pass was recorded"
                    .to_string(),
            location: Some("headers:DKIM-Signature".to_string()),
            snippet: None,
        });
    }

    // Missing Authentication-Results on external email is a coverage fact.
    // It must stay visible without manufacturing a sender-auth failure.
    if !parsed.auth_results_found
        && parsed.has_headers
        && !parsed.is_internal
        && !parsed.sender_is_internal_domain
        && parsed.is_complete
    {
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
// 1d. M365 Direct Send abuse detection
// ---------------------------------------------------------------------------
//
// Microsoft 365 Direct Send (a.k.a. unauthenticated SMTP submission to
// `<tenant>.mail.protection.outlook.com`) lets attackers deliver messages
// **into** a tenant from arbitrary public IPs while spoofing the recipient's
// own domain in `From:`. The recipient-side mail flow looks "internal" so
// external-banner / safety-tip rules are bypassed, even though no
// authentication has occurred (spf=none, dkim=none, dmarc=none).
//
// This check fires only when ALL of the following are observed:
//   1. EOP/Exchange Online routed the message
//      (Authentication-Results emitted by `*.protection.outlook.com`)
//   2. From-domain == one of the recipient (rcpt_to) domains
//   3. SPF + DKIM + DMARC all failed/none
//   4. ARC chain did NOT validate (`arc=pass` short-circuits)
//
// Confidence levels:
//   - All four met            → +0.55  category=`direct_send_abuse`
//   - 1+2+3 met, but no ARC   → +0.30  category=`direct_send_suspected`
//
// False-positive guards:
//   - Internal forwarders that survive `arc=pass` are skipped entirely.
//   - Skipped if rcpt_to is empty (cannot compare domains).
//   - Skipped if no Authentication-Results were emitted at all
//     (no signal to interpret).
pub(super) fn check_direct_send_abuse(
    parsed: &ParsedHeaders,
    ctx: &SecurityContext,
    total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    // Need at least one Authentication-Results header to reason about auth state.
    if !parsed.auth_results_found {
        return;
    }

    // Aggregate explicit fail/none states across trusted Authentication-Results
    // headers. `none` is not general threat evidence, but the three-method
    // absence at EOP is part of the narrow M365 Direct Send signature.
    let mut any_eop = false;
    let mut all_spf_failed_or_none = true;
    let mut all_dkim_failed_or_none = true;
    let mut all_dmarc_failed_or_none = true;
    let mut any_arc_pass = false;

    for ar in &parsed.auth_results {
        if ar.from_eop {
            any_eop = true;
        }
        if !(ar.spf_fail || ar.spf_none) {
            all_spf_failed_or_none = false;
        }
        if !(ar.dkim_fail || ar.dkim_none) {
            all_dkim_failed_or_none = false;
        }
        if !(ar.dmarc_fail || ar.dmarc_none) {
            all_dmarc_failed_or_none = false;
        }
        if ar.arc_pass {
            any_arc_pass = true;
        }
    }

    // Gate 1: must be EOP-bound mail flow.
    if !any_eop {
        return;
    }
    // Gate 2: legitimate forwarders short-circuit via ARC.
    if any_arc_pass {
        return;
    }
    // Gate 3: full auth failure stack required.
    if !(all_spf_failed_or_none && all_dkim_failed_or_none && all_dmarc_failed_or_none) {
        return;
    }

    // Gate 4: From-domain must equal a recipient domain (look-internal spoof).
    let from_domain = parsed
        .from_value
        .as_deref()
        .and_then(extract_domain)
        .map(|d| d.to_ascii_lowercase());
    let Some(from_dom) = from_domain else {
        return;
    };

    let rcpt_match = ctx.session.rcpt_to.iter().any(|r| {
        extract_domain(r)
            .map(|d| d.to_ascii_lowercase() == from_dom)
            .unwrap_or(false)
    });
    if !rcpt_match {
        return;
    }

    // All gates passed. Decide tier:
    //   - If at least one received public IP exists  → high-confidence (the
    //     attacker IP is observable in headers).
    //   - Otherwise → suspected (still strongly indicative of Direct Send,
    //     but we lack the IP to corroborate).
    let has_public_ip = !parsed.received_ips.is_empty();
    let (delta, category, summary) = if has_public_ip {
        (
            0.55,
            "direct_send_abuse",
            format!(
                "M365 Direct Send abuse: From={} matches recipient domain, \
                 SPF/DKIM/DMARC all failed or were absent at EOP, no ARC validation. \
                 Received from public IP(s): {}",
                from_dom,
                parsed.received_ips.join(", ")
            ),
        )
    } else {
        (
            0.30,
            "direct_send_suspected",
            format!(
                "Suspected M365 Direct Send abuse: From={} matches recipient domain, \
                 SPF/DKIM/DMARC all failed or were absent at EOP (no public Received IP captured)",
                from_dom
            ),
        )
    };

    *total_score += delta;
    categories.push(category.to_string());
    evidence.push(Evidence {
        description: summary,
        location: Some("headers:Authentication-Results".to_string()),
        snippet: Some(from_dom),
    });
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
    _total_score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) {
    if let Some(ref mailer) = parsed.x_mailer_value {
        let mailer_lower = mailer.to_lowercase();
        let md = module_data();
        // NetEase/Coremail's official mobile and desktop clients emit a
        // composite X-Mailer such as "Coremail Webmail Server ...
        // MailMasterIOS". The generic "mailmaster" seed remains useful for
        // bulk tools, but a JSON-qualified vendor + product pair is a normal
        // first-party client. Every other header/authentication check remains.
        let has_benign_vendor = md
            .get_list("benign_mailer_vendor_markers")
            .iter()
            .any(|vendor| mailer_lower.contains(&vendor.to_lowercase()));
        let has_benign_product = md
            .get_list("benign_mailer_product_markers")
            .iter()
            .any(|product| mailer_lower.contains(&product.to_lowercase()));
        if has_benign_vendor && has_benign_product {
            return;
        }
        for pattern in md.get_list("suspicious_mailers") {
            if mailer_lower.contains(pattern.as_str()) {
                // X-Mailer is entirely sender-controlled. Keep the client
                // fingerprint for analyst context and compound diagnostics,
                // but never manufacture threat belief from the product name
                // alone. Proven authentication failures, spoofing, content,
                // links, and payload checks remain independent.
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
        categories.push("no_received".to_string());
        evidence.push(Evidence {
            description:
                "Received chain is absent from the captured headers; sender provenance cannot be verified"
                    .to_string(),
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
/// Also reused by link_content's IDN homograph skeleton matching.
pub(crate) fn normalize_homoglyph_simple(s: &str) -> String {
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
            '\u{04CF}' => 'l', // ӏ (Cyrillic palochka) → l (classic аррӏе.com PoC)
            '\u{043C}' => 'm', // м → m (needed for all-Cyrillic TLD spoofs: аррӏе.сом)
            '\u{03BF}' => 'o', // Greek omicron
            '\u{03B1}' => 'a', // Greek alpha
            '\u{03B5}' => 'e', // Greek epsilon
            '\u{03C1}' => 'p', // Greek rho
            '\u{03C4}' => 't', // Greek tau
            '\u{03BA}' => 'k', // Greek kappa
            '\u{03B9}' => 'i', // Greek iota
            '\u{03B7}' => 'n', // Greek eta
            '\u{03C9}' => 'w', // Greek omega
            '\u{0251}' => 'a', // Latin alpha
            '\u{026A}' => 'i', // Latin small capital I
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
    /// Type of similarity: `"homoglyph"`, `"tld_swap"`, or
    /// `"brand_typosquatting"`.
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
    let sender_lower = decode_idna_domain(sender_domain);
    if internal_domains
        .iter()
        .any(|internal| decode_idna_domain(internal) == sender_lower)
    {
        return None;
    }
    let (sender_base, sender_tld) = split_domain_parts(&sender_lower);

    // Skip very short base names — too many false positives
    if sender_base.len() < 3 {
        return None;
    }

    for internal in internal_domains {
        let internal_lower = decode_idna_domain(internal);
        let (int_base, int_tld) = split_domain_parts(&internal_lower);
        if int_base.len() < 3 {
            continue;
        }

        // Skip exact match — that's legitimate traffic, not impersonation
        if sender_lower == internal_lower {
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
        //    e.g. example.net vs example.com
        if sender_base == int_base && sender_tld != int_tld {
            return Some(ImpersonationHit {
                similarity_type: "tld_swap",
                score: 0.35,
                target_domain: internal.clone(),
                sender_domain: sender_lower.clone(),
            });
        }

        if let Some(score) = typo_similarity_score(&sender_base, &int_base) {
            return Some(ImpersonationHit {
                similarity_type: "brand_typosquatting",
                score,
                target_domain: internal.clone(),
                sender_domain: sender_lower.clone(),
            });
        }
    }

    // Real-time checks must also cover externally impersonated brands.  The
    // periodic threat-scene scanner only compares against internal domains,
    // which left `micr0soft.com`/`microsft.com` invisible until the batch run.
    // Brand anchors are runtime data so administrators can extend the set.
    let brand_entries: Vec<(String, String)> = module_data()
        .get_structured("brand_anchor_domains")
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    Some((
                        entry.get("keyword")?.as_str()?.to_string(),
                        entry.get("domain")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    for (_brand, anchor) in brand_entries {
        let anchor_lower = decode_idna_domain(&anchor);
        let (anchor_base, _anchor_tld) = split_domain_parts(&anchor_lower);
        if anchor_base.len() < 3 || sender_lower == anchor_lower {
            continue;
        }
        // Official brand subdomains are legitimate.  Compare only the
        // registrable domain so `login.microsoft.com` does not self-trigger.
        if sender_lower.ends_with(&format!(".{anchor_lower}")) {
            continue;
        }
        let normalized_sender = normalize_homoglyph_simple(&sender_base);
        let normalized_anchor = normalize_homoglyph_simple(&anchor_base);
        if sender_base != anchor_base && normalized_sender == normalized_anchor {
            return Some(ImpersonationHit {
                similarity_type: "brand_homoglyph",
                score: 0.70,
                target_domain: anchor,
                sender_domain: sender_lower.clone(),
            });
        }
        if let Some(score) = typo_similarity_score(&sender_base, &anchor_base) {
            return Some(ImpersonationHit {
                similarity_type: "brand_typosquatting",
                score: score.max(0.55),
                target_domain: anchor,
                sender_domain: sender_lower.clone(),
            });
        }
    }

    None
}

fn decode_idna_domain(domain: &str) -> String {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    if lower.contains("xn--") || !lower.is_ascii() {
        let (decoded, result) = idna::domain_to_unicode(&lower);
        if result.is_ok() {
            return decoded.to_ascii_lowercase();
        }
    }
    lower
}

fn typo_similarity_score(a: &str, b: &str) -> Option<f64> {
    if a == b || a.len() < 4 || b.len() < 4 {
        return None;
    }
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b_chars.len()).collect();
    let mut current = vec![0usize; b_chars.len() + 1];
    for (i, left) in a_chars.iter().enumerate() {
        current[0] = i + 1;
        for (j, right) in b_chars.iter().enumerate() {
            let cost = usize::from(left != right);
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + cost);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    let distance = previous[b_chars.len()];
    // Two arbitrary edits are too permissive for organizational domains:
    // unrelated names such as `acmebank` and `acmepqbank` can be accepted as
    // typosquatting even though no human would read one as a typo of the
    // other. Keep the one-edit path and the common adjacent-transposition
    // path, while leaving homoglyph and TLD-swap checks independent.
    if distance == 1 {
        return Some(0.62);
    }
    if distance == 2 && a_chars.len() == b_chars.len() {
        let mismatches: Vec<usize> = a_chars
            .iter()
            .zip(&b_chars)
            .enumerate()
            .filter_map(|(index, (left, right))| (left != right).then_some(index))
            .collect();
        if mismatches.len() == 2 {
            let first = mismatches[0];
            let second = mismatches[1];
            if second == first + 1
                && a_chars[first] == b_chars[second]
                && a_chars[second] == b_chars[first]
            {
                return Some(0.60);
            }
        }
    }
    None
}

/// Real-time domain impersonation detection.
///
/// Called for every inbound email in the header_scan pipeline.
/// Compares the sender's domain against internal domains and runtime brand
/// anchors using bounded, high-confidence checks.  This is intentionally
/// synchronous so external brand typosquatting and Punycode homographs are
/// visible on the first pass rather than waiting for the five-minute batch.
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

    fn ds_header_pair(from: &str, reply: Option<&str>) -> ParsedHeaders {
        let mut headers = vec![("From".to_string(), from.to_string())];
        if let Some(reply) = reply {
            headers.push(("Reply-To".to_string(), reply.to_string()));
        }
        ParsedHeaders::extract(&headers, "203.0.113.10", Some(from), true, &|_| false)
    }

    #[test]
    fn ds_domain_mismatch_item_keeps_its_own_score_and_field_pair() {
        let parsed = ds_header_pair("sender@one.example", Some("reply@two.example"));
        let mut score = 0.35; // Existing score from an unrelated check.
        let mut categories = vec!["prior_finding".to_string()];
        let mut evidence = vec![];
        let mut items = vec![];
        check_domain_mismatch(
            &parsed,
            &mut score,
            &mut categories,
            &mut evidence,
            &mut items,
        );

        assert!((score - 0.60).abs() < 1e-12);
        assert_eq!(categories, ["prior_finding", "domain_mismatch"]);
        assert_eq!(evidence.len(), 1);
        assert_eq!(
            evidence[0].location.as_deref(),
            Some("headers:From,Reply-To")
        );
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0]["categories"],
            serde_json::json!(["domain_mismatch"])
        );
        assert_eq!(items[0]["score"], 0.25);
        assert_eq!(items[0]["confidence"], 0.80);
        let key = items[0]["causal_key"].as_str().unwrap();
        assert!(key.starts_with("header_from_reply_to:sha256:"));
        assert!(!key.contains("one.example"));

        let mut normalized = vec![];
        check_domain_mismatch(
            &ds_header_pair("other@ONE.EXAMPLE", Some("other@TWO.EXAMPLE")),
            &mut 0.0,
            &mut vec![],
            &mut vec![],
            &mut normalized,
        );
        assert_eq!(items[0]["causal_key"], normalized[0]["causal_key"]);
        let mut changed = vec![];
        check_domain_mismatch(
            &ds_header_pair("sender@one.example", Some("reply@three.example")),
            &mut 0.0,
            &mut vec![],
            &mut vec![],
            &mut changed,
        );
        assert_ne!(items[0]["causal_key"], changed[0]["causal_key"]);
    }

    #[test]
    fn ds_domain_mismatch_item_is_absent_without_the_actual_field_contradiction() {
        for parsed in [
            ds_header_pair("sender@one.example", None),
            ds_header_pair("sender@one.example", Some("reply@one.example")),
        ] {
            let mut score = 0.30;
            let mut categories = vec!["envelope_spoofing".to_string()];
            let mut evidence = vec![];
            let mut items = vec![];
            check_domain_mismatch(
                &parsed,
                &mut score,
                &mut categories,
                &mut evidence,
                &mut items,
            );
            assert_eq!(score, 0.30);
            assert_eq!(categories, ["envelope_spoofing"]);
            assert!(evidence.is_empty());
        }
    }

    #[test]
    fn known_brand_sibling_suffix_is_not_a_from_reply_mismatch() {
        let mut score = 0.0;
        let mut categories = Vec::new();
        let mut evidence = Vec::new();
        let mut items = Vec::new();
        check_domain_mismatch(
            &ds_header_pair("service@rep.hundsun.cn", Some("service@hundsun.com")),
            &mut score,
            &mut categories,
            &mut evidence,
            &mut items,
        );
        assert_eq!(score, 0.0);
        assert!(categories.is_empty());
        assert!(items.is_empty());

        check_domain_mismatch(
            &ds_header_pair("service@hundsun.com", Some("service@evil.example")),
            &mut score,
            &mut categories,
            &mut evidence,
            &mut items,
        );
        assert!(categories.contains(&"domain_mismatch".to_string()));
        assert_eq!(items.len(), 1);
    }

    fn internal_display_ctx(display: &str, address: &str, body: &str) -> SecurityContext {
        use std::sync::Arc;
        use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(address.to_string());
        session.content = EmailContent {
            headers: vec![("From".to_string(), format!("{display} <{address}>"))],
            body_text: Some(body.to_string()),
            ..Default::default()
        };
        SecurityContext::with_internal_domains(
            Arc::new(session),
            Arc::new(HashSet::from(["corp.internal".to_string()])),
        )
    }

    #[test]
    fn exact_internal_domain_display_name_with_account_action_is_authority_lure() {
        let ctx = internal_display_ctx(
            "corp.internal-IT支持中心",
            "it@partner.example",
            "请按通知完成账户维护，谢谢配合。",
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_internal_domain_display_name(&ctx, &mut score, &mut categories, &mut evidence);

        assert!((score - 0.40).abs() < f64::EPSILON);
        assert!(categories.contains(&"display_name_spoof".to_string()));
        assert!(categories.contains(&"authority_display_name_lure".to_string()));
    }

    #[test]
    fn internal_display_name_uses_exact_boundaries_and_external_sender() {
        for ctx in [
            internal_display_ctx(
                "notcorp.internal-IT支持",
                "it@partner.example",
                "请按通知完成账户维护",
            ),
            internal_display_ctx(
                "corp.internal.example-IT支持",
                "it@partner.example",
                "请按通知完成账户维护",
            ),
            internal_display_ctx(
                "corp.internal-IT支持",
                "it@corp.internal",
                "请按通知完成账户维护",
            ),
        ] {
            let mut score = 0.0;
            let mut categories = vec![];
            let mut evidence = vec![];
            check_internal_domain_display_name(&ctx, &mut score, &mut categories, &mut evidence);
            assert_eq!(score, 0.0, "{categories:?} {evidence:?}");
        }
    }

    #[test]
    fn internal_domain_display_name_without_action_stays_weak() {
        let ctx = internal_display_ctx(
            "corp.internal status relay",
            "alerts@partner.example",
            "今日系统状态正常。",
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];
        check_internal_domain_display_name(&ctx, &mut score, &mut categories, &mut evidence);
        assert_eq!(score, 0.24);
        assert_eq!(categories, vec!["display_name_spoof".to_string()]);
    }

    fn parsed_with_mailer(mailer: &str) -> ParsedHeaders {
        ParsedHeaders::extract(
            &[("X-Mailer".to_string(), mailer.to_string())],
            "203.0.113.10",
            Some("sender@example.com"),
            true,
            &|_| false,
        )
    }

    #[test]
    fn official_coremail_mailmaster_client_is_not_suspicious() {
        for mailer in [
            "Coremail Webmail Server Version XT5.0.14 build 20250730 MailMasterIOS",
            "Coremail Webmail Server Version 2023.4-cmXT MailMasterHarmony/3.0.2.1128",
        ] {
            let parsed = parsed_with_mailer(mailer);
            let mut score = 0.0;
            let mut categories = vec![];
            let mut evidence = vec![];

            check_suspicious_mailer(&parsed, &mut score, &mut categories, &mut evidence);

            assert_eq!(score, 0.0, "{mailer}");
            assert!(categories.is_empty(), "{mailer}");
            assert!(evidence.is_empty(), "{mailer}");
        }
    }

    #[test]
    fn generic_mailmaster_and_phpmailer_remain_diagnostic_only() {
        for mailer in ["MailMasterIOS", "PHPMailer 6.9"] {
            let parsed = parsed_with_mailer(mailer);
            let mut score = 0.0;
            let mut categories = vec![];
            let mut evidence = vec![];

            check_suspicious_mailer(&parsed, &mut score, &mut categories, &mut evidence);

            assert_eq!(
                score, 0.0,
                "a self-declared mail client fingerprint is diagnostic, not threat evidence: {mailer}"
            );
            assert!(
                categories
                    .iter()
                    .any(|category| category == "suspicious_mailer")
            );
            assert!(
                !evidence.is_empty(),
                "the analyst-visible client observation must be retained: {mailer}"
            );
        }
    }

    #[test]
    fn parent_and_subdomain_sender_alignment_is_not_spoofing() {
        use std::sync::Arc;
        use vigilyx_core::models::{EmailSession, Protocol};

        let headers = vec![(
            "From".to_string(),
            "Fixture Association <newsletter@vendor.example>".to_string(),
        )];
        let parsed = ParsedHeaders::extract(
            &headers,
            "203.0.113.10",
            Some("relay@mail.vendor.example"),
            true,
            &|_| false,
        );
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("relay@mail.vendor.example".to_string());
        let ctx = SecurityContext::new(Arc::new(session));
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_envelope_spoofing(&parsed, &ctx, &mut score, &mut categories, &mut evidence);

        assert_eq!(score, 0.0);
        assert!(!categories.iter().any(|item| item == "envelope_spoofing"));
    }

    #[test]
    fn cross_organizational_sender_mismatch_remains_spoofing() {
        use std::sync::Arc;
        use vigilyx_core::models::{EmailSession, Protocol};

        let headers = vec![(
            "From".to_string(),
            "Fixture Association <newsletter@vendor.example>".to_string(),
        )];
        let parsed = ParsedHeaders::extract(
            &headers,
            "203.0.113.10",
            Some("bounce@evil.example"),
            true,
            &|_| false,
        );
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("bounce@evil.example".to_string());
        let ctx = SecurityContext::new(Arc::new(session));
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_envelope_spoofing(&parsed, &ctx, &mut score, &mut categories, &mut evidence);

        assert!(score > 0.0);
        assert!(categories.iter().any(|item| item == "envelope_spoofing"));
    }

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
        internals.insert("example.com".to_string());

        // Replace 'a' with Cyrillic а (U+0430)
        let fake = "ex\u{0430}mple.com";
        let hit = check_impersonation_quick(fake, &internals);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.similarity_type, "homoglyph");
        assert!((hit.score - 0.45).abs() < f64::EPSILON);
        assert_eq!(hit.target_domain, "example.com");
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
        internals.insert("example.com".to_string());

        let hit = check_impersonation_quick("example.net", &internals);
        assert!(hit.is_some());
        let hit = hit.unwrap();
        assert_eq!(hit.similarity_type, "tld_swap");
        assert!((hit.score - 0.35).abs() < f64::EPSILON);
    }

    #[test]
    fn test_impersonation_tld_swap_multi_tld() {
        let mut internals = HashSet::new();
        internals.insert("example.com.cn".to_string());

        let hit = check_impersonation_quick("example.org.cn", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "tld_swap");
    }

    #[test]
    fn test_impersonation_exact_match_skipped() {
        let mut internals = HashSet::new();
        internals.insert("example.com".to_string());

        // Exact match should NOT trigger
        let hit = check_impersonation_quick("example.com", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn test_impersonation_unrelated_domain() {
        let mut internals = HashSet::new();
        internals.insert("example.com".to_string());

        let hit = check_impersonation_quick("unrelated.invalid", &internals);
        assert!(hit.is_none());
    }

    #[test]
    fn two_arbitrary_domain_edits_do_not_create_typosquatting() {
        let mut internals = HashSet::new();
        internals.insert("acmepqbank.example".to_string());

        let hit = check_impersonation_quick("acmebank.example", &internals);
        assert!(
            hit.is_none(),
            "two arbitrary edits are not enough for a brand-typo claim"
        );
    }

    #[test]
    fn adjacent_domain_transposition_remains_detected() {
        let mut internals = HashSet::new();
        internals.insert("example.com".to_string());

        let hit = check_impersonation_quick("exmaple.com", &internals);
        assert_eq!(
            hit.expect("adjacent transposition should remain actionable")
                .similarity_type,
            "brand_typosquatting"
        );
    }

    #[test]
    fn missing_received_is_coverage_observation_without_threat_score() {
        let parsed = ParsedHeaders::extract(
            &[("From".to_string(), "sender@vendor.example".to_string())],
            "203.0.113.10",
            Some("sender@vendor.example"),
            true,
            &|_| false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_received_chain(&parsed, &mut score, &mut categories, &mut evidence);

        assert_eq!(score, 0.0);
        assert_eq!(categories, vec!["no_received".to_string()]);
        assert!(evidence[0].description.contains("sender provenance"));
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
    fn test_external_brand_typosquatting_is_realtime() {
        let internals = HashSet::new();
        let hit = check_impersonation_quick("microsft.com", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "brand_typosquatting");

        let hit = check_impersonation_quick("micr0soft.com", &internals);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().similarity_type, "brand_homoglyph");
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

    // ------------------------------------------------------------------
    // Direct Send abuse tests
    // ------------------------------------------------------------------

    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    fn ds_ctx(rcpt_domain: &str, headers: Vec<(&str, &str)>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.5".to_string(), // public attacker IP
            54321,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(format!("ceo@{}", rcpt_domain));
        session.rcpt_to = vec![format!("victim@{}", rcpt_domain)];
        session.content = EmailContent {
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            is_complete: true,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn parse_for_ctx(ctx: &SecurityContext) -> super::super::parsed::ParsedHeaders {
        super::super::parsed::ParsedHeaders::extract(
            &ctx.session.content.headers,
            &ctx.session.client_ip,
            ctx.session.mail_from.as_deref(),
            ctx.session.content.is_complete,
            &|_| false, // no internal domains for these tests
        )
    }

    #[test]
    fn unavailable_auth_verification_is_diagnostic_only() {
        let parsed = ParsedHeaders::extract_for_session(
            &[
                (
                    "From".to_string(),
                    "Fixture Sender <sender@vendor.example>".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "untrusted-auth.invalid; spf=pass smtp.mailfrom=vendor.example".to_string(),
                ),
                (
                    "DKIM-Signature".to_string(),
                    "v=1; d=vendor.example; s=fixture".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("sender@vendor.example"),
            true,
            &|_| false,
            false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_auth_results(&parsed, &mut score, &mut categories, &mut evidence);

        assert_eq!(score, 0.0, "diagnostic auth state must not add risk");
        assert!(
            categories
                .iter()
                .any(|category| category == "untrusted_auth_results")
        );
        assert!(
            categories
                .iter()
                .any(|category| category == "dkim_unverified")
        );
        assert!(
            !evidence.is_empty(),
            "analysts must retain the verification-gap details"
        );
    }

    #[test]
    fn microsoft_account_notification_without_verified_dkim_remains_flagged() {
        let parsed = ParsedHeaders::extract(
            &[
                (
                    "From".to_string(),
                    "Microsoft <fixture-security@accountprotection.microsoft.com>".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "mail.protection.outlook.com; spf=fail; dkim=none; dmarc=fail".to_string(),
                ),
                (
                    "DKIM-Signature".to_string(),
                    "v=1; d=accountprotection.microsoft.com; s=selector".to_string(),
                ),
                (
                    "X-MS-Exchange-CrossTenant-AuthAs".to_string(),
                    "Internal".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("fixture-security@accountprotection.microsoft.com"),
            true,
            &|_| false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_auth_results(&parsed, &mut score, &mut categories, &mut evidence);

        assert!(score >= 0.35, "score={score}, categories={categories:?}");
        assert!(
            categories.iter().any(|c| c == "auth_spf_dmarc_fail"),
            "unverified DKIM must not exempt SPF/DMARC failures: {categories:?}"
        );
        assert!(
            categories.iter().any(|c| c == "dkim_unverified"),
            "a DKIM header without a trusted dkim=pass must be flagged: {categories:?}"
        );
    }

    #[test]
    fn microsoft_auth_failure_without_internal_marker_remains_detected() {
        let parsed = ParsedHeaders::extract(
            &[
                (
                    "From".to_string(),
                    "Microsoft <fixture-security@accountprotection.microsoft.com>".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "mail.protection.outlook.com; spf=fail; dkim=none; dmarc=fail".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("fixture-security@accountprotection.microsoft.com"),
            true,
            &|_| false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_auth_results(&parsed, &mut score, &mut categories, &mut evidence);

        assert!(score >= 0.35);
        assert!(categories.iter().any(|c| c == "auth_spf_dmarc_fail"));
    }

    #[test]
    fn direct_send_abuse_eop_full_auth_fail_fires_high() {
        // Attacker delivers via *.mail.protection.outlook.com with a spoofed
        // From-domain matching the recipient's domain. SPF/DKIM/DMARC all
        // failed, no ARC. Expect direct_send_abuse with high score.
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "CEO <ceo@contoso.com>"),
                (
                    "Received",
                    "from mail.attacker.tld (203.0.113.5) by contoso-com.mail.protection.outlook.com",
                ),
                (
                    "Authentication-Results",
                    "contoso-com.mail.protection.outlook.com; spf=none; dkim=none; dmarc=none",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.iter().any(|c| c == "direct_send_abuse"),
            "expected direct_send_abuse, cats={:?} ev={:?}",
            cats,
            ev
        );
        assert!(score >= 0.50, "score should be >=0.50, got {}", score);
    }

    #[test]
    fn direct_send_arc_pass_clears_signal() {
        // Same EOP + spoof scenario but a legitimate forwarder produced
        // arc=pass. Must NOT fire (would be a false positive on mailing
        // lists / forwarders).
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "CEO <ceo@contoso.com>"),
                (
                    "Authentication-Results",
                    "contoso-com.mail.protection.outlook.com; spf=none; dkim=none; dmarc=none; arc=pass",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(cats.is_empty(), "arc=pass must suppress, got {:?}", cats);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn direct_send_dkim_pass_clears_signal() {
        // SPF and DMARC fail but DKIM passed (e.g. legit cross-tenant
        // M365 internal forwarding). Must NOT fire.
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "user@contoso.com"),
                (
                    "Authentication-Results",
                    "contoso-com.mail.protection.outlook.com; spf=none; dkim=pass; dmarc=none",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.is_empty(),
            "dkim=pass must suppress direct send, got {:?}",
            cats
        );
    }

    #[test]
    fn direct_send_temporary_auth_errors_do_not_fire() {
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "CEO <ceo@contoso.com>"),
                (
                    "Received",
                    "from mail.attacker.tld (203.0.113.5) by contoso-com.mail.protection.outlook.com",
                ),
                (
                    "Authentication-Results",
                    "contoso-com.mail.protection.outlook.com; spf=temperror; dkim=permerror; dmarc=temperror",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.is_empty(),
            "temporary/indeterminate auth states are coverage gaps, not direct-send evidence: {cats:?}"
        );
        assert_eq!(score, 0.0);
    }

    #[test]
    fn direct_send_non_eop_does_not_fire() {
        // Same auth-fail stack but the receiving MTA is Postfix (not EOP).
        // Direct Send is an EOP-specific phenomenon; must NOT fire here.
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "user@contoso.com"),
                (
                    "Authentication-Results",
                    "mx1.contoso.com; spf=none; dkim=none; dmarc=none",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.is_empty(),
            "non-EOP MTA must not trigger direct_send_abuse, got {:?}",
            cats
        );
    }

    #[test]
    fn direct_send_from_domain_not_recipient_does_not_fire() {
        // Auth-fail at EOP but From-domain != recipient domain (regular
        // external phishing — handled by other checks, not direct_send).
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.5".to_string(),
            54321,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("attacker@evil.tld".to_string());
        session.rcpt_to = vec!["victim@contoso.com".to_string()];
        session.content = EmailContent {
            headers: vec![
                ("From".to_string(), "attacker@evil.tld".to_string()),
                (
                    "Authentication-Results".to_string(),
                    "contoso-com.mail.protection.outlook.com; spf=none; dkim=none; dmarc=none"
                        .to_string(),
                ),
            ],
            is_complete: true,
            ..Default::default()
        };
        let ctx = SecurityContext::new(Arc::new(session));
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.is_empty(),
            "From != rcpt domain must not trigger, got {:?}",
            cats
        );
    }

    // ------------------------------------------------------------------
    // Forged Authentication-Results suppression (R4 hardening)
    // ------------------------------------------------------------------

    #[test]
    fn forged_deep_ar_pass_does_not_clear_spf_dmarc_fail() {
        // Attacker appends a forged AR claiming spf=pass/dmarc=pass below the
        // genuine gateway AR. The forgery must not neutralize the failures.
        let parsed = ParsedHeaders::extract(
            &[
                ("From".to_string(), "Attacker <boss@evil.tld>".to_string()),
                (
                    "Authentication-Results".to_string(),
                    "mx.example.org; spf=fail smtp.mailfrom=evil.tld; dkim=none; dmarc=fail"
                        .to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "attacker.tld; spf=pass; dkim=pass; dmarc=pass".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("boss@evil.tld"),
            true,
            &|_| false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_auth_results(&parsed, &mut score, &mut categories, &mut evidence);

        assert!(
            categories.iter().any(|c| c == "auth_spf_dmarc_fail"),
            "forged deep AR must not clear auth failures, categories={categories:?}"
        );
        assert!(score >= 0.35);
    }

    #[test]
    fn microsoft_exemption_requires_eop_evidence_at_trusted_hop() {
        // All four Microsoft-exemption signals are forgeable. The EOP evidence
        // must come from the trusted (topmost) AR hop; a forged deep AR plus
        // a forged Received mentioning protection.outlook.com must not exempt.
        let parsed = ParsedHeaders::extract(
            &[
                (
                    "From".to_string(),
                    "Microsoft <fixture-security@accountprotection.microsoft.com>".to_string(),
                ),
                (
                    "Received".to_string(),
                    "from attacker.tld ([203.0.113.10]) by fake.protection.outlook.com".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "mx.example.org; spf=fail; dkim=none; dmarc=fail".to_string(),
                ),
                (
                    "Authentication-Results".to_string(),
                    "contoso-com.mail.protection.outlook.com; spf=pass; dkim=pass; dmarc=pass"
                        .to_string(),
                ),
                (
                    "DKIM-Signature".to_string(),
                    "v=1; d=accountprotection.microsoft.com; s=forged".to_string(),
                ),
                (
                    "X-MS-Exchange-CrossTenant-AuthAs".to_string(),
                    "Internal".to_string(),
                ),
            ],
            "203.0.113.10",
            Some("fixture-security@accountprotection.microsoft.com"),
            true,
            &|_| false,
        );
        let mut score = 0.0;
        let mut categories = vec![];
        let mut evidence = vec![];

        check_auth_results(&parsed, &mut score, &mut categories, &mut evidence);

        assert!(
            categories.iter().any(|c| c == "auth_spf_dmarc_fail"),
            "forged EOP evidence must not exempt auth failures, categories={categories:?}"
        );
    }

    #[test]
    fn direct_send_forged_deep_arc_pass_does_not_suppress() {
        // Same Direct Send scenario as the positive test, plus a forged deep
        // AR claiming arc=pass. Must still fire.
        let ctx = ds_ctx(
            "contoso.com",
            vec![
                ("From", "CEO <ceo@contoso.com>"),
                (
                    "Received",
                    "from mail.attacker.tld (203.0.113.5) by contoso-com.mail.protection.outlook.com",
                ),
                (
                    "Authentication-Results",
                    "contoso-com.mail.protection.outlook.com; spf=none; dkim=none; dmarc=none",
                ),
                (
                    "Authentication-Results",
                    "forged.attacker.tld; arc=pass; spf=pass; dkim=pass; dmarc=pass",
                ),
            ],
        );
        let parsed = parse_for_ctx(&ctx);
        let mut score = 0.0;
        let mut cats = vec![];
        let mut ev = vec![];
        check_direct_send_abuse(&parsed, &ctx, &mut score, &mut cats, &mut ev);
        assert!(
            cats.iter().any(|c| c == "direct_send_abuse"),
            "forged deep arc=pass must not suppress direct_send_abuse, cats={:?}",
            cats
        );
    }
}
