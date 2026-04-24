//! Engine G: Identity Behavior Anomaly Detection

//! MVP signals derivable from email metadata alone (no IAM integration needed):
//! - First-contact detection (sender-recipient pair never seen before)
//! - Communication pattern mutation (same sender, changed behavior)
//! - Reply-chain anomaly (reply to a thread the recipient never participated in)
//! - Client fingerprint change (User-Agent/X-Mailer sudden shift)

//! Output: BPA triple (b, d, u) with engine_id = "identity_anomaly"

use std::collections::HashSet;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;

use std::sync::Arc;

use crate::bpa::Bpa;
use crate::context::SecurityContext;
use crate::db_service::DbQueryService;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::common::extract_domain_from_email;

/// Maximum score from all checks combined.
const MAX_RAW_SCORE: f64 = 1.0;
/// Individual signal weights.
/// First contact: sender domain has never emailed this organization before
const W_FIRST_CONTACT: f64 = 0.10; // Weak signal alone, but compounds with other signals
const W_DISPLAY_NAME_MISMATCH: f64 = 0.25;
const W_REPLY_CHAIN_ANOMALY: f64 = 0.30;
const W_CLIENT_FINGERPRINT: f64 = 0.15;
const W_ENVELOPE_MISMATCH: f64 = 0.20;
const W_LOCAL_PART_BRAND_SPOOF: f64 = 0.30;

/// Chinese pinyin initials (initial consonants). Used to support pinyin-initial abbreviations like
/// "sxyhxh", where each character is a valid pinyin initial.
/// Note: 'w' and 'y' are included because they commonly appear in abbreviations
/// for words whose romanized form starts with those letters.
const PINYIN_INITIALS: &[u8] = b"bpmfdtnlgkhjqxrzcsyw";

/// Check whether a short string consists entirely of valid pinyin initials.
/// This catches abbreviations like "sxyhxh", "dhcc", and "psbc".
/// It only applies to short labels (2-6 chars) to avoid
/// false negatives on longer DGA strings.
fn is_pinyin_initial_abbreviation(s: &str) -> bool {
    let len = s.len();
    // Only treat very short labels as possible abbreviations (2-6 chars)
    // Real Chinese org abbreviations rarely exceed 6 initials
    if !(2..=6).contains(&len) {
        return false;
    }
    s.bytes()
        .all(|b| PINYIN_INITIALS.contains(&b.to_ascii_lowercase()))
}

/// Check whether a username can be decomposed into pinyin syllables + common English words.
/// If decomposable, it is a legitimate name (e.g., weixinmphelper = weixin + mp + helper), not random.
pub fn is_pinyin_english_name(name: &str) -> bool {
    // Dynamic programming: can_cover[i] = name[0..i] can be fully decomposed
    let n = name.len();
    if n == 0 {
        return true;
    }
    let mut can_cover = vec![false; n + 1];
    can_cover[0] = true;

    let md = crate::module_data::module_data();
    for i in 0..n {
        if !can_cover[i] {
            continue;
        }
        // Try pinyin syllables
        for py in md.get_list("pinyin_syllables") {
            if name[i..].starts_with(py.as_str()) {
                can_cover[i + py.len()] = true;
            }
        }
        // Try common English words
        for ew in md.get_list("common_en_words") {
            if name[i..].starts_with(ew.as_str()) {
                can_cover[i + ew.len()] = true;
            }
        }
    }
    can_cover[n]
}

pub fn is_human_readable_domain_label(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    is_pinyin_english_name(&normalized)
        || is_pinyin_initial_abbreviation(&normalized)
        || crate::module_data::module_data().contains("benign_brand_domain_labels", &normalized)
}

fn sender_domain_has_established_brand_identity(domain: &str) -> bool {
    let normalized = domain.to_ascii_lowercase();
    if crate::modules::link_scan::is_well_known_safe_domain(&normalized)
        || crate::module_data::module_data().contains("known_financial_sender_domains", &normalized)
    {
        return true;
    }

    let labels: Vec<&str> = normalized
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    let brand_label = labels
        .len()
        .checked_sub(2)
        .and_then(|idx| labels.get(idx).copied())
        .unwrap_or(normalized.as_str());

    brand_label.len() >= 3 && is_human_readable_domain_label(brand_label)
}

pub struct IdentityAnomalyModule {
    meta: ModuleMetadata,
    db: Option<Arc<dyn DbQueryService>>,
}

impl Default for IdentityAnomalyModule {
    fn default() -> Self {
        Self::new(None)
    }
}

impl IdentityAnomalyModule {
    pub fn new(db: Option<Arc<dyn DbQueryService>>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "identity_anomaly".to_string(),
                name: "Identity Behavior Anomaly".to_string(),
                description: "Detect sender identity anomalies: first contact, display name spoofing, reply chain anomaly, client fingerprint change"
                    .to_string(),
                pillar: Pillar::Semantic,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None, // First-contact detection requires DB query, not CPU-bound
            },
            db,
        }
    }

    /// Check if display name looks like it's impersonating a different domain
    #[inline]
    fn check_display_name_mismatch(&self, headers: &[(String, String)]) -> Option<(f64, Evidence)> {
        let from_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))?;
        let from_value = &from_header.1;

        // Extract display name and email address from "Display Name <email@domain>" format
        if let Some(angle_start) = from_value.rfind('<') {
            let display_name = from_value[..angle_start].trim().trim_matches('"');
            let email_part = from_value[angle_start..].trim_matches(|c| c == '<' || c == '>');

            if display_name.is_empty() {
                return None;
            }

            let email_domain = email_part.rsplit('@').next()?;
            let dn_lower = display_name.to_ascii_lowercase();

            // Check if display name contains an email-like pattern with a different domain
            static EMAIL_IN_DN: std::sync::LazyLock<Regex> =
                std::sync::LazyLock::new(|| Regex::new(r"[\w.+-]+@[\w.-]+\.\w{2,}").unwrap());

            if let Some(m) = EMAIL_IN_DN.find(&dn_lower) {
                let dn_email = m.as_str();
                if let Some(dn_domain) = dn_email.rsplit('@').next()
                    && dn_domain != email_domain.to_ascii_lowercase()
                {
                    return Some((
                        W_DISPLAY_NAME_MISMATCH,
                        Evidence {
                            description: format!(
                                "Display name contains email from different domain: display=\"{}\" actual sender domain={}",
                                display_name, email_domain
                            ),
                            location: Some("From header".to_string()),
                            snippet: Some(from_value.clone()),
                        },
                    ));
                }
            }

            // Check if display name mimics a well-known service
            for target in
                crate::module_data::module_data().get_list("display_name_impersonation_targets")
            {
                if dn_lower.contains(target.as_str())
                    && !email_domain.to_ascii_lowercase().contains(target.as_str())
                {
                    return Some((
                        W_DISPLAY_NAME_MISMATCH * 0.8,
                        Evidence {
                            description: format!(
                                "Display name impersonates known service: \"{}\" but sender domain is {}",
                                display_name, email_domain
                            ),
                            location: Some("From header".to_string()),
                            snippet: Some(from_value.clone()),
                        },
                    ));
                }
            }
        }

        None
    }

    /// Check if the sender's local part impersonates a known brand.
    /// Pattern: {brand}{separator}{random}@{non-brand-domain}
    /// e.g. apple-stoermoxg@fmworld.net, icloud-jpexyv@ml.nitori-net.jp
    fn check_local_part_brand_spoof(
        &self,
        mail_from: &str,
        sender_domain: &str,
    ) -> Option<(f64, Vec<String>, Evidence)> {
        let local_part = mail_from.split('@').next()?.to_ascii_lowercase();
        let sender_domain_lower = sender_domain.to_ascii_lowercase();

        // Brand → legitimate domain suffixes mapping
        let brand_checks: &[(&str, &[&str])] = &[
            ("apple", &["apple.com", "icloud.com"]),
            ("icloud", &["apple.com", "icloud.com"]),
            ("microsoft", &["microsoft.com", "outlook.com", "live.com"]),
            ("outlook", &["microsoft.com", "outlook.com"]),
            ("google", &["google.com", "gmail.com"]),
            ("amazon", &["amazon."]),
            ("paypal", &["paypal.com"]),
            ("netflix", &["netflix.com"]),
            ("dhl", &["dhl.com", "dhl.de"]),
            ("fedex", &["fedex.com"]),
        ];

        for (brand, legit_domains) in brand_checks {
            // Check if local part starts with the brand name
            if !local_part.starts_with(brand) {
                continue;
            }

            // The character after the brand name
            let after_brand = &local_part[brand.len()..];
            if after_brand.is_empty() {
                // Exact match like "apple@domain" — could be legitimate alias, skip
                continue;
            }

            // Must have a separator (-_.) or random chars
            let first_after = after_brand.chars().next().unwrap_or(' ');
            let has_separator = matches!(first_after, '-' | '_' | '.');
            let suffix_after_brand = if has_separator {
                &after_brand[1..]
            } else {
                after_brand
            };

            // Skip known legitimate suffixes (applepay, applestore, icloudmail, etc.)
            let legit_suffixes = [
                "pay",
                "store",
                "music",
                "news",
                "tv",
                "id",
                "care",
                "support",
                "mail",
                "drive",
                "maps",
                "photos",
                "cloud",
                "one",
                "office",
                "prime",
                "web",
                "seller",
                "ads",
                "alexa",
                "express",
                "ground",
                "freight",
                "ship",
                "noreply",
                "no-reply",
                "donotreply",
            ];
            let suffix_lower = suffix_after_brand.to_ascii_lowercase();
            if legit_suffixes.iter().any(|s| suffix_lower == *s) {
                continue;
            }

            // Check if domain is NOT a legitimate brand domain
            let domain_is_legit = legit_domains.iter().any(|ld| {
                sender_domain_lower == *ld
                    || sender_domain_lower.ends_with(&format!(".{ld}"))
                    || (ld.ends_with('.') && sender_domain_lower.contains(ld.trim_end_matches('.')))
            });

            if domain_is_legit {
                continue;
            }

            // Brand in local part + non-brand domain = suspicious
            let is_strong = has_separator && suffix_after_brand.len() >= 4;
            let score = if is_strong {
                W_LOCAL_PART_BRAND_SPOOF
            } else if suffix_after_brand.len() >= 6 {
                W_LOCAL_PART_BRAND_SPOOF * 0.8
            } else {
                W_LOCAL_PART_BRAND_SPOOF * 0.5
            };

            return Some((
                score,
                vec!["local_part_brand_spoof".to_string()],
                Evidence {
                    description: format!(
                        "Sender local part impersonates brand '{}': {}@{} — domain is not associated with {}",
                        brand, local_part, sender_domain, brand
                    ),
                    location: Some("envelope:MAIL_FROM".to_string()),
                    snippet: Some(mail_from.to_string()),
                },
            ));
        }

        None
    }

    /// Check for reply-chain anomalies (In-Reply-To / References mismatch)
    fn check_reply_chain_anomaly(
        &self,
        headers: &[(String, String)],
        rcpt_to: &[String],
        mail_from: Option<&str>,
    ) -> Option<(f64, Evidence)> {
        let in_reply_to = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("in-reply-to"));
        let references = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("references"));

        // If it claims to be a reply but there's no matching thread context
        if let Some((_, reply_id)) = in_reply_to
            && !reply_id.trim().is_empty()
        {
            // Check if Subject starts with Re: but we have no prior thread evidence
            let subject = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("subject"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");

            let is_reply_subject = subject.starts_with("Re:")
                || subject.starts_with("RE:")
                || subject.starts_with("re:")
                || subject.starts_with("Fwd:")
                || subject.starts_with("FW:");

            // Suspicious: has In-Reply-To but no References header
            // (legitimate mail clients usually include References)
            if references.is_none() && is_reply_subject {
                return Some((
                    W_REPLY_CHAIN_ANOMALY * 0.6,
                    Evidence {
                        description:
                            "Reply email missing References header (possibly spoofed reply chain)"
                                .to_string(),
                        location: Some("In-Reply-To".to_string()),
                        snippet: Some(reply_id.clone()),
                    },
                ));
            }

            // Suspicious: reply claims to be from a thread but neither sender
            // nor recipient domain appears in References
            if let Some((_, refs)) = references {
                let rcpt_domains: HashSet<&str> = rcpt_to
                    .iter()
                    .filter_map(|r| r.rsplit('@').next())
                    .collect();

                let sender_domain = mail_from.and_then(|addr| addr.rsplit('@').next());

                let ref_domains: HashSet<&str> = refs
                    .split_whitespace()
                    .filter_map(|r| r.trim_matches(|c| c == '<' || c == '>').rsplit('@').next())
                    .collect();

                // Check if sender domain appears in References -> normal for legitimate replies
                // (e.g., internal email threads)
                let sender_in_refs =
                    sender_domain.is_some_and(|sd| ref_domains.iter().any(|rd| rd.contains(sd)));

                // Only flag if NEITHER sender nor recipient domain appears in refs
                if !ref_domains.is_empty()
                    && !rcpt_domains.is_empty()
                    && rcpt_domains.is_disjoint(&ref_domains)
                    && !sender_in_refs
                {
                    return Some((
                        W_REPLY_CHAIN_ANOMALY,
                        Evidence {
                            description:
                                "Reply chain domains completely mismatch sender/recipient domains"
                                    .to_string(),
                            location: Some("References".to_string()),
                            snippet: Some(refs.chars().take(200).collect()),
                        },
                    ));
                }
            }
        }

        None
    }

    /// Check for suspicious mail client fingerprints
    fn check_client_fingerprint(&self, headers: &[(String, String)]) -> Option<(f64, Evidence)> {
        // Check X-Mailer and User-Agent headers
        let md = crate::module_data::module_data();
        for (key, value) in headers {
            let k = key.to_ascii_lowercase();
            if k == "x-mailer" || k == "user-agent" {
                let v_lower = value.to_ascii_lowercase();
                for agent in md.get_list("suspicious_user_agents") {
                    if v_lower.contains(agent.as_str()) {
                        return Some((
                            W_CLIENT_FINGERPRINT,
                            Evidence {
                                description: format!(
                                    "Suspicious email client fingerprint: {} = \"{}\"",
                                    key, value
                                ),
                                location: Some(key.clone()),
                                snippet: Some(value.clone()),
                            },
                        ));
                    }
                }
            }
        }

        // Check for missing standard headers (legitimate clients always include these)
        let has_mime_version = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("mime-version"));
        let has_content_type = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));

        if !has_mime_version && !has_content_type {
            return Some((
                W_CLIENT_FINGERPRINT * 0.5,
                Evidence {
                    description:
                        "Missing MIME-Version and Content-Type headers (non-standard email client)"
                            .to_string(),
                    location: Some("headers".to_string()),
                    snippet: None,
                },
            ));
        }

        None
    }

    /// Check envelope vs header mismatch (MAIL FROM vs From header)
    fn check_envelope_mismatch(
        &self,
        mail_from: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<(f64, Evidence)> {
        let envelope_from = mail_from?;
        let header_from = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))
            .map(|(_, v)| v.as_str())?;
        let env_domain = extract_domain_from_email(envelope_from)?;
        let hdr_domain = extract_domain_from_email(header_from)?;

        if env_domain != hdr_domain {
            return Some((
                W_ENVELOPE_MISMATCH,
                Evidence {
                    description: format!(
                        "Envelope sender domain mismatches email header: MAIL FROM=@{} vs From=@{}",
                        env_domain, hdr_domain
                    ),
                    location: Some("MAIL FROM / From header".to_string()),
                    snippet: Some(format!(
                        "envelope: {} | header: {}",
                        envelope_from, header_from
                    )),
                },
            ));
        }

        None
    }
}

#[async_trait]
impl SecurityModule for IdentityAnomalyModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let headers = &ctx.session.content.headers;

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        // 1. Display name mismatch / impersonation
        if let Some((score, ev)) = self.check_display_name_mismatch(headers) {
            total_score += score;
            categories.push("display_name_spoof".to_string());
            evidence.push(ev);
        }

        // 1b. Local part brand impersonation (e.g. apple-stoermoxg@fmworld.net)
        if let Some(mail_from) = ctx.session.mail_from.as_deref()
            && let Some(sender_domain) = mail_from.split('@').nth(1)
            && let Some((score, cats, ev)) =
                self.check_local_part_brand_spoof(mail_from, sender_domain)
        {
            total_score += score;
            categories.extend(cats);
            evidence.push(ev);
        }

        // 2. Reply chain anomaly
        // Skip internal senders: internal users forwarding/replying is normal behavior
        let sender_is_internal = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(|mf| mf.split('@').nth(1))
            .is_some_and(|d| ctx.is_internal_domain(&d.to_lowercase()));
        if !sender_is_internal
            && let Some((score, ev)) = self.check_reply_chain_anomaly(
                headers,
                &ctx.session.rcpt_to,
                ctx.session.mail_from.as_deref(),
            )
        {
            total_score += score;
            categories.push("reply_chain_anomaly".to_string());
            evidence.push(ev);
        }

        // 3. Client fingerprint
        if let Some((score, ev)) = self.check_client_fingerprint(headers) {
            total_score += score;
            categories.push("suspicious_client".to_string());
            evidence.push(ev);
        }

        // 4. Envelope mismatch
        if let Some((score, ev)) =
            self.check_envelope_mismatch(ctx.session.mail_from.as_deref(), headers)
        {
            total_score += score;
            categories.push("envelope_mismatch".to_string());
            evidence.push(ev);
        }

        // 5. First-contact detection (DB-backed)
        // Check if sender domain has ever appeared in session history -> first contact detection
        // Skip internal domains from this check
        if let Some(ref db) = self.db
            && let Some(ref mail_from) = ctx.session.mail_from
            && let Some(sender_domain) = mail_from.split('@').nth(1)
        {
            let sender_domain_lower = sender_domain.to_lowercase();
            // Skip internal domains (dynamic detection + hardcoded)
            let is_internal = ctx.is_internal_domain(&sender_domain_lower)
                || sender_domain_lower == "corp-internal.com";

            // Skip well-known public email providers — millions of individual
            // users share these domains, so domain-level "first contact" is
            // meaningless noise. Individual sender-level checks (random_sender,
            // envelope_mismatch, etc.) still apply.
            let is_public_provider =
                crate::pipeline::internal_domains::is_public_mail_domain(&sender_domain_lower);

            // Heuristic fallback: if the domain has many distinct senders in our
            // history, it's likely a shared/public domain we didn't know about.
            // Threshold: 10+ unique senders → treat as shared domain.
            let is_shared_domain = if !is_internal && !is_public_provider {
                match db
                    .count_distinct_senders_for_domain(&sender_domain_lower)
                    .await
                {
                    Ok(count) if count >= 10 => {
                        tracing::debug!(
                            domain = %sender_domain_lower,
                            distinct_senders = count,
                            "Skipping first-contact: domain has high sender diversity"
                        );
                        true
                    }
                    _ => false,
                }
            } else {
                false
            };

            if !is_internal && !is_public_provider && !is_shared_domain {
                let session_id = ctx.session.id.to_string();
                match db
                    .count_sender_domain_history(&sender_domain_lower, &session_id)
                    .await
                {
                    Ok(0) => {
                        total_score += W_FIRST_CONTACT;
                        categories.push("first_contact".to_string());
                        evidence.push(Evidence {
                            description: format!(
                                "First contact: domain {} has never sent email to this organization in history",
                                sender_domain_lower
                            ),
                            location: Some("envelope:MAIL_FROM".to_string()),
                            snippet: Some(mail_from.clone()),
                        });
                    }
                    Ok(_) => {} // Known sender domain, no additional risk
                    Err(e) => {
                        tracing::warn!("First-contact DB query failed: {}", e);
                    }
                }
            }
        }

        // 6. Sender domain randomness detection (DGA-like domains)
        if let Some(ref mail_from) = ctx.session.mail_from
            && let Some(sender_domain) = mail_from.split('@').nth(1)
        {
            let sender_domain_lower = sender_domain.to_ascii_lowercase();

            let is_internal = ctx.internal_domains.iter().any(|d| {
                sender_domain_lower == *d || sender_domain_lower.ends_with(&format!(".{d}"))
            });

            // Skip well-known safe domains (intel_safe + admin_clean IOC)
            let is_safe =
                crate::modules::link_scan::is_well_known_safe_domain(&sender_domain_lower);

            let main_part = sender_domain.split('.').next().unwrap_or("");

            // (a) 5+ consecutive consonants -> likely random/DGA (snajgc, bncgjwl)
            // (b) Short mixed alphanumeric -> likely random (8t5om, ycgg4)
            // Excludes pinyin+English names (qingcloud = qing+cloud)
            // Excludes pinyin-initial abbreviations such as "sxyhxh".
            // Excludes known brand domains (hundsun, cmbchina, etc.)
            if main_part.len() >= 4
                && !is_human_readable_domain_label(main_part)
                && !is_internal
                && !is_safe
            {
                let mut is_random = false;
                let mut reason = String::new();

                // (a) 5+ consecutive consonants -> likely random/DGA (snajgc, bncgjwl)
                // Chinese pinyin abbreviations naturally produce 3-4 consonant clusters
                // (e.g., "nkw" in hzbankwealth, "ngcr" in baihangcredit), so threshold is 5
                let consecutive_consonants = {
                    let mut max_run = 0u32;
                    let mut run = 0u32;
                    for ch in main_part.chars() {
                        if "bcdfghjklmnpqrstvwxyz".contains(ch.to_ascii_lowercase()) {
                            run += 1;
                            if run > max_run {
                                max_run = run;
                            }
                        } else {
                            run = 0;
                        }
                    }
                    max_run
                };
                if consecutive_consonants >= 5 {
                    is_random = true;
                    reason = format!("{} consecutive consonants", consecutive_consonants);
                }

                // (b): Short mixed alphanumeric (8t5om, ycgg4, 2fkje0)
                if !is_random && main_part.len() <= 8 {
                    let has_digit = main_part.chars().any(|c| c.is_ascii_digit());
                    let has_alpha = main_part.chars().any(|c| c.is_ascii_alphabetic());
                    let alpha_count = main_part
                        .chars()
                        .filter(|c| c.is_ascii_alphabetic())
                        .count();

                    if has_digit && has_alpha && alpha_count <= 5 {
                        is_random = true;
                        reason = "short mixed alphanumeric domain".to_string();
                    }
                }

                if is_random {
                    total_score += 0.25;
                    categories.push("random_domain".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Sender domain {} likely random/DGA-generated ({})",
                            sender_domain, reason
                        ),
                        location: Some("envelope:MAIL_FROM".to_string()),
                        snippet: Some(mail_from.clone()),
                    });
                }
            }
        }

        // --- Random username detection (e.g., pvzpfvq@hleg.com, ktipfnl@udcoraqhs.com) ---
        // Skips internal domains: Chinese pinyin usernames (yybdyy, wnssh) look random but aren't
        // Skips pinyin+English decomposable usernames (e.g., weixinmphelper, alipaynotify)
        // Skips public mail providers (qq.com, 163.com, gmail.com...): free-form usernames are normal
        if let Some(ref mail_from) = ctx.session.mail_from
            && let Some(username) = mail_from.split('@').next()
            && let Some(domain) = mail_from.split('@').nth(1)
            && !ctx.is_internal_domain(domain)
            && !crate::pipeline::internal_domains::is_public_mail_domain(&domain.to_lowercase())
            && !crate::modules::link_scan::is_well_known_safe_domain(&domain.to_lowercase())
            && !sender_domain_has_established_brand_identity(domain)
        {
            // Pure alpha username, 5+ chars, 4+ consecutive consonants -> likely randomly generated
            if username.len() >= 5
                && username.chars().all(|c| c.is_ascii_alphabetic())
                && !is_pinyin_english_name(&username.to_ascii_lowercase())
            {
                let max_consonant_run = {
                    let mut max_run = 0u32;
                    let mut run = 0u32;
                    for ch in username.chars() {
                        if "bcdfghjklmnpqrstvwxyz".contains(ch.to_ascii_lowercase()) {
                            run += 1;
                            if run > max_run {
                                max_run = run;
                            }
                        } else {
                            run = 0;
                        }
                    }
                    max_run
                };
                if max_consonant_run >= 4 {
                    total_score += 0.20;
                    categories.push("random_sender".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Sender username {} contains {} consecutive consonants, likely randomly generated address",
                            username, max_consonant_run
                        ),
                        location: Some("envelope:MAIL_FROM".to_string()),
                        snippet: Some(mail_from.clone()),
                    });
                }
            }
        }

        // Compound signal: Envelope forgery + random sender/domain + first contact
        // All 3 together form a classic spoofing attack pattern with elevated risk
        let has_envelope = categories.contains(&"envelope_mismatch".to_string());
        let has_random = categories.contains(&"random_sender".to_string())
            || categories.contains(&"random_domain".to_string());
        let has_first = categories.contains(&"first_contact".to_string());
        if has_envelope && has_random && has_first {
            total_score += 0.25;
            evidence.push(Evidence {
                description: "Compound identity spoofing: envelope forgery + random sender + first contact — classic attack pattern".to_string(),
                location: Some("compound_signal".to_string()),
                snippet: None,
            });
        } else if has_envelope && has_random {
            // Envelope forgery + random sender (without first contact) still noteworthy
            total_score += 0.15;
            evidence.push(Evidence {
                description: "Compound identity spoofing: envelope forgery + random sender"
                    .to_string(),
                location: Some("compound_signal".to_string()),
                snippet: None,
            });
        }

        total_score = total_score.min(MAX_RAW_SCORE);
        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No identity behavior anomalies found",
                duration_ms,
            ));
        }

        categories.dedup();

        // Confidence: moderate (0.70) since these are heuristic checks
        let confidence = 0.70;
        let bpa = Bpa::from_score_confidence(total_score, confidence);

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories,
            summary: format!(
                "Identity behavior anomaly detection found {} anomalies, composite score {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(bpa),
            engine_id: Some("identity_anomaly".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinyin_english_names_not_random() {
        // All legitimate pinyin + English word combinations, should not be flagged as random
        assert!(
            is_pinyin_english_name("weixinmphelper"),
            "weixinmphelper = weixin+mp+helper"
        );
        assert!(
            is_pinyin_english_name("alipaynotify"),
            "alipaynotify = ali+pay+notify"
        );
        assert!(
            is_pinyin_english_name("dingdingbot"),
            "dingdingbot = ding+ding+bot"
        );
        assert!(is_pinyin_english_name("wangyi"), "wangyi = wang+yi");
        assert!(is_pinyin_english_name("zhifubao"), "zhifubao = zhi+fu+bao");
        assert!(
            is_pinyin_english_name("huaweicloud"),
            "huaweicloud = hua+wei+cloud"
        );
        assert!(is_pinyin_english_name("xiaomi"), "xiaomi = xiao+mi");
        assert!(
            is_pinyin_english_name("systemadmin"),
            "systemadmin = system+admin"
        );
        assert!(
            is_pinyin_english_name("noreply"),
            "noreply = no+re+ply... hmm"
        );
        assert!(is_pinyin_english_name("testmail"), "testmail = test+mail");
    }

    #[test]
    fn test_random_names_detected() {
        // Random strings that cannot be decomposed into pinyin or English words
        assert!(!is_pinyin_english_name("pvzpfvq"), "pvzpfvq is random");
        assert!(!is_pinyin_english_name("ktipfnl"), "ktipfnl is random");
        assert!(!is_pinyin_english_name("xhjqwzk"), "xhjqwzk is random");
        assert!(!is_pinyin_english_name("bdfghjk"), "bdfghjk is random");
    }

    #[test]
    fn test_human_readable_brand_labels_not_treated_as_random() {
        assert!(is_human_readable_domain_label("hundsun"));
        assert!(is_human_readable_domain_label("smartx"));
        assert!(is_human_readable_domain_label("aishu"));
        assert!(!is_human_readable_domain_label("xvkrnbstq"));
    }

    #[test]
    fn test_chinese_finance_domains_not_flagged_as_random() {
        // Pinyin + English word combinations
        assert!(
            is_human_readable_domain_label("baihangcredit"),
            "baihangcredit = bai+hang+credit (百行征信)"
        );
        assert!(
            is_human_readable_domain_label("hzbankwealth"),
            "hzbankwealth is in BENIGN_BRAND_DOMAIN_LABELS (杭州银行财富管理)"
        );

        // Brand list entries
        assert!(
            is_human_readable_domain_label("cjhxfund"),
            "cjhxfund is in BENIGN_BRAND_DOMAIN_LABELS (长安华信基金)"
        );
        assert!(
            is_human_readable_domain_label("crctrust"),
            "crctrust is in BENIGN_BRAND_DOMAIN_LABELS (华润信托)"
        );

        // Pinyin initial abbreviations
        assert!(
            is_human_readable_domain_label("sxyhxh"),
            "sxyhxh = pinyin initials S-X-Y-H-X-H (陕西银行协会)"
        );
        assert!(
            is_human_readable_domain_label("dhcc"),
            "dhcc = pinyin initials D-H-C-C (东华软件)"
        );
        assert!(
            is_human_readable_domain_label("psbc"),
            "psbc = pinyin initials P-S-B-C (邮储银行)"
        );
    }

    #[test]
    fn test_pinyin_initial_abbreviation_rejects_long_random_strings() {
        // Strings > 6 chars should NOT be treated as pinyin abbreviations
        assert!(
            !is_pinyin_initial_abbreviation("xhjqwzk"),
            "7-char string too long for abbreviation"
        );
        assert!(
            !is_pinyin_initial_abbreviation("bdfghjk"),
            "7-char string too long for abbreviation"
        );
        // Strings with non-initial letters
        assert!(
            !is_pinyin_initial_abbreviation("xvkr"),
            "v is not a pinyin initial"
        );
    }

    #[test]
    fn test_new_common_en_words_recognized() {
        // Words added for financial domain support
        assert!(
            is_pinyin_english_name("fund"),
            "fund should be in COMMON_EN_WORDS"
        );
        assert!(
            is_pinyin_english_name("trust"),
            "trust should be in COMMON_EN_WORDS"
        );
        assert!(
            is_pinyin_english_name("credit"),
            "credit should be in COMMON_EN_WORDS"
        );
        assert!(
            is_pinyin_english_name("wealth"),
            "wealth should be in COMMON_EN_WORDS"
        );
        // Compound: pinyin + new English word
        assert!(
            is_pinyin_english_name("baihangcredit"),
            "baihangcredit = bai+hang+credit"
        );
    }

    #[test]
    fn test_envelope_mismatch_ignores_malformed_from_header_without_address() {
        let module = IdentityAnomalyModule::new(None);
        let headers = vec![("From".to_string(), "\"=?utf-8?B?OTE5NzA4NzQx".to_string())];

        let result = module.check_envelope_mismatch(Some("919708741@qq.com"), &headers);

        assert!(result.is_none());
    }

    #[test]
    fn test_envelope_mismatch_still_detects_real_cross_domain_mismatch() {
        let module = IdentityAnomalyModule::new(None);
        let headers = vec![(
            "From".to_string(),
            "Trusted Sender <notice@example.com>".to_string(),
        )];

        let result = module.check_envelope_mismatch(Some("bounce@mailer.other.com"), &headers);

        assert!(result.is_some());
    }

    // ─── P0-3: DGA detection tuning regression tests ───

    #[test]
    fn test_new_brand_domain_labels_not_flagged_as_dga() {
        // Labels that exist in BENIGN_BRAND_DOMAIN_LABELS
        let brand_labels = [
            "kycregistry", // KYC Registry (SWIFT)
            "rescdn",      // Resource CDN
            "bytetos",     // ByteDance TOS CDN
            "feishu",      // Feishu (Lark)
            "dingtalk",    // DingTalk
            "alipay",      // Alipay
            "venustech",   // Security vendor
            "sangfor",     // Security vendor
            "nsfocus",     // Security vendor
            "swift",       // SWIFT financial network
        ];
        for label in &brand_labels {
            assert!(
                is_human_readable_domain_label(label),
                "{} should be recognized as benign brand label",
                label
            );
        }
    }

    #[test]
    fn test_new_it_infrastructure_words_recognized() {
        // IT/infrastructure words that exist in COMMON_EN_WORDS
        let it_words = [
            "cloud", "registry", "cdn", "portal", "proxy", "node", "config", "deploy", "monitor",
            "cache", "edge", "sync", "token", "auth", "verify",
        ];
        for word in &it_words {
            assert!(
                is_pinyin_english_name(word),
                "'{}' should be in COMMON_EN_WORDS and recognized",
                word
            );
        }
    }

    #[test]
    fn test_compound_it_brand_labels() {
        // Brand labels that should be recognized directly
        assert!(
            is_human_readable_domain_label("kycregistry"),
            "kycregistry in brand list"
        );
        assert!(
            is_human_readable_domain_label("rescdn"),
            "rescdn in brand list"
        );
        assert!(
            is_human_readable_domain_label("bytetos"),
            "bytetos in brand list"
        );
    }

    #[test]
    fn test_established_brand_sender_domains_skip_random_sender_heuristic() {
        assert!(sender_domain_has_established_brand_identity("cmbchina.com"));
        assert!(sender_domain_has_established_brand_identity(
            "rep.hundsun.cn"
        ));
        assert!(!sender_domain_has_established_brand_identity(
            "xvkrnbstq-mail.net"
        ));
    }
}
