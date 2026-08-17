//! IOC auto-recording logic

//! Automatically extracts IOCs from critical-threat verdicts (>= Critical only):
//! - `auto_record_from_verdict` - General extraction: IP/domain/email/attachment hash/suspicious links
//! - `auto_record_internal_spoofing` - Internal domain spoofing detection
//! - `auto_record_nonsensical` - Nonsensical email auto-recording
//! - `auto_record_impersonation_domain` - Domain impersonation hits (gate: verdict >= High)
//!
//! IMPORTANT: All auto-record thresholds must be >= High, and most paths require
//! >= Critical (score >= 0.85). Using Medium or lower will re-create the IOC
//! amplification loop discovered in 2026-03-18.

use super::IocManager;
use crate::module::ThreatLevel;
use crate::verdict::SecurityVerdict;
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;
use tracing::{info, warn};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::IocEntry;

/// Check if IP is a private/reserved address
fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("127.")
        || ip.starts_with("0.")
        || ip.starts_with("192.168.")
        || ip.starts_with("169.254.")
        || ip == "::1"
        || {
            if let Some(rest) = ip.strip_prefix("172.")
                && let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok())
            {
                return (16..=31).contains(&second);
            }
            false
        }
}

static RE_BRACKET_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]").unwrap());

/// Extract outermost true external IP from email Received headers

/// Received headers are arranged top to bottom (top = last hop, bottom = first hop).
/// Only the **topmost** Received header is trusted: it is the stamp our own
/// gateway added when accepting the message. Deeper Received headers are
/// attacker-controllable and must not seed IOCs.
fn extract_origin_ip(session: &EmailSession) -> Option<String> {
    let (_, value) = session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("received"))?;
    // Extract IP from brackets: [185.243.242.238]
    for cap in RE_BRACKET_IP.captures_iter(value) {
        if let Some(m) = cap.get(1) {
            let ip = m.as_str();
            if !is_private_ip(ip) {
                return Some(ip.to_string());
            }
        }
    }
    None
}

/// Extract external IPs eligible for auto-recording (deduplicated)

/// Trust rules:
/// - Only the topmost Received header (the gateway stamp) is scanned; forged
///   deeper Received headers cannot inject arbitrary "attacker" IPs.
/// - The network-layer `client_ip` is always included when public: it cannot
///   be forged via headers, and a forged Received chain must not mask it.
fn extract_all_external_ips(session: &EmailSession) -> Vec<String> {
    let mut ips = Vec::new();
    let mut seen = HashSet::new();

    if let Some((_, value)) = session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("received"))
    {
        for cap in RE_BRACKET_IP.captures_iter(value) {
            if let Some(m) = cap.get(1) {
                let ip = m.as_str();
                if !is_private_ip(ip) && seen.insert(ip.to_string()) {
                    ips.push(ip.to_string());
                }
            }
        }
    }

    if !session.client_ip.is_empty()
        && !is_private_ip(&session.client_ip)
        && seen.insert(session.client_ip.to_string())
    {
        ips.push(session.client_ip.to_string());
    }

    ips
}

fn normalize_email_indicator(email: &str) -> Option<String> {
    let trimmed = email.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_lowercase())
    }
}

fn extract_normalized_mail_from_domain(mail_from: &str) -> Option<String> {
    normalize_email_indicator(mail_from)
        .and_then(|email| email.rsplit('@').next().map(str::to_string))
        .map(|domain| domain.trim_end_matches('.').to_string())
        .filter(|domain| !domain.is_empty())
}

/// Infer attack type from verdict categories
fn infer_attack_type(categories: &[String]) -> String {
    for cat in categories {
        let c = cat.to_lowercase();
        if c.contains("phishing") || c.contains("url_typo") || c.contains("brand_impersonation") {
            return "phishing".to_string();
        }
        if c.contains("bec") {
            return "bec".to_string();
        }
        if c.contains("malware") || c.contains("dangerous_extension") {
            return "malware".to_string();
        }
        if c.contains("nonsensical") {
            return "nonsensical_spam".to_string();
        }
        if c.contains("spam") || c.contains("mass_mailing") {
            return "spam".to_string();
        }
        if c.contains("dlp") {
            return "data_leak".to_string();
        }
        if c.contains("xss") || c.contains("header_injection") {
            return "injection".to_string();
        }
    }
    "unknown".to_string()
}

impl IocManager {
    /// Auto-extract IOCs from security verdict (when threat_level>= Critical)

    /// Threshold note: Must be>= Critical, cannot use High/Medium/Low.
    /// Reason: Auto-written IOCs will be queried by intel module and add scores,
    /// if threshold is too low it creates a positive feedback loop causing false positive amplification.
    /// Raised from High to Critical on 2026-04-15 after discovering that many benign emails
    /// (Google Fonts URLs, DGA false positives on service subdomains) can reach High score.
    /// Use batch transactions to write all IOCs at once, avoiding N+1 queries
    pub async fn auto_record_from_verdict(
        &self,
        session: &EmailSession,
        verdict: &SecurityVerdict,
    ) {
        // Critical only. High/Medium/Low must never auto-write IOC or it will
        // re-enter the scoring path and amplify false positives.
        if verdict.threat_level < ThreatLevel::Critical {
            return;
        }

        let confidence = verdict.confidence;
        let ioc_verdict = "malicious";

        // Infer attack type from categories
        let attack_type = infer_attack_type(&verdict.categories);

        // Context includes email subject for quick identification when exporting IOCs
        let subject_text = session.subject.as_deref().unwrap_or("(no subject)");
        let context = format!(
            "subject={} | session={}, verdict={}, categories={}",
            subject_text,
            session.id,
            verdict.threat_level,
            verdict.categories.join(",")
        );

        let mut iocs = Vec::new();

        // Extract all external IPs -> IOC(type=ip)
        // IPs come only from the trusted topmost Received hop plus the
        // network-layer client_ip, and each IP must be observed in >= 2
        // distinct Critical sessions before it is auto-recorded (single-mail
        // IOC poisoning defense).
        let external_ips = extract_all_external_ips(session);
        for ip in &external_ips {
            if !self.note_auto_ip_candidate(ip, session.id) {
                continue;
            }
            if !self.is_whitelisted("ip", ip).await {
                iocs.push(IocEntry::auto_from_indicator_full(
                    ip.clone(),
                    "ip".to_string(),
                    confidence,
                    context.clone(),
                    attack_type.clone(),
                    ioc_verdict.to_string(),
                ));
            }
        }

        // Extract mail_from -> IOC(type=email) + domain -> IOC(type=domain)
        if let Some(ref mail_from) = session.mail_from
            && !mail_from.is_empty()
        {
            if let Some(normalized_mail_from) = normalize_email_indicator(mail_from)
                && !self.is_whitelisted("email", &normalized_mail_from).await
            {
                iocs.push(IocEntry::auto_from_indicator_full(
                    normalized_mail_from.clone(),
                    "email".to_string(),
                    confidence,
                    context.clone(),
                    attack_type.clone(),
                    ioc_verdict.to_string(),
                ));
            }

            if let Some(domain) = extract_normalized_mail_from_domain(mail_from)
                && !self.is_whitelisted("domain", &domain).await
            {
                iocs.push(IocEntry::auto_from_indicator_full(
                    domain,
                    "domain".to_string(),
                    confidence,
                    context.clone(),
                    attack_type.clone(),
                    ioc_verdict.to_string(),
                ));
            }
        }
        // No longer auto-record subject as IOC:
        // Email subjects are too specific and cannot generalize to match other emails,
        // only creating noise and false positives.
        // For subject-based detection, use keyword matching rules in content_scan.

        // Extract attachment hash -> IOC(type=hash)
        for att in &session.content.attachments {
            if !att.hash.is_empty() {
                iocs.push(IocEntry::auto_from_indicator_full(
                    att.hash.to_lowercase(),
                    "hash".to_string(),
                    confidence,
                    context.clone(),
                    attack_type.clone(),
                    ioc_verdict.to_string(),
                ));
            }
        }

        // Extract suspicious links -> IOC(type=url)
        for link in &session.content.links {
            if link.suspicious {
                iocs.push(IocEntry::auto_from_indicator_full(
                    link.url.clone(),
                    "url".to_string(),
                    confidence,
                    context.clone(),
                    attack_type.clone(),
                    ioc_verdict.to_string(),
                ));
            }
        }

        if !iocs.is_empty() {
            let count = iocs.len();
            if let Err(e) = self.db.batch_upsert_iocs(&iocs).await {
                warn!(count, "Failed to batch upsert IOCs: {}", e);
            } else {
                info!(count, "Auto-recorded IOCs in batch");
            }
        }
    }

    /// Internal domain spoofing detection: when both mail_from and rcpt_to are protected internal domains
    /// and verdict>= Critical, automatically record only the external origin IP.

    /// Principle: External attackers forge internal domains to send emails to internal employees
    /// Since the engine is deployed at internal mail gateways, true internal emails come from known internal mail server IPs

    /// Gate: Must have threat_level>= High, otherwise Medium false positives would write IOC creating positive feedback loop
    pub async fn auto_record_internal_spoofing(
        &self,
        session: &EmailSession,
        verdict: &SecurityVerdict,
        internal_domains: &HashSet<String>,
    ) {
        if verdict.threat_level < ThreatLevel::Critical {
            return;
        }
        if internal_domains.is_empty() {
            return;
        }
        let sender_domain = session
            .mail_from
            .as_deref()
            .and_then(|addr| addr.split('@').nth(1))
            .map(|d| d.to_lowercase());
        let sender_domain = match sender_domain {
            Some(d) => d,
            None => return,
        };

        // Check if sender domain is a protected internal domain
        if !internal_domains.contains(&sender_domain) {
            return;
        }

        // Check if any recipient also belongs to internal domain
        let has_internal_recipient = session.rcpt_to.iter().any(|rcpt| {
            rcpt.split('@')
                .nth(1)
                .map(|d| internal_domains.contains(&d.to_lowercase()))
                .unwrap_or(false)
        });

        if !has_internal_recipient {
            return;
        }

        // The claimed sender domain/address belongs to the victim organization.
        // Recording either as malicious would poison the IOC database and block
        // legitimate mail. Only an independently observed external origin IP is
        // eligible for automatic recording.
        // Prefer extracting external IP from Received headers
        let origin_ip = extract_origin_ip(session).unwrap_or_else(|| session.client_ip.to_string());

        if origin_ip.is_empty()
            || is_private_ip(&origin_ip)
            || self.is_whitelisted("ip", &origin_ip).await
        {
            return;
        }

        let context = format!(
            "Internal domain email traffic: {} -> {}, session={}, origin_ip={}",
            session.mail_from.as_deref().unwrap_or("unknown"),
            session.rcpt_to.join(", "),
            session.id,
            origin_ip,
        );

        let iocs = vec![IocEntry::auto_from_indicator_with_attack(
            origin_ip,
            "ip".to_string(),
            0.6, // Medium confidence (might be a legitimate external relay)
            context,
            "spoofing".to_string(),
        )];

        // No longer record subject as IOC (subjects cannot generalize for matching, only create noise)

        let count = iocs.len();
        if let Err(e) = self.db.batch_upsert_iocs(&iocs).await {
            warn!(count, "Failed to record internal spoofing IOCs: {}", e);
        } else {
            info!(
                count,
                mail_from = session.mail_from.as_deref().unwrap_or(""),
                "Recorded external origin IP for internal-domain spoofing"
            );
        }
    }

    /// Auto-record a domain impersonation IOC when header_scan detects
    /// a sender domain that visually impersonates an internal domain.
    ///
    /// Gates (both must pass):
    ///   - Verdict threat_level >= High. Impersonation detection alone is not
    ///     enough: a Low/Medium verdict means the rest of the pipeline saw no
    ///     real threat, and writing a malicious IOC here would feed the
    ///     scoring path (header_scan Step 5c) and amplify false positives.
    ///   - Impersonation similarity score >= 0.30 (effectively all hits, since
    ///     TLD-swap = 0.35 and homoglyph = 0.45).
    ///
    /// IOC is recorded as: source=auto, attack_type=domain_impersonation, verdict=malicious.
    /// Future emails from the same domain will be boosted by the known-impersonation
    /// IOC lookup in header_scan (Step 5c).
    pub async fn auto_record_impersonation_domain(
        &self,
        session: &EmailSession,
        verdict: &SecurityVerdict,
        sender_domain: &str,
        target_domain: &str,
        similarity_type: &str,
        similarity_score: f64,
    ) {
        // Gate: verdict must be >= High, otherwise a weak similarity hit writes
        // a malicious IOC that re-enters the scoring path (amplification loop).
        if verdict.threat_level < ThreatLevel::High {
            return;
        }

        // Gate: skip very low-confidence hits (shouldn't happen given current scores,
        // but future-proofs against accidental threshold changes)
        if similarity_score < 0.30 {
            return;
        }

        // Don't record if already whitelisted
        if self.is_whitelisted("domain", sender_domain).await {
            return;
        }

        let context = format!(
            "target={} | type={} | score={:.2} | session={} | subject={}",
            target_domain,
            similarity_type,
            similarity_score,
            session.id,
            session.subject.as_deref().unwrap_or("(no subject)"),
        );

        // Confidence based on similarity type:
        // homoglyph (0.45) → higher confidence, TLD-swap (0.35) → slightly lower
        let confidence = if similarity_score >= 0.40 { 0.80 } else { 0.70 };

        let mut iocs = Vec::new();

        // Record the impersonating domain
        iocs.push(IocEntry::auto_from_indicator_full(
            sender_domain.to_string(),
            "domain".to_string(),
            confidence,
            context.clone(),
            "domain_impersonation".to_string(),
            "malicious".to_string(),
        ));

        // Record sender email address if available
        if let Some(ref mail_from) = session.mail_from
            && let Some(normalized) = normalize_email_indicator(mail_from)
            && !self.is_whitelisted("email", &normalized).await
        {
            iocs.push(IocEntry::auto_from_indicator_full(
                normalized,
                "email".to_string(),
                confidence,
                context.clone(),
                "domain_impersonation".to_string(),
                "malicious".to_string(),
            ));
        }

        // Record origin IP if external
        let origin_ip = extract_origin_ip(session).unwrap_or_else(|| session.client_ip.to_string());
        if !origin_ip.is_empty()
            && !is_private_ip(&origin_ip)
            && !self.is_whitelisted("ip", &origin_ip).await
        {
            iocs.push(IocEntry::auto_from_indicator_full(
                origin_ip,
                "ip".to_string(),
                confidence * 0.8, // Lower confidence for IP (could be shared hosting)
                context.clone(),
                "domain_impersonation".to_string(),
                "malicious".to_string(),
            ));
        }

        if !iocs.is_empty() {
            let count = iocs.len();
            if let Err(e) = self.db.batch_upsert_iocs(&iocs).await {
                warn!(
                    count,
                    sender_domain,
                    target_domain,
                    "Failed to record impersonation domain IOCs: {}",
                    e
                );
            } else {
                info!(
                    count,
                    sender_domain,
                    target_domain,
                    similarity_type,
                    "Auto-recorded domain impersonation IOCs (self-learning)"
                );
            }
        }
    }

    /// Nonsensical email auto-record IOC
    /// Gate: semantic_scan confidence must be>= 0.70 and threat_level>= Critical
    /// Low-confidence nonsensical detection does not auto-write IOC to avoid false positive -> IOC -> amplification loop
    pub async fn auto_record_nonsensical(
        &self,
        session: &EmailSession,
        sem_result: &crate::module::ModuleResult,
    ) {
        // Gate: Only high-confidence nonsensical detection writes to IOC
        if sem_result.confidence < 0.70
            || sem_result.threat_level < crate::module::ThreatLevel::Critical
        {
            return;
        }

        let confidence = sem_result.confidence;
        let context = format!(
            "semantic_scan: session={}, score={:.2}, summary={}",
            session.id,
            sem_result
                .details
                .get("score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0),
            sem_result.summary,
        );

        let mut iocs = Vec::new();

        // Sender IP (prefer extracting external IP from Received headers)
        let ip = extract_origin_ip(session).unwrap_or_else(|| session.client_ip.to_string());
        if !ip.is_empty() && !is_private_ip(&ip) {
            iocs.push(IocEntry::auto_from_indicator_with_attack(
                ip,
                "ip".to_string(),
                confidence,
                context.clone(),
                "nonsensical_spam".to_string(),
            ));
        }

        // Sender address + domain
        if let Some(ref mail_from) = session.mail_from
            && !mail_from.is_empty()
        {
            if let Some(normalized_mail_from) = normalize_email_indicator(mail_from) {
                iocs.push(IocEntry::auto_from_indicator_with_attack(
                    normalized_mail_from,
                    "email".to_string(),
                    confidence,
                    context.clone(),
                    "nonsensical_spam".to_string(),
                ));
            }

            if let Some(domain) = extract_normalized_mail_from_domain(mail_from) {
                iocs.push(IocEntry::auto_from_indicator_with_attack(
                    domain,
                    "domain".to_string(),
                    confidence,
                    context.clone(),
                    "nonsensical_spam".to_string(),
                ));
            }
        }

        // No longer record subject as IOC (subjects cannot generalize for matching, only create noise)

        if !iocs.is_empty() {
            let count = iocs.len();
            if let Err(e) = self.db.batch_upsert_iocs(&iocs).await {
                warn!(count, "Failed to batch upsert nonsensical IOCs: {}", e);
            } else {
                info!(count, "Auto-recorded nonsensical spam IOCs");
            }
        }
    }
}

// All tests in this module are DB-backed integration tests gated behind the
// `infra-tests` feature (TEST_DATABASE_URL), matching `intel/mod.rs`.
#[cfg(test)]
mod unit_tests {
    use super::*;
    use vigilyx_core::models::{EmailContent, Protocol};

    fn session_with_headers(client_ip: &str, received: &[&str]) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            client_ip.to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            headers: received
                .iter()
                .map(|v| ("Received".to_string(), v.to_string()))
                .collect(),
            is_complete: true,
            ..Default::default()
        };
        session
    }

    /// PoC: forged deep Received headers must not seed IOC IPs; the real
    /// network-layer client_ip must never be masked by them either.
    #[test]
    fn forged_received_chain_neither_seeds_nor_masks_ips() {
        let session = session_with_headers(
            "198.51.100.1",
            &[
                // Topmost hop: stamped by our gateway, carries the real sender IP.
                "from mail.attacker.tld ([203.0.113.66]) by mx.corp.example with ESMTPS",
                // Everything below is attacker-controlled.
                "from fake-bank ([8.8.8.8]) by mail.attacker.tld",
                "from another-forge ([1.1.1.1]) by fake-bank",
            ],
        );

        let ips = extract_all_external_ips(&session);
        assert!(ips.contains(&"203.0.113.66".to_string()), "top hop IP kept");
        assert!(
            ips.contains(&"198.51.100.1".to_string()),
            "network-layer client_ip always recorded"
        );
        assert!(!ips.contains(&"8.8.8.8".to_string()), "forged IP rejected");
        assert!(!ips.contains(&"1.1.1.1".to_string()), "forged IP rejected");
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn client_ip_recorded_even_when_top_received_has_no_public_ip() {
        let session = session_with_headers(
            "203.0.113.77",
            &["from internal-relay ([10.1.2.3]) by mx.corp.example"],
        );
        assert_eq!(
            extract_all_external_ips(&session),
            vec!["203.0.113.77".to_string()]
        );
    }

    #[test]
    fn origin_ip_comes_from_top_hop_only() {
        let session = session_with_headers(
            "192.168.1.5",
            &[
                "from internal ([10.1.1.1]) by mx.corp.example",
                "from forged ([8.8.8.8]) by elsewhere",
            ],
        );
        // Top hop holds no public IP -> no origin IP from headers (callers
        // fall back to client_ip); the forged deeper IP must not be used.
        assert_eq!(extract_origin_ip(&session), None);
    }

    #[test]
    fn mail_from_domain_trims_trailing_dot() {
        assert_eq!(
            extract_normalized_mail_from_domain("attacker@Evil.COM."),
            Some("evil.com".to_string())
        );
        assert_eq!(
            extract_normalized_mail_from_domain("attacker@evil.com"),
            Some("evil.com".to_string())
        );
    }
}

// All tests in this module are DB-backed integration tests gated behind the
// `infra-tests` feature (TEST_DATABASE_URL), matching `intel/mod.rs`.
#[cfg(all(test, feature = "infra-tests"))]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;
    use vigilyx_core::models::Protocol;

    /// Public test IP (TEST-NET-3) so the impersonation path also writes an IP IOC.
    #[cfg(feature = "infra-tests")]
    const TEST_ORIGIN_IP: &str = "203.0.113.66";

    #[cfg(feature = "infra-tests")]
    fn make_impersonation_session(sender_domain: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            TEST_ORIGIN_IP.to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some(format!("attacker@{sender_domain}"));
        session.subject = Some("impersonation test".to_string());
        session
    }

    #[cfg(feature = "infra-tests")]
    fn make_verdict(session_id: Uuid, threat_level: ThreatLevel) -> SecurityVerdict {
        SecurityVerdict {
            id: Uuid::new_v4(),
            session_id,
            threat_level,
            confidence: 0.9,
            categories: vec!["brand_impersonation".to_string()],
            summary: "test verdict".to_string(),
            pillar_scores: HashMap::new(),
            modules_run: 1,
            modules_flagged: 1,
            total_duration_ms: 10,
            created_at: Utc::now(),
            fusion_details: None,
        }
    }

    #[cfg(feature = "infra-tests")]
    async fn make_ioc_manager() -> IocManager {
        let db = vigilyx_db::VigilDb::new(
            &std::env::var("TEST_DATABASE_URL")
                .expect("TEST_DATABASE_URL must be set to run integration tests"),
        )
        .await
        .unwrap();
        db.init_security_tables().await.unwrap();
        IocManager::new(db)
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_impersonation_ioc_not_recorded_below_high() {
        for level in [ThreatLevel::Safe, ThreatLevel::Low, ThreatLevel::Medium] {
            let manager = make_ioc_manager().await;
            let sender_domain = format!("imp-{}.example", Uuid::new_v4().simple());
            let session = make_impersonation_session(&sender_domain);
            let verdict = make_verdict(session.id, level);

            manager
                .auto_record_impersonation_domain(
                    &session,
                    &verdict,
                    &sender_domain,
                    "internal.example",
                    "tld_swap",
                    0.35,
                )
                .await;

            let email = format!("attacker@{sender_domain}");
            for (ioc_type, indicator) in [
                ("domain", sender_domain.as_str()),
                ("email", email.as_str()),
                ("ip", TEST_ORIGIN_IP),
            ] {
                assert!(
                    manager
                        .db
                        .find_ioc(ioc_type, indicator)
                        .await
                        .unwrap()
                        .is_none(),
                    "{level:?} verdict must not write {ioc_type} impersonation IOC"
                );
            }
        }
    }

    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_impersonation_ioc_recorded_at_high_and_critical() {        for level in [ThreatLevel::High, ThreatLevel::Critical] {
            let manager = make_ioc_manager().await;
            let sender_domain = format!("imp-{}.example", Uuid::new_v4().simple());
            let session = make_impersonation_session(&sender_domain);
            let verdict = make_verdict(session.id, level);

            manager
                .auto_record_impersonation_domain(
                    &session,
                    &verdict,
                    &sender_domain,
                    "internal.example",
                    "homoglyph",
                    0.45,
                )
                .await;

            let domain_ioc = manager
                .db
                .find_ioc("domain", &sender_domain)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{level:?} verdict must write domain IOC"));
            assert_eq!(domain_ioc.source, "auto");
            assert_eq!(domain_ioc.verdict, "malicious");
            assert_eq!(domain_ioc.attack_type, "domain_impersonation");

            let email = format!("attacker@{sender_domain}");
            assert!(
                manager
                    .db
                    .find_ioc("email", &email)
                    .await
                    .unwrap()
                    .is_some(),
                "{level:?} verdict must write sender email IOC"
            );
            assert!(
                manager
                    .db
                    .find_ioc("ip", TEST_ORIGIN_IP)
                    .await
                    .unwrap()
                    .is_some(),
                "{level:?} verdict must write origin IP IOC"
            );
        }
    }

    /// PoC (single-mail IOC poisoning): one forged Critical mail must not seed
    /// an IP IOC; the IP becomes recordable only after a second, distinct
    /// Critical session. Domain/email IOCs are still written immediately.
    #[tokio::test]
    #[cfg(feature = "infra-tests")]
    async fn test_auto_ip_ioc_requires_two_distinct_critical_sessions() {
        let manager = make_ioc_manager().await;
        let attacker_ip = format!(
            "203.0.113.{}",
            200 + (Uuid::new_v4().as_bytes()[0] % 50)
        );

        // Mail #1: Critical verdict, sender IP visible in the top Received hop.
        let domain1 = format!("poison1-{}.example", Uuid::new_v4().simple());
        let mut mail1 = make_impersonation_session(&domain1);
        mail1.content.headers = vec![(
            "Received".to_string(),
            format!("from mail.{domain1} ([{attacker_ip}]) by mx.corp.example with ESMTPS"),
        )];
        let verdict1 = make_verdict(mail1.id, ThreatLevel::Critical);
        manager.auto_record_from_verdict(&mail1, &verdict1).await;

        assert!(
            manager
                .db
                .find_ioc("ip", &attacker_ip)
                .await
                .unwrap()
                .is_none(),
            "single Critical mail must not seed an IP IOC"
        );
        assert!(
            manager
                .db
                .find_ioc("domain", &domain1)
                .await
                .unwrap()
                .is_some(),
            "domain IOC is still written immediately"
        );

        // Mail #2: a second, distinct Critical session from the same IP.
        let domain2 = format!("poison2-{}.example", Uuid::new_v4().simple());
        let mut mail2 = make_impersonation_session(&domain2);
        mail2.content.headers = vec![(
            "Received".to_string(),
            format!("from mail.{domain2} ([{attacker_ip}]) by mx.corp.example with ESMTPS"),
        )];
        let verdict2 = make_verdict(mail2.id, ThreatLevel::Critical);
        manager.auto_record_from_verdict(&mail2, &verdict2).await;

        let ip_ioc = manager
            .db
            .find_ioc("ip", &attacker_ip)
            .await
            .unwrap()
            .expect("second Critical session must make the IP eligible");
        assert_eq!(ip_ioc.source, "auto");
        assert_eq!(ip_ioc.verdict, "malicious");
    }
}
