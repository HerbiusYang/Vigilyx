//! IOC auto-recording logic

//! Automatically extracts IOCs from high-threat verdicts:
//! - `auto_record_from_verdict` - General extraction: IP/domain/email/attachment hash/suspicious links
//! - `auto_record_internal_spoofing` - Internal domain spoofing detection
//! - `auto_record_nonsensical` - Nonsensical email auto-recording

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
/// We scan from top to bottom to find the first Received line containing an external IP
/// and recorded by our server.
/// This is typically the IP of the attacker's mail server when connecting to our gateway.
fn extract_origin_ip(session: &EmailSession) -> Option<String> {
    for (name, value) in &session.content.headers {
        if !name.eq_ignore_ascii_case("received") {
            continue;
        }
       // Extract IP from brackets: [185.243.242.238]
        for cap in RE_BRACKET_IP.captures_iter(value) {
            if let Some(m) = cap.get(1) {
                let ip = m.as_str();
                if !is_private_ip(ip) {
                    return Some(ip.to_string());
                }
            }
        }
    }
    None
}

/// Extract all public IPs from email Received headers (deduplicated)

/// When client_ip is an internal MTA address, the true malicious external IP is hidden in Received headers.
/// This function extracts all public IPs from Received headers to ensure all are written to IOC.
fn extract_all_external_ips(session: &EmailSession) -> Vec<String> {
    let mut ips = Vec::new();
    let mut seen = HashSet::new();

   // Iterate through all Received headers, extract bracketed IP [x.x.x.x]
    for (name, value) in &session.content.headers {
        if name.eq_ignore_ascii_case("Received") {
            for cap in RE_BRACKET_IP.captures_iter(value) {
                if let Some(m) = cap.get(1) {
                    let ip = m.as_str();
                    if !is_private_ip(ip) && seen.insert(ip.to_string()) {
                        ips.push(ip.to_string());
                    }
                }
            }
        }
    }

   // Fallback: if no public IPs in Received headers, try network layer client_ip
    if ips.is_empty()
        && !is_private_ip(&session.client_ip)
        && seen.insert(session.client_ip.to_string())
    {
        ips.push(session.client_ip.to_string());
    }

    ips
}

/// Protected internal domain list
/// When both sender and recipient belong to these domains,
/// automatically record the sender IP and domain as IOC
const PROTECTED_INTERNAL_DOMAINS: &[&str] = &["corp-internal.com"];

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
   /// Auto-extract IOCs from security verdict (when threat_level>= High)
    
   /// Threshold note: Must be>= High, cannot use Medium or Low.
   /// Reason: Auto-written IOCs will be queried by intel module and add scores,
   /// if threshold is too low it creates a positive feedback loop causing false positive amplification.
   /// Use batch transactions to write all IOCs at once, avoiding N+1 queries
    pub async fn auto_record_from_verdict(
        &self,
        session: &EmailSession,
        verdict: &SecurityVerdict,
    ) {
       // High/Critical only. Medium/Low must never auto-write IOC or it will
       // re-enter the scoring path and amplify false positives.
        if verdict.threat_level < ThreatLevel::High {
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
       // Extract all public IPs from Received headers (crucial when client_ip is internal MTA)
        let external_ips = extract_all_external_ips(session);
        for ip in &external_ips {
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
   /// and verdict>= Medium, automatically record sender IP and address to IOC (attack_type = spoofing)
    
   /// Principle: External attackers forge internal domains to send emails to internal employees
   /// Since the engine is deployed at internal mail gateways, true internal emails come from known internal mail server IPs
    
   /// Gate: Must have threat_level>= High, otherwise Medium false positives would write IOC creating positive feedback loop
    pub async fn auto_record_internal_spoofing(
        &self,
        session: &EmailSession,
        verdict: &SecurityVerdict,
    ) {
        if verdict.threat_level < ThreatLevel::High {
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
        if !PROTECTED_INTERNAL_DOMAINS
            .iter()
            .any(|&d| sender_domain == d)
        {
            return;
        }

       // Check if any recipient also belongs to internal domain
        let has_internal_recipient = session.rcpt_to.iter().any(|rcpt| {
            rcpt.split('@')
                .nth(1)
                .map(|d| {
                    PROTECTED_INTERNAL_DOMAINS
                        .iter()
                        .any(|&pd| d.eq_ignore_ascii_case(pd))
                })
                .unwrap_or(false)
        });

        if !has_internal_recipient {
            return;
        }

       // Detected internal -> internal email traffic, record sender IP and domain
       // Prefer extracting external IP from Received headers
        let origin_ip = extract_origin_ip(session).unwrap_or_else(|| session.client_ip.to_string());

        if origin_ip.is_empty() || is_private_ip(&origin_ip) {
           // Cannot determine external source IP, still continue to record domain and email IOC
        }

        let context = format!(
            "Internal domain email traffic: {} -> {}, session={}, origin_ip={}",
            session.mail_from.as_deref().unwrap_or("unknown"),
            session.rcpt_to.join(", "),
            session.id,
            &origin_ip,
        );

        let mut iocs = Vec::new();

       // Record sender IP (external IPs only)
        if !origin_ip.is_empty() && !is_private_ip(&origin_ip) {
            iocs.push(IocEntry::auto_from_indicator_with_attack(
                origin_ip,
                "ip".to_string(),
                0.6, // Medium confidence (might be legitimate internal mail server)
                context.clone(),
                "spoofing".to_string(),
            ));
        }

       // Record sender domain
        iocs.push(IocEntry::auto_from_indicator_with_attack(
            sender_domain,
            "domain".to_string(),
            0.6,
            context.clone(),
            "spoofing".to_string(),
        ));

       // Record sender address
        if let Some(ref mail_from) = session.mail_from
            && let Some(normalized_mail_from) = normalize_email_indicator(mail_from)
        {
            iocs.push(IocEntry::auto_from_indicator_with_attack(
                normalized_mail_from,
                "email".to_string(),
                0.6,
                context.clone(),
                "spoofing".to_string(),
            ));
        }

       // No longer record subject as IOC (subjects cannot generalize for matching, only create noise)

        let count = iocs.len();
        if let Err(e) = self.db.batch_upsert_iocs(&iocs).await {
            warn!(count, "Failed to record internal spoofing IOCs: {}", e);
        } else {
            info!(
                count,
                mail_from = session.mail_from.as_deref().unwrap_or(""),
                "Recorded internal domain traffic IOCs (spoofing detection)"
            );
        }
    }

   /// Nonsensical email auto-record IOC
   /// Gate: semantic_scan confidence must be>= 0.70 and threat_level>= High
   /// Low-confidence nonsensical detection does not auto-write IOC to avoid false positive -> IOC -> amplification loop
    pub async fn auto_record_nonsensical(
        &self,
        session: &EmailSession,
        sem_result: &crate::module::ModuleResult,
    ) {
       // Gate: Only high-confidence nonsensical detection writes to IOC
        if sem_result.confidence < 0.70
            || sem_result.threat_level < crate::module::ThreatLevel::High
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
