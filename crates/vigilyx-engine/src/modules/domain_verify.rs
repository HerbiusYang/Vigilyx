//! Domain verification module - checks sender IP/domain/DKIM consistency.
//!
//! This module emits an alignment signal, not a benignity signal.
//! A domain can be perfectly self-consistent and still be malicious.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::LazyLock;

use super::common::extract_domain_from_email;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};

pub struct DomainVerifyModule {
    meta: ModuleMetadata,
}

impl Default for DomainVerifyModule {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainVerifyModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "domain_verify".to_string(),
                name: "Domain Verification".to_string(),
                description: "Checks sender IP/domain/DKIM consistency and provides alignment signal".to_string(),
                pillar: Pillar::Package,
                depends_on: vec![],
                timeout_ms: 3000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

/// Check whether hostname is a subdomain of the given domain
/// "xmbg8.mail.qq.com" is_subdomain_of "qq.com" -> true
fn is_subdomain_of(hostname: &str, domain: &str) -> bool {
    if hostname == domain {
        return true;
    }
    hostname.ends_with(&format!(".{}", domain))
}

/// Extract display name from a From header value.
/// "=?utf-8?B?xxx?= <user@domain.com>" -> Some("decoded_name")
/// "User Name <user@domain.com>" -> Some("User Name")
/// "<user@domain.com>" -> None
fn extract_display_name(from_value: &str) -> Option<String> {
    let trimmed = from_value.trim();
   // Find the angle bracket for the email address
    if let Some(idx) = trimmed.rfind('<') {
        let before_angle = trimmed[..idx].trim();
        if before_angle.is_empty() {
            return None;
        }
       // RFC 2047: =?charset?encoding?text?=
        let mut decoded = before_angle.to_string();
        
        if decoded.starts_with('"') && decoded.ends_with('"') && decoded.len() >= 2 {
            decoded = decoded[1..decoded.len() - 1].to_string();
        }
       // Decode RFC 2047 =?utf-8?B?...?= encoded words
        if decoded.contains("=?") && decoded.contains("?=") {
            let mut result = String::new();
            let mut remaining = decoded.as_str();
            while let Some(start) = remaining.find("=?") {
                result.push_str(&remaining[..start]);
                remaining = &remaining[start + 2..];
               // charset?encoding?text?=
                let parts: Vec<&str> = remaining.splitn(4, '?').collect();
                if parts.len() >= 3 && parts[2].ends_with("?=") || (parts.len() >= 4 && parts[3].starts_with("=")) {
                    let encoding = parts[1].to_uppercase();
                    let text = if parts.len() >= 4 {
                        remaining = if parts[3].starts_with("=") { &parts[3][1..] } else { parts[3] };
                        
                        if let Some(end_idx) = remaining.find("?=") {
                            let t = &parts[2];
                            remaining = &remaining[end_idx.saturating_sub(parts[2].len())..];
                            t
                        } else {
                            parts[2]
                        }
                    } else {
                        let t = parts[2].trim_end_matches("?=");
                        remaining = "";
                        t
                    };
                    if encoding == "B" {
                        use base64::Engine as _;
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text)
                            && let Ok(s) = String::from_utf8(bytes)
                        {
                            result.push_str(&s);
                        }
                    } else if encoding == "Q" {
                       // Q-encoding: _ = space, =XX = hex byte
                        let q_decoded: String = text
                            .replace('_', " ")
                            .split('=')
                            .enumerate()
                            .flat_map(|(i, part)| {
                                if i == 0 {
                                    part.to_string()
                                } else if part.len() >= 2 {
                                    let hex = &part[..2];
                                    let rest = &part[2..];
                                    if let Ok(byte) = u8::from_str_radix(hex, 16) {
                                        format!("{}{}", byte as char, rest)
                                    } else {
                                        format!("={}", part)
                                    }
                                } else {
                                    format!("={}", part)
                                }
                                .chars()
                                .collect::<Vec<_>>()
                            })
                            .collect();
                        result.push_str(&q_decoded);
                    }
                    
                    if let Some(end_pos) = remaining.find("?=") {
                        remaining = &remaining[end_pos + 2..];
                    } else {
                        remaining = "";
                    }
                } else {
                    break;
                }
            }
            result.push_str(remaining);
            let final_name = result.trim().to_string();
            if final_name.is_empty() {
                return None;
            }
            return Some(final_name);
        }
        Some(decoded)
    } else {
        None
    }
}

/// Extract the "from" hostname from a Received header.
/// "from xmbg8.mail.qq.com (unknown [210.51.43.17])..." -> "xmbg8.mail.qq.com"
static RE_RECEIVED_FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"from\s+([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})").unwrap());

/// Extract d= domain from a DKIM-Signature header.
/// "v=1; a=rsa-sha256;... d=qq.com;..." -> "qq.com"
static RE_DKIM_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"d=([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})").unwrap());

#[async_trait]
impl SecurityModule for DomainVerifyModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let headers = &ctx.session.content.headers;

        let mut alignment_score: f64 = 0.0;
        let mut evidence = Vec::new();
        let mut verified = false;

       // Extract sender domain
        let sender_domain = ctx
            .session
            .mail_from
            .as_deref()
            .and_then(extract_domain_from_email);
        let sender_domain = match sender_domain {
            Some(d) => d,
            None => {
                let duration_ms = start.elapsed().as_millis() as u64;
                return Ok(ModuleResult {
                    module_id: self.meta.id.clone(),
                    module_name: self.meta.name.clone(),
                    pillar: self.meta.pillar,
                    threat_level: ThreatLevel::Safe,
                    confidence: 0.0,
                    categories: vec![],
                    summary: "No sender domain available, unable to verify".to_string(),
                    evidence: vec![],
                    details: serde_json::json!({
                        "verified": false,
                        "alignment_score": 0.0,
                        "trust_score": 0.0,
                    }),
                    duration_ms,
                    analyzed_at: Utc::now(),
                    bpa: Some(Bpa::vacuous()),
                    engine_id: None,
                });
            }
        };

       // Check 1: Received hostname vs sender domain
       // Look for the outermost Received header containing a matching hostname
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("received") {
                continue;
            }
            if let Some(cap) = RE_RECEIVED_FROM.captures(value)
                && let Some(hostname) = cap.get(1)
            {
                let hostname = hostname.as_str().to_lowercase();
                if is_subdomain_of(&hostname, &sender_domain) {
                    alignment_score += 0.40;
                    verified = true;
                    evidence.push(Evidence {
                        description: format!(
                            "Received hostname {} matches sender domain {}",
                            hostname, sender_domain
                        ),
                        location: Some("headers:Received".to_string()),
                        snippet: Some(hostname.clone()),
                    });
                    break; // only need the outermost match
                }
            }
        }

       // Check 2: DKIM d= domain vs sender domain
        for (name, value) in headers {
            if !name.eq_ignore_ascii_case("dkim-signature") {
                continue;
            }
            if let Some(cap) = RE_DKIM_DOMAIN.captures(value)
                && let Some(dkim_domain) = cap.get(1)
            {
                let dkim_domain = dkim_domain.as_str().to_lowercase();
                if dkim_domain == sender_domain || is_subdomain_of(&sender_domain, &dkim_domain) {
                    alignment_score += 0.35;
                    verified = true;
                    evidence.push(Evidence {
                        description: format!(
                            "DKIM signing domain {} matches sender domain {}",
                            dkim_domain, sender_domain
                        ),
                        location: Some("headers:DKIM-Signature".to_string()),
                        snippet: Some(dkim_domain.clone()),
                    });
                    break;
                }
            }
        }

        alignment_score = alignment_score.min(1.0);
        if alignment_score > 0.0 {
            verified = true;
        }

       // Envelope forgery detection: From header domain vs MAIL FROM domain
       // If the From header domain differs from the MAIL FROM domain,
       // the attacker may be spoofing the From header while using their own envelope domain
        let from_header_domain = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))
            .and_then(|(_, v)| extract_domain_from_email(v));

        let envelope_mismatch = if let Some(ref fd) = from_header_domain {
            fd != &sender_domain
        } else {
            false
        };

        if envelope_mismatch {
            if alignment_score > 0.0 {
                evidence.push(Evidence {
                    description: format!(
                        "Envelope forgery: From header domain ({}) does not match MAIL FROM domain ({}), alignment score suppressed",
                        from_header_domain.as_deref().unwrap_or("?"),
                        sender_domain
                    ),
                    location: Some("From header vs MAIL FROM".to_string()),
                    snippet: None,
                });
            }
            alignment_score = 0.0;
            verified = false;
        }


       // Display name brand impersonation check:
       // e.g. From: "Microsoft" <attacker@evil.cn> - domain does not match brand.
       // Even if DKIM passes, the display name is misleading.
        if let Some((_, from_value)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("from"))
        {
            let display_name = extract_display_name(from_value);
            if let Some(ref name) = display_name {
                let name_lower = name.to_lowercase();
                
                let brand_domain_map: &[(&[&str], &[&str])] = &[
                    
                    (&["日本郵便", "日本郵政", "japan post"], &[".jp", "japanpost"]),
                    (&["佐川急便", "sagawa"], &[".jp", "sagawa"]),
                    (&["ヤマト運輸", "yamato"], &[".jp", "yamato", "kuronekoyamato"]),
                    (&["amazon", "アマゾン"], &["amazon."]),
                    (&["microsoft", "マイクロソフト"], &["microsoft.", "outlook.", "live."]),
                    (&["apple", "アップル"], &["apple.", "icloud."]),
                    (&["google", "グーグル"], &["google.", "gmail."]),
                    (&["paypal", "ペイパル"], &["paypal."]),
                    (&["dhl"], &["dhl."]),
                    (&["fedex"], &["fedex."]),
                    (&["ups"], &["ups."]),
                ];

                for (brand_keywords, legit_suffixes) in brand_domain_map {
                    let name_matches_brand = brand_keywords
                        .iter()
                        .any(|bk| name_lower.contains(&bk.to_lowercase()));
                    if name_matches_brand {
                        let domain_is_legit = legit_suffixes
                            .iter()
                            .any(|ls| sender_domain.contains(ls));
                        if !domain_is_legit {
                            
                            alignment_score = (alignment_score - 0.50).max(0.0);
                            evidence.push(Evidence {
                                description: format!(
                                    "Display name brand impersonation: \"{}\" claims to be a known brand, but sender domain {} does not match",
                                    name, sender_domain
                                ),
                                location: Some("From:display-name".to_string()),
                                snippet: Some(from_value.clone()),
                            });
                            break;
                        }
                    }
                }
            }
        }

        if alignment_score <= 0.0 {
            verified = false;
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        let summary = if envelope_mismatch {
            format!(
                "Domain verification anomaly: From header ({}) does not match envelope sender domain ({})",
                from_header_domain.as_deref().unwrap_or("?"),
                sender_domain
            )
        } else if verified {
            format!(
                "Sender alignment verified (alignment score {:.2}), sender domain: {}",
                alignment_score, sender_domain
            )
        } else {
            format!("Sender alignment not established, sender domain: {}", sender_domain)
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level: ThreatLevel::Safe,
            confidence: if verified { 0.90 } else { 0.50 },
            categories: vec![],
            summary,
            evidence,
            details: serde_json::json!({
                "verified": verified,
                "alignment_score": alignment_score,
                "trust_score": alignment_score,
                "sender_domain": sender_domain,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(Bpa::safe_analyzed()),
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn make_context(
        mail_from: &str,
        headers: Vec<(String, String)>,
        links: Vec<EmailLink>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.10".to_string(),
            34567,
            "10.0.0.20".to_string(),
            25,
        );
        session.mail_from = Some(mail_from.to_string());
        session.content = EmailContent {
            headers,
            body_text: Some("Please review the message.".to_string()),
            body_html: None,
            attachments: vec![],
            links,
            raw_size: 128,
            is_complete: true,
            is_encrypted: false,
            smtp_dialog: vec![],
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_domain_verify_ignores_attacker_controlled_link_alignment() {
        let ctx = make_context(
            "alerts@change-meme.com",
            vec![
                (
                    "Received".to_string(),
                    "from mail.change-meme.com (unknown [43.243.73.163])".to_string(),
                ),
                (
                    "DKIM-Signature".to_string(),
                    "v=1; a=rsa-sha256; d=change-meme.com; s=mail;".to_string(),
                ),
                (
                    "From".to_string(),
                    "alerts@change-meme.com".to_string(),
                ),
            ],
            vec![EmailLink {
                url: "https://login.change-meme.com/reset?token=abc123".to_string(),
                text: Some("Reset password".to_string()),
                suspicious: false,
            }],
        );

        let result = DomainVerifyModule::new().analyze(&ctx).await.unwrap();
        let alignment = result
            .details
            .get("alignment_score")
            .and_then(|value| value.as_f64())
            .unwrap();

        assert!(
            (alignment - 0.75).abs() < f64::EPSILON,
            "Link/domain self-alignment must not raise the sender alignment score"
        );
    }

    #[tokio::test]
    async fn test_domain_verify_brand_impersonation_reduces_alignment() {
        let ctx = make_context(
            "alerts@change-meme.com",
            vec![
                (
                    "Received".to_string(),
                    "from mail.change-meme.com (unknown [43.243.73.163])".to_string(),
                ),
                (
                    "DKIM-Signature".to_string(),
                    "v=1; a=rsa-sha256; d=change-meme.com; s=mail;".to_string(),
                ),
                (
                    "From".to_string(),
                    "\"Microsoft\" <alerts@change-meme.com>".to_string(),
                ),
            ],
            vec![],
        );

        let result = DomainVerifyModule::new().analyze(&ctx).await.unwrap();
        let alignment = result
            .details
            .get("alignment_score")
            .and_then(|value| value.as_f64())
            .unwrap();

        assert!(
            (alignment - 0.25).abs() < f64::EPSILON,
            "Brand impersonation should suppress the alignment score even when Received/DKIM align"
        );
    }
}
