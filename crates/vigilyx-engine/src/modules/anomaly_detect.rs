//! Anomaly detection module - detects abnormal email behavioral patterns:
//! mass mailing, empty subject with attachments, all-caps subjects, etc.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use vigilyx_core::models::EmailAttachment;
use vigilyx_parser::mime::decode_rfc2047;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AnomalyDetectModule {
    meta: ModuleMetadata,
}

impl Default for AnomalyDetectModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetectModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "anomaly_detect".to_string(),
                name: "Anomaly Detection".to_string(),
                description: "Detects abnormal email patterns: mass mailing, empty subject with attachments, all-caps subjects, etc.".to_string(),
                pillar: Pillar::Package,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

const HIGH_RISK_EMPTY_SUBJECT_EXTENSIONS: &[&str] = &[
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "hta", "msi", "dll", "com", "pif", "wsf",
    "wsh", "zip", "rar", "7z", "iso", "img", "html", "htm", "eml", "lnk", "url",
];

const COMMON_BUSINESS_ATTACHMENT_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "jpg", "jpeg", "png",
];

fn decoded_attachment_filename(filename: &str) -> String {
    decode_rfc2047(filename).trim().trim_matches('"').to_string()
}

fn attachment_extension(att: &EmailAttachment) -> Option<String> {
    let filename = decoded_attachment_filename(&att.filename);
    let (_, ext) = filename.rsplit_once('.')?;
    let ext = ext.trim().trim_end_matches("?=").to_ascii_lowercase();
    if ext.is_empty() { None } else { Some(ext) }
}

fn is_high_risk_empty_subject_attachment(att: &EmailAttachment) -> bool {
    let ext = attachment_extension(att);
    let content_type = att.content_type.to_ascii_lowercase();
    ext.as_deref()
        .is_some_and(|ext| HIGH_RISK_EMPTY_SUBJECT_EXTENSIONS.contains(&ext))
        || content_type.contains("html")
        || content_type.contains("javascript")
        || content_type.contains("zip")
        || content_type.contains("rar")
}

fn is_common_business_attachment(att: &EmailAttachment) -> bool {
    attachment_extension(att)
        .as_deref()
        .is_some_and(|ext| COMMON_BUSINESS_ATTACHMENT_EXTENSIONS.contains(&ext))
}

#[async_trait]
impl SecurityModule for AnomalyDetectModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

        let recipient_count = ctx.session.rcpt_to.len();
        let subject = ctx.session.subject.as_deref().unwrap_or("");
        let has_attachments = !ctx.session.content.attachments.is_empty();

       // --- 1. Mass mailing: recipient count> 10 ---
        if recipient_count > 10 {
            total_score += 0.25;
            categories.push("mass_mailing".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Mass mailing detected: recipient count {} exceeds threshold of 10",
                    recipient_count
                ),
                location: Some("rcpt_to".to_string()),
                snippet: Some(
                    ctx.session
                        .rcpt_to
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                        + if recipient_count > 5 { "..." } else { "" },
                ),
            });
        }

       // --- 2. Empty subject with attachments ---
        if subject.trim().is_empty() && has_attachments {
            let filenames: Vec<String> = ctx
                .session
                .content
                .attachments
                .iter()
                .map(|a| decoded_attachment_filename(&a.filename))
                .collect();
            let attachment_count = ctx.session.content.attachments.len();
            let high_risk_count = ctx
                .session
                .content
                .attachments
                .iter()
                .filter(|att| is_high_risk_empty_subject_attachment(att))
                .count();
            let common_business_count = ctx
                .session
                .content
                .attachments
                .iter()
                .filter(|att| is_common_business_attachment(att))
                .count();

           // Empty-subject attachments are common for business and mobile-sharing workflows.
           // Keep the signal only when the attachment profile itself is risky, or when the
           // message sprays multiple files with no subject.
            let empty_subject_score = if high_risk_count > 0 {
                0.20
            } else if attachment_count > 1 {
                0.16
            } else if common_business_count == attachment_count {
                0.08
            } else {
                0.12
            };

            total_score += empty_subject_score;
            if empty_subject_score >= 0.15 {
                categories.push("empty_subject_with_attachment".to_string());
            }
            evidence.push(Evidence {
                description: format!(
                    "Empty subject with {} attachment(s): {} (risk profile score {:.2})",
                    attachment_count,
                    filenames.join(", "),
                    empty_subject_score,
                ),
                location: Some("subject + attachments".to_string()),
                snippet: None,
            });
        }

       // --- 3. Subject all caps (only consider ASCII Latin letters) ---
       // Skip encoded/timestamp/serial-number subjects: require >=40% letter ratio to avoid flagging IDs
        {
            let latin_chars: String = subject
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .collect();
            let digit_count = subject.chars().filter(|c| c.is_ascii_digit()).count();
            let total_alnum = latin_chars.len() + digit_count;
            let letter_ratio = if total_alnum > 0 {
                latin_chars.len() as f64 / total_alnum as f64
            } else {
                0.0
            };
            if latin_chars.len() >= 5
                && latin_chars == latin_chars.to_uppercase()
                && letter_ratio >= 0.4
            {
                total_score += 0.15;
                categories.push("all_caps_subject".to_string());
                evidence.push(Evidence {
                    description: format!("Subject is all uppercase: \"{}\"", subject),
                    location: Some("subject".to_string()),
                    snippet: Some(subject.to_string()),
                });
            }
        }

       // --- 3.5 Multilingual gibberish subject ---
       // Detect 3+ Unicode scripts mixed (e.g. Latin + CJK + Thai) indicating gibberish
       // Example: "Sq45HQSOHAR Add 3 45HQ"
        if !subject.is_empty() {
            let mut has_latin = false;
            let mut has_cjk = false;
            let mut has_other_script = false;
            for ch in subject.chars() {
                if ch.is_ascii_alphabetic() {
                    has_latin = true;
                } else if ('\u{4E00}'..='\u{9FFF}').contains(&ch)
                    || ('\u{3400}'..='\u{4DBF}').contains(&ch)
                {
                    has_cjk = true;
                } else if ('\u{0E00}'..='\u{0E7F}').contains(&ch)    // Thai
                    || ('\u{1000}'..='\u{109F}').contains(&ch)        // Myanmar
                    || ('\u{0900}'..='\u{097F}').contains(&ch)        // Devanagari
                    || ('\u{0600}'..='\u{06FF}').contains(&ch)        // Arabic
                    || ('\u{0400}'..='\u{04FF}').contains(&ch)        // Cyrillic
                    || ('\u{AC00}'..='\u{D7AF}').contains(&ch)        // Korean
                    || ('\u{3040}'..='\u{309F}').contains(&ch)        // Hiragana
                    || ('\u{30A0}'..='\u{30FF}').contains(&ch)
               // Katakana
                {
                    has_other_script = true;
                }
            }
            let script_count = has_latin as u8 + has_cjk as u8 + has_other_script as u8;
            if script_count >= 3 {
                total_score += 0.35;
                categories.push("multilingual_gibberish".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Subject contains {} different language scripts mixed together, suspected spam/phishing",
                        script_count
                    ),
                    location: Some("subject".to_string()),
                    snippet: Some(subject.chars().take(80).collect()),
                });
            }
        }

       // --- 4. Unusual recipient patterns (all BCC-like: empty rcpt_to is suspicious) ---
        if recipient_count == 0 {
            total_score += 0.10;
            categories.push("no_recipients".to_string());
            evidence.push(Evidence {
                description: "RCPT TO list is empty (possibly all BCC)".to_string(),
                location: Some("rcpt_to".to_string()),
                snippet: None,
            });
        }

       // --- 5. Very large recipient count (potential spam cannon) ---
        if recipient_count > 50 {
            total_score += 0.20; // Additional penalty on top of mass_mailing
            categories.push("spam_cannon".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Suspected spam cannon: recipient count {} far exceeds normal range",
                    recipient_count
                ),
                location: Some("rcpt_to".to_string()),
                snippet: None,
            });
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No anomalous behavioral patterns detected",
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.70,
            categories,
            summary: format!(
                "Anomaly detection found {} issue(s), composite score {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "recipient_count": recipient_count,
                "has_attachments": has_attachments,
                "subject_length": subject.len(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_ctx(attachments: Vec<EmailAttachment>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(String::new());
        session.mail_from = Some("sender@example.com".to_string());
        session
            .rcpt_to
            .push("recipient@example.com".to_string());
        session.content = EmailContent {
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn attachment(filename: &str, content_type: &str) -> EmailAttachment {
        EmailAttachment {
            filename: filename.to_string(),
            content_type: content_type.to_string(),
            size: 1024,
            hash: "deadbeef".to_string(),
            content_base64: None,
        }
    }

    #[tokio::test]
    async fn test_empty_subject_single_business_doc_is_treated_as_safe() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx(vec![attachment(
            "=?utf-8?B?6YKA6K+35Ye95YaF5a65LmRvY3g=?=",
            "application/octet-stream",
        )]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_empty_subject_archive_attachment_remains_low_risk() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx(vec![attachment("invoice.zip", "application/zip")]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert!(result.categories.contains(&"empty_subject_with_attachment".to_string()));
    }
}
