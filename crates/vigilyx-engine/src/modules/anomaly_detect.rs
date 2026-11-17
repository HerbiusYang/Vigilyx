//! Anomaly detection module - detects abnormal email behavioral patterns:
//! mass mailing, empty subject with attachments, all-caps subjects, etc.

use std::time::Instant;

use async_trait::async_trait;
use chrono::{DateTime, Datelike, FixedOffset, Timelike, Utc};
use vigilyx_core::models::EmailAttachment;
use vigilyx_parser::mime::decode_rfc2047;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

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
                description: "Detects abnormal email patterns: mass mailing, recipient enumeration probes, empty subject with attachments, all-caps subjects, etc.".to_string(),
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

fn decoded_attachment_filename(filename: &str) -> String {
    decode_rfc2047(filename)
        .trim()
        .trim_matches('"')
        .to_string()
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
    ext.as_deref().is_some_and(|ext| {
        !matches!(ext, "zip" | "rar" | "7z")
            && module_data().contains("high_risk_empty_subject_extensions", ext)
    }) || content_type.contains("html")
        || content_type.contains("javascript")
}

fn is_public_mail_sender(mail_from: Option<&str>) -> bool {
    mail_from
        .and_then(|value| value.rsplit('@').next())
        .is_some_and(|domain| {
            crate::pipeline::internal_domains::is_public_mail_domain(&domain.to_ascii_lowercase())
        })
}

/// Split an SMTP mailbox into its local part and domain without accepting a
/// malformed address as a behavioral signal.  The parser normally stores
/// bare addresses, but tolerating angle brackets keeps rescans and imported
/// sessions on the same path.
fn mailbox_parts(address: &str) -> Option<(&str, &str)> {
    let address = address.trim().trim_start_matches('<').trim_end_matches('>');
    let (local_part, domain) = address.rsplit_once('@')?;
    let domain = domain.trim_end_matches('.');
    if local_part.is_empty() || domain.is_empty() {
        return None;
    }
    Some((local_part, domain))
}

/// Generated mailbox probes commonly use a short ASCII alphanumeric token
/// containing several digits and consonant-heavy filler (for example
/// `u0001hzzhw` or `h525266r`).  This deliberately rejects ordinary words and
/// long order/reference strings; exact subject/local-part equality is still
/// required by the caller.
fn looks_like_generated_mailbox_token(value: &str) -> bool {
    let value = value.trim();
    if !(8..=32).contains(&value.len())
        || !value.is_ascii()
        || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return false;
    }

    let digit_count = value.bytes().filter(u8::is_ascii_digit).count();
    let letter_count = value.bytes().filter(u8::is_ascii_alphabetic).count();
    let consonant_count = value
        .bytes()
        .filter(|byte| byte.is_ascii_alphabetic() && !b"aeiouAEIOU".contains(byte))
        .count();

    digit_count >= 2
        && letter_count >= 2
        && consonant_count.saturating_mul(5) >= letter_count.saturating_mul(3)
        && digit_count < value.len().saturating_sub(1)
}

/// Automated probes may put the generated token after a descriptive sender
/// prefix, such as `notify-vjbgfvqm92cae9q`.  Check each alphanumeric run so
/// the prefix itself does not hide the random token from the detector.
fn looks_like_generated_sender_local_part(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|part| {
            if looks_like_generated_mailbox_token(part) {
                return true;
            }

            // Shorter sender tokens are also common (`notify-jspe6g`).  Keep
            // this fallback stricter than a generic alphanumeric check: it
            // needs a digit, several letters, and consonant-heavy filler.
            if !(6..=24).contains(&part.len())
                || !part.is_ascii()
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric())
            {
                return false;
            }
            let digit_count = part.bytes().filter(u8::is_ascii_digit).count();
            let letter_count = part.bytes().filter(u8::is_ascii_alphabetic).count();
            let consonant_count = part
                .bytes()
                .filter(|byte| byte.is_ascii_alphabetic() && !b"aeiouAEIOU".contains(byte))
                .count();
            digit_count >= 1
                && letter_count >= 3
                && consonant_count.saturating_mul(5) >= letter_count.saturating_mul(3)
        })
}

/// Some campaign senders are short consonant-heavy tokens without digits,
/// such as `snxvrvc` or `isbqgwm`.  Keep this separate from the generated
/// mailbox-token heuristic so ordinary names and the existing token contract
/// remain unchanged.
fn looks_like_short_random_sender_token(value: &str) -> bool {
    let value = value.trim();
    if !(6..=12).contains(&value.len())
        || !value.is_ascii()
        || !value.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }

    let consonant_count = value
        .bytes()
        .filter(|byte| !b"aeiouAEIOU".contains(byte))
        .count();
    consonant_count >= 5 && consonant_count.saturating_mul(5) >= value.len().saturating_mul(4)
}

/// Detect a single-message mailbox-enumeration candidate.
///
/// This is intentionally a narrow, per-message signal.  The full composite is
/// strong enough for a Medium triage verdict, while confirmation that an actor
/// is enumerating a directory still benefits from correlation across sessions.
fn detect_mailbox_enumeration_probe(ctx: &SecurityContext, subject: &str) -> Option<String> {
    if ctx.session.rcpt_to.len() != 1 {
        return None;
    }

    let (sender_local_part, sender_domain) =
        ctx.session.mail_from.as_deref().and_then(mailbox_parts)?;
    if ctx.is_internal_domain(sender_domain) {
        return None;
    }

    let (recipient_local_part, recipient_domain) = mailbox_parts(&ctx.session.rcpt_to[0])?;
    if !ctx.is_internal_domain(recipient_domain) {
        return None;
    }

    let subject = subject.trim();
    if !subject.eq_ignore_ascii_case(recipient_local_part) {
        return None;
    }

    // The target can itself be a generated token (the `u0001hzzhw` /
    // `h525266r` family), or the sender can carry a generated/random token
    // after a prefix while probing a normal-looking internal mailbox such as
    // `boardoffice`. Public-mail senders are included because the observed
    // campaign also uses ordinary-looking local-parts from free mailboxes;
    // exact subject/local-part equality remains mandatory.
    if !looks_like_generated_mailbox_token(recipient_local_part)
        && !looks_like_generated_sender_local_part(sender_local_part)
        && !looks_like_short_random_sender_token(sender_local_part)
        && !is_public_mail_sender(ctx.session.mail_from.as_deref())
    {
        return None;
    }

    Some(recipient_local_part.to_string())
}

fn looks_like_filename_subject(subject: &str) -> bool {
    let trimmed = subject.trim();
    let Some((stem, ext)) = trimmed.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && (2..=5).contains(&ext.len())
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' ' | '(' | ')'))
}

/// Extract the sender-asserted send time from the `Date:` header and return
/// it expressed in the *sender's own* local time (preserving the timezone
/// offset declared in the header). This lets us reason about what hour the
/// message was sent at the originating end — the relevant signal for
/// "dead-of-night campaign from a compromised mailbox".
///
/// Returns `None` when the header is missing or unparseable; callers must
/// not fall back to capture time, since arrival time at the recipient is
/// timezone-shifted and would create false positives.
fn extract_declared_send_time(headers: &[(String, String)]) -> Option<DateTime<FixedOffset>> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("date") {
            let cleaned = value.trim();
            if cleaned.is_empty() {
                return None;
            }
            // RFC 2822 is the canonical form; tolerate the legacy RFC 822 form too.
            if let Ok(dt) = DateTime::parse_from_rfc2822(cleaned) {
                return Some(dt);
            }
            // Some MTAs append parenthetical timezone names — strip and retry.
            if let Some(idx) = cleaned.find(" (")
                && let Ok(dt) = DateTime::parse_from_rfc2822(cleaned[..idx].trim())
            {
                return Some(dt);
            }
            return None;
        }
    }
    None
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
        let subject_raw = ctx.session.subject.as_deref().unwrap_or("");
        let subject_decoded = decode_rfc2047(subject_raw);
        let subject = subject_decoded.as_str();
        let has_attachments = !ctx.session.content.attachments.is_empty();

        // --- 1b. Single-recipient mailbox enumeration probe ---
        // A subject copied exactly from the internal mailbox local-part, with
        // one external-to-internal envelope and either a generated/random
        // sender/target or a public-mail sender, is a named Medium triage
        // scenario. Cross-session correlation can still confirm whether the
        // actor is running a broader directory scan.
        if let Some(recipient_local_part) = detect_mailbox_enumeration_probe(ctx, subject) {
            total_score += 0.45;
            categories.push("mailbox_enumeration_probe".to_string());
            evidence.push(Evidence {
                description: "External sender addressed one internal mailbox from a generated/random or public-mail sender, with a subject exactly matching the recipient local-part — possible mailbox enumeration probe".to_string(),
                location: Some("subject + envelope recipient".to_string()),
                snippet: Some(recipient_local_part),
            });
        }

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

            // Mobile sharing, scanners and plain file forwarding send attachments
            // without a subject every day, whatever the number or type of files.
            // The pattern is corroboration only and stays below Low on its own;
            // a high-risk attachment type (HTML, script, executable) adds weight.
            let empty_subject_score = if high_risk_count > 0 { 0.10 } else { 0.05 };

            total_score += empty_subject_score;
            if high_risk_count > 0 {
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
            // P2-1 fix: skip all_caps check if subject contains CJK characters.
            // CJK+Latin mixed subjects (for example, uppercase abbreviations plus Chinese business text)
            // often use uppercase
            // abbreviations that are perfectly normal, not phishing.
            let has_cjk = subject.chars().any(|c| {
                ('\u{4E00}'..='\u{9FFF}').contains(&c) || ('\u{3400}'..='\u{4DBF}').contains(&c)
            });
            // Shouting is a phrase. A single token such as a camera or scanner
            // file name (`RETOUCH_IMG_20261112_161912`) is an identifier.
            let word_count = subject
                .split_whitespace()
                .filter(|word| word.chars().filter(|c| c.is_ascii_alphabetic()).count() >= 2)
                .count();
            if latin_chars.len() >= 5
                && latin_chars == latin_chars.to_uppercase()
                && letter_ratio >= 0.4
                && word_count >= 2
                && !has_cjk
                && !looks_like_filename_subject(subject)
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
            // A script counts only with at least two letters: decorated
            // nicknames ("༺ꦾ随🥀心҉࿐") borrow single combining marks and symbols
            // from other blocks, which says nothing about the text itself.
            let mut latin = 0usize;
            let mut cjk = 0usize;
            let mut other_script = 0usize;
            for ch in subject.chars() {
                if ch.is_ascii_alphabetic() {
                    latin += 1;
                } else if ('\u{4E00}'..='\u{9FFF}').contains(&ch)
                    || ('\u{3400}'..='\u{4DBF}').contains(&ch)
                {
                    cjk += 1;
                } else if ('\u{0E00}'..='\u{0E7F}').contains(&ch)    // Thai
                    || ('\u{1000}'..='\u{109F}').contains(&ch)        // Myanmar
                    || ('\u{0900}'..='\u{097F}').contains(&ch)        // Devanagari
                    || ('\u{0600}'..='\u{06FF}').contains(&ch)        // Arabic
                    || ('\u{0400}'..='\u{0482}').contains(&ch)        // Cyrillic letters (not combining marks)
                    || ('\u{048A}'..='\u{04FF}').contains(&ch)
                    || ('\u{AC00}'..='\u{D7AF}').contains(&ch)        // Korean
                    || ('\u{3040}'..='\u{309F}').contains(&ch)        // Hiragana
                    || ('\u{30A0}'..='\u{30FF}').contains(&ch)
                // Katakana
                {
                    other_script += 1;
                }
            }
            let script_count = (latin >= 2) as u8 + (cjk >= 2) as u8 + (other_script >= 2) as u8;
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
            // Mirror captures and BCC-only messages commonly have no visible
            // RCPT TO.  Keep this as a metadata note, never threat evidence.
            categories.push("recipient_metadata_incomplete".to_string());
            evidence.push(Evidence {
                description:
                    "RCPT TO list is empty (possibly all BCC or capture metadata unavailable)"
                        .to_string(),
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

        // --- 6. Off-hours send time ---
        // Phishing campaigns frequently originate from compromised mailboxes
        // operated by threat actors in distant time zones. The asserted send
        // time (Date: header) often falls in the middle of the recipient's
        // night, especially when paired with urgent language or attachments.
        //
        // We deliberately keep this signal weak (+0.10) and gate it on at
        // least one corroborating risk feature so legitimate cross-time-zone
        // mail is not penalised.
        if let Some(send_time) = extract_declared_send_time(&ctx.session.content.headers) {
            let local_hour = send_time.hour();
            let weekday = send_time.weekday().num_days_from_monday(); // 0=Mon..6=Sun
            let is_dead_of_night = local_hour < 5; // 00:00 – 04:59 (sender-local)
            let is_weekend = weekday >= 5;

            // Risk amplifiers — any of these turns "unusual hour" into a real signal.
            let urgency_terms = [
                "urgent",
                "immediately",
                "asap",
                "verify",
                "verification",
                "confirm",
                "suspended",
                "locked",
                "expire",
                "expired",
                "紧急",
                "立即",
                "尽快",
                "验证",
                "确认",
                "冻结",
                "停用",
                "限时",
            ];
            let subject_lower = subject.to_lowercase();
            let has_urgency = urgency_terms.iter().any(|t| subject_lower.contains(t));
            let has_executable_attach = ctx.session.content.attachments.iter().any(|a| {
                let n = decoded_attachment_filename(&a.filename).to_ascii_lowercase();
                n.ends_with(".exe")
                    || n.ends_with(".scr")
                    || n.ends_with(".js")
                    || n.ends_with(".vbs")
                    || n.ends_with(".lnk")
                    || n.ends_with(".iso")
                    || n.ends_with(".html")
                    || n.ends_with(".htm")
            });

            if is_dead_of_night && (has_urgency || has_executable_attach || has_attachments) {
                let off_hours_score = if has_urgency && has_executable_attach {
                    0.20
                } else if has_urgency || has_executable_attach {
                    0.15
                } else {
                    0.10
                };
                total_score += off_hours_score;
                categories.push("off_hours_send".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Email asserted send time is {:02}:{:02} (sender-local, weekday={}); \
                         dead-of-night transmission combined with risky payload",
                        local_hour,
                        send_time.minute(),
                        weekday
                    ),
                    location: Some("headers:Date".to_string()),
                    snippet: None,
                });
            } else if is_weekend && is_dead_of_night && has_urgency {
                // Weekend pre-dawn + urgency is an even stronger combination.
                total_score += 0.12;
                categories.push("off_hours_send".to_string());
                evidence.push(Evidence {
                    description: "Weekend pre-dawn send with urgency keywords in subject"
                        .to_string(),
                    location: Some("headers:Date".to_string()),
                    snippet: None,
                });
            }
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
    use std::collections::HashSet;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_ctx(attachments: Vec<EmailAttachment>) -> SecurityContext {
        make_ctx_with_sender("sender@example.com", attachments)
    }

    fn make_ctx_with_sender(sender: &str, attachments: Vec<EmailAttachment>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(String::new());
        session.mail_from = Some(sender.to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
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
    async fn test_empty_subject_archive_attachment_is_treated_as_safe() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx(vec![attachment("invoice.zip", "application/zip")]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_empty_subject_public_mail_archive_attachment_is_treated_as_safe() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_sender(
            "fixture-archive@qq.com",
            vec![attachment("invoice.zip", "application/zip")],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    /// Production false positive (2026-11-13): a script document plus an
    /// unnamed part from a personal mailbox, no subject, rated Low alone.
    #[tokio::test]
    async fn empty_subject_with_several_attachments_is_not_a_standalone_risk() {
        let module = AnomalyDetectModule::new();
        for attachments in [
            vec![
                attachment(
                    "副本台词(2)(4).docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                ),
                attachment("attachment_0", "application/octet-stream"),
            ],
            vec![
                attachment("image0.jpeg", "image/jpeg"),
                attachment("image1.jpeg", "image/jpeg"),
            ],
            vec![
                attachment("中电三季度维保发票.pdf", "application/pdf"),
                attachment("attachment_0", "application/octet-stream"),
            ],
        ] {
            let ctx = make_ctx_with_sender("fixture-user@163.com", attachments);
            let result = module.analyze(&ctx).await.unwrap();
            assert_eq!(result.threat_level, ThreatLevel::Safe);
        }
    }

    #[tokio::test]
    async fn empty_subject_with_html_attachment_alone_stays_below_low() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx(vec![attachment("invoice.html", "text/html")]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn identifier_subject_is_not_shouting() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("RETOUCH_IMG_20261112_161912", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn decorated_nickname_is_not_multilingual_gibberish() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("༺ꦾ随🥀心້໌ᮨꦿ҉࿐ 和 W🥑。 的聊天记录", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn japanese_brand_subject_with_latin_is_still_mixed_script() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject(
            "【 至 急 】SMBC IDが変更されました — 三井住友カード",
            vec![],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result
                .categories
                .contains(&"multilingual_gibberish".to_string())
        );
    }

    fn make_mailbox_probe_ctx(
        subject: &str,
        sender: &str,
        recipient: &str,
        internal_domain: &str,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some(sender.to_string());
        session.rcpt_to.push(recipient.to_string());
        SecurityContext::with_internal_domains(
            Arc::new(session),
            Arc::new(HashSet::from([internal_domain.to_string()])),
        )
    }

    #[test]
    fn generated_mailbox_token_shape_keeps_human_references_out() {
        assert!(looks_like_generated_mailbox_token("u0001hzzhw"));
        assert!(looks_like_generated_mailbox_token("h525266r"));
        assert!(!looks_like_generated_mailbox_token("employee2024"));
        assert!(!looks_like_generated_mailbox_token("short"));
        assert!(looks_like_generated_sender_local_part(
            "notify-vjbgfvqm92cae9q"
        ));
        assert!(looks_like_generated_sender_local_part("notify-jspe6g"));
        assert!(!looks_like_generated_sender_local_part("notify"));
        assert!(!looks_like_generated_sender_local_part("notify-john2"));
        assert!(looks_like_short_random_sender_token("snxvrvc"));
        assert!(looks_like_short_random_sender_token("isbqgwm"));
        assert!(!looks_like_short_random_sender_token("notify"));
        assert!(!looks_like_short_random_sender_token("shuiwudaikai"));
    }

    #[tokio::test]
    async fn exact_generated_subject_and_internal_recipient_are_flagged() {
        let module = AnomalyDetectModule::new();
        let ctx = make_mailbox_probe_ctx(
            "u0001hzzhw",
            "notify@random-sender.example",
            "u0001hzzhw@ccabchina.com.example",
            "ccabchina.com.example",
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Medium);
        assert!(
            result
                .categories
                .contains(&"mailbox_enumeration_probe".to_string())
        );
    }

    #[tokio::test]
    async fn mailbox_probe_requires_external_sender_and_internal_recipient() {
        let module = AnomalyDetectModule::new();

        let internal_sender = make_mailbox_probe_ctx(
            "synthetic-user",
            "service@corp.example",
            "synthetic-user@corp.example",
            "corp.example",
        );
        let external_recipient = make_mailbox_probe_ctx(
            "synthetic-user",
            "notify@random-sender.example",
            "h525266r@external.example",
            "corp.example",
        );

        for ctx in [&internal_sender, &external_recipient] {
            let result = module.analyze(ctx).await.unwrap();
            assert_eq!(result.threat_level, ThreatLevel::Safe);
            assert!(
                !result
                    .categories
                    .contains(&"mailbox_enumeration_probe".to_string())
            );
        }
    }

    #[tokio::test]
    async fn human_readable_subject_matching_recipient_is_not_probe_evidence() {
        let module = AnomalyDetectModule::new();
        let ctx = make_mailbox_probe_ctx(
            "employee2024",
            "notify@random-sender.example",
            "employee2024@ccabchina.com.example",
            "ccabchina.com.example",
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result
                .categories
                .contains(&"mailbox_enumeration_probe".to_string())
        );
    }

    #[tokio::test]
    async fn generated_sender_can_probe_a_human_named_internal_mailbox() {
        let module = AnomalyDetectModule::new();
        let ctx = make_mailbox_probe_ctx(
            "boardoffice",
            "notify-vjbgfvqm92cae9q@nj.cn.example",
            "boardoffice@ccabchina.com.example",
            "ccabchina.com.example",
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Medium);
        assert!(
            result
                .categories
                .contains(&"mailbox_enumeration_probe".to_string())
        );
    }

    #[tokio::test]
    async fn short_generated_sender_can_probe_a_human_named_internal_mailbox() {
        let module = AnomalyDetectModule::new();
        let ctx = make_mailbox_probe_ctx(
            "bqzhanglu",
            "notify-jspe6g@vkobxk.cn.example",
            "bqzhanglu@ccabchina.com.example",
            "ccabchina.com.example",
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Medium);
        assert!(
            result
                .categories
                .contains(&"mailbox_enumeration_probe".to_string())
        );
    }

    #[tokio::test]
    async fn public_mail_sender_with_exact_recipient_subject_is_flagged() {
        let module = AnomalyDetectModule::new();
        let ctx = make_mailbox_probe_ctx(
            "songsongjun",
            "shuiwudaikai1@hotmail.com",
            "songsongjun@ccabchina.com.example",
            "ccabchina.com.example",
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Medium);
        assert!(
            result
                .categories
                .contains(&"mailbox_enumeration_probe".to_string())
        );
    }

    // ─── P2-1: all_caps_subject CJK skip regression tests ───

    fn make_ctx_with_subject(subject: &str, attachments: Vec<EmailAttachment>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some("sender@example.com".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        session.content = EmailContent {
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_all_caps_with_cjk_does_not_trigger() {
        // P2-1: uppercase Latin mixed with CJK text is a normal business subject pattern, not phishing.
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("GOAIDC资产管理通知", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"all_caps_subject".to_string()),
            "CJK+Latin mixed subject should not trigger all_caps_subject, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_all_caps_pure_latin_still_triggers() {
        // Pure Latin uppercase subject without CJK should still be flagged
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("URGENT ACTION REQUIRED NOW PLEASE", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"all_caps_subject".to_string()),
            "Pure uppercase Latin subject should trigger all_caps_subject, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_filename_subject_does_not_trigger_all_caps() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("IMG_7619.HEIC", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"all_caps_subject".to_string()),
            "Filename-like subjects should not trigger all_caps_subject, got categories={:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_all_caps_too_few_latin_chars_does_not_trigger() {
        // Subject with < 5 Latin chars should not trigger even if all uppercase
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject("KYC审核通知", vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"all_caps_subject".to_string()),
            "Subject with < 5 Latin chars + CJK should not trigger, got categories={:?}",
            result.categories
        );
    }

    // ─── Off-hours send time tests ───

    fn make_ctx_with_subject_and_date(
        subject: &str,
        date_header: Option<&str>,
        attachments: Vec<EmailAttachment>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some("sender@example.com".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        let mut content = EmailContent {
            attachments,
            ..Default::default()
        };
        if let Some(d) = date_header {
            content.headers.push(("Date".to_string(), d.to_string()));
        }
        session.content = content;
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn test_extract_declared_send_time_rfc2822() {
        let headers = vec![(
            "Date".to_string(),
            "Tue, 15 Apr 2025 03:14:22 +0800".to_string(),
        )];
        let dt = extract_declared_send_time(&headers).expect("should parse");
        assert_eq!(dt.hour(), 3);
        assert_eq!(dt.minute(), 14);
    }

    #[tokio::test]
    async fn test_extract_declared_send_time_with_paren_tz() {
        // MTAs sometimes append a parenthetical timezone name.
        let headers = vec![(
            "Date".to_string(),
            "Tue, 15 Apr 2025 03:14:22 +0800 (CST)".to_string(),
        )];
        let dt = extract_declared_send_time(&headers).expect("should parse");
        assert_eq!(dt.hour(), 3);
    }

    #[tokio::test]
    async fn test_off_hours_with_urgency_triggers() {
        // 03:00 sender-local + urgency keyword = off_hours_send
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject_and_date(
            "URGENT: verify your account",
            Some("Tue, 15 Apr 2025 03:00:00 +0800"),
            vec![],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"off_hours_send".to_string()),
            "expected off_hours_send, got {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_office_hours_does_not_trigger_off_hours() {
        // 14:00 sender-local with urgency should NOT trigger off_hours_send
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject_and_date(
            "URGENT please verify",
            Some("Tue, 15 Apr 2025 14:00:00 +0800"),
            vec![],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"off_hours_send".to_string()),
            "office-hours mail must not be flagged off_hours, got {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_off_hours_without_risk_features_does_not_trigger() {
        // 03:00 but no urgency, no attachments — bare timestamp alone is too weak
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject_and_date(
            "Weekly status report",
            Some("Tue, 15 Apr 2025 03:00:00 +0800"),
            vec![],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"off_hours_send".to_string()),
            "bare off-hours timestamp must not trigger without risk features, got {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_off_hours_with_executable_attach_triggers() {
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject_and_date(
            "report",
            Some("Tue, 15 Apr 2025 02:30:00 +0800"),
            vec![attachment("invoice.exe", "application/octet-stream")],
        );

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            result.categories.contains(&"off_hours_send".to_string()),
            "executable attachment at 02:30 should trigger, got {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_missing_date_header_does_not_trigger_off_hours() {
        // No Date header → cannot evaluate off-hours, must not fall back to capture time.
        let module = AnomalyDetectModule::new();
        let ctx = make_ctx_with_subject_and_date("URGENT verify", None, vec![]);

        let result = module.analyze(&ctx).await.unwrap();

        assert!(
            !result.categories.contains(&"off_hours_send".to_string()),
            "missing Date header must not trigger off_hours, got {:?}",
            result.categories
        );
    }
}
