//! MIME structuredetectModule - Checkemail MIME structureAbnormal: depth, Content-Type, EncodeAbnormalwait

use std::collections::HashSet;
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct MimeScanModule {
    meta: ModuleMetadata,
}

impl Default for MimeScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl MimeScanModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "mime_scan".to_string(),
                name: "MIMEstructuredetect".to_string(),
                description: "Checkemail MIME structureof嵌套depth、Content-Type、EncodeAbnormal"
                    .to_string(),
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

#[async_trait]
impl SecurityModule for MimeScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let headers = &ctx.session.content.headers;

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;

       // Collect all header values into one block for multipart analysis
        let mut content_type_header: Option<String> = None;
        let mut content_transfer_encoding: Option<String> = None;
        let mut content_transfer_encoding_values: Vec<String> = Vec::new();
        let mut boundary_count = 0usize;
        let mut boundaries: Vec<String> = Vec::new();

        // Per-header occurrence counts — RFC 5322 requires the following
        // headers to appear at most once. Duplicates are a classic MIME /
        // header smuggling trick where the second instance is parsed by the
        // MUA while spam/anti-phishing engines only see the first.
        let mut from_count = 0usize;
        let mut to_count = 0usize;
        let mut subject_count = 0usize;
        let mut date_count = 0usize;
        let mut message_id_count = 0usize;
        let mut sender_count = 0usize;
        let mut content_type_count = 0usize;
        let mut cte_count = 0usize;
        let mut reply_to_count = 0usize;

        let mut from_empty = false;
        let mut to_empty = false;
        let mut subject_empty_present = false;
        let mut first_from_value: Option<String> = None;

        for (name, value) in headers {
            let name_lower = name.to_lowercase();

           // Count boundary= occurrences across all headers (multipart nesting indicator)
            let value_lower = value.to_lowercase();
            let bc = value_lower.matches("boundary=").count();
            boundary_count += bc;

           // Extract boundary values for conflict detection
            if bc > 0 {
                let mut search = value_lower.as_str();
                while let Some(idx) = search.find("boundary=") {
                    let after = &search[idx + 9..];
                    let boundary_val = if let Some(stripped) = after.strip_prefix('"') {
                       // Quoted boundary
                        stripped.split('"').next().unwrap_or("").to_string()
                    } else {
                        after
                            .split(|c: char| c.is_whitespace() || c == ';')
                            .next()
                            .unwrap_or("")
                            .to_string()
                    };
                    if !boundary_val.is_empty() {
                        boundaries.push(boundary_val);
                    }
                    search = &search[idx + 9..];
                }
            }

            match name_lower.as_str() {
                "content-type" => {
                    content_type_count += 1;
                    if content_type_header.is_none() {
                        content_type_header = Some(value.clone());
                    }
                }
                "content-transfer-encoding" => {
                    cte_count += 1;
                    content_transfer_encoding_values.push(value.clone());
                    if content_transfer_encoding.is_none() {
                        content_transfer_encoding = Some(value.clone());
                    }
                }
                "from" => {
                    from_count += 1;
                    if value.trim().is_empty() {
                        from_empty = true;
                    } else if first_from_value.is_none() {
                        first_from_value = Some(value.clone());
                    }
                }
                "to" => {
                    to_count += 1;
                    if value.trim().is_empty() {
                        to_empty = true;
                    }
                }
                "subject" => {
                    subject_count += 1;
                    if value.trim().is_empty() {
                        subject_empty_present = true;
                    }
                }
                "date" => date_count += 1,
                "message-id" => message_id_count += 1,
                "sender" => sender_count += 1,
                "reply-to" => reply_to_count += 1,
                _ => {}
            }
        }

       // --- 1. Deep MIME nesting (boundary count> 3 is suspicious) ---
        if boundary_count > 3 {
            let severity = ((boundary_count as f64 - 3.0) * 0.10).min(0.4);
            total_score += severity;
            categories.push("deep_nesting".to_string());
            evidence.push(Evidence {
                description: format!(
                    "MIME 嵌套depthAbnormal: Found {}  boundary 声明（Normalemail通常 <= 3）",
                    boundary_count
                ),
                location: Some("headers".to_string()),
                snippet: None,
            });
        }

       // --- 2. Empty Content-Type ---
        if let Some(ref ct) = content_type_header {
            if ct.trim().is_empty() {
                total_score += 0.15;
                categories.push("empty_content_type".to_string());
                evidence.push(Evidence {
                    description: "Content-Type Headervalue 空".to_string(),
                    location: Some("headers:Content-Type".to_string()),
                    snippet: None,
                });
            }
        } else {
           // Missing Content-Type entirely
            total_score += 0.05;
            categories.push("missing_content_type".to_string());
            evidence.push(Evidence {
                description: "缺少 Content-Type Header".to_string(),
                location: Some("headers".to_string()),
                snippet: None,
            });
        }

       // --- 3. Content-Transfer-Encoding anomalies ---
        if let Some(ref cte) = content_transfer_encoding {
            let cte_lower = cte.to_lowercase().trim().to_string();
            let valid_encodings = ["7bit", "8bit", "binary", "quoted-printable", "base64"];
            if !valid_encodings.contains(&cte_lower.as_str()) {
                total_score += 0.15;
                categories.push("invalid_encoding".to_string());
                evidence.push(Evidence {
                    description: format!("非Standard Content-Transfer-Encoding: {}", cte),
                    location: Some("headers:Content-Transfer-Encoding".to_string()),
                    snippet: Some(cte.clone()),
                });
            }
        }

       // --- 4. Duplicate / conflicting MIME boundaries ---
        {
            let unique_count = {
                let mut sorted = boundaries.clone();
                sorted.sort();
                sorted.dedup();
                sorted.len()
            };
            if boundaries.len() > 1 && unique_count < boundaries.len() {
                total_score += 0.20;
                categories.push("boundary_conflict".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "MIME boundary 冲突: {} 声明Medium有 {} 重复",
                        boundaries.len(),
                        boundaries.len() - unique_count
                    ),
                    location: Some("headers".to_string()),
                    snippet: None,
                });
            }
        }

        // --- 5. Duplicate singleton headers (RFC 5322 violation / smuggling) ---
        // These headers MUST appear at most once. Duplicates are a classic
        // smuggling trick where anti-phishing engines parse the first value
        // while the MUA renders the second. We score each occurrence.
        let cte_duplicate_is_incomplete_multipart_layering = cte_count == 2
            && content_type_header
                .as_deref()
                .is_some_and(|ct| ct.trim().to_ascii_lowercase().starts_with("multipart/"))
            && !ctx.session.content.is_complete
            && duplicate_cte_looks_like_nested_part_encoding(&content_transfer_encoding_values);

        let duplicate_headers: &[(&str, usize, f64)] = &[
            ("From", from_count, 0.35),
            ("To", to_count, 0.20),
            ("Subject", subject_count, 0.20),
            ("Date", date_count, 0.10),
            ("Message-ID", message_id_count, 0.15),
            ("Sender", sender_count, 0.20),
            ("Content-Type", content_type_count, 0.25),
            ("Content-Transfer-Encoding", cte_count, 0.15),
            ("Reply-To", reply_to_count, 0.15),
        ];
        let mut any_duplicate = false;
        for (name, count, weight) in duplicate_headers {
            if *count > 1 {
                if *name == "Content-Transfer-Encoding"
                    && cte_duplicate_is_incomplete_multipart_layering
                {
                    continue;
                }
                any_duplicate = true;
                total_score += weight;
                categories.push("duplicate_header".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "Header `{}` appears {} times (RFC 5322 requires singleton) — possible header smuggling",
                        name, count
                    ),
                    location: Some(format!("headers:{}", name)),
                    snippet: None,
                });
            }
        }
        if any_duplicate {
            // Additional penalty when multiple distinct headers are duplicated
            // simultaneously — that's almost never accidental.
            let duplicated_kinds = duplicate_headers
                .iter()
                .filter(|(name, c, _)| {
                    *c > 1
                        && !(*name == "Content-Transfer-Encoding"
                            && cte_duplicate_is_incomplete_multipart_layering)
                })
                .count();
            if duplicated_kinds >= 2 {
                total_score += 0.15;
                categories.push("header_smuggling".to_string());
            }
        }

        // --- 6. Missing / empty critical identity headers ---
        // RFC 5322 requires From and Date at minimum. Missing From on a mail
        // that somehow reached us is a structural anomaly that commonly
        // accompanies header-injection or malformed-message exploitation.
        if from_count == 0 || from_empty {
            let missing_from_weight = if ctx.session.mail_from.is_some() { 0.08 } else { 0.25 };
            total_score += missing_from_weight;
            categories.push("missing_from".to_string());
            evidence.push(Evidence {
                description: if from_count == 0 {
                    "Message is missing a From: header entirely (RFC 5322 violation)".to_string()
                } else {
                    "From: header is present but empty".to_string()
                },
                location: Some("headers:From".to_string()),
                snippet: None,
            });
        }
        if to_count == 0 || to_empty {
            // Missing To: is less severe — bulk/BCC-only mail may legitimately
            // omit it — but combined with other anomalies it contributes.
            total_score += 0.05;
            categories.push("missing_to".to_string());
            evidence.push(Evidence {
                description: "To: header is missing or empty (uncommon in legitimate mail)".to_string(),
                location: Some("headers:To".to_string()),
                snippet: None,
            });
        }
        if subject_count > 0 && subject_empty_present && subject_count == 1 {
            // Single empty Subject — sometimes legitimate but worth a small
            // signal when combined with other anomalies.
            total_score += 0.02;
            categories.push("empty_subject".to_string());
        }

        // --- 7. Multiple addresses smuggled in a single From: header ---
        // RFC 5322 does permit a group-list in From, but in practice legitimate
        // mail has a single mailbox. Multiple comma-separated addresses are a
        // display-name spoofing / sender confusion vector.
        if let Some(ref fv) = first_from_value {
            let address_count = count_email_addresses_in_header(fv);
            if address_count > 1 {
                total_score += 0.20;
                categories.push("multi_address_from".to_string());
                evidence.push(Evidence {
                    description: format!(
                        "From: header contains {} email addresses — ambiguous sender identity",
                        address_count
                    ),
                    location: Some("headers:From".to_string()),
                    snippet: Some(fv.clone()),
                });
            }
        }

        let only_mild_parser_gaps = !categories.is_empty()
            && categories.iter().all(|category| {
                matches!(
                    category.as_str(),
                    "missing_content_type" | "missing_from" | "missing_to" | "empty_subject"
                )
            })
            && ctx.session.mail_from.is_some()
            && !ctx.session.rcpt_to.is_empty();
        if only_mild_parser_gaps {
            total_score = total_score.min(0.12);
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
                "MIME structureNormal",
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.75,
            categories,
            summary: format!(
                "MIME structuredetectFound {} 处Abnormal，综合评分 {:.2}",
                evidence.len(),
                total_score
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "boundary_count": boundary_count,
                "boundaries": boundaries,
                "from_count": from_count,
                "to_count": to_count,
                "subject_count": subject_count,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

/// Roughly count email addresses inside a single header value. We look for
/// normalized address patterns and deduplicate them so a display name like
/// `"alice@example.com" <alice@example.com>` still counts as one sender.
static HEADER_EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
        .expect("header email regex should compile")
});

fn count_email_addresses_in_header(value: &str) -> usize {
    let mut seen = HashSet::new();
    for matched in HEADER_EMAIL_RE.find_iter(value) {
        seen.insert(matched.as_str().to_ascii_lowercase());
    }
    seen.len()
}

fn duplicate_cte_looks_like_nested_part_encoding(values: &[String]) -> bool {
    if values.len() != 2 {
        return false;
    }

    let normalized: HashSet<String> = values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect();
    if normalized.len() != 2 {
        return false;
    }

    let has_transport_level = normalized
        .iter()
        .any(|value| matches!(value.as_str(), "7bit" | "8bit" | "binary"));
    let has_payload_level = normalized
        .iter()
        .any(|value| matches!(value.as_str(), "base64" | "quoted-printable"));

    has_transport_level && has_payload_level
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};

    #[test]
    fn counts_single_address() {
        assert_eq!(count_email_addresses_in_header("alice@example.com"), 1);
        assert_eq!(
            count_email_addresses_in_header("Alice <alice@example.com>"),
            1
        );
    }

    #[test]
    fn counts_multiple_addresses() {
        assert_eq!(
            count_email_addresses_in_header("alice@example.com, bob@example.com"),
            2
        );
        assert_eq!(
            count_email_addresses_in_header(
                "Alice <a@x.com>, \"Mr Bob\" <b@y.org>, charlie@z.net"
            ),
            3
        );
    }

    #[test]
    fn no_address() {
        assert_eq!(count_email_addresses_in_header("Undisclosed recipients"), 0);
    }

    #[test]
    fn duplicated_display_name_address_counts_once() {
        assert_eq!(
            count_email_addresses_in_header("\"12306@rails.com.cn\" <12306@rails.com.cn>"),
            1
        );
    }

    fn make_ctx_without_identity_headers() -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("sender@example.com".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        session.content = EmailContent::default();
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn parser_gap_only_headers_with_envelope_remain_safe() {
        let module = MimeScanModule::new();
        let ctx = make_ctx_without_identity_headers();

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn incomplete_multipart_cte_pair_is_treated_as_layering_not_smuggling() {
        assert!(duplicate_cte_looks_like_nested_part_encoding(&[
            "8Bit".to_string(),
            "base64".to_string(),
        ]));
        assert!(duplicate_cte_looks_like_nested_part_encoding(&[
            "7bit".to_string(),
            "quoted-printable".to_string(),
        ]));
    }

    #[test]
    fn same_level_cte_duplicates_still_look_suspicious() {
        assert!(!duplicate_cte_looks_like_nested_part_encoding(&[
            "base64".to_string(),
            "base64".to_string(),
        ]));
        assert!(!duplicate_cte_looks_like_nested_part_encoding(&[
            "8bit".to_string(),
            "binary".to_string(),
        ]));
    }

    fn make_incomplete_multipart_cte_ctx() -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("1790341540@qq.com".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        let content = EmailContent {
            headers: vec![
                ("From".to_string(), "\"Monologue*\" <1790341540@qq.com>".to_string()),
                ("To".to_string(), "<recipient@example.com>".to_string()),
                ("Subject".to_string(), "扫描全能王 2026-4-20 16.55".to_string()),
                (
                    "Content-Type".to_string(),
                    "multipart/mixed; boundary=\"----=_NextPart_123\"".to_string(),
                ),
                ("Content-Transfer-Encoding".to_string(), "8Bit".to_string()),
                ("Content-Transfer-Encoding".to_string(), "base64".to_string()),
            ],
            is_complete: false,
            ..Default::default()
        };
        session.content = content;
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn incomplete_multipart_transport_plus_base64_does_not_trigger_duplicate_header() {
        let module = MimeScanModule::new();
        let ctx = make_incomplete_multipart_cte_ctx();

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn complete_singlepart_duplicate_cte_still_triggers_duplicate_header() {
        let module = MimeScanModule::new();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("sender@example.com".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        let content = EmailContent {
            headers: vec![
                ("From".to_string(), "sender@example.com".to_string()),
                ("To".to_string(), "recipient@example.com".to_string()),
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Content-Transfer-Encoding".to_string(), "base64".to_string()),
                ("Content-Transfer-Encoding".to_string(), "8bit".to_string()),
            ],
            is_complete: true,
            ..Default::default()
        };
        session.content = content;
        let ctx = SecurityContext::new(Arc::new(session));

        let result = module.analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Low);
        assert!(result.categories.contains(&"duplicate_header".to_string()));
    }
}
