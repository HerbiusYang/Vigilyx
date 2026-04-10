//! Attachment content scan module.
//!
//! Reuses the runtime keyword lists from `content_scan` and extends attachment
//! text extraction beyond plain text so PDF / OOXML / legacy Office documents
//! are covered by the same `/security/keywords` configuration.

use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use vigilyx_core::magic_bytes::detect_file_type;
use vigilyx_core::models::decode_base64_bytes;

use crate::context::SecurityContext;
use crate::data_security::document_extract;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

pub struct AttachContentModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
    weak_phishing_keywords: Vec<String>,
    bec_phrases: Vec<String>,
}

impl Default for AttachContentModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachContentModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "attach_content".to_string(),
                name: "Attachment Content Analysis".to_string(),
                description: "Scan attachment text for runtime keywords and DLP signals"
                    .to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec!["attach_scan".to_string()],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords: effective.phishing_keywords,
            weak_phishing_keywords: effective.weak_phishing_keywords,
            bec_phrases: effective.bec_phrases,
        }
    }
}

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());
static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{17}[\dXx]\b").unwrap());

fn is_text_mime_candidate(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("text/")
        || ct.contains("application/json")
        || ct.contains("application/xml")
        || ct.contains("application/csv")
}

fn decode_plain_text_bytes(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn extract_attachment_text(content_type: &str, content_base64: &str) -> Option<String> {
    let bytes = decode_base64_bytes(content_base64)?;
    let file_type = detect_file_type(&bytes);

    if file_type.is_some_and(|ft| ft.is_extractable_document()) {
        return document_extract::extract_text(&bytes, file_type);
    }

    if file_type.is_some_and(|ft| ft.is_text_scannable()) || is_text_mime_candidate(content_type) {
        return decode_plain_text_bytes(&bytes);
    }

    None
}

fn scan_attachment_text(
    text: &str,
    filename: &str,
    phishing_keywords: &[String],
    weak_phishing_keywords: &[String],
    bec_phrases: &[String],
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score: f64 = 0.0;
    let text_lower = normalize_text(&text.to_lowercase())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let mut phishing_hits = Vec::new();
    for kw in phishing_keywords {
        if text_lower.contains(kw.as_str()) {
            phishing_hits.push(kw.clone());
        }
    }
    if !phishing_hits.is_empty() {
        score += (phishing_hits.len() as f64 * 0.08).min(0.5);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} phishing keyword(s)",
                filename,
                phishing_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(phishing_hits.join(", ")),
        });
    }

    let mut weak_hits = Vec::new();
    for kw in weak_phishing_keywords {
        if text_lower.contains(kw.as_str()) {
            weak_hits.push(kw.clone());
        }
    }
    if weak_hits.len() >= 3 {
        score += (weak_hits.len() as f64 * 0.03).min(0.18);
        categories.push("weak_phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} weak phishing keyword(s)",
                filename,
                weak_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(weak_hits.join(", ")),
        });
    }

    let mut bec_hits = Vec::new();
    for phrase in bec_phrases {
        if text_lower.contains(phrase.as_str()) {
            bec_hits.push(phrase.clone());
        }
    }
    if !bec_hits.is_empty() {
        score += (bec_hits.len() as f64 * 0.10).min(0.4);
        categories.push("bec".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} matched {} BEC phrase(s)",
                filename,
                bec_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(bec_hits.join(", ")),
        });
    }

    let cc_count = RE_CREDIT_CARD.find_iter(text).count();
    if cc_count > 0 {
        score += 0.25;
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} possible credit card number(s)",
                filename, cc_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    let id_count = RE_CHINESE_ID.find_iter(text).count();
    if id_count > 0 {
        score += 0.20;
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} contains {} possible Chinese ID number(s)",
                filename, id_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

    score
}

#[async_trait]
impl SecurityModule for AttachContentModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut scanned_count = 0usize;
        let mut retained_count = 0usize;

        for attachment in &ctx.session.content.attachments {
            let Some(content_base64) = attachment.content_base64.as_deref() else {
                continue;
            };
            retained_count += 1;

            let Some(text) = extract_attachment_text(&attachment.content_type, content_base64) else {
                continue;
            };

            scanned_count += 1;
            total_score += scan_attachment_text(
                &text,
                &attachment.filename,
                &self.phishing_keywords,
                &self.weak_phishing_keywords,
                &self.bec_phrases,
                &mut evidence,
                &mut categories,
            );
        }

        if scanned_count == 0 {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No attachments with extractable text content",
                duration_ms,
            ));
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
                &format!(
                    "Scanned {} attachment(s) with extractable text, no threats found",
                    scanned_count
                ),
                duration_ms,
            ));
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.80,
            categories,
            summary: format!(
                "Attachment content analysis found {} finding(s) across {} scanned attachment(s)",
                evidence.len(),
                scanned_count
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "scanned_count": scanned_count,
                "retained_attachments": retained_count,
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
    use std::io::{Cursor, Write};
    use std::sync::Arc;

    use base64::Engine as _;
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_ctx(attachments: Vec<EmailAttachment>) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_module_with_keywords(
        phishing_keywords: &[&str],
        weak_phishing_keywords: &[&str],
    ) -> AttachContentModule {
        AttachContentModule::new_with_keyword_lists(EffectiveKeywordLists {
            phishing_keywords: phishing_keywords
                .iter()
                .map(|keyword| normalize_text(&keyword.to_lowercase()))
                .collect(),
            weak_phishing_keywords: weak_phishing_keywords
                .iter()
                .map(|keyword| normalize_text(&keyword.to_lowercase()))
                .collect(),
            ..Default::default()
        })
    }

    fn build_docx_like_attachment_xml(text: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>
</w:document>"#
        )
    }

    fn build_ooxml_zip(files: &[(&str, &str)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip_w = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for (name, content) in files {
            zip_w.start_file(name, options).expect("start zip entry");
            zip_w
                .write_all(content.as_bytes())
                .expect("write zip entry");
        }

        zip_w.finish().expect("finish zip").into_inner()
    }

    #[tokio::test]
    async fn test_docx_attachment_uses_runtime_keywords() {
        let docx = build_ooxml_zip(&[(
            "word/document.xml",
            &build_docx_like_attachment_xml(
                "Please review the secure voicemail and verify your account immediately",
            ),
        )]);
        let attachment = EmailAttachment {
            filename: "voicemail.docx".to_string(),
            content_type:
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                    .to_string(),
            size: docx.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(docx)),
        };

        let result = make_module_with_keywords(
            &["secure voicemail", "verify your account"],
            &[],
        )
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"phishing".to_string()),
            "OOXML attachment text should reuse runtime keywords: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_plain_text_attachment_uses_weak_keyword_list() {
        let content =
            "Please review today the employee handbook acknowledgement policy document update";
        let attachment = EmailAttachment {
            filename: "notice.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: content.len(),
            hash: "hash".to_string(),
            content_base64: Some(
                base64::engine::general_purpose::STANDARD.encode(content.as_bytes()),
            ),
        };

        let result = make_module_with_keywords(
            &[],
            &[
                "employee handbook",
                "acknowledgement",
                "policy document",
                "document update",
                "review today",
            ],
        )
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert!(
            result.categories.contains(&"weak_phishing".to_string()),
            "weak phishing keywords from runtime config should be honored: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_binary_image_attachment_is_not_scanned_as_text() {
        let png_stub = vec![0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1A, b'\n'];
        let attachment = EmailAttachment {
            filename: "logo.png".to_string(),
            content_type: "image/png".to_string(),
            size: png_stub.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(png_stub)),
        };

        let result = AttachContentModule::new()
            .analyze(&make_ctx(vec![attachment]))
            .await
            .unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.summary, "No attachments with extractable text content");
    }
}
