//! AttachmentContentdetectModule - TextClassAttachment lineKeywords (content_scan SharedKeywords)

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::sync::LazyLock;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

pub struct AttachContentModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
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
                name: "AttachmentContentdetect".to_string(),
                description: "对TextClassAttachmentContent进lineKeywordsAndSensitivedata扫描"
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
            bec_phrases: effective.bec_phrases,
        }
    }
}

static RE_CREDIT_CARD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());
static RE_CHINESE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{17}[\dXx]\b").unwrap());

/// Check if the attachment MIME type is text-scannable
fn is_text_scannable(content_type: &str) -> bool {
    let ct = content_type.to_lowercase();
    ct.starts_with("text/")
        || ct.contains("application/pdf")
        || ct.contains("application/json")
        || ct.contains("application/xml")
        || ct.contains("application/csv")
}

/// Try to decode base64 content to UTF-8 text (best effort)
fn decode_base64_to_text(b64: &str) -> Option<String> {
   // Strip whitespace that may exist in the base64 data
    let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();

   // Use a simple base64 decoder
   // We rely on the standard base64 alphabet; since the engine crate
   // does not explicitly depend on the `base64` crate, we implement a
   // minimal decoder here. For robustness we tolerate padding.
    decode_base64_bytes(&cleaned).and_then(|bytes| String::from_utf8(bytes).ok())
}

fn decode_base64_bytes(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &ch) in TABLE.iter().enumerate() {
        lookup[ch as usize] = i as u8;
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);

    let chunks = bytes.chunks(4);
    for chunk in chunks {
        let mut buf = [0u8; 4];
        let len = chunk.len();
        for (i, &b) in chunk.iter().enumerate() {
            let val = lookup[b as usize];
            if val == 255 {
                return None; // Invalid character
            }
            buf[i] = val;
        }

        if len >= 2 {
            out.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if len >= 3 {
            out.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if len >= 4 {
            out.push((buf[2] << 6) | buf[3]);
        }
    }

    Some(out)
}

fn scan_attachment_text(
    text: &str,
    filename: &str,
    phishing_keywords: &[String],
    bec_phrases: &[String],
    evidence: &mut Vec<Evidence>,
    categories: &mut Vec<String>,
) -> f64 {
    let mut score: f64 = 0.0;
    let text_lower = normalize_text(&text.to_lowercase());

   // Phishing keywords (constants are already lowercase)
    let mut phishing_hits = Vec::new();
    for kw in phishing_keywords {
        if text_lower.contains(kw.as_str()) {
            phishing_hits.push(kw.clone());
        }
    }
    if !phishing_hits.is_empty() {
        score += (phishing_hits.len() as f64 * 0.06).min(0.4);
        categories.push("phishing".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} Found in {} PhishingKeywords",
                filename,
                phishing_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(phishing_hits.join(", ")),
        });
    }

   // BEC phrases (constants are already lowercase)
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
                "Attachment {} Found in {}  BEC short语",
                filename,
                bec_hits.len()
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: Some(bec_hits.join(", ")),
        });
    }

   // Credit card numbers
    let cc_count = RE_CREDIT_CARD.find_iter(text).count();
    if cc_count > 0 {
        score += 0.25;
        categories.push("dlp_credit_card".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} Found in {} 疑似信用Card number",
                filename, cc_count
            ),
            location: Some(format!("attachment:{}", filename)),
            snippet: None,
        });
    }

   // Chinese ID numbers
    let id_count = RE_CHINESE_ID.find_iter(text).count();
    if id_count > 0 {
        score += 0.20;
        categories.push("dlp_id_number".to_string());
        evidence.push(Evidence {
            description: format!(
                "Attachment {} Found in {} 疑似ID cardNumber",
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
        let attachments = &ctx.session.content.attachments;

       // Only scan text-based attachments that have content
        let scannable: Vec<_> = attachments
            .iter()
            .filter(|a| is_text_scannable(&a.content_type) && a.content_base64.is_some())
            .collect();

        if scannable.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "无可扫描ofTextClassAttachment",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut scanned_count = 0usize;

        for att in &scannable {
            if let Some(ref b64) = att.content_base64
                && let Some(text) = decode_base64_to_text(b64)
            {
                scanned_count += 1;
                total_score += scan_attachment_text(
                    &text,
                    &att.filename,
                    &self.phishing_keywords,
                    &self.bec_phrases,
                    &mut evidence,
                    &mut categories,
                );
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
                &format!("already扫描 {} TextAttachment，未Found威胁", scanned_count),
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
                "AttachmentContent扫描Found {} Item证According to（already扫描 {} Attachment）",
                evidence.len(),
                scanned_count
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "scanned_count": scanned_count,
                "total_scannable": scannable.len(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}
