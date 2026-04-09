//! emailSandboxDynamicAnalyzeModule - emailAttachment CAPEv2 Sandbox lineline Analyze

//! Stream:
//! 1. ExtractemailMediumofHighRiskAttachment(Executable file, DocumentationClassAttachment)
//! 2. According to SHA256 Deduplicate(alreadyAnalyzeof ConnectGetcache)
//! 3. CAPEv2 REST API lineDynamicAnalyze
//! 4. waitWaitAnalyzecomplete
//! 5. Parse:ExtractMalicious, line Sign, Malicious, Network IOC
//! 6. Result D-S verdict


//! - Sandbox Return `not_applicable`(downgradelevel)
//! - email Analyze 3 Attachment(AvoidSandbox)
//! - hops>25MB ofAttachment(Sandbox sourcelimit)
//! - AnalyzeHighRiskFileType(EXE/DLL/DOC/XLS/PDF/ZIP/RAR/JS/VBS/HTA/PS1)

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::sandbox::SandboxClient;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

/// email AnalyzeofAttachment
const MAX_ATTACHMENTS_PER_EMAIL: usize = 3;

/// Attachmentsize (25 MB)
const MAX_ATTACHMENT_SIZE: usize = 25 * 1024 * 1024;

/// Need/RequireSandboxAnalyzeofHighRiskFileextension
const SANDBOX_EXTENSIONS: &[&str] = &[
   // Executeline
    "exe", "dll", "scr", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "msi",
    "msp", // Documentation(Contains)
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf", "odt",
    "ods", // PDF
    "pdf", // Compresspacket
    "zip", "rar", "7z", "gz", "tar", "iso", "img", 
    "lnk", "url", "iqy", "slk",
];

pub struct SandboxScanModule {
    meta: ModuleMetadata,
    client: Arc<SandboxClient>,
}

impl SandboxScanModule {
    pub fn new(client: Arc<SandboxClient>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "sandbox_scan".to_string(),
                name: "SandboxDynamicAnalyze".to_string(),
                description: "将HighRiskAttachment提交至 CAPEv2 Sandbox进lineline Analyze（DynamicdetectMalicious软件、C2 communication、data窃Getwait）".to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec![],
                timeout_ms: 360_000, // 6 minute(ContainsSandboxAnalyzetimestamp)
                is_remote: true,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            client,
        }
    }
}

/// CheckFileextensionwhetherNeed/RequireSandboxAnalyze
fn needs_sandbox(filename: &str) -> bool {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    SANDBOX_EXTENSIONS.contains(&ext.as_str())
}

/// dataof SHA256 Hash
fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// CAPEv2 score (0-10) Mapping ThreatLevel
fn score_to_threat_level(score: f64) -> ThreatLevel {
    if score >= 8.0 {
        ThreatLevel::Critical
    } else if score >= 6.0 {
        ThreatLevel::High
    } else if score >= 4.0 {
        ThreatLevel::Medium
    } else if score >= 2.0 {
        ThreatLevel::Low
    } else {
        ThreatLevel::Safe
    }
}

/// small base64 Decodehandler(av_attach_scan 1)
fn decode_base64_bytes(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &b) in TABLE.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ' && b != b'\t')
        .collect();
    if clean.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in &clean {
        if b == b'=' {
            break;
        }
        let val = lookup[b as usize];
        if val == 255 {
            continue;
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[async_trait]
impl SecurityModule for SandboxScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let attachments = &ctx.session.content.attachments;

        if attachments.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "无Attachment，hopsSandboxAnalyze",
                start.elapsed().as_millis() as u64,
            ));
        }

       // Need/RequireSandboxAnalyzeofAttachment
        let candidates: Vec<_> = attachments
            .iter()
            .filter(|att| {
                let filename = &att.filename;
                let has_content = att.content_base64.is_some();
                let size_ok = att
                    .content_base64
                    .as_ref()
                    .map(|c| c.len() * 3 / 4 <= MAX_ATTACHMENT_SIZE)
                    .unwrap_or(false);
                needs_sandbox(filename) && has_content && size_ok
            })
            .take(MAX_ATTACHMENTS_PER_EMAIL)
            .collect();

        if candidates.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "无HighRiskAttachmentNeed/RequireSandboxAnalyze",
                start.elapsed().as_millis() as u64,
            ));
        }

        let mut max_score: f64 = 0.0;
        let mut all_evidence = Vec::new();
        let mut all_categories = Vec::new();
        let mut all_reports = Vec::new();

        for att in &candidates {
            let filename = &att.filename;
            let b64 = match att.content_base64.as_deref() {
                Some(s) => s,
                None => continue,
            };

            let data = match decode_base64_bytes(b64) {
                Some(d) if !d.is_empty() => d,
                _ => {
                    debug!(filename, "Sandbox: AttachmentDecodeFailed，hops");
                    continue;
                }
            };

            let sha256 = compute_sha256(&data);
            info!(filename, sha256 = %sha256, size = data.len(), "Sandbox: 提交AttachmentAnalyze");

            match self.client.analyze_file(filename, data, &sha256).await {
                Ok(report) => {
                    let threat = score_to_threat_level(report.score);

                    if report.score > max_score {
                        max_score = report.score;
                    }

                   // According to
                    all_evidence.push(Evidence {
                        description: format!(
                            "SandboxAnalyze {}: score={:.1}/10, Sign={}, 家族={}, IOC={}",
                            filename,
                            report.score,
                            report.signatures.len(),
                            report.malfamily.as_deref().unwrap_or("unknown"),
                            report.network_iocs.len(),
                        ),
                        location: Some(format!("attachment:{}", filename)),
                        snippet: if !report.signatures.is_empty() {
                            Some(
                                report
                                    .signatures
                                    .iter()
                                    .take(3)
                                    .map(|s| format!("[sev:{}] {}", s.severity, s.name))
                                    .collect::<Vec<_>>()
                                    .join("; "),
                            )
                        } else {
                            None
                        },
                    });

                   // Classification
                    if threat >= ThreatLevel::Medium {
                        all_categories.push("sandbox_malicious".to_string());
                    }
                    if report.malfamily.is_some() {
                        all_categories.push("sandbox_malware_family".to_string());
                    }
                    if !report.network_iocs.is_empty() {
                        all_categories.push("sandbox_c2_detected".to_string());
                    }
                    if report.payload_count > 0 {
                        all_categories.push("sandbox_payload_extracted".to_string());
                    }

                    all_reports.push(report);
                }
                Err(e) => {
                    warn!(filename, error = %e, "SandboxAnalyzeFailed");
                    all_evidence.push(Evidence {
                        description: format!("SandboxAnalyze {} Failed: {}", filename, e),
                        location: Some(format!("attachment:{}", filename)),
                        snippet: None,
                    });
                }
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        if all_reports.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "SandboxAnalyze未ReturnValidResult ",
                duration_ms,
            ));
        }

        all_categories.sort();
        all_categories.dedup();

        let threat_level = score_to_threat_level(max_score);
       // CAPEv2 score 0-10 -> confidence Mapping
        let confidence = if max_score >= 8.0 {
            0.95
        } else if max_score >= 6.0 {
            0.85
        } else if max_score >= 4.0 {
            0.75
        } else {
            0.60
        };

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "SandboxAnalyzecomplete: {}/{} Attachment, 最High score={:.1}",
                    all_reports.len(),
                    candidates.len(),
                    max_score
                ),
                duration_ms,
            ));
        }

        let bpa = crate::bpa::Bpa::from_score_confidence(max_score / 10.0, confidence);

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories: all_categories,
            summary: format!(
                "SandboxDetectedMaliciousline : score={:.1}/10, Sign={}, 家族={}",
                max_score,
                all_reports
                    .iter()
                    .map(|r| r.signatures.len())
                    .sum::<usize>(),
                all_reports
                    .iter()
                    .filter_map(|r| r.malfamily.as_deref())
                    .next()
                    .unwrap_or("unknown"),
            ),
            evidence: all_evidence,
            details: serde_json::json!({
                "reports": all_reports,
                "max_score": max_score,
                "attachments_analyzed": all_reports.len(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(bpa),
            engine_id: Some("content_analysis".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_sandbox() {
        assert!(needs_sandbox("report.docx"));
        assert!(needs_sandbox("invoice.pdf"));
        assert!(needs_sandbox("setup.exe"));
        assert!(needs_sandbox("archive.zip"));
        assert!(needs_sandbox("MACRO.XLSM"));
        assert!(!needs_sandbox("image.png"));
        assert!(!needs_sandbox("photo.jpg"));
        assert!(!needs_sandbox("readme.txt"));
        assert!(!needs_sandbox("style.css"));
    }

    #[test]
    fn test_score_to_threat_level() {
        assert_eq!(score_to_threat_level(9.0), ThreatLevel::Critical);
        assert_eq!(score_to_threat_level(7.0), ThreatLevel::High);
        assert_eq!(score_to_threat_level(5.0), ThreatLevel::Medium);
        assert_eq!(score_to_threat_level(3.0), ThreatLevel::Low);
        assert_eq!(score_to_threat_level(1.0), ThreatLevel::Safe);
        assert_eq!(score_to_threat_level(0.0), ThreatLevel::Safe);
    }

    #[test]
    fn test_compute_sha256() {
        let hash = compute_sha256(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
