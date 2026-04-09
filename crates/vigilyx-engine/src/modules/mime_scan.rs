//! MIME structuredetectModule - Checkemail MIME structureAbnormal: depth, Content-Type, EncodeAbnormalwait

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

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
        let mut boundary_count = 0usize;
        let mut boundaries: Vec<String> = Vec::new();

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

            if name_lower == "content-type" {
                content_type_header = Some(value.clone());
            }
            if name_lower == "content-transfer-encoding" {
                content_transfer_encoding = Some(value.clone());
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
            total_score += 0.10;
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
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}
