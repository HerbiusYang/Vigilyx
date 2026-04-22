//! verdictModule - first ModuleofResult Output.

//! ofAdd bit `crate::verdict::aggregate_verdict` Medium.
//! Module DAG of,Ensure Module complete.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

/// All module IDs that must complete before verdict runs
const ALL_PREREQUISITE_IDS: &[&str] = &[
    "content_scan",
    "html_scan",
    "html_pixel_art",
    "attach_scan",
    "attach_content",
    "attach_hash",
    "mime_scan",
    "header_scan",
    "link_scan",
    "link_reputation",
    "link_content",
    "anomaly_detect",
    "semantic_scan",
    "domain_verify",
    "identity_anomaly",
    "transaction_correlation",
];

pub struct VerdictModule {
    meta: ModuleMetadata,
}

impl Default for VerdictModule {
    fn default() -> Self {
        Self::new()
    }
}

impl VerdictModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "verdict".to_string(),
                name: "Composite verdict".to_string(),
                description: "Collect all module results and generate composite verdict"
                    .to_string(),
                pillar: Pillar::Package,
                depends_on: ALL_PREREQUISITE_IDS.iter().map(|s| s.to_string()).collect(),
                timeout_ms: 1000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
        }
    }
}

#[async_trait]
impl SecurityModule for VerdictModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        // Read all prior results from context
        let all_results = ctx.module_results().await;

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut max_threat = ThreatLevel::Safe;
        let mut flagged_modules: Vec<String> = Vec::new();
        let mut total_modules = 0u32;
        let mut pillar_summary: Vec<serde_json::Value> = Vec::new();

        for (module_id, result) in &all_results {
            if module_id == "verdict" {
                continue;
            }
            total_modules += 1;

            if result.threat_level > ThreatLevel::Safe {
                flagged_modules.push(module_id.clone());
                if result.threat_level > max_threat {
                    max_threat = result.threat_level;
                }
                for cat in &result.categories {
                    categories.push(cat.clone());
                }
                // Summarize each flagged module as evidence
                evidence.push(Evidence {
                    description: format!(
                        "[{}] {} — threat level: {}, confidence: {:.0}%",
                        module_id,
                        result.summary,
                        result.threat_level,
                        result.confidence * 100.0
                    ),
                    location: Some(format!("module:{}", module_id)),
                    snippet: None,
                });
            }

            pillar_summary.push(serde_json::json!({
                "module_id": module_id,
                "pillar": result.pillar.to_string(),
                "threat_level": result.threat_level.to_string(),
                "confidence": result.confidence,
                "duration_ms": result.duration_ms,
            }));
        }

        categories.sort();
        categories.dedup();
        flagged_modules.sort();

        let duration_ms = start.elapsed().as_millis() as u64;

        // Build summary text
        let summary = if max_threat == ThreatLevel::Safe {
            format!(
                "Composite verdict: Safe — {} modules found no threats",
                total_modules
            )
        } else {
            format!(
                "Composite verdict: {} — {}/{} modules flagged anomalies [{}]",
                max_threat,
                flagged_modules.len(),
                total_modules,
                categories.join(", ")
            )
        };

        // Verdict module itself reports the aggregated threat level with high confidence
        // (the actual weighted aggregation is done by verdict.rs in the orchestrator)
        let confidence = if flagged_modules.is_empty() {
            1.0
        } else {
            // Confidence is higher when more modules agree
            let agreement_ratio = flagged_modules.len() as f64 / total_modules.max(1) as f64;
            (0.60 + agreement_ratio * 0.40).min(1.0)
        };

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level: max_threat,
            confidence,
            categories,
            summary,
            evidence,
            details: serde_json::json!({
                "total_modules": total_modules,
                "flagged_modules": flagged_modules,
                "pillar_summary": pillar_summary,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}
