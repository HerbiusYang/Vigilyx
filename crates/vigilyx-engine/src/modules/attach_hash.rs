//! AttachmentHashReputationModule - Name Check + Query (VT Scrape)

use std::collections::HashSet;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::intel::IntelLayer;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct AttachHashModule {
    meta: ModuleMetadata,
   /// Local hash blacklist - will be populated from IOC feeds in a future phase.
    hash_blacklist: HashSet<String>,
   /// (VT Scrape FileHashQuery)
    intel: Option<IntelLayer>,
}

impl AttachHashModule {
    pub fn new(intel: Option<IntelLayer>) -> Self {
        let timeout_ms = if intel.is_some() { 8000 } else { 5000 };
        Self {
            meta: ModuleMetadata {
                id: "attach_hash".to_string(),
                name: "AttachmentHashReputation".to_string(),
                description: "CheckAttachment SHA256 Hash: 本地黑Name单 + VirusTotal 外部情报Query"
                    .to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec![],
                timeout_ms,
                is_remote: intel.is_some(),
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            hash_blacklist: HashSet::new(),
            intel,
        }
    }
}

#[async_trait]
impl SecurityModule for AttachHashModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let attachments = &ctx.session.content.attachments;

        if attachments.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "email无Attachment",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut hashes_found: Vec<serde_json::Value> = Vec::new();
        let mut flagged_files: Vec<String> = Vec::new();
       // Recordingalready Name MediumofHash,
        let mut blacklisted_hashes: HashSet<String> = HashSet::new();

        for att in attachments {
            let hash_lower = att.hash.to_lowercase();

           // Record every hash we see (for reporting / future IOC matching)
            hashes_found.push(serde_json::json!({
                "filename": att.filename,
                "hash": hash_lower,
                "size": att.size,
                "content_type": att.content_type,
            }));

           // Check against local blacklist
            if self.hash_blacklist.contains(&hash_lower) {
                total_score += 0.90;
                categories.push("malware_hash".to_string());
                flagged_files.push(att.filename.clone());
                blacklisted_hashes.insert(hash_lower.clone());
                evidence.push(Evidence {
                    description: format!(
                        "Attachment {} ofHash {} 命MediumMaliciousFile黑Name单",
                        att.filename, hash_lower
                    ),
                    location: Some(format!("attachment:{}", att.filename)),
                    snippet: Some(hash_lower.clone()),
                });
            }
        }

       // --- Query: VT Hash (Name MediumofAttachmentQuery VT) ---
        if let Some(ref intel) = self.intel {
            let mut join_set = tokio::task::JoinSet::new();

            for att in attachments {
                let hash_lower = att.hash.to_lowercase();
               // already Medium Name of
                if blacklisted_hashes.contains(&hash_lower) {
                    continue;
                }
               // Hashhops
                if hash_lower.is_empty() {
                    continue;
                }

                let intel_c = intel.clone();
                let filename = att.filename.clone();

                join_set.spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(6),
                        intel_c.query_hash(&hash_lower),
                    )
                    .await
                    {
                        Ok(result) => Some((filename, hash_lower, result)),
                        Err(_) => {
                            tracing::warn!(
                                hash = hash_lower.as_str(),
                                "AttachmentHash情报QueryTimeout (15s)"
                            );
                            None
                        }
                    }
                });
            }

            while let Some(join_result) = join_set.join_next().await {
                if let Ok(Some((filename, hash, intel_result))) = join_result {
                    if !intel_result.found {
                        continue;
                    }
                    match intel_result.verdict.as_str() {
                        "malicious" => {
                            total_score += 0.85;
                            categories.push("hash_intel_malicious".to_string());
                            flagged_files.push(filename.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "Attachment {} Hash被外部情报MarkMalicious (source: {}, {})",
                                    filename,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
                                location: Some(format!("attachment:{}", filename)),
                                snippet: Some(hash),
                            });
                        }
                        "suspicious" => {
                            total_score += 0.40;
                            categories.push("hash_intel_suspicious".to_string());
                            flagged_files.push(filename.clone());
                            evidence.push(Evidence {
                                description: format!(
                                    "Attachment {} Hash被外部情报MarkSuspicious (source: {}, {})",
                                    filename,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("")
                                ),
                                location: Some(format!("attachment:{}", filename)),
                                snippet: Some(hash),
                            });
                        }
                        _ => {
                            evidence.push(Evidence {
                                description: format!(
                                    "Attachment {} HashReputationNormal (source: {}, {})",
                                    filename,
                                    intel_result.source,
                                    intel_result.details.as_deref().unwrap_or("无威胁Recording")
                                ),
                                location: Some(format!("attachment:{}", filename)),
                                snippet: Some(hash),
                            });
                        }
                    }
                }
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();
        flagged_files.sort();
        flagged_files.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);

        if threat_level == ThreatLevel::Safe {
            let intel_status = if self.intel.is_some() {
                "本地黑Name单 + VirusTotal"
            } else {
                "仅本地黑Name单"
            };
            return Ok(ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 1.0,
                categories: vec![],
                summary: format!(
                    "alreadyCheck {} AttachmentHash，未Found威胁 ({})",
                    attachments.len(),
                    intel_status,
                ),
                evidence,
                details: serde_json::json!({
                    "hashes": hashes_found,
                    "blacklist_size": self.hash_blacklist.len(),
                    "intel_enabled": self.intel.is_some(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: None,
                engine_id: None,
            });
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.95,
            categories,
            summary: format!(
                "AttachmentHashdetect命Medium {} MaliciousFile: {}",
                flagged_files.len(),
                flagged_files.join(", ")
            ),
            evidence,
            details: serde_json::json!({
                "hashes": hashes_found,
                "flagged_files": flagged_files,
                "blacklist_size": self.hash_blacklist.len(),
                "intel_enabled": self.intel.is_some(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}
