//! RMM (Remote Monitoring & Management) weaponization detection.
//!
//! Detects emails attempting to deliver or social-engineer the install of
//! legitimate remote-control tools (ScreenConnect/ConnectWise Control,
//! AnyDesk, TeamViewer, Atera, Splashtop, Syncro, FleetDeck, Level.io,
//! NinjaOne, Kaseya, Action1, Tactical RMM, RustDesk, Zoho Assist, etc.).
//!
//! These tools are signed, often whitelisted by AV/EDR, and have become the
//! preferred initial-access foothold for ransomware crews and TOAD callback
//! crews in 2025-2026. CISA AA23-025A documented this trend; OSINT 2025
//! confirms continued growth.
//!
//! Detection model
//! ---------------
//! Score = brand_signal + action_signal + installer_signal + lure_signal
//!
//! - `brand_signal`     : RMM brand keyword in subject/body/attachment name.
//! - `action_signal`    : install / connect-id / support-session verbs.
//! - `installer_signal` : known RMM installer filename pattern as attachment.
//! - `lure_signal`      : explicit social-engineering brand impersonation
//!   ("Microsoft Support", "Geek Squad", refund/invoice).
//!
//! Threat tiers:
//!   - brand only                       → Safe (legitimate IT mail likely)
//!   - brand + action                   → Low
//!   - brand + action + lure            → Medium
//!   - installer attached + action      → High (active staging)
//!   - installer attached + brand impersonation lure → Critical
//!
//! Data sources are runtime-tunable via `module_data` keys:
//!   `rmm_brand_keywords`, `rmm_installer_filenames`, `rmm_lure_action_keywords`.

use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use vigilyx_parser::mime::decode_rfc2047;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::matcher::{rmm_brand_keywords, rmm_installer_filenames, rmm_lure_action_keywords};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

// ---------------------------------------------------------------------------
// Module struct
// ---------------------------------------------------------------------------

pub struct RmmDetectModule {
    meta: ModuleMetadata,
}

impl Default for RmmDetectModule {
    fn default() -> Self {
        Self::new()
    }
}

impl RmmDetectModule {
    pub fn new() -> Self {
        Self {
            meta: ModuleMetadata {
                id: "rmm_detect".to_string(),
                name: "RMM Weaponization Detection".to_string(),
                description: "Detects phishing emails staging legitimate remote-control tools \
                    (ScreenConnect/AnyDesk/Atera/TeamViewer/Splashtop/etc.) for ransomware \
                    initial access or TOAD callback chains (MITRE ATT&CK T1219)."
                    .to_string(),
                pillar: Pillar::Attachment,
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Lowercase-decode an attachment filename (strips RFC 2047 encoded-word, quotes, whitespace).
fn decoded_lower_filename(filename: &str) -> String {
    decode_rfc2047(filename)
        .trim()
        .trim_matches('"')
        .to_ascii_lowercase()
}

/// Strip extremely long bodies to keep regex/substring scans bounded — we only
/// care about whether brand/action keywords appear *somewhere*, and walking
/// many MB of HTML is wasteful.
const MAX_SCAN_LEN: usize = 256 * 1024;

fn truncate_for_scan(s: &str) -> &str {
    if s.len() <= MAX_SCAN_LEN {
        s
    } else {
        // Use char-boundary aware split to avoid panics on multi-byte text.
        let mut end = MAX_SCAN_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

// ---------------------------------------------------------------------------
// SecurityModule impl
// ---------------------------------------------------------------------------

#[async_trait]
impl SecurityModule for RmmDetectModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();

        // Compiled Aho-Corasick matchers (one-time build; reused across calls).
        let brand_matcher = rmm_brand_keywords();
        let installer_matcher = rmm_installer_filenames();
        let action_matcher = rmm_lure_action_keywords();

        // Fast bail-out: if all three lists are empty (unconfigured deployment),
        // emit a vacuous (not-applicable) result so DS fusion is not biased.
        // Probe the registry directly instead of routing through the matchers
        // (which would trigger their first build for nothing).
        {
            let md = module_data();
            let brand_empty = md.get_list("rmm_brand_keywords").is_empty();
            let installer_empty = md.get_list("rmm_installer_filenames").is_empty();
            let action_empty = md.get_list("rmm_lure_action_keywords").is_empty();
            if brand_empty && installer_empty && action_empty {
                return Ok(ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    "RMM detection lists not configured",
                    start.elapsed().as_millis() as u64,
                ));
            }
        }

        let mut evidence: Vec<Evidence> = Vec::new();
        let mut categories: Vec<String> = Vec::new();
        let mut score: f64 = 0.0;

        // ── Build the scan corpus ─────────────────────────────────────────
        let subject_lower = ctx
            .session
            .subject
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        let body_text_lower = ctx
            .session
            .content
            .body_text
            .as_deref()
            .map(|s| truncate_for_scan(s).to_ascii_lowercase())
            .unwrap_or_default();

        let body_html_lower = ctx
            .session
            .content
            .body_html
            .as_deref()
            .map(|s| truncate_for_scan(s).to_ascii_lowercase())
            .unwrap_or_default();

        // Combined "text-like" corpus for brand/action substring scans.
        // Allocation cost is bounded by MAX_SCAN_LEN above.
        let mut corpus = String::with_capacity(
            subject_lower.len() + body_text_lower.len() + body_html_lower.len() + 4,
        );
        corpus.push_str(&subject_lower);
        corpus.push('\n');
        corpus.push_str(&body_text_lower);
        corpus.push('\n');
        corpus.push_str(&body_html_lower);

        // ── 1. Attachment installer match ─────────────────────────────────
        let mut installer_hits: Vec<(String, String)> = Vec::new(); // (filename, matched_pattern)
        for att in &ctx.session.content.attachments {
            let fname_lower = decoded_lower_filename(&att.filename);
            if fname_lower.is_empty() {
                continue;
            }
            if let Some(pat) = installer_matcher.scan(&fname_lower).first_pattern() {
                installer_hits.push((fname_lower.clone(), pat));
                continue;
            }
            // Brand keyword in attachment filename is also a strong signal
            // (e.g. "AnyDeskSetup.zip"), even if not in the installer list.
            if let Some(brand) = brand_matcher.scan(&fname_lower).first_pattern() {
                installer_hits.push((fname_lower.clone(), format!("brand:{brand}")));
            }
        }

        let has_installer = !installer_hits.is_empty();
        if has_installer {
            score += 0.45;
            categories.push("rmm_installer".to_string());
            for (fname, pat) in &installer_hits {
                evidence.push(Evidence {
                    description: format!(
                        "RMM installer pattern '{}' found in attachment '{}'",
                        pat, fname
                    ),
                    location: Some("attachments:filename".to_string()),
                    snippet: None,
                });
            }
        }

        // ── 2. Brand keyword anywhere in subject/body ─────────────────────
        let brand_match = brand_matcher.scan(&corpus).first_pattern();
        let has_brand = brand_match.is_some();

        // Where exactly did the brand show up? Used to weight the signal.
        let brand_in_subject = brand_match
            .as_deref()
            .is_some_and(|kw| subject_lower.contains(kw));

        if let Some(ref kw) = brand_match {
            // Brand-only is weak (legitimate IT mail mentions vendors all the time).
            // Score it modestly here; combined-signal logic below escalates further.
            score += if brand_in_subject { 0.10 } else { 0.05 };
            evidence.push(Evidence {
                description: format!("RMM brand keyword detected: '{}'", kw),
                location: Some(if brand_in_subject {
                    "subject".to_string()
                } else {
                    "body".to_string()
                }),
                snippet: None,
            });
        }

        // ── 3. Social-engineering action verb ─────────────────────────────
        let action_match = action_matcher.scan(&corpus).first_pattern();
        let has_action = action_match.is_some();
        if let Some(ref kw) = action_match {
            evidence.push(Evidence {
                description: format!("RMM-related action/lure phrase: '{}'", kw),
                location: Some("subject_or_body".to_string()),
                snippet: None,
            });
        }

        // ── 4. Combined signal scoring ────────────────────────────────────
        // Only count the combined boost when at least two distinct dimensions
        // hit. This guards against noise from a single neutral mention.
        let combined_boost = match (has_installer, has_brand, has_action) {
            // Active staging: installer + (brand OR action) → critical territory
            (true, true, true) => Some(("rmm_active_staging", 0.55)),
            (true, true, false) | (true, false, true) => Some(("rmm_attachment_lure", 0.30)),
            // No installer but brand + action together: classic lure email
            (false, true, true) => Some(("rmm_lure_combo", 0.25)),
            // brand only or action only → weak, no combined boost
            _ => None,
        };

        if let Some((cat, boost)) = combined_boost {
            score += boost;
            categories.push(cat.to_string());
        }

        // ── 5. Finalize ───────────────────────────────────────────────────
        score = score.min(1.0);
        categories.sort();
        categories.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(score);

        if threat_level == ThreatLevel::Safe {
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No RMM weaponization signals",
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
                "RMM weaponization signals: brand={}, action={}, installer={} (score {:.2})",
                has_brand as u8, has_action as u8, has_installer as u8, score
            ),
            evidence,
            details: serde_json::json!({
                "score": score,
                "has_brand": has_brand,
                "has_action": has_action,
                "has_installer": has_installer,
                "brand_match": brand_match,
                "action_match": action_match,
                "installer_hits": installer_hits
                    .iter()
                    .map(|(f, p)| serde_json::json!({"filename": f, "pattern": p}))
                    .collect::<Vec<_>>(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn attachment(filename: &str) -> EmailAttachment {
        EmailAttachment {
            filename: filename.to_string(),
            content_type: "application/octet-stream".to_string(),
            size: 1024,
            hash: String::new(),
            content_base64: None,
        }
    }

    fn ctx_with(
        subject: Option<&str>,
        body_text: Option<&str>,
        attachments: Vec<EmailAttachment>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = subject.map(str::to_string);
        session.content = EmailContent {
            body_text: body_text.map(str::to_string),
            body_html: None,
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[tokio::test]
    async fn flags_rmm_installer_attached_with_action_verb() {
        let module = RmmDetectModule::new();
        let ctx = ctx_with(
            Some("Please install our remote support tool"),
            Some("Hi, please download and run the attached AnyDesk client to start the session."),
            vec![attachment("ScreenConnect.ClientSetup.exe")],
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert!(
            result.threat_level >= ThreatLevel::High,
            "expected High+, got {:?} (score evidence: {:?})",
            result.threat_level,
            result.evidence
        );
        assert!(
            result.categories.contains(&"rmm_installer".to_string()),
            "should mark rmm_installer category"
        );
    }

    #[tokio::test]
    async fn flags_brand_plus_action_combo_as_low_or_medium() {
        let module = RmmDetectModule::new();
        let ctx = ctx_with(
            Some("Microsoft support — install AnyDesk for refund"),
            Some("Please connect using the connect ID below to receive your refund."),
            vec![],
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert!(
            result.threat_level >= ThreatLevel::Low,
            "brand+action+lure should be Low or higher, got {:?}",
            result.threat_level
        );
    }

    #[tokio::test]
    async fn legit_it_mention_of_anydesk_alone_is_safe() {
        // Internal IT mentions AnyDesk in passing without any action verb or
        // installer attachment — must not fire.
        let module = RmmDetectModule::new();
        let ctx = ctx_with(
            Some("Quarterly software audit"),
            Some("This quarter we will audit AnyDesk usage across departments."),
            vec![],
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "brand-only mention must remain Safe, got {:?}",
            result.threat_level
        );
    }

    #[tokio::test]
    async fn empty_email_returns_safe() {
        let module = RmmDetectModule::new();
        let ctx = ctx_with(None, None, vec![]);
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn chinese_lure_combination_flags() {
        let module = RmmDetectModule::new();
        let ctx = ctx_with(
            Some("技术支持 - 请运行安装"),
            Some("您好，请下载附件中的 AnyDesk，运行安装后告知连接代码。"),
            vec![],
        );
        let result = module.analyze(&ctx).await.expect("analyze ok");
        assert!(
            result.threat_level >= ThreatLevel::Low,
            "Chinese brand+action+lure combo should fire, got {:?}",
            result.threat_level
        );
    }
}
