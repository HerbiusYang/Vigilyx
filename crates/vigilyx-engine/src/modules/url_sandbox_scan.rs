//! Deferred dynamic analysis for high-risk external links.
//!
//! Static URL inspection and the landing-page fetcher deliberately do not
//! execute page JavaScript.  This module is the explicit opt-in bridge to the
//! CAPEv2 browser/VM URL task API.  It is never eligible for the MTA inline
//! pipeline and it does not submit ordinary links: only parser-marked or
//! auth-flow-shaped candidates are considered.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use vigilyx_core::models::EmailLinkExtractionSource;

use super::common::{
    extract_domain_from_url, is_probable_cloud_asset_url, is_probable_opaque_mail_callback_url,
    is_probable_safe_static_asset_url,
};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::sandbox::{SandboxClient, SandboxReport};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::module_data::module_data;

pub(crate) const MAX_CANDIDATE_URLS: usize = 2;
const DEFAULT_URL_ANALYSIS_TIMEOUT_SECS: u32 = 120;

pub struct UrlSandboxScanModule {
    meta: ModuleMetadata,
    client: Option<Arc<SandboxClient>>,
}

impl UrlSandboxScanModule {
    pub fn new(client: Option<Arc<SandboxClient>>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "url_sandbox_scan".to_string(),
                name: "External URL Sandbox".to_string(),
                description: "Submit narrowly selected external links to the isolated CAPEv2 browser/VM for deferred dynamic analysis".to_string(),
                pillar: Pillar::Link,
                depends_on: vec!["link_scan".to_string(), "landing_page_scan".to_string()],
                timeout_ms: 360_000,
                is_remote: true,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            client,
        }
    }
}

fn env_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn analysis_timeout_secs() -> u32 {
    std::env::var("SANDBOX_URL_ANALYSIS_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|value| value.clamp(30, 300))
        .unwrap_or(DEFAULT_URL_ANALYSIS_TIMEOUT_SECS)
}

fn is_trusted_destination(ctx: &SecurityContext, url: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url) else {
        return false;
    };
    ctx.is_internal_domain(&domain)
        || module_data().contains("protected_domains", &domain)
        || crate::modules::link_scan::is_trusted_url_domain(&domain)
        || crate::modules::link_scan::is_well_known_safe_domain(&domain)
}

fn has_auth_flow_shape(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let data = module_data();
    data.get_list("credential_auth_path_segments")
        .iter()
        .chain(data.get_list("oauth_flow_terms").iter())
        .any(|term| lower.contains(term))
}

fn effective_target(url: &str) -> Option<String> {
    let effective = crate::modules::link_scan::unwrap_redirect_target_for_analysis(url)
        .unwrap_or_else(|| url.to_string());
    let parsed = url::Url::parse(&effective).ok()?;
    matches!(parsed.scheme(), "http" | "https").then_some(parsed.to_string())
}

fn is_candidate(ctx: &SecurityContext, url: &str, suspicious: bool) -> bool {
    if is_trusted_destination(ctx, url)
        || is_probable_cloud_asset_url(url)
        || is_probable_opaque_mail_callback_url(url)
        || is_probable_safe_static_asset_url(url)
    {
        return false;
    }
    suspicious || has_auth_flow_shape(url)
}

pub(crate) fn collect_candidates(
    ctx: &SecurityContext,
) -> Vec<(String, EmailLinkExtractionSource)> {
    let mut seen = HashSet::new();
    ctx.analysis_link_observations()
        .into_iter()
        .filter_map(|observation| {
            let target = effective_target(&observation.link.url)?;
            if !is_candidate(ctx, &target, observation.link.suspicious)
                || !seen.insert(target.clone())
            {
                return None;
            }
            Some((target, observation.extraction_source))
        })
        .take(MAX_CANDIDATE_URLS)
        .collect()
}

fn report_threat_level(score: f64) -> ThreatLevel {
    let score = score.clamp(0.0, 10.0);
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

pub(crate) fn source_name(source: EmailLinkExtractionSource) -> &'static str {
    match source {
        EmailLinkExtractionSource::HtmlHref => "html_href",
        EmailLinkExtractionSource::HtmlText => "html_text",
        EmailLinkExtractionSource::PlainText => "plain_text",
        EmailLinkExtractionSource::Qr => "qr",
        EmailLinkExtractionSource::Attachment => "attachment",
        EmailLinkExtractionSource::Unknown => "unknown",
    }
}

fn report_details(
    candidates: &[(String, EmailLinkExtractionSource)],
    reports: &[(String, EmailLinkExtractionSource, SandboxReport)],
    failures: &[(String, EmailLinkExtractionSource, String)],
) -> serde_json::Value {
    serde_json::json!({
        "scan_status": if failures.is_empty() { "complete" } else { "partial" },
        "candidate_count": candidates.len(),
        "reports": reports.iter().map(|(url, source, report)| serde_json::json!({
            "url": url,
            "extraction_source": source_name(*source),
            "report": report,
        })).collect::<Vec<_>>(),
        "failures": failures.iter().map(|(url, source, error)| serde_json::json!({
            "url": url,
            "extraction_source": source_name(*source),
            "error": error,
        })).collect::<Vec<_>>(),
    })
}

#[async_trait]
impl SecurityModule for UrlSandboxScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, ctx: &SecurityContext) -> bool {
        self.client.is_some()
            && env_enabled("SANDBOX_URL_ANALYSIS_ENABLED")
            && !collect_candidates(ctx).is_empty()
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let candidates = collect_candidates(ctx);
        let Some(client) = self.client.as_ref() else {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "CAPE URL sandbox is not configured",
                start.elapsed().as_millis() as u64,
            ));
        };
        if !env_enabled("SANDBOX_URL_ANALYSIS_ENABLED") || candidates.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "External URL sandbox is disabled or has no eligible candidates",
                start.elapsed().as_millis() as u64,
            ));
        }

        let timeout_secs = analysis_timeout_secs();
        let mut reports = Vec::new();
        let mut failures = Vec::new();
        for (url, source) in &candidates {
            match client.analyze_url(url, timeout_secs).await {
                Ok(report) => reports.push((url.clone(), *source, report)),
                Err(error) => failures.push((url.clone(), *source, error.to_string())),
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        if reports.is_empty() {
            let mut result = ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Low,
                confidence: 0.10,
                categories: vec!["scan_incomplete".to_string()],
                summary: format!(
                    "External URL sandbox could not complete {} candidate analysis(es)",
                    candidates.len()
                ),
                evidence: failures
                    .iter()
                    .map(|(url, _, error)| Evidence {
                        description: format!("External URL sandbox failed for {url}: {error}"),
                        location: Some("external_url".to_string()),
                        snippet: None,
                    })
                    .collect(),
                details: report_details(&candidates, &reports, &failures),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92)),
                engine_id: Some("url_analysis".to_string()),
            };
            result.mark_inspection_incomplete("dynamic URL sandbox did not return a report");
            return Ok(result);
        }

        let max_score = reports
            .iter()
            .map(|(_, _, report)| report.score)
            .fold(0.0_f64, f64::max)
            .clamp(0.0, 10.0);
        let threat_level = report_threat_level(max_score);
        let confidence = if max_score >= 8.0 {
            0.95
        } else if max_score >= 6.0 {
            0.85
        } else if max_score >= 4.0 {
            0.75
        } else {
            0.60
        };
        let mut categories = Vec::new();
        if threat_level >= ThreatLevel::Medium {
            categories.push("sandbox_url_malicious".to_string());
        }
        if reports
            .iter()
            .any(|(_, _, report)| !report.network_iocs.is_empty())
        {
            categories.push("sandbox_url_network_observed".to_string());
        }
        let evidence = reports
            .iter()
            .map(|(url, _, report)| Evidence {
                description: format!(
                    "CAPE URL sandbox observed score={:.1}/10, signatures={}, network_iocs={}",
                    report.score,
                    report.signatures.len(),
                    report.network_iocs.len()
                ),
                location: Some("external_url".to_string()),
                snippet: Some(url.clone()),
            })
            .chain(failures.iter().map(|(url, _, error)| Evidence {
                description: format!("External URL sandbox did not complete for {url}: {error}"),
                location: Some("external_url".to_string()),
                snippet: None,
            }))
            .collect();
        let bpa = crate::bpa::Bpa::from_score_confidence(max_score / 10.0, confidence);
        let mut result = ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence,
            categories,
            summary: format!(
                "CAPE URL sandbox analyzed {}/{} external candidate(s), max score={:.1}/10",
                reports.len(),
                candidates.len(),
                max_score
            ),
            evidence,
            details: report_details(&candidates, &reports, &failures),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: Some(bpa),
            engine_id: Some("url_analysis".to_string()),
        };
        if !failures.is_empty() {
            result.mark_inspection_incomplete("one or more dynamic URL sandbox tasks failed");
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn context(link: EmailLink) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            links: vec![link],
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[test]
    fn module_never_runs_without_a_configured_client() {
        let module = UrlSandboxScanModule::new(None);
        let ctx = context(EmailLink {
            url: "https://login.example.invalid/verify".to_string(),
            text: Some("verify".to_string()),
            suspicious: true,
        });
        assert!(!module.should_run(&ctx));
    }

    #[test]
    fn candidate_selection_skips_tracking_and_safe_assets() {
        let tracking = context(EmailLink {
            url: "https://storage.googleapis.com/bucket/pixel.png".to_string(),
            text: None,
            suspicious: true,
        });
        assert!(collect_candidates(&tracking).is_empty());
    }

    #[test]
    fn auth_shaped_external_url_is_a_candidate_when_not_trusted() {
        let ctx = context(EmailLink {
            url: "https://login.example.invalid/verify".to_string(),
            text: Some("review".to_string()),
            suspicious: false,
        });
        assert_eq!(collect_candidates(&ctx).len(), 1);
    }
}
