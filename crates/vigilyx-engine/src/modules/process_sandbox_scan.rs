//! Deferred, observation-only adapter for the Vigilyx-owned process worker.
//!
//! This module deliberately does not assign a threat score.  It is the
//! runtime seam for the staged process sandbox ADR; the worker must first
//! return bounded observations and a complete coverage state before any
//! scenario-specific promotion can be considered.

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use uuid::Uuid;
use vigilyx_core::models::EmailLinkExtractionSource;

use super::url_sandbox_scan::{collect_candidates, source_name};
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::external::process_sandbox::{
    ProcessSandbox, ProcessSandboxRequest, ProcessSandboxResponse, WorkerResponseStatus,
};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};

pub struct ProcessSandboxScanModule {
    meta: ModuleMetadata,
    sandbox: Option<Arc<ProcessSandbox>>,
    unavailable_reason: Option<String>,
}

impl ProcessSandboxScanModule {
    pub fn new(sandbox: Option<Arc<ProcessSandbox>>, unavailable_reason: Option<String>) -> Self {
        Self {
            meta: ModuleMetadata {
                id: "process_sandbox_scan".to_string(),
                name: "Process URL Sandbox".to_string(),
                description:
                    "Run bounded external-link observations in a Vigilyx-owned isolated worker"
                        .to_string(),
                pillar: Pillar::Link,
                depends_on: vec!["link_scan".to_string(), "landing_page_scan".to_string()],
                timeout_ms: 180_000,
                is_remote: true,
                supports_ai: false,
                cpu_bound: false,
                inline_priority: None,
            },
            sandbox,
            unavailable_reason,
        }
    }
}

fn enabled() -> bool {
    std::env::var("PROCESS_SANDBOX_ENABLED")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn details(
    candidates: &[(String, EmailLinkExtractionSource)],
    responses: &[(String, EmailLinkExtractionSource, ProcessSandboxResponse)],
    failures: &[(String, EmailLinkExtractionSource, String)],
    profile: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "scan_status": if failures.is_empty() { "complete" } else { "partial" },
        "profile": profile,
        "candidate_count": candidates.len(),
        "responses": responses.iter().map(|(url, source, response)| serde_json::json!({
            "url": url,
            "extraction_source": source_name(*source),
            "response": response,
        })).collect::<Vec<_>>(),
        "failures": failures.iter().map(|(url, source, error)| serde_json::json!({
            "url": url,
            "extraction_source": source_name(*source),
            "error": error,
        })).collect::<Vec<_>>(),
    })
}

fn failure_evidence(failures: &[(String, EmailLinkExtractionSource, String)]) -> Vec<Evidence> {
    failures
        .iter()
        .map(|(url, _, error)| Evidence {
            description: format!("Process sandbox did not complete for {url}: {error}"),
            location: Some("external_url".to_string()),
            snippet: None,
        })
        .collect()
}

fn response_is_partial(response: &ProcessSandboxResponse) -> bool {
    response.status == WorkerResponseStatus::Partial
}

#[async_trait]
impl SecurityModule for ProcessSandboxScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, ctx: &SecurityContext) -> bool {
        enabled()
            && !collect_candidates(ctx).is_empty()
            && (self.sandbox.is_some() || self.unavailable_reason.is_some())
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let started = Instant::now();
        let candidates = collect_candidates(ctx);
        if !enabled() || candidates.is_empty() {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "Process sandbox is disabled or has no eligible candidates",
                started.elapsed().as_millis() as u64,
            ));
        }

        let profile = self.sandbox.as_ref().map(|sandbox| sandbox.profile());
        let mut responses = Vec::new();
        let mut failures = Vec::new();
        for (url, source) in &candidates {
            let Some(sandbox) = self.sandbox.as_ref() else {
                failures.push((
                    url.clone(),
                    *source,
                    self.unavailable_reason
                        .clone()
                        .unwrap_or_else(|| "worker is not configured".to_string()),
                ));
                continue;
            };

            let request = ProcessSandboxRequest::offline(Uuid::new_v4().to_string(), url);
            match sandbox.run(&request).await {
                Ok(response) => responses.push((url.clone(), *source, response)),
                Err(error) => failures.push((url.clone(), *source, error.to_string())),
            }
        }

        let has_partial_response = responses
            .iter()
            .any(|(_, _, response)| response_is_partial(response));
        let scan_incomplete = !failures.is_empty() || has_partial_response;
        let mut result = ModuleResult::not_applicable(
            &self.meta.id,
            &self.meta.name,
            self.meta.pillar,
            "Process sandbox returned observation-only external-link results",
            started.elapsed().as_millis() as u64,
        );
        result.details = details(&candidates, &responses, &failures, profile);
        result.evidence = failure_evidence(&failures);
        if scan_incomplete {
            result.threat_level = ThreatLevel::Low;
            result.confidence = 0.10;
            result.categories.push("scan_incomplete".to_string());
            result.bpa = Some(vigilyx_core::security::Bpa::new(0.08, 0.0, 0.92));
            result.summary =
                "Process sandbox inspection is incomplete; observations are not threat evidence"
                    .to_string();
            result.mark_inspection_incomplete(
                "process sandbox did not provide complete bounded coverage",
            );
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn context() -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            links: vec![EmailLink {
                url: "https://login.example.invalid/verify".to_string(),
                text: Some("verify".to_string()),
                suspicious: true,
            }],
            ..Default::default()
        };
        SecurityContext::with_internal_domains(Arc::new(session), Arc::new(HashSet::new()))
    }

    #[test]
    fn disabled_module_does_not_run() {
        let module = ProcessSandboxScanModule::new(None, None);
        assert!(!module.should_run(&context()));
    }
}
