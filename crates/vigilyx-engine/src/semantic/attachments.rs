//! Attachment text as additional semantic sources.
//!
//! Each attachment is analyzed in its own coordinate space with the plain-text
//! relation rules, and its claims are then attributed to the attachment. The
//! pass has its own time budget. Skipped attachments and budget exhaustion are
//! recorded as observations, not coverage gaps: attachment inspection coverage
//! is reported by attach_content.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{SemanticClaim, SemanticMessageContext, SemanticSourcePart};

use crate::modules::attach_content::{
    attribute_attachment_claim, attribute_attachment_context, semantic_attachment_sources,
};

use super::budget::SemanticCpuBudget;
use super::classifier::{TextClassifierInput, classify};
use super::compiled::CompiledSemanticData;
use super::policy::evaluate_semantic_scenarios_with_data;
use super::relations::{
    ExtortionRelation, prepare_semantic_claims_with_header, qualified_extortion_relations_prepared,
};
use super::risk::analyze_risks;
use super::solicitation::{NativeSolicitationFinding, qualified_native_solicitations};
use super::source::SemanticSource;
use super::workflow::analyze_workflows;

/// The attachment pass ends this long after the module started, which leaves
/// room before the module timeout.
pub(super) const SEMANTIC_ATTACHMENT_PHASE_END: Duration = Duration::from_millis(2400);
/// Upper bound on the attachment pass itself.
pub(super) const SEMANTIC_ATTACHMENT_CPU_BUDGET: Duration = Duration::from_millis(1000);

const ATTACHMENT_POLICY: &str = "semantic_attachment_policy_v1";

/// `score` lets attachment relations raise the module result; `shadow` runs
/// the same analysis and records it in details only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AttachmentMode {
    #[default]
    Score,
    Shadow,
}

#[derive(Deserialize)]
struct AttachmentPolicy {
    enabled: bool,
    #[serde(default)]
    mode: AttachmentMode,
}

struct AttachmentPolicyState {
    enabled: bool,
    shadow: bool,
    diagnostic: Option<&'static str>,
}

fn parse_attachment_policy(value: Option<&Value>) -> AttachmentPolicyState {
    let disabled = |diagnostic| AttachmentPolicyState {
        enabled: false,
        shadow: false,
        diagnostic: Some(diagnostic),
    };
    match value.map(|value| serde_json::from_value::<AttachmentPolicy>(value.clone())) {
        Some(Ok(policy)) => AttachmentPolicyState {
            enabled: policy.enabled,
            shadow: policy.mode == AttachmentMode::Shadow,
            diagnostic: None,
        },
        Some(Err(_)) => disabled(
            "semantic attachment policy (semantic_attachment_policy_v1) is malformed; attachment text is not analyzed",
        ),
        None => disabled(
            "semantic attachment policy (semantic_attachment_policy_v1) is missing; attachment text is not analyzed",
        ),
    }
}

/// Attachment analysis is additive, so a missing policy is a diagnostic, not
/// a gap in the body inspection.
fn attachment_policy(data: &CompiledSemanticData) -> Arc<AttachmentPolicyState> {
    data.cached(ATTACHMENT_POLICY, |registry| {
        parse_attachment_policy(registry.get_structured(ATTACHMENT_POLICY))
    })
}

pub(super) fn attachment_policy_diagnostic_with_data(
    data: &CompiledSemanticData,
) -> Option<&'static str> {
    attachment_policy(data).diagnostic
}

#[derive(Default)]
pub(super) struct AttachmentSemantics {
    pub(super) extortion_relations: Vec<ExtortionRelation>,
    pub(super) native_solicitations: Vec<NativeSolicitationFinding>,
    pub(super) risk_findings: Vec<NativeSolicitationFinding>,
    pub(super) workflow_diagnostics: Vec<Value>,
    pub(super) risk_diagnostics: Vec<Value>,
    /// Filenames of attachments that contributed a relation or finding.
    pub(super) contributing_filenames: Vec<String>,
    pub(super) details: Value,
}

/// Header claims keep their own source; only plain-text attachment claims are
/// attributed to the attachment.
fn attribute(claim: &mut SemanticClaim, attachment_hash: &str) {
    if claim.source_part == SemanticSourcePart::PlainText {
        attribute_attachment_claim(claim, attachment_hash);
    }
}

fn attribute_finding(finding: &mut NativeSolicitationFinding, attachment_hash: &str) {
    finding.source_part = SemanticSourcePart::Attachment;
    attribute(&mut finding.claim, attachment_hash);
    for claim in &mut finding.supporting_claims {
        attribute(claim, attachment_hash);
    }
}

fn tag_diagnostics(diagnostics: Vec<Value>, attachment_hash: &str) -> impl Iterator<Item = Value> {
    diagnostics.into_iter().map(move |mut diagnostic| {
        if let Some(object) = diagnostic.as_object_mut() {
            object.insert("attachment_hash".to_string(), json!(attachment_hash));
        }
        diagnostic
    })
}

pub(super) fn analyze_attachments(
    session: &EmailSession,
    subject: Option<&str>,
    header_context: Option<&SemanticMessageContext>,
    data: &CompiledSemanticData,
    deadline: Instant,
) -> AttachmentSemantics {
    let mut output = AttachmentSemantics::default();
    let policy = attachment_policy(data);
    if !policy.enabled {
        output.details = json!({"mode": "disabled", "sources": [], "skipped": []});
        return output;
    }
    let extracted = semantic_attachment_sources(session, deadline);
    let budget = SemanticCpuBudget { deadline };
    let subject = subject.filter(|subject| !subject.trim().is_empty());
    let header_source =
        subject.map(|subject| SemanticSource::new(subject, SemanticSourcePart::Header));
    let mut skipped = extracted
        .skipped
        .iter()
        .map(|(filename, reason)| json!({"filename": filename, "reason": reason}))
        .collect::<Vec<_>>();
    let mut sources = Vec::new();

    for source in extracted.sources {
        if budget.exhausted() {
            skipped.push(json!({"filename": source.filename, "reason": "time_budget"}));
            continue;
        }
        // Like alternate projections, subject facts may complete a relation
        // whose other roles are in the attachment.
        let mut context = source.context.clone();
        if let Some(header) = header_context {
            context.claims.extend(header.claims.iter().cloned());
        }
        let text_source = SemanticSource::new(&source.text, SemanticSourcePart::PlainText);
        let mut analysis_errors = Vec::new();

        let mut relations =
            prepare_semantic_claims_with_header(text_source, header_source, &context, &budget)
                .and_then(|prepared| {
                    qualified_extortion_relations_prepared(&prepared, &budget, data)
                })
                .unwrap_or_else(|reason| {
                    analysis_errors.push(reason);
                    Vec::new()
                });
        let mut solicitations = Vec::new();
        let mut risks = Vec::new();
        let mut workflow_diagnostics = Vec::new();
        let mut risk_diagnostics = Vec::new();
        match qualified_native_solicitations(text_source, &context, &budget, data) {
            Ok(findings) => solicitations.extend(findings),
            Err(reason) => analysis_errors.push(reason),
        }
        match analyze_workflows(text_source, &context, &budget, data) {
            Ok(analysis) => {
                solicitations.extend(analysis.findings);
                workflow_diagnostics.extend(analysis.diagnostics);
            }
            Err(reason) => analysis_errors.push(reason),
        }
        match analyze_risks(text_source, &context, &budget, data) {
            Ok(analysis) => {
                risks.extend(analysis.findings);
                risk_diagnostics.extend(analysis.diagnostics);
            }
            Err(reason) => analysis_errors.push(reason),
        }
        for analyze in [
            super::intent_phishing::analyze,
            super::intent_economic::analyze,
            super::intent_coercion::analyze,
        ] {
            match analyze(text_source, &context, &budget, data) {
                Ok(analysis) => {
                    risks.extend(analysis.findings);
                    risk_diagnostics.extend(analysis.diagnostics);
                }
                Err(reason) => analysis_errors.push(reason),
            }
        }
        let scenarios = evaluate_semantic_scenarios_with_data(&context, data);
        let text_classifier = classify(TextClassifierInput {
            subject,
            body: &source.text,
            source_part: SemanticSourcePart::PlainText,
            context: &context,
            scenarios: &scenarios,
            data,
            deadline,
            export_features: false,
        });

        for relation in &mut relations {
            relation.source_part = SemanticSourcePart::Attachment;
            attribute(&mut relation.threat_claim, &source.hash);
            attribute(&mut relation.payment_claim, &source.hash);
            attribute(&mut relation.consequence_claim, &source.hash);
        }
        for finding in solicitations.iter_mut().chain(risks.iter_mut()) {
            attribute_finding(finding, &source.hash);
        }
        let finding_count = relations.len() + solicitations.len() + risks.len();
        if finding_count > 0 && !policy.shadow {
            output.contributing_filenames.push(source.filename.clone());
        }

        let mut reported_context = source.context;
        attribute_attachment_context(&mut reported_context, &source.hash);
        sources.push(json!({
            "filename": source.filename,
            "attachment_hash": &source.hash,
            "text_bytes": source.text.len(),
            "projection_limited": source.projection_limited,
            "finding_count": finding_count,
            "analysis_errors": analysis_errors,
            "semantic_context": reported_context,
            "text_classifier": text_classifier,
        }));
        output
            .workflow_diagnostics
            .extend(tag_diagnostics(workflow_diagnostics, &source.hash));
        output
            .risk_diagnostics
            .extend(tag_diagnostics(risk_diagnostics, &source.hash));
        // Shadow mode keeps the per-attachment counts above but returns no
        // finding that could raise the module result.
        if !policy.shadow {
            output.extortion_relations.extend(relations);
            output.native_solicitations.extend(solicitations);
            output.risk_findings.extend(risks);
        }
    }

    output.details = json!({
        "mode": if policy.shadow { "shadow" } else { "score" },
        "sources": sources,
        "skipped": skipped,
    });
    output
}
