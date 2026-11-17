//! Semantic engine module: scheduling local analysis and optional AI/OCR work.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use vigilyx_core::security::{SemanticCoverageStatus, SemanticSourcePart};

use crate::ai::nlp::{NLP_BODY_MAX_BYTES, NlpRequest, complete_nlp_request, start_nlp_request};
use crate::ai::remote::{RemoteError, RemoteModuleProxy};
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule};
use crate::modules::common::looks_like_raw_mime_container_text;
use crate::pipeline::context::SecurityContext;

use super::attachments::{
    AttachmentSemantics, SEMANTIC_ATTACHMENT_CPU_BUDGET, SEMANTIC_ATTACHMENT_PHASE_END,
    analyze_attachments, attachment_policy_diagnostic_with_data,
};
use super::budget::{
    SEMANTIC_BODY_MAX_BYTES, SEMANTIC_INSPECTION_LIMITED, SEMANTIC_OCR_CPU_BUDGET,
    SemanticCpuBudget,
};
use super::classifier::{
    TextClassifierInput, classify, text_classifier_policy_diagnostic_with_data,
};
use super::compiled::{CompiledSemanticData, compiled_semantic_data};
use super::context::extract_semantic_context_until;
use super::intent_model::{
    INTENT_MODEL_DETAILS_KEY, IntentModel, complete_intent_request, intent_model_result,
    start_intent_request,
};
use super::language::observe_language;
use super::ocr::{bounded_visual_ocr_request, bounded_visual_ocr_semantics_with_data};
use super::policy::{
    cross_claim_policy_diagnostic_with_data, evaluate_semantic_scenarios_with_data,
    scenario_policy_diagnostic_with_data,
};
use super::projection::{
    SemanticBodyProjection, body_selection_policy_diagnostic_with_data, sanitize_semantic_inputs,
    select_semantic_projection_with_data,
};
use super::relations::{
    prepare_semantic_claims_with_header, qualified_extortion_relations_prepared,
    qualified_nlp_authorities_prepared,
};
use super::result::{
    SemanticAlternativeContext, SemanticResultInput, append_semantic_coverage_reason,
    build_semantic_result, limited_semantic_result,
};
use super::risk::analyze_risks;
use super::solicitation::qualified_native_solicitations;
use super::source::{SemanticSource, sampled_claim_present};
use super::statistics::score_semantics_with_budget;
use super::style::{detect_llm_generated_text_with_budget, llm_style_policy_diagnostic_with_data};
use super::text::floor_char_boundary;
use super::workflow::analyze_workflows;

/// Observation-only policies (scenarios, cross-claim candidates, prose style,
/// body selection) never score. A missing or invalid copy is reported as a
/// human-readable diagnostic, not as an inspection coverage gap that would
/// force coverage-aware MTA disposition of every message.
pub(super) fn semantic_policy_diagnostics(data: &CompiledSemanticData) -> Vec<String> {
    [
        scenario_policy_diagnostic_with_data(data),
        cross_claim_policy_diagnostic_with_data(data),
        llm_style_policy_diagnostic_with_data(data),
        body_selection_policy_diagnostic_with_data(data),
        text_classifier_policy_diagnostic_with_data(data),
        attachment_policy_diagnostic_with_data(data),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .collect()
}

pub struct SemanticScanModule {
    meta: ModuleMetadata,
    /// Remote NLP Service (Python HuggingFace)
    remote: Option<RemoteModuleProxy>,
    /// Offline training only: copy the text classifier feature vector into
    /// the result details so the trainer uses the exact inference features.
    export_text_classifier_features: bool,
    /// Optional in-process intent model. In shadow mode its outcome is only
    /// recorded; in scored mode it replaces the local rule analysis.
    intent: Option<Arc<IntentModel>>,
}

impl SemanticScanModule {
    pub fn new(remote: Option<RemoteModuleProxy>) -> Self {
        let has_nlp = remote.is_some();
        Self {
            meta: ModuleMetadata {
                id: "semantic_scan".to_string(),
                name: "Semantic Analysis".to_string(),
                description: if has_nlp {
                    "Recipient intent and local threat relations with optional NLP analysis"
                        .to_string()
                } else {
                    "Analyze recipient requests, credential disclosure, extortion, and funds-release solicitations".to_string()
                },
                pillar: Pillar::Semantic,
                depends_on: vec![],
                timeout_ms: if has_nlp { 12_000 } else { 3000 },
                is_remote: has_nlp,
                supports_ai: has_nlp,
                // Both configurations perform local parsing and statistics.
                // Remote I/O is awaited from the blocking runtime context.
                cpu_bound: true,
                inline_priority: None,
            },
            remote,
            export_text_classifier_features: false,
            intent: None,
        }
    }

    /// Intent model (`None` keeps it off).
    pub fn with_intent_model(mut self, intent: Option<Arc<IntentModel>>) -> Self {
        self.intent = intent;
        self
    }

    /// Offline trainer hook; production construction never enables export.
    pub fn with_text_classifier_feature_export(mut self) -> Self {
        self.export_text_classifier_features = true;
        self
    }

    /// Scored mode: the intent model alone judges the projected subject and
    /// body. Mail without body text is not judged at all.
    async fn analyze_with_intent_model(
        &self,
        ctx: &SecurityContext,
        intent: &Arc<IntentModel>,
        data: &CompiledSemanticData,
        start: Instant,
    ) -> ModuleResult {
        let projection = select_semantic_projection_with_data(
            ctx.session.subject.as_deref(),
            ctx.session.content.body_text.as_deref(),
            ctx.session.content.body_html.as_deref(),
            data,
        )
        .filter(|projection| !projection.body.trim().is_empty());
        let Some(projection) = projection else {
            return ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No email body text, skipping semantic intent model",
                start.elapsed().as_millis() as u64,
            );
        };
        let request = start_intent_request(
            Some(intent),
            projection.subject.as_deref(),
            &projection.body,
        );
        let outcome = complete_intent_request(request, start).await;
        intent_model_result(&self.meta, outcome, start.elapsed().as_millis() as u64)
    }
}

#[async_trait]
impl SecurityModule for SemanticScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let cpu_budget = SemanticCpuBudget::new();
        let data = compiled_semantic_data();

        // A raw MIME container without a parsed HTML alternative has no
        // reliable semantic body. When HTML is present, the selector below
        // intentionally ignores the raw container and uses sanitized HTML.
        if matches!(
            (
                ctx.session.content.body_text.as_deref(),
                ctx.session.content.body_html.as_deref(),
            ),
            (Some(text), None) if looks_like_raw_mime_container_text(
                &text[..floor_char_boundary(text, SEMANTIC_BODY_MAX_BYTES)]
            )
        ) {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(limited_semantic_result(
                &self.meta,
                "Body appears to be raw MIME container text; semantic inspection is incomplete",
                duration_ms,
            ));
        }

        if let Some(intent) = self.intent.as_ref().filter(|model| model.is_scored()) {
            return Ok(self
                .analyze_with_intent_model(ctx, intent, &data, start)
                .await);
        }

        let projection = if let Some(projection) = select_semantic_projection_with_data(
            ctx.session.subject.as_deref(),
            ctx.session.content.body_text.as_deref(),
            ctx.session.content.body_html.as_deref(),
            &data,
        ) {
            projection
        } else {
            let duration_ms = start.elapsed().as_millis() as u64;
            if ctx
                .session
                .content
                .body_text
                .as_ref()
                .is_some_and(|text| text.len() > SEMANTIC_BODY_MAX_BYTES)
                || ctx
                    .session
                    .content
                    .body_html
                    .as_ref()
                    .is_some_and(|html| html.len() > SEMANTIC_BODY_MAX_BYTES)
            {
                return Ok(limited_semantic_result(
                    &self.meta,
                    "Semantic source projection omitted bytes before a reliable body was available",
                    duration_ms,
                ));
            }
            let cleaned_header = sanitize_semantic_inputs(
                ctx.session
                    .subject
                    .as_deref()
                    .map(|subject| &subject[..floor_char_boundary(subject, 8192)]),
                "",
            )
            .0
            .filter(|header| !header.trim().is_empty());
            let has_attachment_bytes = ctx
                .session
                .content
                .attachments
                .iter()
                .any(|attachment| attachment.content_base64.is_some());
            let capture_complete =
                ctx.session.content.is_complete && !ctx.session.content.truncated;
            if has_attachment_bytes || (capture_complete && cleaned_header.is_some()) {
                // No text body, but attachment text or a completely captured
                // subject: analyze them with an empty body. An incomplete
                // capture still reports its gap through context extraction.
                SemanticBodyProjection::empty(cleaned_header)
            } else if let Some(header) = cleaned_header {
                let mut context = extract_semantic_context_until(
                    &ctx.session,
                    &header,
                    SemanticSourcePart::Header,
                    &data,
                    cpu_budget.deadline,
                );
                let missing_body_reason = "email body or MIME entities were not retained; subject-only facts cannot bind link text or target";
                context.coverage = SemanticCoverageStatus::Incomplete;
                append_semantic_coverage_reason(&mut context.coverage_reason, missing_body_reason);
                let semantic_policy_diagnostics = semantic_policy_diagnostics(&data);
                let semantic_scenarios = evaluate_semantic_scenarios_with_data(&context, &data);
                // Short text is still classified; the outcome is recorded only.
                let text_classifier = classify(TextClassifierInput {
                    subject: Some(header.as_str()),
                    body: "",
                    source_part: SemanticSourcePart::Header,
                    context: &context,
                    scenarios: &semantic_scenarios,
                    data: &data,
                    deadline: cpu_budget.deadline,
                    export_features: self.export_text_classifier_features,
                });
                let context_json = serde_json::to_value(&context).unwrap_or_default();
                let mut result = ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    "Body was not retained; header-only semantic facts are incomplete",
                    duration_ms,
                );
                result
                    .categories
                    .push(SEMANTIC_INSPECTION_LIMITED.to_string());
                result.details = serde_json::json!({
                    "score": 0.0,
                    "semantic_coverage_limited": true,
                    "semantic_coverage_reasons": [context.coverage_reason],
                    "semantic_context": context_json,
                    "semantic_header_context": context,
                    "semantic_fact_coverage": SemanticCoverageStatus::Incomplete,
                    "semantic_scenarios": semantic_scenarios,
                    "semantic_alternative_contexts": [],
                    "semantic_policy_diagnostics": semantic_policy_diagnostics,
                    "semantic_text_classifier": text_classifier,
                });
                return Ok(result);
            } else {
                return Ok(ModuleResult::not_applicable(
                    &self.meta.id,
                    &self.meta.name,
                    self.meta.pillar,
                    if ctx.session.content.body_text.is_none()
                        && ctx.session.content.body_html.is_none()
                    {
                        "No email body, skipping semantic analysis"
                    } else {
                        "Body contains only gateway/notice banner noise, skipping semantic analysis"
                    },
                    duration_ms,
                ));
            }
        };

        let cleaned_subject = projection.subject;
        let body = projection.body;
        let body_source = projection.source;
        let semantic_source_part = projection.source_part;
        let primary_source = SemanticSource::new(&body, semantic_source_part);
        let alternatives = projection.alternatives;
        let statistics_complete = projection.coverage_reasons.is_empty()
            && ctx.session.content.is_complete
            && !ctx.session.content.truncated;
        let projection_coverage_reasons = projection.coverage_reasons;
        let mut semantic_coverage_reasons = projection_coverage_reasons.clone();
        let semantic_policy_diagnostics = semantic_policy_diagnostics(&data);
        if cpu_budget.exhausted() {
            return Ok(limited_semantic_result(
                &self.meta,
                "Semantic projection exceeded its wall-clock budget",
                start.elapsed().as_millis() as u64,
            ));
        }

        // Stage 1 semantic foundation: extract bounded, typed facts for
        // inspection and tests only.  Scenario scoring remains unchanged
        // until a later migration explicitly consumes these claims.
        let mut semantic_context = extract_semantic_context_until(
            &ctx.session,
            &body,
            semantic_source_part,
            &data,
            cpu_budget.deadline,
        );
        if semantic_context.coverage != SemanticCoverageStatus::Complete {
            semantic_coverage_reasons.push(
                semantic_context
                    .coverage_reason
                    .clone()
                    .unwrap_or_else(|| "semantic context observation was incomplete".to_string()),
            );
        }
        // Keep the subject as a separate, source-attributed header projection.
        // Cross-part scenario candidates may refer to it, but body and header
        // offsets are never concatenated or treated as one source span.
        let semantic_header_context = cleaned_subject
            .as_deref()
            .filter(|subject| !subject.trim().is_empty())
            .map(|subject| {
                extract_semantic_context_until(
                    &ctx.session,
                    subject,
                    SemanticSourcePart::Header,
                    &data,
                    cpu_budget.deadline,
                )
            });
        if let Some(header_context) = &semantic_header_context {
            if header_context.coverage != SemanticCoverageStatus::Complete {
                semantic_coverage_reasons.push(
                    header_context
                        .coverage_reason
                        .clone()
                        .unwrap_or_else(|| "semantic header context was incomplete".to_string()),
                );
            }
            semantic_context
                .claims
                .extend(header_context.claims.iter().cloned());
        }
        let mut alternative_contexts = Vec::new();
        for alternate in &alternatives {
            if cpu_budget.exhausted() {
                semantic_coverage_reasons.push(
                    "semantic alternate inspection exceeded its wall-clock budget".to_string(),
                );
                break;
            }
            let mut context = extract_semantic_context_until(
                &ctx.session,
                &alternate.body,
                alternate.source_part,
                &data,
                cpu_budget.deadline,
            );
            if !projection_coverage_reasons.is_empty() {
                context.coverage = SemanticCoverageStatus::Incomplete;
                for reason in &projection_coverage_reasons {
                    append_semantic_coverage_reason(&mut context.coverage_reason, reason);
                }
            }
            if let Some(header_context) = &semantic_header_context {
                context.claims.extend(header_context.claims.iter().cloned());
                if header_context.coverage != SemanticCoverageStatus::Complete {
                    context.coverage = SemanticCoverageStatus::Incomplete;
                    context.coverage_reason = Some(
                        match (
                            context.coverage_reason.take(),
                            header_context.coverage_reason.clone(),
                        ) {
                            (Some(body_reason), Some(header_reason)) => {
                                format!("{body_reason}; {header_reason}")
                            }
                            (Some(body_reason), None) => body_reason,
                            (None, Some(header_reason)) => header_reason,
                            (None, None) => "semantic header context was incomplete".to_string(),
                        },
                    );
                }
            }
            if context.coverage != SemanticCoverageStatus::Complete {
                semantic_coverage_reasons.push(context.coverage_reason.clone().unwrap_or_else(
                    || "semantic alternate context observation was incomplete".to_string(),
                ));
            }
            alternative_contexts.push((alternate, context));
        }
        if !semantic_coverage_reasons.is_empty() {
            semantic_context.coverage = SemanticCoverageStatus::Incomplete;
            semantic_context.coverage_reason = Some(semantic_coverage_reasons.join("; "));
        }
        // Engine B: NLP phishing detection - fire request immediately (async, non-blocking)

        let nlp_configured = self.remote.is_some();
        let nlp_body_original_bytes = body.len();
        let semantic_source_original_bytes = projection.original_body_bytes;
        // RT-011: body length is an intrinsic bounded-inspection gap, not a
        // property of whether the optional AI remote is enabled. Keeping this
        // independent of `nlp_configured` ensures rules-only MTA deployments
        // cannot accept a deep payload as if the whole body had AI coverage.
        let nlp_body_coverage_limited = nlp_body_original_bytes > NLP_BODY_MAX_BYTES;
        let NlpRequest {
            handle: nlp_handle,
            sampled_body: nlp_sampled_body,
            request_status: nlp_request_status,
        } = start_nlp_request(
            self.remote.as_ref(),
            &ctx.session,
            cleaned_subject.as_deref(),
            &body,
        );
        // Shadow-mode intent model: runs alongside local analysis; recorded only.
        let intent_request =
            start_intent_request(self.intent.as_ref(), cleaned_subject.as_deref(), &body);
        let nlp_body_sampled_bytes = nlp_sampled_body.as_ref().map_or(0, String::len);

        // OCR is a separate advisory path. It receives only bounded image
        // bytes resolved from data/CID references; external resources are not
        // fetched here. The result is kept in Ocr-scoped semantic details and
        // does not contribute threat score in this migration.
        let visual_ocr_enabled = std::env::var("AI_VISUAL_OCR_ENABLED")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let (visual_ocr_request, visual_ocr_source_limited) = if visual_ocr_enabled {
            bounded_visual_ocr_request(&ctx.session)
        } else {
            (None, false)
        };
        if visual_ocr_source_limited {
            semantic_coverage_reasons.push(
                "requested visual OCR source HTML exceeded the bounded 512 KiB inspection budget"
                    .to_string(),
            );
        }
        let visual_ocr_requested = visual_ocr_request.is_some();
        let visual_ocr_handle = match (self.remote.clone(), visual_ocr_request) {
            (Some(remote), Some(request)) if remote.is_request_available() => {
                Some(tokio::spawn(async move {
                    match tokio::time::timeout(
                        Duration::from_secs(6),
                        remote.analyze_visual(&request),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => Err(RemoteError::Timeout),
                    }
                }))
            }
            _ => None,
        };

        // Engine A: Rust CJK gibberish detection (runs in parallel with NLP request)

        let (mut statistics_score, mut statistics_evidence, mut semantic_observations) =
            if !statistics_complete {
                (0.0, Vec::new(), Vec::new())
            } else {
                score_semantics_with_budget(&body, &cpu_budget).unwrap_or_else(|| {
                    semantic_coverage_reasons
                        .push("semantic statistics exceeded their wall-clock budget".to_string());
                    (0.0, Vec::new(), Vec::new())
                })
            };
        for (alternate, _) in &alternative_contexts {
            if !statistics_complete {
                break;
            }
            if let Some((alternate_score, alternate_evidence, alternate_observations)) =
                score_semantics_with_budget(&alternate.body, &cpu_budget)
            {
                if alternate_score > statistics_score {
                    statistics_score = alternate_score;
                    statistics_evidence = alternate_evidence;
                }
                semantic_observations.extend(alternate_observations);
            } else {
                semantic_coverage_reasons.push(
                    "semantic alternate statistics exceeded their wall-clock budget".to_string(),
                );
                break;
            }
        }
        // Statistical CJK anomalies retain their spam classification and raw
        // observations. Only admitted native relations and corroborated NLP
        // contribute to the separate malicious scalar.
        let mut score: f64 = 0.0;
        let gibberish_evidence_count = statistics_evidence.len();
        let mut evidence = statistics_evidence.clone();
        let has_repetitive_text_observation = !semantic_observations.is_empty();
        let mut categories: Vec<String> = Vec::new();

        // Style is an observation even when native attack evidence exists.
        // It must not change the malicious BPA of another evidence family.
        let (llm_style_score, llm_hits) =
            detect_llm_generated_text_with_budget(&body, &cpu_budget, &data).unwrap_or_else(|| {
                semantic_coverage_reasons
                    .push("semantic style inspection exceeded its wall-clock budget".to_string());
                (0.0, Vec::new())
            });
        if !llm_hits.is_empty() {
            evidence.push(Evidence {
                description: format!(
                    "AI/LLM-generated prose fingerprint: {}",
                    llm_hits.join("; ")
                ),
                location: Some("body:style".to_string()),
                snippet: Some(body.chars().take(120).collect::<String>()),
            });
        }

        let (is_non_chinese, language_observations) = observe_language(
            ctx,
            &body,
            &cpu_budget,
            &mut evidence,
            &mut semantic_coverage_reasons,
            &data,
        );

        // Native coercion admission uses typed claims and same-source local
        // relations. Mentioned/quoted threats and cryptocurrency nouns remain
        // observations; they cannot raise malicious belief.
        // Only the threat role may come from the subject; its own header text
        // is consulted and its offsets never enter a body envelope.
        let header_source = cleaned_subject
            .as_deref()
            .filter(|subject| !subject.trim().is_empty())
            .map(|subject| SemanticSource::new(subject, SemanticSourcePart::Header));
        let mut extortion_relations = Vec::new();
        let prepared_primary = prepare_semantic_claims_with_header(
            primary_source,
            header_source,
            &semantic_context,
            &cpu_budget,
        );
        match prepared_primary
            .as_ref()
            .map_err(Clone::clone)
            .and_then(|prepared| {
                qualified_extortion_relations_prepared(prepared, &cpu_budget, &data)
            }) {
            Ok(relations) => extortion_relations.extend(relations),
            Err(reason) => semantic_coverage_reasons.push(reason),
        }
        for (alternate, context) in &alternative_contexts {
            let relations = prepare_semantic_claims_with_header(
                SemanticSource::new(&alternate.body, alternate.source_part),
                header_source,
                context,
                &cpu_budget,
            )
            .and_then(|prepared| {
                qualified_extortion_relations_prepared(&prepared, &cpu_budget, &data)
            });
            match relations {
                Ok(relations) => extortion_relations.extend(relations),
                Err(reason) => semantic_coverage_reasons.push(reason),
            }
        }
        // Plain-text and HTML projections of one message describe one fact.
        // The primary projection wins; identical alternates are dropped before
        // evidence and causal findings are built.
        let mut seen_relation_keys = std::collections::HashSet::new();
        extortion_relations
            .retain(|relation| seen_relation_keys.insert(relation.causal_key.clone()));
        let mut native_solicitations = Vec::new();
        let mut workflow_diagnostics = Vec::new();
        let mut risk_findings = Vec::new();
        let mut risk_diagnostics = Vec::new();
        for (source, context) in std::iter::once((primary_source, &semantic_context)).chain(
            alternative_contexts.iter().map(|(alternate, context)| {
                (
                    SemanticSource::new(&alternate.body, alternate.source_part),
                    context,
                )
            }),
        ) {
            match qualified_native_solicitations(source, context, &cpu_budget, &data) {
                Ok(findings) => native_solicitations.extend(findings),
                Err(reason) => semantic_coverage_reasons.push(reason),
            }
            match analyze_workflows(source, context, &cpu_budget, &data) {
                Ok(analysis) => {
                    native_solicitations.extend(analysis.findings);
                    workflow_diagnostics.extend(analysis.diagnostics);
                }
                Err(reason) => semantic_coverage_reasons.push(reason),
            }
            match analyze_risks(source, context, &cpu_budget, &data) {
                Ok(analysis) => {
                    risk_findings.extend(analysis.findings);
                    risk_diagnostics.extend(analysis.diagnostics);
                }
                Err(reason) => semantic_coverage_reasons.push(reason),
            }
            for analyze in [
                super::intent_phishing::analyze,
                super::intent_economic::analyze,
                super::intent_coercion::analyze,
            ] {
                match analyze(source, context, &cpu_budget, &data) {
                    Ok(analysis) => {
                        risk_findings.extend(analysis.findings);
                        risk_diagnostics.extend(analysis.diagnostics);
                    }
                    Err(reason) => semantic_coverage_reasons.push(reason),
                }
            }
        }
        let mut seen_native_solicitations = std::collections::HashSet::new();
        native_solicitations
            .retain(|finding| seen_native_solicitations.insert(finding.causal_key.clone()));
        let mut risk_positions = std::collections::HashMap::<String, usize>::new();
        let mut unique_risks: Vec<super::solicitation::NativeSolicitationFinding> = Vec::new();
        for finding in risk_findings {
            if let Some(&position) = risk_positions.get(&finding.causal_key) {
                if finding.score > unique_risks[position].score {
                    unique_risks[position] = finding;
                }
            } else {
                risk_positions.insert(finding.causal_key.clone(), unique_risks.len());
                unique_risks.push(finding);
            }
        }
        let mut risk_findings = unique_risks;
        // Scenario candidates observe the final primary context. They are
        // evaluated here so the text classifier runs inside the CPU budget,
        // before the optional NLP and OCR waits consume wall-clock time.
        let semantic_scenarios = evaluate_semantic_scenarios_with_data(&semantic_context, &data);
        let text_classifier = classify(TextClassifierInput {
            subject: cleaned_subject.as_deref(),
            body: &body,
            source_part: semantic_source_part,
            context: &semantic_context,
            scenarios: &semantic_scenarios,
            data: &data,
            deadline: cpu_budget.deadline,
            export_features: self.export_text_classifier_features,
        });
        if text_classifier.budget_exhausted() {
            semantic_coverage_reasons
                .push("semantic text classifier exceeded its wall-clock budget".to_string());
        }

        // Attachment text runs after every body analysis so it cannot consume
        // the body's CPU budget. Identical facts share causal keys with body
        // facts and are counted once.
        let attachment_deadline = (start + SEMANTIC_ATTACHMENT_PHASE_END)
            .min(Instant::now() + SEMANTIC_ATTACHMENT_CPU_BUDGET);
        let AttachmentSemantics {
            extortion_relations: attachment_relations,
            native_solicitations: attachment_solicitations,
            risk_findings: attachment_risks,
            workflow_diagnostics: attachment_workflow_diagnostics,
            risk_diagnostics: attachment_risk_diagnostics,
            contributing_filenames: attachment_filenames,
            details: attachment_details,
        } = analyze_attachments(
            &ctx.session,
            cleaned_subject.as_deref(),
            semantic_header_context.as_ref(),
            &data,
            attachment_deadline,
        );
        for relation in attachment_relations {
            if seen_relation_keys.insert(relation.causal_key.clone()) {
                extortion_relations.push(relation);
            }
        }
        let has_native_extortion = !extortion_relations.is_empty();
        for finding in attachment_solicitations {
            if seen_native_solicitations.insert(finding.causal_key.clone()) {
                native_solicitations.push(finding);
            }
        }
        for finding in attachment_risks {
            if let Some(&position) = risk_positions.get(&finding.causal_key) {
                if finding.score > risk_findings[position].score {
                    risk_findings[position] = finding;
                }
            } else {
                risk_positions.insert(finding.causal_key.clone(), risk_findings.len());
                risk_findings.push(finding);
            }
        }
        workflow_diagnostics.extend(attachment_workflow_diagnostics);
        risk_diagnostics.extend(attachment_risk_diagnostics);
        if !attachment_filenames.is_empty() {
            evidence.push(Evidence {
                description: format!(
                    "Semantic relations found in attachment text: {}",
                    attachment_filenames.join(", ")
                ),
                location: Some("attachment:semantic".to_string()),
                snippet: None,
            });
        }

        if has_native_extortion {
            score += 0.60;
            categories.push("sextortion".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Qualified extortion: {} locally connected sender threat, current recipient payment instruction, and coercive consequence relations",
                    extortion_relations.len()
                ),
                location: Some("body:semantic".to_string()),
                snippet: None,
            });
        }

        // P2-4 fix: only push nonsensical_spam when gibberish detection (score_semantics)
        // actually produced evidence. Previously this checked ALL evidence including
        // language mismatch, sextortion etc., causing false positives on normal emails
        // like scanner-generated forwards.
        if gibberish_evidence_count > 0 {
            categories.push("nonsensical_spam".to_string());
        }

        // Await NLP result (Rust analysis already complete, NLP should be done or nearly done)

        let nlp_authorities = if nlp_configured {
            prepared_primary
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|prepared| {
                    qualified_nlp_authorities_prepared(prepared, &cpu_budget, &data)
                })
                .unwrap_or_else(|reason| {
                    semantic_coverage_reasons.push(reason);
                    Vec::new()
                })
        } else {
            Vec::new()
        };
        drop(prepared_primary);
        let has_rule_corroboration = nlp_sampled_body.as_deref().is_some_and(|sampled| {
            nlp_authorities
                .iter()
                .any(|claim| sampled_claim_present(primary_source, sampled, claim))
                || extortion_relations.iter().any(|relation| {
                    relation.source_part == semantic_source_part
                        && sampled_claim_present(primary_source, sampled, &relation.threat_claim)
                        && sampled_claim_present(primary_source, sampled, &relation.payment_claim)
                        && sampled_claim_present(
                            primary_source,
                            sampled,
                            &relation.consequence_claim,
                        )
                })
        });

        let mut visual_ocr_status = if visual_ocr_source_limited {
            "limited"
        } else if visual_ocr_requested {
            "pending"
        } else {
            "not_applicable"
        }
        .to_string();
        let mut visual_ocr_details = serde_json::Value::Null;
        let mut visual_ocr_semantic_context = serde_json::Value::Null;

        let nlp = complete_nlp_request(
            nlp_handle,
            has_rule_corroboration,
            nlp_request_status,
            &mut score,
            &mut categories,
            &mut evidence,
        )
        .await;

        // A native secret request and an NLP judgment of that same request
        // use a maximum, so neither duplicate projections nor a second opinion
        // multiply the evidence. Other benign prose cannot subtract it.
        for finding in &native_solicitations {
            score = score.max(finding.score);
            categories.push(finding.category.clone());
        }
        let risk_drives_score = risk_findings.iter().any(|finding| finding.score > score);
        for finding in &risk_findings {
            score = score.max(finding.score);
            categories.push(finding.category.clone());
        }
        if !risk_findings.is_empty() {
            evidence.push(Evidence {
                description: "Static semantic risk combination: attributed request, operation and related purpose or collection channel".to_string(),
                location: Some("body:semantic_risk_combination".to_string()),
                snippet: None,
            });
        }
        if !native_solicitations.is_empty() {
            evidence.push(Evidence {
                description:
                    "Qualified local solicitation or deception workflow, with source-bound actions and supporting relations"
                        .to_string(),
                location: Some("body:semantic_solicitation".to_string()),
                snippet: None,
            });
        }

        if let Some(handle) = visual_ocr_handle {
            match handle.await {
                Ok(Ok(response)) => {
                    visual_ocr_status = response.status.clone();
                    // I/O latency has its own timeout. All returned sources
                    // share one fresh CPU budget after the response arrives.
                    // OCR text arrives after network I/O; give its local parsing a
                    // short bounded slice instead of a second full module budget.
                    let ocr_cpu_budget = SemanticCpuBudget {
                        deadline: Instant::now() + SEMANTIC_OCR_CPU_BUDGET,
                    };
                    let (details, contexts, coverage_reasons) =
                        bounded_visual_ocr_semantics_with_data(
                            &ctx.session,
                            response,
                            &ocr_cpu_budget,
                            &data,
                        );
                    visual_ocr_details = details;
                    visual_ocr_semantic_context = contexts;
                    semantic_coverage_reasons.extend(coverage_reasons);
                }
                Ok(Err(RemoteError::Timeout)) => visual_ocr_status = "timeout".to_string(),
                Ok(Err(_)) => visual_ocr_status = "error".to_string(),
                Err(_) => visual_ocr_status = "error".to_string(),
            }
        } else if visual_ocr_requested {
            visual_ocr_status = "unavailable".to_string();
        }

        if nlp_configured && !nlp.nlp_used {
            semantic_coverage_reasons.push(format!(
                "configured AI/NLP inspection did not complete ({})",
                nlp.request_status.nlp_status
            ));
        }
        if visual_ocr_requested && visual_ocr_status != "ok" {
            semantic_coverage_reasons.push(format!(
                "requested visual OCR inspection did not complete ({visual_ocr_status})"
            ));
        }

        let mut result = build_semantic_result(SemanticResultInput {
            meta: &self.meta,
            start,
            body: &body,
            body_source,
            semantic_source_part,
            score,
            categories,
            evidence,
            statistics_score,
            statistics_evidence,
            semantic_observations,
            has_repetitive_text_observation,
            gibberish_evidence_count,
            language_observations,
            is_non_chinese,
            llm_style_score,
            llm_hits,
            extortion_relations,
            native_solicitations,
            workflow_diagnostics,
            risk_findings,
            risk_diagnostics,
            risk_drives_score,
            nlp_authorities,
            has_rule_corroboration,
            nlp,
            nlp_sampled_body,
            nlp_configured,
            nlp_body_original_bytes,
            nlp_body_sampled_bytes,
            nlp_body_coverage_limited,
            semantic_source_original_bytes,
            semantic_coverage_reasons,
            semantic_policy_diagnostics,
            data: &data,
            semantic_header_context,
            semantic_scenarios,
            text_classifier,
            semantic_alternative_contexts: alternative_contexts
                .into_iter()
                .map(|(alternate, context)| SemanticAlternativeContext {
                    source_part: alternate.source_part,
                    context,
                })
                .collect(),
            semantic_context,
            visual_ocr_requested,
            visual_ocr_status,
            visual_ocr_details,
            visual_ocr_semantic_context,
        });
        let intent_details = complete_intent_request(intent_request, start)
            .await
            .and_then(|outcome| serde_json::to_value(outcome).ok());
        if let Some(details) = result.details.as_object_mut() {
            details.insert(
                "semantic_attachment_sources".to_string(),
                attachment_details,
            );
            if let Some(intent) = intent_details {
                details.insert(INTENT_MODEL_DETAILS_KEY.to_string(), intent);
            }
        }
        Ok(result)
    }
}
