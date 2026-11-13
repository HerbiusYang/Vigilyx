//! Existing semantic coverage, causal findings, and final module result assembly.

use std::time::Instant;

use chrono::Utc;
use sha2::{Digest, Sha256};
use vigilyx_core::security::{
    SemanticClaim, SemanticMessageContext, SemanticPolarity, SemanticScenarioFinding,
    SemanticScenarioResolution, SemanticSourcePart, SemanticSpeechAct,
};

use crate::ai::nlp::{NLP_TIMEOUT, NlpOutcome, NlpRequestStatus};
use crate::module::{Evidence, ModuleMetadata, ModuleResult, ThreatLevel};

use super::budget::{SEMANTIC_BODY_MAX_BYTES, SEMANTIC_CPU_BUDGET, SEMANTIC_INSPECTION_LIMITED};
use super::classifier::{TEXT_CLASSIFIER_CATEGORY, TEXT_CLASSIFIER_SCORE, TextClassifierOutcome};
use super::compiled::CompiledSemanticData;
use super::context::UNVERIFIED_THREAD_PROVENANCE;
use super::policy::evaluate_semantic_scenarios_with_data;
use super::projection::SemanticBodySource;
use super::relations::ExtortionRelation;
use super::source::{SemanticSource, sampled_claim_present};
use super::text::normalized_lowercase_body;

pub(super) fn limited_semantic_result(
    meta: &ModuleMetadata,
    reason: &str,
    duration_ms: u64,
) -> ModuleResult {
    let mut result =
        ModuleResult::not_applicable(&meta.id, &meta.name, meta.pillar, reason, duration_ms);
    result
        .categories
        .push(SEMANTIC_INSPECTION_LIMITED.to_string());
    result.details = serde_json::json!({
        "semantic_coverage_limited": true,
        "semantic_coverage_reasons": [reason],
    });
    result
}

pub(super) fn append_semantic_coverage_reason(reason: &mut Option<String>, addition: &str) {
    *reason = Some(reason.take().map_or_else(
        || addition.to_string(),
        |existing| format!("{existing}; {addition}"),
    ));
}

pub(super) struct SemanticAlternativeContext {
    pub(super) source_part: SemanticSourcePart,
    pub(super) context: SemanticMessageContext,
}

pub(super) struct SemanticResultInput<'a> {
    pub(super) meta: &'a ModuleMetadata,
    pub(super) start: Instant,
    pub(super) body: &'a str,
    pub(super) body_source: SemanticBodySource,
    pub(super) semantic_source_part: SemanticSourcePart,
    pub(super) score: f64,
    pub(super) categories: Vec<String>,
    pub(super) evidence: Vec<Evidence>,
    pub(super) statistics_score: f64,
    pub(super) statistics_evidence: Vec<Evidence>,
    pub(super) semantic_observations: Vec<Evidence>,
    pub(super) has_repetitive_text_observation: bool,
    pub(super) gibberish_evidence_count: usize,
    pub(super) language_observations: Vec<serde_json::Value>,
    pub(super) is_non_chinese: bool,
    pub(super) llm_style_score: f64,
    pub(super) llm_hits: Vec<&'static str>,
    pub(super) extortion_relations: Vec<ExtortionRelation>,
    pub(super) native_solicitations: Vec<super::solicitation::NativeSolicitationFinding>,
    pub(super) workflow_diagnostics: Vec<serde_json::Value>,
    pub(super) risk_findings: Vec<super::solicitation::NativeSolicitationFinding>,
    pub(super) risk_diagnostics: Vec<serde_json::Value>,
    pub(super) risk_drives_score: bool,
    pub(super) nlp_authorities: Vec<SemanticClaim>,
    pub(super) has_rule_corroboration: bool,
    pub(super) nlp: NlpOutcome,
    pub(super) nlp_sampled_body: Option<String>,
    pub(super) nlp_configured: bool,
    pub(super) nlp_body_original_bytes: usize,
    pub(super) nlp_body_sampled_bytes: usize,
    pub(super) nlp_body_coverage_limited: bool,
    pub(super) semantic_source_original_bytes: usize,
    pub(super) semantic_coverage_reasons: Vec<String>,
    /// Observation-only policy problems; never coverage reasons.
    pub(super) semantic_policy_diagnostics: Vec<String>,
    pub(super) data: &'a CompiledSemanticData,
    pub(super) semantic_header_context: Option<SemanticMessageContext>,
    /// Scenario candidates of `semantic_context`, evaluated within the CPU budget.
    pub(super) semantic_scenarios: Vec<SemanticScenarioFinding>,
    pub(super) text_classifier: TextClassifierOutcome,
    pub(super) semantic_alternative_contexts: Vec<SemanticAlternativeContext>,
    pub(super) semantic_context: SemanticMessageContext,
    pub(super) visual_ocr_requested: bool,
    pub(super) visual_ocr_status: String,
    pub(super) visual_ocr_details: serde_json::Value,
    pub(super) visual_ocr_semantic_context: serde_json::Value,
}

pub(super) fn build_semantic_result(input: SemanticResultInput<'_>) -> ModuleResult {
    let SemanticResultInput {
        meta,
        start,
        body,
        body_source,
        semantic_source_part,
        mut score,
        mut categories,
        mut evidence,
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
        mut semantic_coverage_reasons,
        mut semantic_policy_diagnostics,
        data,
        semantic_header_context,
        semantic_scenarios,
        mut text_classifier,
        semantic_alternative_contexts,
        semantic_context,
        visual_ocr_requested,
        visual_ocr_status,
        visual_ocr_details,
        visual_ocr_semantic_context,
    } = input;
    let NlpOutcome {
        nlp_used,
        nlp_contributed,
        nlp_contribution_score,
        nlp_reported_coverage_limited,
        nlp_details,
        nlp_observed_categories,
        nlp_scored_categories,
        request_status:
            NlpRequestStatus {
                nlp_status,
                nlp_skipped_temporarily,
                nlp_retry_after_secs,
                nlp_status_message,
            },
    } = nlp;

    // Build final result

    // The classifier supplies at most a review-only Low score. It never lowers
    // a native relation and is recorded separately from relation evidence. In
    // shadow mode its outcome is only recorded in details.
    let text_classifier_scores = text_classifier.scores();
    let text_classifier_drives_score = text_classifier_scores && score < TEXT_CLASSIFIER_SCORE;
    if text_classifier_scores {
        score = score.max(TEXT_CLASSIFIER_SCORE);
        categories.push(TEXT_CLASSIFIER_CATEGORY.to_string());
        evidence.push(Evidence {
            description: format!(
                "Local text classifier probability {:.3} reached threshold {:.3}; review required",
                text_classifier.probability.unwrap_or_default(),
                text_classifier.threshold.unwrap_or_default(),
            ),
            location: Some("body:semantic_text_classifier".to_string()),
            snippet: None,
        });
    }
    let text_classifier_features = text_classifier.exported.take();

    if has_repetitive_text_observation {
        categories.push("repetitive_template_text".to_string());
        evidence.extend(semantic_observations);
    }

    let semantic_ai_coverage_limited = nlp_body_coverage_limited || nlp_reported_coverage_limited;
    if semantic_ai_coverage_limited {
        categories.push("semantic_ai_inspection_limited".to_string());
        let coverage_description = if nlp_body_sampled_bytes == 0 {
            format!(
                "AI/NLP did not receive the {}-byte body; coverage-aware disposition is required",
                nlp_body_original_bytes,
            )
        } else {
            format!(
                "AI/NLP inspected a distributed {}-byte view of a {}-byte body; omitted bytes require coverage-aware disposition",
                nlp_body_sampled_bytes, nlp_body_original_bytes,
            )
        };
        evidence.push(Evidence {
            description: coverage_description,
            location: Some("body:nlp_coverage".to_string()),
            snippet: None,
        });
    }

    semantic_coverage_reasons.sort();
    semantic_coverage_reasons.dedup();
    semantic_policy_diagnostics.sort();
    semantic_policy_diagnostics.dedup();
    let semantic_coverage_limited = !semantic_coverage_reasons.is_empty();
    if semantic_coverage_limited {
        categories.push(SEMANTIC_INSPECTION_LIMITED.to_string());
        evidence.push(Evidence {
            description: format!(
                "Semantic inspection incomplete: {}",
                semantic_coverage_reasons.join("; ")
            ),
            location: Some("body:semantic_coverage".to_string()),
            snippet: None,
        });
    }

    score = score.min(1.0);
    categories.sort();
    categories.dedup();
    // Relation keys hash the normalized claim texts, not projection offsets,
    // so plain-text and HTML projections of one relation share one key.
    let mut causal_keys = std::collections::HashSet::new();
    let mut causal_findings = extortion_relations
        .iter()
        .filter(|relation| causal_keys.insert(relation.causal_key.clone()))
        .map(|relation| {
            let mut derived_categories = vec!["sextortion"];
            if nlp_authorities.is_empty() {
                derived_categories.extend(nlp_scored_categories.iter().map(String::as_str));
            }
            serde_json::json!({ "causal_key": relation.causal_key, "categories": derived_categories })
        })
        .collect::<Vec<_>>();
    for finding in &native_solicitations {
        if causal_keys.insert(finding.causal_key.clone()) {
            causal_findings.push(serde_json::json!({
                "causal_key": finding.causal_key, "categories": [finding.category],
            }));
        }
    }
    for finding in &risk_findings {
        if causal_keys.insert(finding.causal_key.clone()) {
            causal_findings.push(serde_json::json!({
                "causal_key": finding.causal_key, "categories": [finding.category],
                "evidence_tier": "risk_combination",
            }));
        }
    }
    if !nlp_scored_categories.is_empty() {
        let source = SemanticSource::new(body, semantic_source_part);
        for authority in &nlp_authorities {
            if nlp_sampled_body
                .as_deref()
                .is_some_and(|sampled| sampled_claim_present(source, sampled, authority))
            {
                let key_input = source.claim_text(authority).map_or_else(
                    || authority.causal_key.clone(),
                    |text| {
                        format!(
                            "nlp_authority_v2\u{1f}{}",
                            normalized_lowercase_body(text)
                                .split_whitespace()
                                .collect::<Vec<_>>()
                                .join(" ")
                        )
                    },
                );
                let causal_key = format!(
                    "body_relation:{}",
                    hex::encode(Sha256::digest(key_input.as_bytes()))
                );
                if causal_keys.insert(causal_key.clone()) {
                    causal_findings.push(serde_json::json!({
                        "causal_key": causal_key, "categories": nlp_scored_categories,
                    }));
                }
            }
        }
    }

    // Serialize once, after local inspection and optional I/O have finished.
    // Per-projection fact coverage stays separate from module-wide I/O gaps.
    // A reply/forward layout without envelope thread evidence (no
    // In-Reply-To/References, no Re:/Fw: subject) that still asks the
    // recipient to act, or carries a link, is a fake-thread observation.
    let unverified_thread_actions = std::iter::once(&semantic_context)
        .chain(
            semantic_alternative_contexts
                .iter()
                .map(|alternate| &alternate.context),
        )
        .flat_map(|context| context.claims.iter())
        .filter(|claim| {
            claim
                .provenance
                .iter()
                .any(|value| value == UNVERIFIED_THREAD_PROVENANCE)
                && (!claim.link_ids.is_empty()
                    || (claim.polarity == SemanticPolarity::Action
                        && matches!(
                            claim.speech_act,
                            SemanticSpeechAct::Request | SemanticSpeechAct::Instruction
                        )))
        })
        .count();
    let risk_combination_only = !risk_findings.is_empty()
        && native_solicitations.is_empty()
        && extortion_relations.is_empty()
        && !nlp_contributed;
    let semantic_risk_review_required = !risk_findings.is_empty();
    let semantic_review_required = semantic_risk_review_required
        || text_classifier_scores
        || unverified_thread_actions > 0
        || std::iter::once(&semantic_context)
            .chain(semantic_header_context.iter())
            .chain(
                semantic_alternative_contexts
                    .iter()
                    .map(|alternate| &alternate.context),
            )
            .any(|context| {
                context.claims.iter().any(|claim| {
                    (!claim.link_ids.is_empty() && !claim.counter_context_ids.is_empty())
                        || claim.provenance.iter().any(|value| {
                            value == "semantic_report_link_requires_review_v1"
                                || value == "semantic_quoted_link_requires_review_v1"
                        })
                })
            });
    let mut semantic_scenarios_observed = semantic_scenarios
        .iter()
        .any(|finding| finding.resolution != SemanticScenarioResolution::Countered);
    let semantic_alternative_contexts = semantic_alternative_contexts
        .into_iter()
        .map(|alternate| {
            let scenarios = evaluate_semantic_scenarios_with_data(&alternate.context, data);
            semantic_scenarios_observed |= scenarios
                .iter()
                .any(|finding| finding.resolution != SemanticScenarioResolution::Countered);
            serde_json::json!({
                "source_part": alternate.source_part,
                "semantic_context": alternate.context,
                "semantic_scenarios": scenarios,
            })
        })
        .collect::<Vec<_>>();
    // Make the boundary between extraction, observation and scored proof
    // explicit. A recognized request is not itself an admitted risk relation.
    let primary_context_request_count = semantic_context
        .claims
        .iter()
        .filter(|claim| super::is_current_recipient_action(claim))
        .count();
    let native_relation_count = extortion_relations.len() + native_solicitations.len();
    let semantic_scoring_decision = serde_json::json!({
        "primary_context_request_count": primary_context_request_count,
        "scenario_observed": semantic_scenarios_observed,
        "native_relation_count": native_relation_count,
        "risk_combination_count": risk_findings.len(),
        "risk_drives_score": risk_drives_score,
        "text_classifier_fired": text_classifier.fired,
        "text_classifier_shadow": text_classifier.shadow,
        "text_classifier_drives_score": text_classifier_drives_score,
        "nlp_contributed": nlp_contributed,
        "disposition": if text_classifier_drives_score {
            "scored_text_classifier"
        } else if risk_drives_score {
            "scored_risk_combination"
        } else if native_relation_count > 0 || nlp_contributed {
            "scored_relation"
        } else if !risk_findings.is_empty() {
            "scored_risk_combination"
        } else if semantic_coverage_limited {
            "inspection_incomplete"
        } else if semantic_scenarios_observed || primary_context_request_count > 0 {
            "request_or_scenario_without_admitted_relation"
        } else {
            "no_local_risk_relation_found"
        },
    });
    // Keep each JSON macro bounded; assembling the same object in two parts
    // avoids the default macro recursion limit as observation fields grow.
    let mut details = serde_json::json!({
        "score": score,
        "semantic_statistics_observation": {"raw_score": statistics_score,
            "evidence": statistics_evidence, "disposition": "classification_only"},
        "nlp_configured": nlp_configured,
        "nlp_enabled": nlp_used,
        "nlp_used": nlp_used,
        "nlp_contributed": nlp_contributed,
        "nlp_contribution_score": nlp_contribution_score,
        "nlp_status": nlp_status,
        "nlp_status_message": nlp_status_message,
        "nlp_skipped_temporarily": nlp_skipped_temporarily,
        "nlp_retry_after_secs": nlp_retry_after_secs,
        "nlp_timeout_secs": NLP_TIMEOUT.as_secs(),
        "nlp_body_original_bytes": nlp_body_original_bytes,
        "nlp_body_sampled_bytes": nlp_body_sampled_bytes,
        "nlp_body_coverage_limited": nlp_body_coverage_limited,
        "nlp_reported_coverage_limited": nlp_reported_coverage_limited,
        "semantic_ai_coverage_limited": semantic_ai_coverage_limited,
        "semantic_body_source": body_source.as_str(),
        "semantic_source_original_bytes": semantic_source_original_bytes,
        "semantic_cpu_budget_ms": SEMANTIC_CPU_BUDGET.as_millis(),
        "semantic_projection_max_bytes": SEMANTIC_BODY_MAX_BYTES,
        "semantic_coverage_limited": semantic_coverage_limited,
        "semantic_coverage_reasons": semantic_coverage_reasons,
    });
    let serde_json::Value::Object(context_details) = serde_json::json!({
        "semantic_policy_diagnostics": semantic_policy_diagnostics,
        "semantic_header_context": semantic_header_context,
        "semantic_alternative_contexts": semantic_alternative_contexts,
        "qualified_extortion_relations": extortion_relations,
        "semantic_native_findings": native_solicitations,
        "semantic_workflow_diagnostics": workflow_diagnostics,
        "semantic_scoring_decision": semantic_scoring_decision,
        "semantic_risk_findings": risk_findings,
        "semantic_risk_diagnostics": risk_diagnostics,
        "semantic_risk_review_required": semantic_risk_review_required,
        "causal_findings": causal_findings,
        "nlp_details": nlp_details,
        "nlp_observed_categories": nlp_observed_categories,
        "qualified_nlp_authorities": nlp_authorities,
        "nlp_semantic_provenance": if !nlp_configured { "not_applicable" }
            else if has_rule_corroboration { "native_current_recipient_relation" } else { "unknown" },
        "visual_ocr_requested": visual_ocr_requested,
        "visual_ocr_status": visual_ocr_status,
        "visual_ocr_details": visual_ocr_details,
        "visual_ocr_semantic_context": visual_ocr_semantic_context,
        "analysis_type": if nlp_contributed {
            "rules_plus_nlp_corroboration"
        } else if nlp_used {
            "rules_primary_nlp_observed"
        } else {
            "rules_only"
        },
        "language_observations": language_observations,
        "llm_style_observation": {"style_score": llm_style_score,
            "hits": llm_hits, "disposition": "context_only"},
        "semantic_context": semantic_context,
        "semantic_scenarios": semantic_scenarios,
        "semantic_review_required": semantic_review_required,
        "semantic_unverified_thread_actions": unverified_thread_actions,
        "semantic_fact_coverage": semantic_context.coverage,
    }) else {
        unreachable!("semantic context details are an object");
    };
    details
        .as_object_mut()
        .expect("semantic details object")
        .extend(context_details);
    details["semantic_text_classifier"] =
        serde_json::to_value(&text_classifier).unwrap_or_default();
    if let Some(features) = text_classifier_features {
        details["semantic_text_classifier_features"] = serde_json::json!(features);
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let threat_level = ThreatLevel::from_score(score);

    if threat_level == ThreatLevel::Safe {
        let safe_categories = categories
            .iter()
            .filter(|category| {
                matches!(
                    category.as_str(),
                    "semantic_ai_inspection_limited"
                        | SEMANTIC_INSPECTION_LIMITED
                        | "repetitive_template_text"
                        | "transactional_notice"
                        | "nlp_spam"
                        | "nonsensical_spam"
                        | "llm_injection_suspected"
                )
            })
            .cloned()
            .collect();
        // Only an empty, complete and review-free analysis may claim normal
        // semantics. Observed scenarios or review-required relations are not
        // evidence of safety: they carry no belief either way.
        let observation_only =
            semantic_coverage_limited || semantic_review_required || semantic_scenarios_observed;
        let summary = if semantic_coverage_limited {
            "Semantic inspection incomplete; result reflects bounded inspected content only"
                .to_string()
        } else if semantic_review_required {
            "Semantic relation requires review; no scoring relation admitted".to_string()
        } else if semantic_scenarios_observed {
            "Semantic scenarios observed; no scoring relation admitted".to_string()
        } else if nlp_contributed {
            "Rule engine + corroborated NLP analysis: email body semantics normal".to_string()
        } else if nlp_used {
            "Rule engine analysis completed; advisory NLP signal did not affect scoring".to_string()
        } else if nlp_status == "timeout" {
            format!(
                "Rule engine analysis completed after NLP timeout ({}s)",
                NLP_TIMEOUT.as_secs()
            )
        } else if nlp_skipped_temporarily {
            if let Some(retry_after_secs) = nlp_retry_after_secs {
                format!(
                    "Rule engine analysis completed while NLP service cooldown was active (retry after ~{}s)",
                    retry_after_secs
                )
            } else {
                "Rule engine analysis completed while NLP service cooldown was active".to_string()
            }
        } else if nlp_status == "error" {
            "Rule engine analysis completed because AI/NLP request failed".to_string()
        } else if has_repetitive_text_observation {
            "Email body semantics normal; repetitive template structure recorded as a non-threat observation"
                .to_string()
        } else if gibberish_evidence_count > 0 {
            "CJK statistical anomalies recorded as spam classification; no actionable semantic threat admitted"
                .to_string()
        } else if nlp_status == "disabled" {
            "Rule engine analysis completed (AI/NLP not configured)".to_string()
        } else if is_non_chinese {
            "Pure foreign-language email, below threat threshold (NLP service not enabled)"
                .to_string()
        } else {
            "Email body semantics normal, no gibberish or rare character anomalies found"
                .to_string()
        };

        return ModuleResult {
            module_id: meta.id.clone(),
            module_name: meta.name.clone(),
            pillar: meta.pillar,
            threat_level: ThreatLevel::Safe,
            confidence: if observation_only {
                0.0
            } else if nlp_contributed {
                0.62
            } else {
                0.70
            },
            categories: safe_categories,
            summary,
            evidence,
            details,
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: observation_only.then(crate::module::Bpa::vacuous),
            engine_id: None,
        };
    }

    // NLP corroboration never lowers native confidence. Incomplete coverage
    // caps it: the admitted relation stands, but omitted bytes are unknown.
    let confidence: f64 = if semantic_coverage_limited {
        0.50
    } else if risk_drives_score || text_classifier_drives_score {
        0.55
    } else {
        0.80
    };

    let summary = if text_classifier_drives_score {
        format!(
            "Local text classifier requires review (score {score:.2}); no native relation admitted"
        )
    } else if risk_combination_only {
        format!(
            "Static semantic risk combination requires review (score {score:.2}); no complete native relation admitted"
        )
    } else if risk_drives_score {
        format!(
            "Static semantic risk combination raises the score and requires review (score {score:.2}); native relations are recorded separately"
        )
    } else if nlp_contributed {
        format!(
            "Rule engine + corroborated NLP detected threat (score {:.2}, {} evidence items)",
            score,
            evidence.len()
        )
    } else if nlp_used {
        format!(
            "Rule engine detected threat (score {:.2}); advisory NLP signal did not raise the score",
            score
        )
    } else if nlp_status == "timeout" {
        format!(
            "Semantic anomaly detected (score {:.2}); NLP timed out after {}s and rule-based detection continued",
            score,
            NLP_TIMEOUT.as_secs()
        )
    } else if nlp_status == "disabled" {
        format!(
            "Semantic anomaly detected (score {:.2}) using rule-based analysis only (AI/NLP not configured)",
            score
        )
    } else if nlp_status == "error" {
        format!(
            "Semantic anomaly detected (score {:.2}) after AI/NLP request failure; rule-based detection continued",
            score
        )
    } else if nlp_skipped_temporarily {
        if let Some(retry_after_secs) = nlp_retry_after_secs {
            format!(
                "Semantic anomaly detected (score {:.2}) while AI/NLP service cooldown was active (~{}s retry)",
                score, retry_after_secs
            )
        } else {
            format!(
                "Semantic anomaly detected (score {:.2}) while AI/NLP service cooldown was active",
                score
            )
        }
    } else {
        format!(
            "Semantic anomaly detected (score {:.2}), found {} anomalous evidence items",
            score,
            evidence.len()
        )
    };

    ModuleResult {
        module_id: meta.id.clone(),
        module_name: meta.name.clone(),
        pillar: meta.pillar,
        threat_level,
        confidence,
        categories,
        summary,
        evidence,
        details,
        duration_ms,
        analyzed_at: Utc::now(),
        bpa: None,
        engine_id: None,
    }
}
