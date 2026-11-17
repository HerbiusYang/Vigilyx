//! Authoritative one-sided, artifact-deduplicated D-S V2 fusion.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{
    Bpa, DsLearningDiagnostics, DsLearningEvidence, EngineBpaDetail, EpistemicState, FusionDetails,
    FusionModelResult, ModuleResult, RiskConstraintConflict, RiskConstraintTrace, SecurityVerdict,
    ThreatLevel,
};

use crate::config::VerdictConfig;

const MODEL_NAME: &str = "clustered_ds_v2";
const MODEL_VERSION: u32 = 5;
const ACTIVE_SIGNAL_THRESHOLD: f64 = 0.01;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum V2Cluster {
    InheritedGatewayPrior,
    DeliveryIntegrity,
    SenderIdentityAuthenticity,
    LinkAndHtmlDeception,
    PayloadMalware,
    ExternalReputationIoc,
    SocialEngineeringIntent,
    BusinessSensitivity,
}

impl V2Cluster {
    const fn label(self) -> &'static str {
        match self {
            Self::InheritedGatewayPrior => "inherited_gateway_prior",
            Self::DeliveryIntegrity => "delivery_integrity",
            Self::SenderIdentityAuthenticity => "sender_identity_authenticity",
            Self::LinkAndHtmlDeception => "link_and_html_deception",
            Self::PayloadMalware => "payload_malware",
            Self::ExternalReputationIoc => "external_reputation_ioc",
            Self::SocialEngineeringIntent => "social_engineering_intent",
            Self::BusinessSensitivity => "business_sensitivity",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::InheritedGatewayPrior => "Inherited Gateway Prior",
            Self::DeliveryIntegrity => "Delivery Integrity",
            Self::SenderIdentityAuthenticity => "Sender Identity Authenticity",
            Self::LinkAndHtmlDeception => "Link and HTML Deception",
            Self::PayloadMalware => "Payload Malware",
            Self::ExternalReputationIoc => "External Reputation and IOC",
            Self::SocialEngineeringIntent => "Social Engineering Intent",
            Self::BusinessSensitivity => "Business Sensitivity",
        }
    }

    const fn reliability_scale(self) -> f64 {
        match self {
            Self::InheritedGatewayPrior => 0.45,
            Self::DeliveryIntegrity => 0.55,
            Self::SenderIdentityAuthenticity => 0.82,
            Self::LinkAndHtmlDeception => 0.86,
            Self::PayloadMalware => 0.92,
            Self::ExternalReputationIoc => 0.72,
            Self::SocialEngineeringIntent => 0.76,
            Self::BusinessSensitivity => 0.50,
        }
    }
}

#[derive(Debug, Clone)]
struct ObservationAccumulator {
    cluster: V2Cluster,
    strength: f64,
    reliability: f64,
    modules: BTreeSet<String>,
    factors: BTreeSet<String>,
    confirmed_anchor_mass: f64,
}

#[derive(Debug, Default)]
struct ArtifactAccumulator {
    fallback: bool,
    principles: BTreeMap<String, ObservationAccumulator>,
}

#[derive(Debug)]
struct ArtifactEvidence {
    key: String,
    cluster: V2Cluster,
    malicious_mass: f64,
    modules: BTreeSet<String>,
    factors: BTreeSet<String>,
    fallback: bool,
    confirmed_anchor_mass: f64,
}

#[derive(Debug, Clone)]
struct IntervalConstraint {
    id: String,
    lower: f64,
    upper: f64,
    basis: Vec<String>,
}

#[derive(Debug)]
struct ConstraintEvaluation {
    risk: f64,
    traces: Vec<RiskConstraintTrace>,
    conflict: Option<RiskConstraintConflict>,
}

#[derive(Deserialize)]
struct EvidenceProfile {
    cluster: V2Cluster,
    strength_scale: f64,
}

fn evidence_profile(module: &str, category: &str) -> Option<EvidenceProfile> {
    static COMPILED: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let registry = crate::module_data::module_data();
    let parse = |value: &serde_json::Value| {
        serde_json::from_value::<EvidenceProfile>(value.get(module)?.get(category)?.clone())
            .ok()
            .filter(|profile| (0.0..=1.0).contains(&profile.strength_scale))
    };
    registry
        .get_structured("ds_v2_evidence_profiles")
        .and_then(parse)
        .or_else(|| {
            let profiles = COMPILED.get_or_init(|| {
                serde_json::from_str::<serde_json::Value>(
                    vigilyx_db::security::embedded_module_data_seed(),
                )
                .ok()
                .and_then(|seed| {
                    seed.get("lists")?
                        .get("ds_v2_evidence_profiles")?
                        .get("items")
                        .cloned()
                })
                .unwrap_or_default()
            });
            parse(profiles)
        })
}

pub(super) fn evaluate_model(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> FusionModelResult {
    let (artifacts, learning_evidence) = collect_artifacts_and_inputs(session, results, config);
    let artifact_count = artifacts.len() as u32;
    let fallback_artifact_count = artifacts
        .iter()
        .filter(|artifact| artifact.fallback)
        .count() as u32;

    let mut by_cluster: BTreeMap<V2Cluster, Vec<&ArtifactEvidence>> = BTreeMap::new();
    for artifact in &artifacts {
        by_cluster
            .entry(artifact.cluster)
            .or_default()
            .push(artifact);
    }

    let mut source_bpas = Vec::new();
    let mut source_details = Vec::new();
    for (cluster, cluster_artifacts) in by_cluster {
        let malicious_mass = 1.0
            - cluster_artifacts.iter().fold(1.0, |remaining, artifact| {
                remaining * (1.0 - artifact.malicious_mass)
            });
        // Admission already applies the minimum strength to original items.
        // A dependency correction can leave a smaller, still necessary residual.
        if malicious_mass <= 0.0 {
            continue;
        }
        let bpa = malicious_bpa(malicious_mass, 1.0);
        source_bpas.push(bpa);

        let mut modules = BTreeSet::new();
        let mut factors = BTreeSet::new();
        for artifact in cluster_artifacts {
            modules.extend(artifact.modules.iter().cloned());
            factors.insert(format!("artifact:{}", artifact.key));
            factors.extend(artifact.factors.iter().cloned());
        }
        let key_factors = factors
            .iter()
            .filter(|factor| factor.starts_with("unbound_"))
            .chain(
                factors
                    .iter()
                    .filter(|factor| !factor.starts_with("unbound_")),
            )
            .take(8)
            .cloned()
            .collect();
        source_details.push(EngineBpaDetail {
            engine_id: cluster.label().to_string(),
            engine_name: cluster.display_name().to_string(),
            bpa,
            modules: modules.into_iter().collect(),
            key_factors,
        });
    }

    // This frame is {email threat, no email threat}. Domain authorization
    // and communication history concern identity, not message harmlessness.
    // Preserve those facts in their module results; they cannot supply a
    // global Normal BPA against payload, target, or social-engineering evidence.

    let (mut fused_bpa, mut k_conflict) = combine_once_conflict_to_uncertainty(&source_bpas);
    // One immutable state snapshot per email: a reload cannot mix revisions.
    let learning_state = crate::ds_learning::runtime_state();
    let active_prediction = learning_state
        .active
        .as_ref()
        .and_then(|parameters| crate::ds_learning::predict(&learning_evidence, parameters).ok());
    let candidate_prediction = learning_state
        .candidate
        .as_ref()
        .and_then(|parameters| crate::ds_learning::predict(&learning_evidence, parameters).ok());
    if let Some(prediction) = &active_prediction {
        fused_bpa = prediction.bpa;
        k_conflict = 0.0;
        source_details = vec![EngineBpaDetail {
            engine_id: "learned_dependency_groups".into(),
            engine_name: "Learned D-S dependency groups".into(),
            bpa: prediction.bpa,
            modules: learning_evidence
                .iter()
                .map(|i| i.source_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            key_factors: vec![format!(
                "dependency_groups:{}",
                prediction.dependency_groups
            )],
        }];
    }
    let risk_base = fused_bpa.b;
    let decision_probability = active_prediction
        .as_ref()
        // A learned prior/calibration intercept is a probability projection,
        // never standalone malicious evidence. Keep vacuous mail unpromoted.
        .filter(|p| p.bpa.b > 0.0)
        .map(|p| p.calibrated.unwrap_or(p.probability))
        .unwrap_or(risk_base);

    let mut constraints = vec![IntervalConstraint {
        id: "bounded_probability".to_string(),
        lower: 0.0,
        upper: 1.0,
        basis: vec!["probability_frame".to_string()],
    }];
    let mut anchor_basis = artifacts
        .iter()
        .filter(|artifact| artifact.confirmed_anchor_mass > 0.0)
        .map(|artifact| artifact.key.clone())
        .collect::<Vec<_>>();
    anchor_basis.sort();
    anchor_basis.dedup();
    let anchor_floor = artifacts
        .iter()
        .map(|artifact| artifact.confirmed_anchor_mass)
        .fold(0.0, f64::max);
    if anchor_floor > 0.0 {
        constraints.push(IntervalConstraint {
            id: "confirmed_malicious_anchor".to_string(),
            lower: anchor_floor,
            upper: 1.0,
            basis: anchor_basis,
        });
    }

    let constrained = evaluate_constraints(decision_probability, &constraints);
    let epistemic_state = classify_epistemic_state(fused_bpa, k_conflict);

    FusionModelResult {
        model: MODEL_NAME.to_string(),
        model_version: MODEL_VERSION,
        fused_bpa,
        k_conflict,
        risk_base,
        risk_constrained: constrained.risk,
        epistemic_state,
        source_details,
        active_constraints: constrained.traces,
        constraint_conflict: constrained.conflict,
        artifact_count,
        fallback_artifact_count,
        learning_model: Some(DsLearningDiagnostics {
            status: if active_prediction.is_some() {
                "validated_active"
            } else {
                "bootstrap"
            }
            .into(),
            parameter_version: learning_state
                .active
                .as_ref()
                .map(|p| p.parameter_version.clone()),
            parameter_sha256: learning_state
                .active
                .as_ref()
                .map(crate::ds_learning::parameter_sha256),
            learned_items: active_prediction.as_ref().map_or(0, |p| p.learned_items),
            fallback_items: active_prediction
                .as_ref()
                .map_or(learning_evidence.len() as u32, |p| p.fallback_items),
            dependency_groups: active_prediction
                .as_ref()
                .map_or(artifact_count, |p| p.dependency_groups),
            projected_probability: active_prediction.as_ref().map(|p| p.probability),
            calibrated_probability: active_prediction.as_ref().and_then(|p| p.calibrated),
            candidate_belief: candidate_prediction.as_ref().map(|p| p.bpa.b),
            candidate_probability: candidate_prediction
                .as_ref()
                .map(|p| p.calibrated.unwrap_or(p.probability)),
        }),
        learning_evidence,
        input_content_sha256: session
            .and_then(|s| s.content.raw_mime.as_ref())
            .filter(|raw| !raw.is_empty())
            .map(|raw| hex::encode(Sha256::digest(raw))),
    }
}

/// The final risk is V2 belief followed by named evidence constraints and an
/// explicit operator review policy. Policy elevation never rewrites BPA belief.
pub(super) fn aggregate_clustered_ds_v2(
    session: Option<&EmailSession>,
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    use super::{evidence_clusters::normalize_results, risk_constraints as policy};
    let now = Utc::now();
    let normalized = normalize_results(session, results, config);
    let allowed = super::evidence_clusters::actionable_fusion_categories(results, config);
    let identity_policy = review_policy("identity_review_policy_v2", 0.40);
    let mut governed = results.clone();
    for result in governed.values_mut() {
        let module = result.module_id.clone();
        result.categories.retain(|category| {
            is_context_only(category)
                || allowed.contains(&(module.clone(), category.clone()))
                || identity_policy.as_ref().is_some_and(|policy| {
                    policy.enabled
                        && policy
                            .triggers
                            .get(&module)
                            .is_some_and(|categories| categories.contains(category))
                })
        });
    }
    let mut model = evaluate_model(session, &governed, config);
    let mut clusters = normalized.clusters.clone();
    policy::apply_context_adjustments(&mut clusters, &normalized);
    let constrained = policy::apply_cluster_floors_and_caps_with_config(
        model.risk_constrained,
        &clusters,
        &normalized,
        config,
    );
    let scenario_risk = constrained
        .risk
        .max(policy::zero_cluster_contextual_risk(&normalized));
    if (scenario_risk - model.risk_constrained).abs() > 1e-12 {
        model.active_constraints.push(RiskConstraintTrace {
            id: "qualified_scenario_constraints".to_string(),
            lower: if scenario_risk > model.risk_constrained {
                scenario_risk
            } else {
                0.0
            },
            upper: if scenario_risk < model.risk_constrained {
                scenario_risk
            } else {
                1.0
            },
            basis: normalized
                .scenario
                .admitted_categories
                .iter()
                .cloned()
                .collect(),
        });
    }
    model.risk_constrained = scenario_risk;
    apply_identity_review_policy(&mut model, results);
    if let Some(policy) = review_policy("semantic_intent_review_policy_v2", 0.40) {
        apply_review_minimum(
            &mut model,
            results,
            &policy,
            "semantic_intent_review_minimum",
        );
    }
    if let Some(policy) = review_policy("recipient_targeting_review_policy_v2", 0.40) {
        apply_review_minimum(
            &mut model,
            results,
            &policy,
            "recipient_targeting_review_minimum",
        );
    }
    // All applied bounds share one final feasibility check. A later cap
    // cannot silently invalidate a confirmed malicious lower bound.
    let final_bounds = model
        .active_constraints
        .iter()
        .map(|trace| IntervalConstraint {
            id: trace.id.clone(),
            lower: trace.lower,
            upper: trace.upper,
            basis: trace.basis.clone(),
        })
        .collect::<Vec<_>>();
    let final_constraints = evaluate_constraints(model.risk_constrained, &final_bounds);
    model.risk_constrained = final_constraints.risk;
    model.constraint_conflict = final_constraints.conflict;
    let risk = model.risk_constrained;
    let level = ThreatLevel::from_score(risk);
    let mut summary = policy::build_clustered_summary(
        level,
        &normalized.categories,
        normalized.modules_flagged,
        normalized.modules_run,
        model.source_details.len(),
        risk,
        &normalized.scenario,
    );
    if level == ThreatLevel::Safe && model.epistemic_state == EpistemicState::Unknown {
        summary = policy::append_scenario_context(
            format!(
                "Insufficient evidence to establish threat or safety ({} modules, risk={risk:.3})",
                normalized.modules_run
            ),
            &normalized.scenario,
        );
    }
    if model
        .active_constraints
        .iter()
        .any(|c| c.id == "operator_identity_review_minimum")
    {
        summary.push_str(
            "; operator identity-review policy requires at least Medium; raw belief is unchanged",
        );
    }
    let confidence = (1.0 - model.fused_bpa.u).clamp(0.0, 1.0);
    SecurityVerdict {
        id: Uuid::new_v4(),
        session_id,
        threat_level: level,
        inspection_coverage: Default::default(),
        coverage_reasons: vec![],
        threat_type: None,
        classification: None,
        confidence,
        categories: normalized.categories,
        summary,
        pillar_scores: policy::compute_pillar_scores(results, config),
        modules_run: normalized.modules_run,
        modules_flagged: normalized.modules_flagged,
        total_duration_ms: normalized.total_duration_ms,
        created_at: now,
        fusion_details: Some(FusionDetails {
            fused_bpa: model.fused_bpa,
            k_conflict: model.k_conflict,
            risk_single: risk,
            eta: 0.0,
            engine_details: model.source_details.clone(),
            credibility_weights: HashMap::new(),
            novelty: None,
            k_cross: None,
            betp: None,
            fusion_method: Some(MODEL_NAME.to_string()),
            circuit_breaker: constrained.circuit_breaker,
            convergence_breaker: constrained.convergence_breaker,
            shadow_results: vec![],
            primary_result: Some(model),
            relational_shadow: Some(super::relational_v2::assess(session, results)),
        }),
    }
}

#[derive(Deserialize)]
struct IdentityReviewPolicy {
    enabled: bool,
    minimum_risk: f64,
    triggers: BTreeMap<String, BTreeSet<String>>,
}

fn review_policy(name: &str, minimum_allowed: f64) -> Option<IdentityReviewPolicy> {
    let registry = crate::module_data::module_data();
    let parse = |value: &serde_json::Value| {
        serde_json::from_value::<IdentityReviewPolicy>(value.clone())
            .ok()
            .filter(|p| {
                p.minimum_risk.is_finite()
                    && (minimum_allowed..=1.0).contains(&p.minimum_risk)
                    && !p.triggers.is_empty()
                    && p.triggers.values().all(|categories| !categories.is_empty())
            })
    };
    registry.get_structured(name).and_then(parse).or_else(|| {
        let seed: serde_json::Value =
            serde_json::from_str(vigilyx_db::security::embedded_module_data_seed()).ok()?;
        parse(seed.get("lists")?.get(name)?.get("items")?)
    })
}

fn apply_identity_review_policy(
    model: &mut FusionModelResult,
    results: &HashMap<String, ModuleResult>,
) {
    if let Some(policy) = review_policy("identity_review_policy_v2", 0.40) {
        apply_review_minimum(model, results, &policy, "operator_identity_review_minimum");
    }
}

fn apply_review_minimum(
    model: &mut FusionModelResult,
    results: &HashMap<String, ModuleResult>,
    policy: &IdentityReviewPolicy,
    id: &str,
) {
    if !policy.enabled {
        return;
    }
    let basis: BTreeSet<String> = results
        .values()
        .filter(|r| {
            r.module_id != "verdict"
                && r.threat_level > ThreatLevel::Safe
                && r.raw_score() > 0.0
                && r.confidence > 0.0
        })
        .flat_map(|r| {
            r.categories
                .iter()
                .filter(|category| {
                    policy
                        .triggers
                        .get(&r.module_id)
                        .is_some_and(|categories| categories.contains(*category))
                        && super::evidence_clusters::attributed_findings(None, r, category)
                            .iter()
                            .any(|finding| finding.score > 0.0 && finding.confidence > 0.0)
                })
                .map(|category| format!("{}:{}", r.module_id, category))
        })
        .collect();
    if basis.is_empty() {
        return;
    }
    model.risk_constrained = model.risk_constrained.max(policy.minimum_risk);
    // The explicit review requirement takes precedence over contextual-only caps.
    model
        .active_constraints
        .retain(|c| c.id != "qualified_scenario_constraints" || c.upper >= policy.minimum_risk);
    model.active_constraints.push(RiskConstraintTrace {
        id: id.to_string(),
        lower: policy.minimum_risk,
        upper: 1.0,
        basis: basis.into_iter().collect(),
    });
}

fn malicious_bpa(strength: f64, reliability: f64) -> Bpa {
    let mass = strength.clamp(0.0, 1.0) * reliability.clamp(0.0, 1.0);
    Bpa::new(mass, 0.0, 1.0 - mass)
}

#[cfg(test)]
fn normal_bpa(strength: f64, reliability: f64) -> Bpa {
    let mass = strength.clamp(0.0, 1.0) * reliability.clamp(0.0, 1.0);
    Bpa::new(0.0, mass, 1.0 - mass)
}

/// Symmetric n-ary conflict-to-uncertainty fusion.
///
/// Each source appears exactly once.  Direct Threat-vs-Normal conflict is
/// transferred to Theta instead of being normalized away.
fn combine_once_conflict_to_uncertainty(sources: &[Bpa]) -> (Bpa, f64) {
    if sources.is_empty() {
        return (Bpa::vacuous(), 0.0);
    }

    let all_uncertain = sources.iter().map(|mass| mass.u).product::<f64>();
    let threat_or_uncertain = sources.iter().map(|mass| mass.b + mass.u).product::<f64>();
    let normal_or_uncertain = sources.iter().map(|mass| mass.d + mass.u).product::<f64>();
    let belief = (threat_or_uncertain - all_uncertain).max(0.0);
    let disbelief = (normal_or_uncertain - all_uncertain).max(0.0);
    let conflict = (1.0 - belief - disbelief - all_uncertain).clamp(0.0, 1.0);
    (
        Bpa::new(belief, disbelief, all_uncertain + conflict),
        conflict,
    )
}

fn classify_epistemic_state(bpa: Bpa, conflict: f64) -> EpistemicState {
    if conflict >= 0.10 {
        EpistemicState::Conflicted
    } else if bpa.b >= 0.15 && bpa.b > bpa.d {
        EpistemicState::ThreatSupported
    } else if bpa.d >= 0.15 && bpa.d > bpa.b {
        EpistemicState::NormalSupported
    } else {
        EpistemicState::Unknown
    }
}

fn evaluate_constraints(
    base_risk: f64,
    constraints: &[IntervalConstraint],
) -> ConstraintEvaluation {
    let lower = constraints
        .iter()
        .map(|constraint| constraint.lower)
        .fold(0.0, f64::max);
    let upper = constraints
        .iter()
        .map(|constraint| constraint.upper)
        .fold(1.0, f64::min);
    let traces = constraints
        .iter()
        .map(|constraint| RiskConstraintTrace {
            id: constraint.id.to_string(),
            lower: constraint.lower,
            upper: constraint.upper,
            basis: constraint.basis.clone(),
        })
        .collect::<Vec<_>>();

    if lower <= upper {
        ConstraintEvaluation {
            risk: base_risk.clamp(lower, upper),
            traces,
            conflict: None,
        }
    } else {
        let mut ids = constraints
            .iter()
            .map(|constraint| constraint.id.to_string())
            .collect::<Vec<_>>();
        ids.sort();
        tracing::error!(
            effective_lower = lower,
            effective_upper = upper,
            constraints = ?ids,
            "clustered_ds_v2 risk constraints have an empty intersection"
        );
        ConstraintEvaluation {
            // Threat-preserving failure behavior: retain the strongest lower
            // bound and expose the impossible intersection for operations.
            risk: lower.clamp(0.0, 1.0),
            traces,
            conflict: Some(RiskConstraintConflict {
                effective_lower: lower,
                effective_upper: upper,
                constraint_ids: ids,
            }),
        }
    }
}

fn collect_artifacts_and_inputs(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> (Vec<ArtifactEvidence>, Vec<DsLearningEvidence>) {
    let mut ordered_results = results
        .values()
        .filter(|result| result.module_id != "verdict")
        .collect::<Vec<_>>();
    ordered_results.sort_by(|left, right| left.module_id.cmp(&right.module_id));

    let mut artifacts: BTreeMap<String, ArtifactAccumulator> = BTreeMap::new();
    let mut learning_inputs = Vec::new();
    for result in ordered_results {
        if result.threat_level <= ThreatLevel::Safe
            || result
                .bpa
                .as_ref()
                .is_some_and(|mass| mass.b <= f64::EPSILON)
        {
            continue;
        }
        let module_weight = config
            .weights
            .get(&result.module_id)
            .copied()
            .unwrap_or(1.0)
            .clamp(0.0, 5.0);

        let mut categories = result.categories.iter().collect::<Vec<_>>();
        categories.sort();
        categories.dedup();
        for category in categories {
            if is_context_only(category) {
                continue;
            }
            let profile = evidence_profile(&result.module_id, category);
            let Some(cluster) = profile
                .as_ref()
                .map(|profile| profile.cluster)
                .or_else(|| cluster_for(&result.module_id, category))
            else {
                continue;
            };
            let principle = detection_principle(&result.module_id).to_string();
            // Registered native anchors must not be discounted merely because
            // their machine category lacks a generic "phishing" substring.
            let scale = if let Some(profile) = profile {
                profile.strength_scale
            } else if super::evidence_clusters::is_breaker_eligible_signal(
                &result.module_id,
                category,
            ) {
                1.0
            } else {
                category_scale(category)
            };
            for item in super::evidence_clusters::attributed_findings(session, result, category) {
                let strength = (item.score * module_weight).clamp(0.0, 1.0) * scale;
                let reliability = item.confidence * cluster.reliability_scale();
                // Preserve the raw, admitted item separately from all manual
                // weights, cluster scales, maximums and policy constraints.
                let legacy_mass = if strength * reliability > ACTIVE_SIGNAL_THRESHOLD {
                    strength * reliability
                } else {
                    0.0
                };
                let mut learning_input = DsLearningEvidence {
                    source_id: format!("{}:{}", result.module_id, category),
                    causal_key: item.causal_key.clone(),
                    cluster: cluster.label().into(),
                    raw_score: item.score,
                    confidence: item.confidence,
                    item_scored: item.item_scored,
                    legacy_mass,
                    confirmed_anchor_mass: if is_confirmed_anchor(result, category, cluster) {
                        legacy_mass
                    } else {
                        0.0
                    },
                };
                // Migration-only producer metadata leaves bootstrap scoring
                // intact while providing genuinely individual raw learning inputs.
                // It cannot admit a category that this fusion pass excluded.
                let explicit = result.details["ds_learning_items"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|record| {
                        record["categories"].as_array().is_some_and(|values| {
                            values.iter().any(|v| v.as_str() == Some(category.as_str()))
                        })
                    });
                if let Some(record) = explicit {
                    let score = record["score"].as_f64();
                    let confidence = record["confidence"].as_f64();
                    let key = record["causal_key"].as_str();
                    if let (Some(score), Some(confidence), Some(key)) = (score, confidence, key)
                        && score.is_finite()
                        && (0.0..=1.0).contains(&score)
                        && confidence.is_finite()
                        && (0.0..=1.0).contains(&confidence)
                        && !key.is_empty()
                        && key.len() <= 8192
                    {
                        learning_input.raw_score = score;
                        learning_input.confidence = confidence;
                        learning_input.causal_key = Some(key.into());
                        learning_input.item_scored = true;
                    }
                }
                learning_inputs.push(learning_input);
                let (artifact_key, fallback) = item.causal_key.map_or_else(
                    || (fallback_artifact_key(cluster), true),
                    |key| (key, false),
                );
                if strength * reliability <= ACTIVE_SIGNAL_THRESHOLD {
                    continue;
                }

                let artifact = artifacts.entry(artifact_key).or_default();
                artifact.fallback |= fallback;
                let observation =
                    artifact
                        .principles
                        .entry(principle.clone())
                        .or_insert_with(|| ObservationAccumulator {
                            cluster,
                            strength: 0.0,
                            reliability: 0.0,
                            modules: BTreeSet::new(),
                            factors: BTreeSet::new(),
                            confirmed_anchor_mass: 0.0,
                        });
                if strength * reliability > observation.strength * observation.reliability {
                    observation.cluster = cluster;
                    observation.strength = strength;
                    observation.reliability = reliability;
                }
                observation.modules.insert(result.module_id.clone());
                observation
                    .factors
                    .insert(format!("{}:{}", result.module_id, category));
                if is_confirmed_anchor(result, category, cluster) {
                    observation.confirmed_anchor_mass = observation
                        .confirmed_anchor_mass
                        .max(strength * reliability);
                }
                if !item.item_scored {
                    observation
                        .factors
                        .insert("legacy_module_score".to_string());
                }
            }
        }
    }

    let mut evidence = artifacts
        .into_iter()
        .filter_map(|(key, artifact)| finalize_artifact(key, artifact))
        .collect::<Vec<_>>();
    discount_unbound_overlap(&mut evidence);
    (evidence, learning_inputs)
}

/// Unbound legacy summaries may overlap each other and any concrete object.
/// Cluster labels do not prove disjoint causes (e.g. AITM spans body and links).
/// Retain max(S, F), where S combines concrete objects and F is the strongest
/// unbound summary. Only one algebraic residual enters n-ary fusion; it is not
/// an independent source or learned reliability. Preserve original anchor floors.
fn discount_unbound_overlap(artifacts: &mut [ArtifactEvidence]) {
    let remaining = artifacts
        .iter()
        .filter(|artifact| !artifact.fallback)
        .map(|artifact| 1.0 - artifact.malicious_mass)
        .product::<f64>();
    let known = 1.0 - remaining;
    let winner = artifacts
        .iter()
        .filter(|artifact| artifact.fallback)
        .max_by(|left, right| {
            left.malicious_mass
                .total_cmp(&right.malicious_mass)
                .then_with(|| right.key.cmp(&left.key))
        })
        .map(|artifact| artifact.key.clone());
    for artifact in artifacts.iter_mut().filter(|artifact| artifact.fallback) {
        let original = artifact.malicious_mass;
        artifact.malicious_mass = if remaining > 0.0 && winner.as_ref() == Some(&artifact.key) {
            ((original - known).max(0.0) / remaining).clamp(0.0, 1.0)
        } else {
            0.0
        };
        artifact
            .factors
            .insert(format!("unbound_support_before_overlap:{original:.8}"));
        artifact
            .factors
            .insert("unbound_overlap_residual".to_string());
    }
}

fn finalize_artifact(key: String, artifact: ArtifactAccumulator) -> Option<ArtifactEvidence> {
    let best = artifact.principles.values().max_by(|left, right| {
        let left_mass = left.strength * left.reliability;
        let right_mass = right.strength * right.reliability;
        left_mass
            .total_cmp(&right_mass)
            .then_with(|| right.cluster.cmp(&left.cluster))
    })?;
    let malicious_mass = best.strength * best.reliability;
    let mut modules = BTreeSet::new();
    let mut factors = BTreeSet::new();
    let mut confirmed_anchor_mass: f64 = 0.0;
    for observation in artifact.principles.values() {
        modules.extend(observation.modules.iter().cloned());
        factors.extend(observation.factors.iter().cloned());
        confirmed_anchor_mass = confirmed_anchor_mass.max(observation.confirmed_anchor_mass);
    }
    Some(ArtifactEvidence {
        key,
        cluster: best.cluster,
        malicious_mass,
        modules,
        factors,
        fallback: artifact.fallback,
        confirmed_anchor_mass,
    })
}

fn is_context_only(category: &str) -> bool {
    matches!(
        category,
        "inspection_incomplete"
            | "inspection_coverage_incomplete"
            | "inspection_execution_incomplete"
            | "scan_incomplete"
            | "scan_skipped_size_limit"
            | "attachment_inspection_limited"
            | "attachment_qr_inspection_limited"
            | "semantic_ai_inspection_limited"
            | "semantic_inspection_limited"
            | "encrypted_attachment"
            | "encrypted_archive"
            | "encrypted_pdf"
            | "unsupported_container"
            | "ocr_unavailable"
            | "recipient_metadata_incomplete"
            | "missing_content_type"
            | "missing_from"
            | "missing_to"
            | "empty_subject"
            | "long_url_observed"
            | "authentication_unverified"
            | "alignment_observed"
            | "envelope_spoofing"
            | "protected_domain_spoof"
            | "attachment_url_shape_observation"
            | "attachment_business_keyword_observation"
            | "sandbox_url_network_observed"
    )
}

fn fallback_artifact_key(cluster: V2Cluster) -> String {
    let surface = match cluster {
        V2Cluster::SenderIdentityAuthenticity | V2Cluster::DeliveryIntegrity => "headers",
        V2Cluster::LinkAndHtmlDeception | V2Cluster::ExternalReputationIoc => "links",
        V2Cluster::PayloadMalware => "attachments",
        V2Cluster::SocialEngineeringIntent | V2Cluster::BusinessSensitivity => "body",
        V2Cluster::InheritedGatewayPrior => "gateway",
    };
    format!("fallback:{surface}:message")
}

fn detection_principle(module_id: &str) -> &'static str {
    match module_id {
        "av_eml_scan" | "av_attach_scan" | "yara_scan" | "attach_hash" => "signature_or_hash",
        "sandbox_scan" | "url_sandbox_scan" | "process_sandbox_scan" => "dynamic_execution",
        "link_reputation" => "external_reputation",
        "landing_page_scan" => "dynamic_link_content",
        "link_scan" | "link_content" | "html_scan" | "html_pixel_art" | "attach_qr_scan" => {
            "static_link_structure"
        }
        "domain_verify" | "header_scan" | "identity_anomaly" => "identity_or_authentication",
        "transaction_correlation" => "transaction_semantics",
        "semantic_scan" | "content_scan" | "toad_detect" | "prompt_injection_scan" => {
            "message_semantics"
        }
        "attach_scan" | "attach_content" | "rmm_detect" => "static_payload",
        "mime_scan" | "anomaly_detect" => "delivery_structure",
        _ => "detector_observation",
    }
}

fn cluster_for(module_id: &str, category: &str) -> Option<V2Cluster> {
    match module_id {
        "domain_verify" => None,
        "identity_anomaly" | "aitm_detect" => Some(V2Cluster::SenderIdentityAuthenticity),
        "header_scan" => {
            if category == "gateway_pre_classified" {
                Some(V2Cluster::InheritedGatewayPrior)
            } else if contains_any(
                category,
                &[
                    "spf", "dkim", "dmarc", "spoof", "mismatch", "forgery", "imperson",
                ],
            ) {
                Some(V2Cluster::SenderIdentityAuthenticity)
            } else {
                Some(V2Cluster::DeliveryIntegrity)
            }
        }
        "mime_scan" | "anomaly_detect" => Some(V2Cluster::DeliveryIntegrity),
        "av_eml_scan" | "av_attach_scan" | "sandbox_scan" | "yara_scan" | "attach_scan"
        | "attach_content" | "rmm_detect" => Some(V2Cluster::PayloadMalware),
        "attach_hash" => {
            if contains_any(category, &["intel", "ioc", "reputation", "malicious"]) {
                Some(V2Cluster::ExternalReputationIoc)
            } else {
                Some(V2Cluster::PayloadMalware)
            }
        }
        "link_reputation" => {
            if contains_any(
                category,
                &["intel", "ioc", "reputation", "malicious", "blacklist"],
            ) {
                Some(V2Cluster::ExternalReputationIoc)
            } else {
                Some(V2Cluster::LinkAndHtmlDeception)
            }
        }
        "link_scan"
        | "link_content"
        | "html_scan"
        | "html_pixel_art"
        | "attach_qr_scan"
        | "landing_page_scan"
        | "url_sandbox_scan"
        | "process_sandbox_scan" => Some(V2Cluster::LinkAndHtmlDeception),
        "transaction_correlation" => Some(V2Cluster::BusinessSensitivity),
        // Review-only classifier signal; see map_semantic_signal.
        "semantic_scan" if category == crate::semantic::TEXT_CLASSIFIER_CATEGORY => None,
        "content_scan" | "semantic_scan" | "toad_detect" | "prompt_injection_scan" => {
            if contains_any(
                category,
                &["payment", "invoice", "bank", "wallet", "financial", "bec"],
            ) {
                Some(V2Cluster::BusinessSensitivity)
            } else {
                Some(V2Cluster::SocialEngineeringIntent)
            }
        }
        _ => Some(V2Cluster::SocialEngineeringIntent),
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn category_scale(category: &str) -> f64 {
    if contains_any(
        category,
        &[
            "malicious",
            "malware",
            "ransomware",
            "trojan",
            "credential",
            "phishing",
        ],
    ) {
        1.0
    } else if contains_any(
        category,
        &[
            "spoof",
            "forgery",
            "mismatch",
            "redirect",
            "obfuscat",
            "random_domain",
        ],
    ) {
        0.82
    } else {
        0.65
    }
}

fn is_confirmed_anchor(result: &ModuleResult, category: &str, cluster: V2Cluster) -> bool {
    if !matches!(
        cluster,
        V2Cluster::PayloadMalware
            | V2Cluster::ExternalReputationIoc
            | V2Cluster::LinkAndHtmlDeception
    ) {
        return false;
    }
    let detector_anchor = matches!(
        result.module_id.as_str(),
        "av_eml_scan"
            | "av_attach_scan"
            | "sandbox_scan"
            | "url_sandbox_scan"
            | "process_sandbox_scan"
            | "yara_scan"
            | "attach_hash"
    ) && result.threat_level >= ThreatLevel::High;
    detector_anchor
        || contains_any(
            category,
            &[
                "malicious",
                "malware_hash",
                "ioc_hit",
                "intel_malicious",
                "high_risk_credential_target",
            ],
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol, SessionSource};
    use vigilyx_core::security::{ModuleResult, Pillar};

    fn result(
        module: &str,
        category: &str,
        score: f64,
        confidence: f64,
        causal_key: Option<&str>,
    ) -> ModuleResult {
        ModuleResult {
            module_id: module.to_string(),
            module_name: module.to_string(),
            pillar: Pillar::Link,
            threat_level: ThreatLevel::from_score(score),
            confidence,
            categories: vec![category.to_string()],
            summary: String::new(),
            evidence: Vec::new(),
            details: serde_json::json!({
                "score": score,
                "causal_findings": causal_key.map(|key| vec![serde_json::json!({
                    "causal_key": key,
                    "categories": [category],
                })]).unwrap_or_default(),
            }),
            duration_ms: 0,
            analyzed_at: Utc::now(),
            bpa: Some(Bpa::from_score_confidence(score, confidence)),
            engine_id: Some(module.to_string()),
        }
    }

    #[test]
    fn admitted_bec_is_social_engineering_while_financial_context_stays_non_actionable() {
        let bec = HashMap::from([(
            "content_scan".to_string(),
            result("content_scan", "bec", 0.75, 0.85, None),
        )]);
        let verdict =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &bec, &VerdictConfig::default());
        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
        let context = HashMap::from([(
            "transaction_correlation".to_string(),
            result(
                "transaction_correlation",
                "bank_account_detected",
                0.75,
                0.85,
                None,
            ),
        )]);
        let verdict =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &context, &VerdictConfig::default());
        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn native_aitm_compound_retains_strength_while_mfa_context_stays_weak() {
        for (category, expected) in [
            ("aitm_compound_platform_mfa", ThreatLevel::Medium),
            ("aitm_mfa_bait", ThreatLevel::Low),
        ] {
            let results = HashMap::from([(
                "aitm_detect".to_string(),
                result("aitm_detect", category, 0.80, 0.80, None),
            )]);
            let verdict = aggregate_clustered_ds_v2(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(verdict.threat_level, expected, "{category}");
        }
    }

    #[test]
    fn content_review_signals_require_medium_individually_and_together() {
        for signals in [
            vec![("semantic_scan", "semantic_intent_model")],
            vec![("link_content", "recipient_in_url")],
            vec![
                ("semantic_scan", "semantic_intent_model"),
                ("link_content", "recipient_in_url"),
            ],
        ] {
            let results = signals
                .iter()
                .map(|(module, category)| {
                    let mut signal = result(module, category, 0.40, 0.55, None);
                    signal.categories.push((*category).into());
                    ((*module).to_string(), signal)
                })
                .collect::<HashMap<_, _>>();
            let raw = evaluate_model(None, &results, &VerdictConfig::default());
            let mut reviewed = raw.clone();
            for (name, id) in [
                (
                    "semantic_intent_review_policy_v2",
                    "semantic_intent_review_minimum",
                ),
                (
                    "recipient_targeting_review_policy_v2",
                    "recipient_targeting_review_minimum",
                ),
            ] {
                apply_review_minimum(
                    &mut reviewed,
                    &results,
                    &review_policy(name, 0.40).unwrap(),
                    id,
                );
            }
            assert_eq!(
                reviewed.fused_bpa, raw.fused_bpa,
                "review policy must not rewrite raw belief"
            );
            let verdict = aggregate_clustered_ds_v2(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(verdict.threat_level, ThreatLevel::Medium, "{signals:?}");
            let primary = verdict.fusion_details.unwrap().primary_result.unwrap();
            assert_eq!(primary.risk_constrained, 0.40);
            assert_eq!(primary.risk_base, primary.fused_bpa.b);
            assert!(primary.risk_base < primary.risk_constrained);
            assert_eq!(
                primary
                    .active_constraints
                    .iter()
                    .filter(|c| {
                        matches!(
                            c.id.as_str(),
                            "semantic_intent_review_minimum" | "recipient_targeting_review_minimum"
                        )
                    })
                    .count(),
                signals.len(),
                "duplicate categories must not create repeated review votes"
            );
        }
    }

    #[test]
    fn content_review_policy_ignores_unscored_or_wrong_module_categories() {
        for (module, category, score, confidence) in [
            ("semantic_scan", "semantic_intent_model", 0.0, 0.55),
            ("semantic_scan", "semantic_intent_model", 0.40, 0.0),
            ("link_scan", "recipient_in_url", 0.40, 0.75),
            ("link_content", "long_url", 0.10, 0.75),
        ] {
            let results = HashMap::from([(
                module.to_string(),
                result(module, category, score, confidence, None),
            )]);
            let verdict = aggregate_clustered_ds_v2(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            let primary = verdict.fusion_details.unwrap().primary_result.unwrap();
            assert!(!primary.active_constraints.iter().any(|c| {
                matches!(
                    c.id.as_str(),
                    "semantic_intent_review_minimum" | "recipient_targeting_review_minimum"
                )
            }));
        }
    }

    #[test]
    fn requested_single_identity_signals_require_medium_without_rewriting_belief() {
        for (module, category) in [
            ("identity_anomaly", "random_domain"),
            ("header_scan", "domain_mismatch"),
        ] {
            let results = HashMap::from([(
                module.to_string(),
                result(module, category, 0.25, 0.70, None),
            )]);
            let verdict = aggregate_clustered_ds_v2(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(verdict.threat_level, ThreatLevel::Medium);
            let fusion = verdict.fusion_details.unwrap();
            let primary = fusion.primary_result.unwrap();
            assert!(primary.risk_base < 0.15);
            assert_eq!(primary.risk_constrained, 0.40);
            assert_eq!(primary.fused_bpa.d, 0.0);
            assert_eq!(primary.epistemic_state, EpistemicState::Unknown);
            assert!(
                primary
                    .active_constraints
                    .iter()
                    .any(|c| c.id == "operator_identity_review_minimum")
            );
        }
    }

    #[test]
    fn unrelated_domain_mismatch_or_missing_received_cannot_trigger_identity_policy() {
        for (module, category) in [
            ("link_content", "domain_mismatch"),
            ("header_scan", "no_received"),
            ("identity_anomaly", "first_contact"),
        ] {
            let results = HashMap::from([(
                module.to_string(),
                result(module, category, 0.10, 0.70, None),
            )]);
            let mut model = evaluate_model(None, &results, &VerdictConfig::default());
            let before = model.risk_constrained;
            apply_identity_review_policy(&mut model, &results);
            assert_eq!(model.risk_constrained, before);
            assert!(
                !model
                    .active_constraints
                    .iter()
                    .any(|c| c.id == "operator_identity_review_minimum")
            );
        }
    }

    #[test]
    fn duplicate_identity_flags_never_add_repeated_policy_votes() {
        let results = HashMap::from([
            (
                "identity_anomaly".to_string(),
                result("identity_anomaly", "random_domain", 0.47, 0.70, None),
            ),
            (
                "header_scan".to_string(),
                result("header_scan", "domain_mismatch", 0.25, 0.80, None),
            ),
        ]);
        let verdict =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &results, &VerdictConfig::default());
        let primary = verdict.fusion_details.unwrap().primary_result.unwrap();
        assert_eq!(primary.risk_constrained, 0.40);
        assert_eq!(
            primary
                .active_constraints
                .iter()
                .filter(|c| c.id == "operator_identity_review_minimum")
                .count(),
            1
        );
    }

    #[test]
    fn one_sided_bpa_does_not_invent_normal_mass() {
        let mass = malicious_bpa(0.40, 0.75);
        assert!((mass.b - 0.30).abs() < 1e-12);
        assert_eq!(mass.d, 0.0);
        assert!((mass.u - 0.70).abs() < 1e-12);
    }

    #[test]
    fn envelope_mismatch_is_context_until_an_independent_relation_exists() {
        let results = HashMap::from([
            (
                "header_scan".to_string(),
                result("header_scan", "envelope_spoofing", 0.65, 0.85, None),
            ),
            (
                "header_scan_protected".to_string(),
                result("header_scan", "protected_domain_spoof", 0.65, 0.85, None),
            ),
        ]);

        let shadow = evaluate_model(None, &results, &VerdictConfig::default());

        assert_eq!(shadow.artifact_count, 0);
        assert!(shadow.source_details.is_empty());
    }

    #[test]
    fn nary_fusion_is_permutation_invariant_and_vacuous_is_identity() {
        let sources = vec![
            malicious_bpa(0.40, 0.80),
            normal_bpa(0.50, 0.70),
            malicious_bpa(0.25, 0.60),
        ];
        let mut reversed = sources.clone();
        reversed.reverse();
        let (left, left_k) = combine_once_conflict_to_uncertainty(&sources);
        let (right, right_k) = combine_once_conflict_to_uncertainty(&reversed);
        assert!((left.b - right.b).abs() < 1e-12);
        assert!((left.d - right.d).abs() < 1e-12);
        assert!((left.u - right.u).abs() < 1e-12);
        assert!((left_k - right_k).abs() < 1e-12);

        let (with_vacuous, _) = combine_once_conflict_to_uncertainty(&[sources[0], Bpa::vacuous()]);
        assert!((with_vacuous.b - sources[0].b).abs() < 1e-12);
        assert!((with_vacuous.u - sources[0].u).abs() < 1e-12);
    }

    #[test]
    fn conflict_becomes_uncertainty_and_threat_addition_is_monotone() {
        let threat = malicious_bpa(0.60, 0.90);
        let normal = normal_bpa(0.70, 0.90);
        let (conflicted, conflict) = combine_once_conflict_to_uncertainty(&[threat, normal]);
        assert!(conflict > 0.0);
        assert!(conflicted.u > threat.u * normal.u);

        let (before, _) = combine_once_conflict_to_uncertainty(&[normal, threat]);
        let (after, _) =
            combine_once_conflict_to_uncertainty(&[normal, threat, malicious_bpa(0.20, 0.80)]);
        assert!(after.b >= before.b);
    }

    #[test]
    fn duplicate_causal_artifact_is_idempotent_across_detectors() {
        let mut results = HashMap::from([(
            "link_content".to_string(),
            result(
                "link_content",
                "suspicious_tld",
                0.50,
                0.80,
                Some("host:attack.invalid"),
            ),
        )]);
        let one = evaluate_model(None, &results, &VerdictConfig::default());
        results.insert(
            "link_reputation".to_string(),
            result(
                "link_reputation",
                "suspicious_tld",
                0.50,
                0.80,
                Some("host:attack.invalid"),
            ),
        );
        let duplicate = evaluate_model(None, &results, &VerdictConfig::default());
        assert_eq!(one.artifact_count, 1);
        assert_eq!(duplicate.artifact_count, 1);
        assert!((one.risk_base - duplicate.risk_base).abs() < 1e-12);
    }

    #[test]
    fn distinct_artifacts_noisy_or_inside_cluster() {
        let results = HashMap::from([
            (
                "link_content".to_string(),
                result(
                    "link_content",
                    "suspicious_tld",
                    0.50,
                    0.80,
                    Some("host:one.invalid"),
                ),
            ),
            (
                "link_scan".to_string(),
                result("link_scan", "ip_url", 0.50, 0.80, Some("host:two.invalid")),
            ),
        ]);
        let shadow = evaluate_model(None, &results, &VerdictConfig::default());
        assert_eq!(shadow.artifact_count, 2);
        assert!(shadow.risk_base > malicious_bpa(0.50 * 0.82, 0.80 * 0.86).b);
    }

    #[test]
    fn auth_and_relationship_do_not_claim_message_harmlessness() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent::default();
        session.content.is_complete = true;
        let mut domain = ModuleResult::safe_analyzed(
            "domain_verify",
            "Domain Verify",
            Pillar::Package,
            "verified",
            0,
        );
        domain.confidence = 0.90;
        domain.details = serde_json::json!({
            "verified": true,
            "cryptographic_dkim_pass": true,
            "trust_score": 0.70,
        });
        let mut identity = ModuleResult::safe_analyzed(
            "identity_anomaly",
            "Identity",
            Pillar::Package,
            "known relationship",
            0,
        );
        identity.details = serde_json::json!({
            "sender_history": {"completed_count": 5, "distinct_days": 3},
            "recipient_relationship_history": {"completed_count": 4, "distinct_days": 3},
        });
        let malware = result(
            "av_attach_scan",
            "malware",
            0.90,
            0.95,
            Some("sha256:deadbeef"),
        );
        let results = HashMap::from([
            ("domain_verify".to_string(), domain),
            ("identity_anomaly".to_string(), identity),
            ("av_attach_scan".to_string(), malware),
        ]);
        let shadow = evaluate_model(Some(&session), &results, &VerdictConfig::default());
        assert_eq!(shadow.fused_bpa.d, 0.0);
        assert_eq!(shadow.k_conflict, 0.0);
        assert!(
            shadow
                .active_constraints
                .iter()
                .any(|constraint| constraint.id == "confirmed_malicious_anchor")
        );
        let anchor_floor = shadow
            .active_constraints
            .iter()
            .find(|constraint| constraint.id == "confirmed_malicious_anchor")
            .unwrap()
            .lower;
        assert!(shadow.risk_constrained >= anchor_floor);
        assert!(shadow.risk_constrained >= shadow.risk_base);
    }

    #[test]
    fn incomplete_or_imported_sessions_cannot_create_normal_mass() {
        let mut domain = ModuleResult::safe_analyzed(
            "domain_verify",
            "Domain Verify",
            Pillar::Package,
            "verified",
            0,
        );
        domain.confidence = 0.90;
        domain.details = serde_json::json!({
            "verified": true,
            "cryptographic_dkim_pass": true,
            "trust_score": 0.70,
        });
        let results = HashMap::from([("domain_verify".to_string(), domain)]);
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );

        session.content.is_complete = false;
        let incomplete = evaluate_model(Some(&session), &results, &VerdictConfig::default());
        assert_eq!(incomplete.fused_bpa, Bpa::vacuous());

        session.content.is_complete = true;
        session.source = SessionSource::Import;
        let imported = evaluate_model(Some(&session), &results, &VerdictConfig::default());
        assert_eq!(imported.fused_bpa, Bpa::vacuous());
    }

    #[test]
    fn authenticated_sender_does_not_discount_bec_or_payload_threat() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.1".into(),
            2525,
            "192.0.2.2".into(),
            25,
        );
        session.content.is_complete = true;
        let mut auth = ModuleResult::safe_analyzed(
            "domain_verify",
            "Domain Verify",
            Pillar::Package,
            "trusted aligned DKIM pass",
            0,
        );
        auth.confidence = 0.90;
        auth.details = serde_json::json!({"verified": true,
            "cryptographic_dkim_pass": true, "trust_score": 0.70});
        for (module, category) in [("content_scan", "bec"), ("av_attach_scan", "malware")] {
            let mut results = HashMap::from([(
                module.to_string(),
                result(module, category, 0.75, 0.85, None),
            )]);
            let before = aggregate_clustered_ds_v2(
                Some(&session),
                session.id,
                &results,
                &VerdictConfig::default(),
            );
            results.insert("domain_verify".into(), auth.clone());
            let after = aggregate_clustered_ds_v2(
                Some(&session),
                session.id,
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(
                before.fusion_details.as_ref().unwrap().fused_bpa,
                after.fusion_details.as_ref().unwrap().fused_bpa
            );
            assert!(after.threat_level >= ThreatLevel::Medium);
            assert_eq!(before.threat_level, after.threat_level);
        }
    }

    #[test]
    fn item_bpa_is_invariant_to_unrelated_module_score_and_observations() {
        let mut payload = result("link_content", "encoded_protocol_param", 0.30, 0.75, None);
        payload.details["evidence_items_version"] = serde_json::json!(1);
        payload.details["causal_findings"] = serde_json::json!([{
            "causal_key": "host:payload.example", "categories": ["encoded_protocol_param"],
            "score": 0.30, "confidence": 0.75,
        }]);
        let mut results = HashMap::from([("link_content".to_string(), payload)]);
        let before =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &results, &VerdictConfig::default());
        let payload = results.get_mut("link_content").unwrap();
        payload.details["score"] = serde_json::json!(1.0);
        payload.threat_level = ThreatLevel::Critical;
        payload.categories.push("recipient_in_url".into());
        let after =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &results, &VerdictConfig::default());
        assert_eq!(
            before.fusion_details.as_ref().unwrap().fused_bpa,
            after.fusion_details.as_ref().unwrap().fused_bpa
        );
        assert_eq!(
            before.fusion_details.unwrap().risk_single,
            after.fusion_details.unwrap().risk_single
        );
    }

    #[test]
    fn added_scored_cause_is_monotone_and_repeated_cause_is_idempotent() {
        let mut payload = result("link_content", "encoded_protocol_param", 1.0, 0.75, None);
        payload.details = serde_json::json!({"score": 1.0, "evidence_items_version": 1,
            "causal_findings": [{"causal_key": "host:a.example",
                "categories": ["encoded_protocol_param"], "score": 0.60, "confidence": 0.75}]});
        let mut results = HashMap::from([("link_content".to_string(), payload)]);
        let before = evaluate_model(None, &results, &VerdictConfig::default());
        let records = results.get_mut("link_content").unwrap().details["causal_findings"]
            .as_array_mut()
            .unwrap();
        records.push(records[0].clone());
        let duplicate = evaluate_model(None, &results, &VerdictConfig::default());
        assert_eq!(before.fused_bpa, duplicate.fused_bpa);
        let records = results.get_mut("link_content").unwrap().details["causal_findings"]
            .as_array_mut()
            .unwrap();
        records[1]["causal_key"] = serde_json::json!("host:b.example");
        let added = evaluate_model(None, &results, &VerdictConfig::default());
        assert_eq!(added.artifact_count, 2);
        assert_eq!(added.fallback_artifact_count, 0);
        assert!(added.risk_base > before.risk_base);
    }

    #[test]
    fn confirmed_anchor_cannot_borrow_a_stronger_non_anchor_mass() {
        let weak_anchor = result(
            "link_content",
            "malicious_target",
            0.40,
            0.75,
            Some("host:a.example"),
        );
        let strong_observation = result("html_scan", "data_uri", 1.0, 0.80, Some("host:a.example"));
        let baseline = evaluate_model(
            None,
            &HashMap::from([("link_content".into(), weak_anchor.clone())]),
            &VerdictConfig::default(),
        );
        let mixed = evaluate_model(
            None,
            &HashMap::from([
                ("link_content".into(), weak_anchor),
                ("html_scan".into(), strong_observation),
            ]),
            &VerdictConfig::default(),
        );
        let lower = |model: &FusionModelResult| {
            model
                .active_constraints
                .iter()
                .find(|c| c.id == "confirmed_malicious_anchor")
                .unwrap()
                .lower
        };
        assert_eq!(lower(&baseline), lower(&mixed));
        assert!(mixed.risk_base > baseline.risk_base);
    }

    #[test]
    fn scenario_cap_cannot_silently_invalidate_confirmed_anchor() {
        let results = HashMap::from([(
            "attach_hash".to_string(),
            result(
                "attach_hash",
                "hash_intel_malicious",
                1.0,
                0.95,
                Some("artifact:synthetic-malware"),
            ),
        )]);
        let verdict =
            aggregate_clustered_ds_v2(None, Uuid::new_v4(), &results, &VerdictConfig::default());
        let model = verdict.fusion_details.unwrap().primary_result.unwrap();
        let anchor = model
            .active_constraints
            .iter()
            .find(|c| c.id == "confirmed_malicious_anchor")
            .unwrap()
            .lower;
        assert!(model.risk_constrained >= anchor);
        assert!(model.constraint_conflict.is_some());
        assert_eq!(verdict.threat_level, ThreatLevel::High);
    }

    #[test]
    fn empty_constraint_intersection_is_reported_and_threat_preserving() {
        let constraints = vec![
            IntervalConstraint {
                id: "floor".to_string(),
                lower: 0.70,
                upper: 1.0,
                basis: vec!["anchor:a".to_string()],
            },
            IntervalConstraint {
                id: "cap".to_string(),
                lower: 0.0,
                upper: 0.30,
                basis: vec!["context:b".to_string()],
            },
        ];
        let evaluated = evaluate_constraints(0.50, &constraints);
        assert_eq!(evaluated.risk, 0.70);
        assert!(evaluated.conflict.is_some());
    }

    #[test]
    fn known_key_does_not_make_an_unbound_summary_independent() {
        let broad = result(
            "aitm_detect",
            "aitm_compound_platform_mfa",
            0.80,
            0.80,
            None,
        );
        let concrete = result(
            "header_scan",
            "stale_date",
            0.15,
            0.80,
            Some("header_identity:synthetic"),
        );
        let standalone = evaluate_model(
            None,
            &HashMap::from([("aitm_detect".into(), broad.clone())]),
            &VerdictConfig::default(),
        );
        let combined = evaluate_model(
            None,
            &HashMap::from([
                ("aitm_detect".into(), broad),
                ("header_scan".into(), concrete),
            ]),
            &VerdictConfig::default(),
        );
        assert!((combined.risk_base - standalone.risk_base).abs() < 1e-12);
        assert_eq!(combined.artifact_count, 2);
        assert_eq!(combined.fallback_artifact_count, 1);
    }

    #[test]
    fn unbound_overlap_keeps_one_residual_and_preserves_small_increments() {
        let make = |key: &str, cluster, mass, fallback| ArtifactEvidence {
            key: key.to_string(),
            cluster,
            malicious_mass: mass,
            modules: BTreeSet::new(),
            factors: BTreeSet::new(),
            fallback,
            confirmed_anchor_mass: if fallback { mass } else { 0.0 },
        };
        for (known, fallback) in [(0.4, 0.6), (0.599, 0.6), (1.0, 0.6)] {
            let mut items = vec![
                make(
                    "host:one.example",
                    V2Cluster::LinkAndHtmlDeception,
                    known,
                    false,
                ),
                make(
                    "fallback:headers:message",
                    V2Cluster::SenderIdentityAuthenticity,
                    fallback,
                    true,
                ),
                make(
                    "fallback:body:message",
                    V2Cluster::SocialEngineeringIntent,
                    fallback,
                    true,
                ),
            ];
            discount_unbound_overlap(&mut items);
            let mass = 1.0
                - items
                    .iter()
                    .map(|item| 1.0 - item.malicious_mass)
                    .product::<f64>();
            assert!((mass - known.max(fallback)).abs() < 1e-12);
            assert_eq!(items[1].confirmed_anchor_mass, fallback);
            assert_eq!(items[2].confirmed_anchor_mass, fallback);
            assert!(
                items
                    .iter()
                    .filter(|item| item.fallback && item.malicious_mass > 0.0)
                    .count()
                    <= 1
            );
        }
    }
}
