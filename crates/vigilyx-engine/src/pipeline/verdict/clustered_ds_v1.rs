use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{
    dempster_combine, dempster_combine_n, Bpa, CircuitBreakerInfo, ConvergenceBreakerInfo,
    EngineBpaDetail, FusionDetails, ModuleResult, SecurityVerdict, ThreatLevel, ALL_PILLARS,
    PILLAR_COUNT,
};

use crate::config::VerdictConfig;

use super::empty_verdict;
use super::evidence_clusters::{
    normalize_results, ClusterEvidence, EvidenceClusterId, NormalizedEvidence, ScenarioContext,
};

/// Result of floor/cap adjustments, including breaker activation records.
struct FloorCapResult {
    risk: f64,
    circuit_breaker: Option<CircuitBreakerInfo>,
    convergence_breaker: Option<ConvergenceBreakerInfo>,
}

fn append_scenario_context(summary: String, scenario: &ScenarioContext) -> String {
    if scenario.tags.is_empty() {
        summary
    } else {
        format!("{summary} [context: {}]", scenario.tags.join(", "))
    }
}

pub(super) fn aggregate_clustered_ds_v1(
    session: Option<&EmailSession>,
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    let now = Utc::now();
    let normalized = normalize_results(session, results, config);

    if normalized.modules_run == 0 {
        return empty_verdict(session_id, now);
    }

    let mut pillar_scores = compute_pillar_scores(results, config);
    if normalized.clusters.is_empty() {
        return SecurityVerdict {
            id: Uuid::new_v4(),
            session_id,
            threat_level: ThreatLevel::Safe,
            confidence: 1.0,
            categories: normalized.categories,
            summary: append_scenario_context(
                format!(
                    "No security threats found ({} modules, 0 evidence clusters active)",
                    normalized.modules_run
                ),
                &normalized.scenario,
            ),
            pillar_scores: std::mem::take(&mut pillar_scores),
            modules_run: normalized.modules_run,
            modules_flagged: normalized.modules_flagged,
            total_duration_ms: normalized.total_duration_ms,
            created_at: now,
            fusion_details: Some(FusionDetails {
                fused_bpa: Bpa::vacuous(),
                k_conflict: 0.0,
                risk_single: 0.0,
                eta: config.eta,
                engine_details: Vec::new(),
                credibility_weights: HashMap::new(),
                novelty: None,
                k_cross: None,
                betp: None,
                fusion_method: Some("clustered_ds_v1".to_string()),
                circuit_breaker: None,
                convergence_breaker: None,
            }),
        };
    }

    let mut cluster_state: Vec<ClusterEvidence> = normalized.clusters.clone();
    apply_context_adjustments(&mut cluster_state, &normalized);

    let active_clusters: Vec<&ClusterEvidence> = cluster_state
        .iter()
        .filter(|cluster| cluster.score >= 0.05)
        .collect();

    if active_clusters.is_empty() {
        return SecurityVerdict {
            id: Uuid::new_v4(),
            session_id,
            threat_level: ThreatLevel::Safe,
            confidence: 1.0,
            categories: normalized.categories,
            summary: append_scenario_context(
                format!(
                    "No security threats found ({} modules, 0 evidence clusters active after normalization)",
                    normalized.modules_run
                ),
                &normalized.scenario,
            ),
            pillar_scores: std::mem::take(&mut pillar_scores),
            modules_run: normalized.modules_run,
            modules_flagged: normalized.modules_flagged,
            total_duration_ms: normalized.total_duration_ms,
            created_at: now,
            fusion_details: Some(FusionDetails {
                fused_bpa: Bpa::vacuous(),
                k_conflict: 0.0,
                risk_single: 0.0,
                eta: config.eta,
                engine_details: Vec::new(),
                credibility_weights: HashMap::new(),
                novelty: None,
                k_cross: None,
                betp: None,
                fusion_method: Some("clustered_ds_v1".to_string()),
                circuit_breaker: None,
                convergence_breaker: None,
            }),
        };
    }

    let mut cluster_bpas = Vec::with_capacity(active_clusters.len());
    let mut engine_details = Vec::with_capacity(active_clusters.len());
    let mut weight_inputs = Vec::with_capacity(active_clusters.len());

    for cluster in &active_clusters {
        let effective_score = (cluster.score * cluster.id.threat_scale()).min(1.0);
        let bpa = Bpa::from_score_confidence(effective_score, cluster.confidence);
        cluster_bpas.push((cluster.id, bpa));
        weight_inputs.push((cluster.id, (effective_score * cluster.confidence).max(0.05)));
        engine_details.push(EngineBpaDetail {
            engine_id: cluster.id.label().to_string(),
            engine_name: cluster.id.display_name().to_string(),
            bpa,
            modules: cluster.modules.clone(),
            key_factors: cluster.key_factors.clone(),
        });
    }

    let credibility_weights = normalize_weights(&weight_inputs);
    let averaged_bpa = weighted_average_bpa(&cluster_bpas, &credibility_weights);

    let mut fused = averaged_bpa;
    let mut total_k = 0.0;
    for _ in 0..cluster_bpas.len().saturating_sub(1) {
        let step = dempster_combine(fused, averaged_bpa);
        total_k = 1.0 - (1.0 - total_k) * (1.0 - step.conflict);
        fused = step.combined;
    }

    let simple_conflict = if cluster_bpas.len() > 1 {
        dempster_combine_n(&cluster_bpas.iter().map(|(_, bpa)| *bpa).collect::<Vec<_>>()).conflict
    } else {
        0.0
    };
    total_k = total_k.max(simple_conflict);

    let mut risk_single = fused.risk_score(config.eta);
    let floor_result = apply_cluster_floors_and_caps(risk_single, &cluster_state, &normalized);
    risk_single = floor_result.risk;
    let final_level = ThreatLevel::from_score(risk_single);
    let confidence = active_clusters
        .iter()
        .map(|cluster| cluster.confidence)
        .fold(0.0, f64::max)
        .max(0.55);

    let summary = build_clustered_summary(
        final_level,
        &normalized.categories,
        normalized.modules_flagged,
        normalized.modules_run,
        active_clusters.len(),
        risk_single,
        &normalized.scenario,
    );

    SecurityVerdict {
        id: Uuid::new_v4(),
        session_id,
        threat_level: final_level,
        confidence,
        categories: normalized.categories,
        summary,
        pillar_scores,
        modules_run: normalized.modules_run,
        modules_flagged: normalized.modules_flagged,
        total_duration_ms: normalized.total_duration_ms,
        created_at: now,
        fusion_details: Some(FusionDetails {
            fused_bpa: fused,
            k_conflict: total_k,
            risk_single,
            eta: config.eta,
            engine_details,
            credibility_weights: credibility_weights
                .into_iter()
                .map(|(cluster, weight)| (cluster.label().to_string(), weight))
                .collect(),
            novelty: None,
            k_cross: None,
            betp: Some(fused.pignistic_threat()),
            fusion_method: Some("clustered_ds_v1".to_string()),
            circuit_breaker: floor_result.circuit_breaker,
            convergence_breaker: floor_result.convergence_breaker,
        }),
    }
}

fn compute_pillar_scores(
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> HashMap<String, f64> {
    let mut pillar_scores_raw: [Vec<f64>; PILLAR_COUNT] = Default::default();
    for result in results
        .values()
        .filter(|result| result.module_id != "verdict")
    {
        let weight = config
            .weights
            .get(&result.module_id)
            .copied()
            .unwrap_or(1.0);
        let effective = (result.raw_score() * weight).min(1.0);
        if effective > 0.0 {
            pillar_scores_raw[result.pillar.as_index()].push(effective);
        }
    }

    let mut pillar_threat = HashMap::new();
    for &pillar in &ALL_PILLARS {
        let scores = &pillar_scores_raw[pillar.as_index()];
        let value = if scores.is_empty() {
            0.0
        } else {
            1.0 - scores.iter().fold(1.0, |acc, score| acc * (1.0 - score))
        };
        pillar_threat.insert(pillar.to_string(), value);
    }
    pillar_threat
}

fn apply_context_adjustments(clusters: &mut [ClusterEvidence], normalized: &NormalizedEvidence) {
    let mut scores: HashMap<EvidenceClusterId, f64> = clusters
        .iter()
        .map(|cluster| (cluster.id, cluster.score))
        .collect();
    let alignment = normalized.scenario.alignment_score;

    let link_raw = score_of(&scores, EvidenceClusterId::LinkAndHtmlDeception);
    let payload_raw = score_of(&scores, EvidenceClusterId::PayloadMalware);
    let identity_raw = score_of(&scores, EvidenceClusterId::SenderIdentityAuthenticity);
    let external_raw = score_of(&scores, EvidenceClusterId::ExternalReputationIoc);
    let social_raw = score_of(&scores, EvidenceClusterId::SocialEngineeringIntent);

    let strong_link = link_raw >= 0.55;
    let strong_payload = payload_raw >= 0.55;
    let strong_identity = identity_raw >= 0.55;
    let strong_external = external_raw >= 0.65;
    let corroborated_threat = has_corroborated_threat_signal(
        identity_raw,
        link_raw,
        payload_raw,
        external_raw,
        social_raw,
    );
    let gateway_independent_corroboration = gateway_banner_has_independent_corroboration(
        &normalized.scenario,
        identity_raw,
        payload_raw,
        external_raw,
    );
    let only_contextual = !strong_link
        && !strong_payload
        && !strong_identity
        && !strong_external
        && social_raw < 0.45;

    if alignment > 0.0 && !corroborated_threat {
        scale_cluster(
            &mut scores,
            EvidenceClusterId::DeliveryIntegrity,
            1.0 - 0.50 * alignment,
        );
        if !strong_identity {
            scale_cluster(
                &mut scores,
                EvidenceClusterId::SenderIdentityAuthenticity,
                1.0 - 0.22 * alignment,
            );
        }
    }

    if normalized.scenario.gateway_banner_polluted {
        scale_cluster(&mut scores, EvidenceClusterId::InheritedGatewayPrior, 0.35);
        if !strong_identity && !strong_link && !strong_payload {
            // Pure structural heuristics under a gateway banner are still
            // advisory. Only independently corroborated signals should let the
            // social-engineering cluster retain most of its weight.
            let social_scale = if gateway_independent_corroboration {
                0.88
            } else if normalized.scenario.has_structural_threat_signal {
                0.52
            } else {
                0.40
            };
            scale_cluster(
                &mut scores,
                EvidenceClusterId::SocialEngineeringIntent,
                social_scale,
            );
        }
        if !gateway_independent_corroboration && link_raw < 0.45 && payload_raw < 0.45 {
            scale_cluster(&mut scores, EvidenceClusterId::LinkAndHtmlDeception, 0.72);
            scale_cluster(&mut scores, EvidenceClusterId::BusinessSensitivity, 0.78);
        }
    }

    if normalized.scenario.notice_banner_polluted
        && !strong_identity
        && !strong_link
        && !strong_payload
        && !strong_external
    {
        scale_cluster(
            &mut scores,
            EvidenceClusterId::SocialEngineeringIntent,
            0.28,
        );
        scale_cluster(&mut scores, EvidenceClusterId::InheritedGatewayPrior, 0.25);
    }

    if normalized.scenario.dsn_like_system_mail && payload_raw < 0.45 && link_raw < 0.45 {
        scale_cluster(&mut scores, EvidenceClusterId::DeliveryIntegrity, 0.40);
        scale_cluster(
            &mut scores,
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.55,
        );
        if !strong_external {
            scale_cluster(
                &mut scores,
                EvidenceClusterId::SocialEngineeringIntent,
                0.45,
            );
        }
    }

    if normalized.scenario.auto_reply_like
        && payload_raw < 0.45
        && link_raw < 0.45
        && external_raw < 0.45
    {
        scale_cluster(
            &mut scores,
            EvidenceClusterId::SocialEngineeringIntent,
            0.35,
        );
        scale_cluster(
            &mut scores,
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.60,
        );
    }

    if normalized.scenario.semantic_nlp_only_signal
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
        && link_raw < 0.20
        && payload_raw < 0.20
        && identity_raw < 0.25
        && external_raw < 0.25
    {
        scale_cluster(
            &mut scores,
            EvidenceClusterId::SocialEngineeringIntent,
            0.58,
        );
    }

    if only_contextual {
        scale_cluster(&mut scores, EvidenceClusterId::InheritedGatewayPrior, 0.80);
        scale_cluster(&mut scores, EvidenceClusterId::BusinessSensitivity, 0.85);
    }

    for cluster in clusters {
        if let Some(score) = scores.get(&cluster.id) {
            cluster.score = score.clamp(0.0, cluster.id.score_cap());
        }
    }
}

fn apply_cluster_floors_and_caps(
    mut risk: f64,
    clusters: &[ClusterEvidence],
    normalized: &NormalizedEvidence,
) -> FloorCapResult {
    let score_map: HashMap<EvidenceClusterId, f64> = clusters
        .iter()
        .map(|cluster| (cluster.id, cluster.score))
        .collect();
    let identity = score_of(&score_map, EvidenceClusterId::SenderIdentityAuthenticity);
    let link = score_of(&score_map, EvidenceClusterId::LinkAndHtmlDeception);
    let payload = score_of(&score_map, EvidenceClusterId::PayloadMalware);
    let external = score_of(&score_map, EvidenceClusterId::ExternalReputationIoc);
    let social = score_of(&score_map, EvidenceClusterId::SocialEngineeringIntent);
    let business = score_of(&score_map, EvidenceClusterId::BusinessSensitivity);
    let inherited = score_of(&score_map, EvidenceClusterId::InheritedGatewayPrior);
    let delivery = score_of(&score_map, EvidenceClusterId::DeliveryIntegrity);
    let has_cross_locale_lure_signal = normalized.categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "japanese_to_cn_corp"
                | "foreign_to_cn_corp"
                | "japanese_unexpected"
                | "multilingual_gibberish"
        )
    });
    let structural_credential_phish = identity >= 0.10
        && link >= 0.08
        && external >= 0.12
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal;
    let payment_redirect_lure = normalized.scenario.has_payment_change_signal
        && normalized.scenario.has_credential_link_signal
        && (normalized.scenario.has_malicious_ioc_signal
            || normalized.scenario.has_structural_threat_signal);
    let gateway_independent_corroboration = gateway_banner_has_independent_corroboration(
        &normalized.scenario,
        identity,
        payload,
        external,
    );

    // ── Phase 1: Scenario-specific floors (hand-written rules) ──────────
    if payload >= 0.75 {
        risk = risk.max(payload.clamp(0.75, 0.90));
    }
    if identity >= 0.40 && link >= 0.45 {
        risk = risk.max(((identity + link) / 2.0).max(0.65));
    }
    if payload >= 0.45 && external >= 0.45 {
        risk = risk.max(0.70);
    }
    if social >= 0.55
        && link >= 0.10
        && external >= 0.20
        && normalized.scenario.has_account_security_signal
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
    {
        risk = risk.max(0.68);
    }
    if social >= 0.30
        && link >= 0.08
        && external >= 0.12
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
    {
        let credential_floor = if normalized.scenario.has_account_security_signal {
            0.68
        } else {
            0.56
        };
        risk = risk.max(credential_floor);
    }
    if identity >= 0.10
        && link >= 0.08
        && external >= 0.12
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
    {
        let structural_phish_floor = if normalized.scenario.has_account_security_signal {
            0.68
        } else {
            0.48
        };
        risk = risk.max(structural_phish_floor);
    }
    if normalized.scenario.has_account_security_signal
        && normalized.scenario.has_credential_link_signal
        && social >= 0.24
        && link >= 0.08
    {
        let account_floor = if identity >= 0.15
            || external >= 0.15
            || normalized.scenario.has_structural_threat_signal
        {
            0.56
        } else {
            0.48
        };
        risk = risk.max(account_floor);
    }
    if identity >= 0.35
        && social >= 0.40
        && business >= 0.35
        && normalized.scenario.has_payment_change_signal
    {
        risk = risk.max(0.60);
    }
    if normalized.scenario.has_account_security_signal
        && normalized.scenario.has_payment_change_signal
        && has_cross_locale_lure_signal
        && social >= 0.18
    {
        risk = risk.max(0.68);
    }
    if social >= 0.40
        && link >= 0.28
        && external >= 0.35
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
    {
        let redirect_phish_floor = if normalized.scenario.has_account_security_signal {
            0.78
        } else {
            0.70
        };
        risk = risk.max(redirect_phish_floor);
    }
    if normalized.scenario.has_subsidy_fraud_signal {
        let subsidy_floor = if link >= 0.20
            && (normalized.scenario.has_structural_threat_signal
                || normalized.scenario.has_credential_link_signal
                || external >= 0.20)
        {
            0.74
        } else {
            0.48
        };
        risk = risk.max(subsidy_floor);
    }
    if normalized.scenario.has_invoice_spam_signal {
        let invoice_floor = if link >= 0.15 || identity >= 0.20 || external >= 0.20 {
            0.56
        } else {
            0.48
        };
        risk = risk.max(invoice_floor);
    }
    if normalized.scenario.has_attachment_phishing_signal
        && payload >= 0.24
        && (link >= 0.16 || normalized.scenario.has_high_risk_attachment_content)
        && !normalized.scenario.dsn_like_system_mail
        && !normalized.scenario.auto_reply_like
    {
        let attachment_payload_floor =
            if normalized.scenario.has_high_risk_attachment_content || payload >= 0.40 {
                0.68
            } else {
                0.56
            };
        risk = risk.max(attachment_payload_floor);
    }
    if normalized.scenario.has_payment_change_signal
        && normalized.scenario.has_credential_link_signal
        && (normalized.scenario.has_malicious_ioc_signal
            || normalized.scenario.has_structural_threat_signal)
        && (external >= 0.20 || link >= 0.18)
        && (link >= 0.18 || social >= 0.20 || business >= 0.18)
    {
        risk = risk.max(0.72);
    }
    if normalized.scenario.has_high_risk_attachment_content
        && normalized.scenario.has_attachment_phishing_signal
        && normalized.scenario.has_attachment_sensitive_data_signal
    {
        risk = risk.max(0.68);
    }
    if normalized.scenario.has_crypto_wallet_signal && business >= 0.24 {
        let wallet_floor = if social >= 0.30 || external >= 0.20 || payload >= 0.25 {
            0.64
        } else {
            0.40
        };
        risk = risk.max(wallet_floor);
    }
    if normalized.scenario.has_header_spoof_signal
        && identity >= 0.35
        && business >= 0.18
        && !normalized.scenario.dsn_like_system_mail
        && !normalized.scenario.auto_reply_like
    {
        let spoofed_finance_floor = if normalized.scenario.has_payment_change_signal {
            0.62
        } else {
            0.44
        };
        risk = risk.max(spoofed_finance_floor);
    }
    if normalized.scenario.has_encrypted_attachment_signal
        && payload >= 0.12
        && (social >= 0.28 || identity >= 0.30 || link >= 0.16 || external >= 0.18)
        && !normalized.scenario.dsn_like_system_mail
        && !normalized.scenario.auto_reply_like
    {
        risk = risk.max(0.56);
    }

    // ── Phase 2: Generic cluster-level circuit breaker ──────────────────
    //
    // Safety net for scenarios not covered by hand-written floor rules.
    // When a single cluster has a strong score (>= 0.55) with decent
    // confidence (>= 0.70), D-S fusion should not dilute it below a
    // minimum floor. This is the cluster-level equivalent of the legacy
    // ds_murphy circuit breaker.
    //
    // Thresholds:
    //   - cluster score >= 0.55 (meaningful threat signal)
    //   - confidence >= 0.70 (not speculative)
    //   - floor = score * 0.80, minimum 0.40 (at least Medium)
    let mut cb_info: Option<CircuitBreakerInfo> = None;
    for cluster in clusters {
        if cluster.score >= 0.55 && cluster.confidence >= 0.70 {
            let floor = (cluster.score * 0.80).max(0.40);
            if risk < floor {
                cb_info = Some(CircuitBreakerInfo {
                    trigger_module_id: cluster.id.label().to_string(),
                    trigger_belief: cluster.score,
                    floor_value: floor,
                    original_risk: risk,
                });
                risk = floor;
            }
        }
    }

    // ── Phase 3: Cluster convergence breaker ────────────────────────────
    //
    // When 3+ independent evidence clusters have meaningful signal
    // (score >= 0.15), their convergence is strong evidence of a real
    // threat even if no single cluster is dominant. D-S fusion can dilute
    // many weak signals to Safe — this breaker prevents that.
    //
    // Floor formula: 0.35 + 0.05 * (active_count - 2), capped at 0.55.
    //   3 clusters → 0.40 (Low/Medium boundary)
    //   4 clusters → 0.45 (Medium)
    //   5 clusters → 0.50 (Medium)
    //   6+ clusters → 0.55 (Medium)
    let mut conv_info: Option<ConvergenceBreakerInfo> = None;
    let convergence_clusters: Vec<&ClusterEvidence> =
        clusters.iter().filter(|c| c.score >= 0.15).collect();
    let active_count = convergence_clusters.len();
    if active_count >= 3 {
        let convergence_floor = (0.35 + 0.05 * (active_count as f64 - 2.0)).min(0.55);
        if risk < convergence_floor {
            let flagged_modules: Vec<String> = convergence_clusters
                .iter()
                .map(|c| c.id.label().to_string())
                .collect();
            conv_info = Some(ConvergenceBreakerInfo {
                modules_flagged: active_count as u32,
                floor_value: convergence_floor,
                original_risk: risk,
                flagged_modules,
            });
            risk = convergence_floor;
        }
    }

    // ── Phase 4: Scenario-specific caps (suppress false positives) ──────
    let only_contextual = inherited > 0.0
        && link < 0.30
        && payload < 0.30
        && external < 0.40
        && identity < 0.35
        && social < 0.40;
    if only_contextual
        && !structural_credential_phish
        && !payment_redirect_lure
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.35);
    }

    let intel_only =
        external > 0.0 && identity < 0.25 && link < 0.30 && payload < 0.30 && social < 0.30;
    if intel_only && !structural_credential_phish && !payment_redirect_lure {
        risk = risk.min(0.55);
    }

    if normalized.scenario.gateway_banner_polluted
        && link < 0.45
        && payload < 0.45
        && identity < 0.45
        && external < 0.35
        && !gateway_independent_corroboration
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.35);
    }

    let gateway_prior_only_noise = inherited > 0.0
        && social < 0.08
        && identity < 0.20
        && link < 0.20
        && payload < 0.20
        && external < 0.20
        && business < 0.20
        && delivery < 0.20;
    if normalized.scenario.gateway_banner_polluted
        && gateway_prior_only_noise
        && !gateway_independent_corroboration
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.12);
    }

    let semantic_only = social > 0.0
        && identity < 0.20
        && link < 0.20
        && payload < 0.20
        && external < 0.20
        && business < 0.20
        && inherited < 0.20
        && delivery < 0.20;
    if normalized.scenario.semantic_nlp_only_signal
        && semantic_only
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
    {
        risk = risk.min(0.14);
    }

    if normalized.scenario.transcript_like_structure
        && normalized.scenario.semantic_nlp_only_signal
        && semantic_only
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
    {
        risk = risk.min(0.18);
    }

    let semantic_notice_only =
        social > 0.0 && identity < 0.25 && link < 0.25 && payload < 0.25 && external < 0.25;
    if (normalized.scenario.notice_banner_polluted
        || normalized.scenario.auto_reply_like
        || normalized.scenario.dsn_like_system_mail)
        && semantic_notice_only
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.12);
    }

    if normalized.scenario.dsn_like_system_mail
        && payload < 0.45
        && link < 0.45
        && external < 0.55
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.30_f64.max(delivery));
    }

    let dsn_identity_only = identity > 0.0
        && social < 0.20
        && link < 0.20
        && payload < 0.20
        && external < 0.20
        && business < 0.20;
    if normalized.scenario.dsn_like_system_mail
        && dsn_identity_only
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
    {
        risk = risk.min(0.12);
    }

    FloorCapResult {
        risk: risk.clamp(0.0, 0.99),
        circuit_breaker: cb_info,
        convergence_breaker: conv_info,
    }
}

fn has_corroborated_threat_signal(
    identity_raw: f64,
    link_raw: f64,
    payload_raw: f64,
    external_raw: f64,
    social_raw: f64,
) -> bool {
    if payload_raw >= 0.45 || link_raw >= 0.45 || identity_raw >= 0.55 || external_raw >= 0.65 {
        return true;
    }

    if identity_raw >= 0.10 && link_raw >= 0.08 && external_raw >= 0.12 {
        return true;
    }

    social_raw >= 0.55 && (link_raw >= 0.10 || external_raw >= 0.25 || identity_raw >= 0.35)
}

fn gateway_banner_has_independent_corroboration(
    scenario: &ScenarioContext,
    identity: f64,
    payload: f64,
    external: f64,
) -> bool {
    scenario.has_account_security_signal
        || scenario.has_credential_link_signal
        || scenario.has_malicious_ioc_signal
        || scenario.has_header_spoof_signal
        || scenario.has_payment_change_signal
        || scenario.has_subsidy_fraud_signal
        || scenario.has_invoice_spam_signal
        || scenario.has_crypto_wallet_signal
        || scenario.has_attachment_phishing_signal
        || scenario.has_high_risk_attachment_content
        || scenario.has_encrypted_attachment_signal
        || payload >= 0.45
        || external >= 0.35
        || identity >= 0.45
}

fn normalize_weights(inputs: &[(EvidenceClusterId, f64)]) -> HashMap<EvidenceClusterId, f64> {
    let total: f64 = inputs.iter().map(|(_, weight)| *weight).sum();
    if total <= 0.0 {
        let equal = 1.0 / inputs.len().max(1) as f64;
        return inputs
            .iter()
            .map(|(cluster, _)| (*cluster, equal))
            .collect::<HashMap<_, _>>();
    }

    inputs
        .iter()
        .map(|(cluster, weight)| (*cluster, *weight / total))
        .collect()
}

fn weighted_average_bpa(
    cluster_bpas: &[(EvidenceClusterId, Bpa)],
    weights: &HashMap<EvidenceClusterId, f64>,
) -> Bpa {
    let mut b = 0.0;
    let mut d = 0.0;
    let mut u = 0.0;
    for (cluster, bpa) in cluster_bpas {
        let weight = weights.get(cluster).copied().unwrap_or(0.0);
        b += weight * bpa.b;
        d += weight * bpa.d;
        u += weight * bpa.u;
    }
    Bpa::new(b, d, u)
}

fn scale_cluster(
    scores: &mut HashMap<EvidenceClusterId, f64>,
    cluster: EvidenceClusterId,
    factor: f64,
) {
    if let Some(score) = scores.get_mut(&cluster) {
        *score = (*score * factor.clamp(0.0, 1.0)).min(cluster.score_cap());
    }
}

fn score_of(scores: &HashMap<EvidenceClusterId, f64>, cluster: EvidenceClusterId) -> f64 {
    scores.get(&cluster).copied().unwrap_or(0.0)
}

fn build_clustered_summary(
    level: ThreatLevel,
    categories: &[String],
    flagged: u32,
    total: u32,
    active_clusters: usize,
    risk: f64,
    scenario: &ScenarioContext,
) -> String {
    if level == ThreatLevel::Safe {
        return append_scenario_context(
            format!(
                "No security threats found ({total} modules, {active_clusters} evidence clusters, risk={risk:.3})"
            ),
            scenario,
        );
    }

    let level_str = match level {
        ThreatLevel::Low => "Low risk",
        ThreatLevel::Medium => "Medium risk",
        ThreatLevel::High => "High risk",
        ThreatLevel::Critical => "Critical threat",
        ThreatLevel::Safe => "Safe",
    };

    let headline_categories = select_headline_categories(categories, scenario);
    let cat_str = if headline_categories.is_empty() {
        String::new()
    } else {
        format!(" ({})", headline_categories.join(", "))
    };
    append_scenario_context(
        format!(
            "{level_str}{cat_str} — {flagged}/{total} modules flagged, {active_clusters} evidence clusters active, risk={risk:.3}"
        ),
        scenario,
    )
}

fn select_headline_categories(categories: &[String], scenario: &ScenarioContext) -> Vec<String> {
    let has_strong_signal = categories
        .iter()
        .any(|category| headline_category_priority(category) >= 90);

    let mut headline: Vec<String> = categories
        .iter()
        .filter(|category| !suppress_headline_category(category, has_strong_signal, scenario))
        .cloned()
        .collect();

    if headline.is_empty() {
        headline = categories.to_vec();
    }

    headline.sort_by(|left, right| {
        headline_category_priority(right)
            .cmp(&headline_category_priority(left))
            .then_with(|| left.cmp(right))
    });
    headline.truncate(6);
    headline
}

fn suppress_headline_category(
    category: &str,
    has_strong_signal: bool,
    scenario: &ScenarioContext,
) -> bool {
    match category {
        "gateway_pre_classified" => has_strong_signal || scenario.gateway_banner_polluted,
        "nlp_phishing" | "nlp_scam" | "nlp_bec" | "nlp_spam" | "nonsensical_spam" => {
            scenario.gateway_banner_polluted && has_strong_signal
        }
        "no_auth_results" | "no_received" | "first_contact" => has_strong_signal,
        _ => false,
    }
}

fn headline_category_priority(category: &str) -> u8 {
    match category {
        "malware_hash"
        | "virus_detected"
        | "sandbox_malicious"
        | "sandbox_c2_detected"
        | "malicious_document"
        | "webshell" => 120,
        "targeted_credential_phishing"
        | "account_security_phishing"
        | "brand_spoof_reply_to"
        | "protected_domain_spoof"
        | "envelope_spoofing"
        | "display_name_spoof" => 114,
        "ioc_ip_hit"
        | "sender_ip_malicious"
        | "intel_malicious"
        | "url_intel_malicious"
        | "hash_intel_malicious" => 108,
        "recipient_in_url"
        | "at_sign_obfuscation"
        | "suspicious_params"
        | "redirect_target"
        | "redirect_url"
        | "href_text_mismatch"
        | "idn_homograph" => 103,
        "phishing" | "phishing_subject" | "bec" | "payment_change" | "wire_transfer" => 96,
        "random_domain" | "domain_mismatch" | "random_sender" => 72,
        "dlp_api_key" | "bank_account_detected" | "iban_detected" | "swift_code_detected" => 48,
        "gateway_pre_classified" => 10,
        "no_auth_results" | "no_received" | "first_contact" => 16,
        _ => 60,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests for apply_cluster_floors_and_caps (Phase 2 & Phase 3 breakers)
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::super::evidence_clusters::{
        ClusterEvidence, EvidenceClusterId, NormalizedEvidence, ScenarioContext,
    };
    use super::*;

    fn make_cluster(id: EvidenceClusterId, score: f64, confidence: f64) -> ClusterEvidence {
        ClusterEvidence {
            id,
            score,
            confidence,
            modules: vec![],
            key_factors: vec![],
        }
    }

    fn make_normalized(clusters: &[ClusterEvidence]) -> NormalizedEvidence {
        NormalizedEvidence {
            clusters: clusters.to_vec(),
            categories: vec![],
            modules_run: 15,
            modules_flagged: 0,
            total_duration_ms: 100,
            scenario: ScenarioContext::default(),
        }
    }

    // ── Phase 2: Generic cluster-level circuit breaker ──────────────────

    #[test]
    fn test_generic_cluster_floor_fires_for_strong_identity() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.65,
            0.80,
        )];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // floor = 0.65 * 0.80 = 0.52
        assert!(
            (result.risk - 0.52).abs() < 1e-9,
            "risk should be 0.52, got {}",
            result.risk
        );
        assert!(result.circuit_breaker.is_some());
        let cb = result.circuit_breaker.unwrap();
        assert_eq!(cb.trigger_module_id, "sender_identity_authenticity");
        assert!((cb.trigger_belief - 0.65).abs() < 1e-9);
        assert!((cb.floor_value - 0.52).abs() < 1e-9);
        assert!((cb.original_risk - 0.10).abs() < 1e-9);
    }

    #[test]
    fn test_generic_cluster_floor_does_not_fire_low_score() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.40, // < 0.55 threshold
            0.80,
        )];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        assert!(
            (result.risk - 0.10).abs() < 1e-9,
            "risk should remain 0.10, got {}",
            result.risk
        );
        assert!(result.circuit_breaker.is_none());
    }

    #[test]
    fn test_generic_cluster_floor_does_not_fire_low_confidence() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.60,
            0.50, // < 0.70 threshold
        )];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        assert!(
            (result.risk - 0.10).abs() < 1e-9,
            "risk should remain 0.10, got {}",
            result.risk
        );
        assert!(result.circuit_breaker.is_none());
    }

    #[test]
    fn test_generic_cluster_floor_skipped_when_risk_already_above() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.60,
            0.80,
        )];
        let normalized = make_normalized(&clusters);
        // floor = 0.60 * 0.80 = 0.48, but risk = 0.55 > 0.48
        let result = apply_cluster_floors_and_caps(0.55, &clusters, &normalized);
        assert!(
            (result.risk - 0.55).abs() < 1e-9,
            "risk should remain 0.55, got {}",
            result.risk
        );
        assert!(result.circuit_breaker.is_none());
    }

    // ── Phase 3: Cluster convergence breaker ────────────────────────────

    #[test]
    fn test_convergence_floor_fires_for_3_clusters() {
        // Use 3 clusters without InheritedGatewayPrior to avoid only_contextual cap
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
            make_cluster(EvidenceClusterId::PayloadMalware, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // floor = 0.35 + 0.05 * (3 - 2) = 0.40
        assert!(
            (result.risk - 0.40).abs() < 1e-9,
            "risk should be 0.40, got {}",
            result.risk
        );
        assert!(result.convergence_breaker.is_some());
        let conv = result.convergence_breaker.unwrap();
        assert_eq!(conv.modules_flagged, 3);
        assert!((conv.floor_value - 0.40).abs() < 1e-9);
        assert!((conv.original_risk - 0.10).abs() < 1e-9);
    }

    #[test]
    fn test_convergence_floor_scales_with_cluster_count() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.30),
            make_cluster(EvidenceClusterId::PayloadMalware, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
            make_cluster(EvidenceClusterId::DeliveryIntegrity, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // floor = 0.35 + 0.05 * (5 - 2) = 0.50
        assert!(
            (result.risk - 0.50).abs() < 1e-9,
            "risk should be 0.50, got {}",
            result.risk
        );
        assert!(result.convergence_breaker.is_some());
        assert_eq!(result.convergence_breaker.unwrap().modules_flagged, 5);
    }

    #[test]
    fn test_convergence_floor_capped_at_055() {
        // All 8 clusters; identity=0.40 to avoid only_contextual cap (needs identity < 0.35)
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.40, 0.30),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.30),
            make_cluster(EvidenceClusterId::PayloadMalware, 0.20, 0.30),
            make_cluster(EvidenceClusterId::ExternalReputationIoc, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
            make_cluster(EvidenceClusterId::DeliveryIntegrity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::InheritedGatewayPrior, 0.20, 0.30),
            make_cluster(EvidenceClusterId::BusinessSensitivity, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // formula = 0.35 + 0.05 * (8 - 2) = 0.65, capped at 0.55
        assert!(
            (result.risk - 0.55).abs() < 1e-9,
            "risk should be 0.55 (convergence capped), got {}",
            result.risk
        );
        assert!(result.convergence_breaker.is_some());
        assert_eq!(result.convergence_breaker.unwrap().modules_flagged, 8);
    }

    #[test]
    fn test_convergence_floor_does_not_fire_below_3() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        assert!(
            (result.risk - 0.10).abs() < 1e-9,
            "risk should remain 0.10, got {}",
            result.risk
        );
        assert!(result.convergence_breaker.is_none());
    }

    // ── Phase 4: Cap overrides breaker ──────────────────────────────────

    #[test]
    fn test_cap_overrides_convergence_floor() {
        // 3 clusters including InheritedGatewayPrior → only_contextual cap fires at 0.35
        // (inherited=0.20>0, link=0<0.30, payload=0<0.30, external=0<0.40,
        //  identity=0.20<0.35, social=0<0.40)
        let clusters = vec![
            make_cluster(EvidenceClusterId::InheritedGatewayPrior, 0.20, 0.30),
            make_cluster(EvidenceClusterId::DeliveryIntegrity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // Convergence floor = 0.40, then only_contextual cap → 0.35
        assert!(
            (result.risk - 0.35).abs() < 1e-9,
            "risk should be capped at 0.35, got {}",
            result.risk
        );
        // Convergence breaker was activated (before cap overrode it)
        assert!(result.convergence_breaker.is_some());
    }

    // ── Gateway-banner pollution only escapes with independent corroboration ──

    #[test]
    fn test_gateway_banner_cap_fires_without_structural_signal() {
        // gateway_banner_polluted + no structural signals → cap at 0.35
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.40,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        let result = apply_cluster_floors_and_caps(0.42, &clusters, &normalized);
        assert!(
            (result.risk - 0.35).abs() < 1e-9,
            "risk should be capped at 0.35 (no structural signal), got {}",
            result.risk
        );
    }

    #[test]
    fn test_gateway_banner_cap_still_fires_for_structural_only_signal() {
        // gateway_banner_polluted + structural heuristics alone should stay capped.
        let clusters = vec![
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.40, 0.80),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.70),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        normalized.scenario.has_structural_threat_signal = true;
        let result = apply_cluster_floors_and_caps(0.42, &clusters, &normalized);
        assert!(
            (result.risk - 0.35).abs() < 1e-9,
            "risk should remain capped at 0.35 (structural-only under gateway banner), got {}",
            result.risk
        );
    }

    #[test]
    fn test_gateway_prior_only_noise_stays_capped_for_structural_only_signal() {
        // gateway_banner_polluted + gateway_prior_only_noise + structural-only heuristics
        // should still collapse to gateway noise.
        let clusters = vec![make_cluster(
            EvidenceClusterId::InheritedGatewayPrior,
            0.15,
            0.30,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        normalized.scenario.has_structural_threat_signal = true;
        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);
        assert!(
            (result.risk - 0.12).abs() < 1e-9,
            "risk should remain capped at 0.12 (structural-only under gateway banner), got {}",
            result.risk
        );
    }

    #[test]
    fn test_gateway_banner_cap_escapes_with_independent_ioc_signal() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.40, 0.80),
            make_cluster(EvidenceClusterId::ExternalReputationIoc, 0.44, 0.86),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        normalized.scenario.has_malicious_ioc_signal = true;

        let result = apply_cluster_floors_and_caps(0.42, &clusters, &normalized);

        assert!(
            result.risk > 0.35,
            "independent IOC corroboration should escape gateway-only cap, got {}",
            result.risk
        );
    }

    #[test]
    fn test_gateway_prior_only_noise_cap_fires_without_structural() {
        // gateway_banner_polluted + gateway_prior_only_noise, no structural
        // → cap at 0.12
        let clusters = vec![make_cluster(
            EvidenceClusterId::InheritedGatewayPrior,
            0.15,
            0.30,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);
        assert!(
            (result.risk - 0.12).abs() < 1e-9,
            "risk should be capped at 0.12 (no structural signal), got {}",
            result.risk
        );
    }

    #[test]
    fn test_gateway_banner_cap_does_not_collapse_invoice_spam_signal() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.34,
            0.84,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.gateway_banner_polluted = true;
        normalized.scenario.has_invoice_spam_signal = true;

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            (result.risk - 0.48).abs() < 1e-9,
            "gateway noise caps should not collapse invoice-spam signals, got {}",
            result.risk
        );
    }

    #[test]
    fn test_dsn_cap_does_not_collapse_subsidy_signal() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.28,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.dsn_like_system_mail = true;
        normalized.scenario.has_subsidy_fraud_signal = true;

        let result = apply_cluster_floors_and_caps(0.12, &clusters, &normalized);

        assert!(
            (result.risk - 0.48).abs() < 1e-9,
            "dsn-like senders should not suppress subsidy-fraud signals to Safe/Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_redirect_ioc_phish_without_sender_spoof_gets_high_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.42, 0.88),
            make_cluster(EvidenceClusterId::ExternalReputationIoc, 0.48, 0.90),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.52, 0.86),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_credential_link_signal = true;
        normalized.scenario.has_malicious_ioc_signal = true;

        let result = apply_cluster_floors_and_caps(0.34, &clusters, &normalized);

        assert!(
            (result.risk - 0.70).abs() < 1e-9,
            "malicious redirect phishing should hold a High floor, got {}",
            result.risk
        );
    }

    #[test]
    fn test_subsidy_fraud_with_structural_link_signal_gets_high_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.30, 0.82),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.50, 0.88),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_subsidy_fraud_signal = true;
        normalized.scenario.has_structural_threat_signal = true;

        let result = apply_cluster_floors_and_caps(0.36, &clusters, &normalized);

        assert!(
            (result.risk - 0.74).abs() < 1e-9,
            "subsidy fraud with structural corroboration should not stay Medium, got {}",
            result.risk
        );
    }

    #[test]
    fn test_subsidy_fraud_without_link_still_gets_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.42,
            0.86,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_subsidy_fraud_signal = true;

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            (result.risk - 0.48).abs() < 1e-9,
            "external subsidy-fraud themes should not remain Safe/Low without link corroboration, got {}",
            result.risk
        );
    }

    #[test]
    fn test_invoice_spam_signal_gets_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.44,
            0.88,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_invoice_spam_signal = true;

        let result = apply_cluster_floors_and_caps(0.16, &clusters, &normalized);

        assert!(
            (result.risk - 0.48).abs() < 1e-9,
            "invoice-spam solicitations should not remain Safe/Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_attachment_phish_with_sensitive_data_gets_high_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.48,
            0.84,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_high_risk_attachment_content = true;
        normalized.scenario.has_attachment_phishing_signal = true;
        normalized.scenario.has_attachment_sensitive_data_signal = true;

        let result = apply_cluster_floors_and_caps(0.42, &clusters, &normalized);

        assert!(
            (result.risk - 0.68).abs() < 1e-9,
            "attachment phishing with sensitive data should be uplifted to High, got {}",
            result.risk
        );
    }

    #[test]
    fn test_attachment_phish_with_payload_signal_gets_medium_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.26, 0.82),
            make_cluster(EvidenceClusterId::PayloadMalware, 0.34, 0.88),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_attachment_phishing_signal = true;

        let result = apply_cluster_floors_and_caps(0.28, &clusters, &normalized);

        assert!(
            (result.risk - 0.56).abs() < 1e-9,
            "attachment phishing backed by payload evidence should not remain Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_account_security_with_link_gets_medium_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.28, 0.86),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.12, 0.78),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_account_security_signal = true;
        normalized.scenario.has_credential_link_signal = true;

        let result = apply_cluster_floors_and_caps(0.27, &clusters, &normalized);

        assert!(
            (result.risk - 0.48).abs() < 1e-9,
            "account-security lures with credential links should not remain Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_cross_locale_account_lure_with_payment_signal_gets_high_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.24, 0.84),
            make_cluster(EvidenceClusterId::BusinessSensitivity, 0.18, 0.76),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_account_security_signal = true;
        normalized.scenario.has_payment_change_signal = true;
        normalized
            .categories
            .extend([
                "japanese_to_cn_corp".to_string(),
                "multilingual_gibberish".to_string(),
            ]);

        let result = apply_cluster_floors_and_caps(0.32, &clusters, &normalized);

        assert!(
            (result.risk - 0.68).abs() < 1e-9,
            "cross-locale account-payment lures should be uplifted to High, got {}",
            result.risk
        );
    }

    #[test]
    fn test_payment_update_lure_with_redirect_and_ioc_gets_high_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.24, 0.82),
            make_cluster(EvidenceClusterId::ExternalReputationIoc, 0.48, 0.88),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.22, 0.76),
            make_cluster(EvidenceClusterId::BusinessSensitivity, 0.20, 0.74),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_payment_change_signal = true;
        normalized.scenario.has_credential_link_signal = true;
        normalized.scenario.has_malicious_ioc_signal = true;

        let result = apply_cluster_floors_and_caps(0.56, &clusters, &normalized);

        assert!(
            (result.risk - 0.72).abs() < 1e-9,
            "payment-update redirect phish should be uplifted to High, got {}",
            result.risk
        );
    }

    #[test]
    fn test_crypto_wallet_signal_forces_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::BusinessSensitivity,
            0.30,
            0.86,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_crypto_wallet_signal = true;

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            (result.risk - 0.40).abs() < 1e-9,
            "standalone crypto wallet demands should not remain Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_header_spoof_plus_financial_context_gets_medium_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.44, 0.82),
            make_cluster(EvidenceClusterId::BusinessSensitivity, 0.22, 0.78),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_header_spoof_signal = true;

        let result = apply_cluster_floors_and_caps(0.24, &clusters, &normalized);

        assert!(
            (result.risk - 0.44).abs() < 1e-9,
            "spoofed sender plus financial context should not collapse to Low, got {}",
            result.risk
        );
    }

    #[test]
    fn test_encrypted_attachment_plus_social_signal_gets_medium_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::PayloadMalware, 0.16, 0.82),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.34, 0.80),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_encrypted_attachment_signal = true;

        let result = apply_cluster_floors_and_caps(0.26, &clusters, &normalized);

        assert!(
            (result.risk - 0.56).abs() < 1e-9,
            "encrypted attachment plus social lure should be uplifted to Medium, got {}",
            result.risk
        );
    }
}
