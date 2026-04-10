use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{
    ALL_PILLARS, Bpa, EngineBpaDetail, FusionDetails, ModuleResult, PILLAR_COUNT, SecurityVerdict,
    ThreatLevel, dempster_combine, dempster_combine_n,
};

use crate::config::VerdictConfig;

use super::empty_verdict;
use super::evidence_clusters::{
    ClusterEvidence, EvidenceClusterId, NormalizedEvidence, ScenarioContext,
    normalize_results,
};

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
            summary: format!(
                "No security threats found ({} modules, 0 evidence clusters active)",
                normalized.modules_run
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
            summary: format!(
                "No security threats found ({} modules, 0 evidence clusters active after normalization)",
                normalized.modules_run
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
        dempster_combine_n(
            &cluster_bpas
                .iter()
                .map(|(_, bpa)| *bpa)
                .collect::<Vec<_>>(),
        )
        .conflict
    } else {
        0.0
    };
    total_k = total_k.max(simple_conflict);

    let mut risk_single = fused.risk_score(config.eta);
    risk_single = apply_cluster_floors_and_caps(risk_single, &cluster_state, &normalized);
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
            circuit_breaker: None,
            convergence_breaker: None,
        }),
    }
}

fn compute_pillar_scores(
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> HashMap<String, f64> {
    let mut pillar_scores_raw: [Vec<f64>; PILLAR_COUNT] = Default::default();
    for result in results.values().filter(|result| result.module_id != "verdict") {
        let weight = config.weights.get(&result.module_id).copied().unwrap_or(1.0);
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
    let mut scores: HashMap<EvidenceClusterId, f64> =
        clusters.iter().map(|cluster| (cluster.id, cluster.score)).collect();
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
            scale_cluster(&mut scores, EvidenceClusterId::SocialEngineeringIntent, 0.72);
        }
    }

    if normalized.scenario.notice_banner_polluted
        && !strong_identity
        && !strong_link
        && !strong_payload
        && !strong_external
    {
        scale_cluster(&mut scores, EvidenceClusterId::SocialEngineeringIntent, 0.28);
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

    if normalized.scenario.auto_reply_like && payload_raw < 0.45 && link_raw < 0.45 && external_raw < 0.45
    {
        scale_cluster(&mut scores, EvidenceClusterId::SocialEngineeringIntent, 0.35);
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
        scale_cluster(&mut scores, EvidenceClusterId::SocialEngineeringIntent, 0.58);
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
) -> f64 {
    let score_map: HashMap<EvidenceClusterId, f64> =
        clusters.iter().map(|cluster| (cluster.id, cluster.score)).collect();
    let identity = score_of(&score_map, EvidenceClusterId::SenderIdentityAuthenticity);
    let link = score_of(&score_map, EvidenceClusterId::LinkAndHtmlDeception);
    let payload = score_of(&score_map, EvidenceClusterId::PayloadMalware);
    let external = score_of(&score_map, EvidenceClusterId::ExternalReputationIoc);
    let social = score_of(&score_map, EvidenceClusterId::SocialEngineeringIntent);
    let business = score_of(&score_map, EvidenceClusterId::BusinessSensitivity);
    let inherited = score_of(&score_map, EvidenceClusterId::InheritedGatewayPrior);
    let delivery = score_of(&score_map, EvidenceClusterId::DeliveryIntegrity);
    let structural_credential_phish = identity >= 0.10
        && link >= 0.08
        && external >= 0.12
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal;

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
    if identity >= 0.35
        && social >= 0.40
        && business >= 0.35
        && normalized.scenario.has_payment_change_signal
    {
        risk = risk.max(0.60);
    }

    let only_contextual = inherited > 0.0
        && link < 0.30
        && payload < 0.30
        && external < 0.40
        && identity < 0.35
        && social < 0.40;
    if only_contextual && !structural_credential_phish {
        risk = risk.min(0.35);
    }

    let intel_only = external > 0.0
        && identity < 0.25
        && link < 0.30
        && payload < 0.30
        && social < 0.30;
    if intel_only && !structural_credential_phish {
        risk = risk.min(0.55);
    }

    if normalized.scenario.gateway_banner_polluted
        && link < 0.45
        && payload < 0.45
        && identity < 0.45
        && external < 0.35
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
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
    if normalized.scenario.gateway_banner_polluted && gateway_prior_only_noise {
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
        risk = risk.min(0.24);
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

    let semantic_notice_only = social > 0.0
        && identity < 0.25
        && link < 0.25
        && payload < 0.25
        && external < 0.25;
    if (normalized.scenario.notice_banner_polluted
        || normalized.scenario.auto_reply_like
        || normalized.scenario.dsn_like_system_mail)
        && semantic_notice_only
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
    {
        risk = risk.min(0.12);
    }

    if normalized.scenario.dsn_like_system_mail
        && payload < 0.45
        && link < 0.45
        && external < 0.55
    {
        risk = risk.min(0.30_f64.max(delivery));
    }

    let dsn_identity_only = identity > 0.0
        && social < 0.20
        && link < 0.20
        && payload < 0.20
        && external < 0.20
        && business < 0.20;
    if normalized.scenario.dsn_like_system_mail && dsn_identity_only {
        risk = risk.min(0.12);
    }

    risk.clamp(0.0, 0.99)
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
    let context_str = if scenario.tags.is_empty() {
        String::new()
    } else {
        format!(" [context: {}]", scenario.tags.join(", "))
    };

    if level == ThreatLevel::Safe {
        return format!(
            "No security threats found ({total} modules, {active_clusters} evidence clusters, risk={risk:.3}){context_str}"
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
    format!(
        "{level_str}{cat_str} — {flagged}/{total} modules flagged, {active_clusters} evidence clusters active, risk={risk:.3}{context_str}"
    )
}

fn select_headline_categories(
    categories: &[String],
    scenario: &ScenarioContext,
) -> Vec<String> {
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
