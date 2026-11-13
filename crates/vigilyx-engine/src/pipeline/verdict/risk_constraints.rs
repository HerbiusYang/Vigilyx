use std::collections::{BTreeSet, HashMap};

use vigilyx_core::security::{
    ALL_PILLARS, CircuitBreakerInfo, ConvergenceBreakerInfo, ModuleResult, PILLAR_COUNT,
    ThreatLevel,
};

use crate::config::VerdictConfig;

// Named risk constraints shared by the authoritative V2 model. No fusion algorithm lives here.
use super::evidence_clusters::{
    ClusterEvidence, EvidenceClusterId, FORGED_SENDER_ACCOUNT_LURE, FORGED_SENDER_LINK_LURE,
    FORGED_SENDER_LINK_LURE_CORROBORATED, FORGED_SENDER_UNAUTHENTICATED, NormalizedEvidence,
    ScenarioContext, credential_brand_target_scenario_policy,
    high_confidence_link_impersonation_policy, image_only_phishing_medium_policy,
    is_runtime_causal_key, obfuscated_domain_lure_verdict_policy,
};

/// Result of floor/cap adjustments, including breaker activation records.
pub(super) struct FloorCapResult {
    pub(super) risk: f64,
    pub(super) circuit_breaker: Option<CircuitBreakerInfo>,
    pub(super) convergence_breaker: Option<ConvergenceBreakerInfo>,
}

pub(super) fn append_scenario_context(summary: String, scenario: &ScenarioContext) -> String {
    if scenario.tags.is_empty() {
        summary
    } else {
        format!("{summary} [context: {}]", scenario.tags.join(", "))
    }
}

/// Compare source views atomically. A cluster containing A and B cannot
/// bridge those independent sources into one component.
fn independent_cluster_sources(
    clusters: &[ClusterEvidence],
    thresholds: &[(EvidenceClusterId, f64)],
) -> bool {
    let selected = clusters
        .iter()
        .filter_map(|cluster| {
            let threshold = thresholds.iter().find(|(id, _)| *id == cluster.id)?.1;
            cluster
                .causal_atoms
                .iter()
                .any(|atom| atom.score >= threshold && atom.score > 1e-12)
                .then_some((cluster, threshold))
        })
        .collect::<Vec<_>>();
    if selected.iter().any(|(cluster, threshold)| {
        !cluster.causal_atoms.iter().any(|atom| {
            atom.score >= *threshold
                && atom.score > 1e-12
                && is_runtime_causal_key(&atom.causal_key)
        })
    }) {
        return false;
    }
    let sources = selected
        .iter()
        .flat_map(|(cluster, threshold)| {
            cluster
                .causal_atoms
                .iter()
                .filter(move |atom| {
                    atom.score >= *threshold
                        && atom.score > 1e-12
                        && is_runtime_causal_key(&atom.causal_key)
                })
                .map(move |atom| (cluster.id, atom.causal_key.as_str()))
        })
        .collect::<Vec<_>>();
    sources.iter().any(|(left_cluster, left_key)| {
        sources.iter().any(|(right_cluster, right_key)| {
            left_cluster != right_cluster && left_key != right_key
        })
    })
}

pub(super) fn zero_cluster_contextual_risk(normalized: &NormalizedEvidence) -> f64 {
    let image_only_dga_asset = normalized.scenario.image_only_layout_observed
        && !normalized.scenario.sender_alignment_verified
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "dga_random_domain")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "suspicious_tld");

    let image_only_floor: f64 = if image_only_dga_asset { 0.40 } else { 0.0 };
    image_only_floor.max(forged_sender_compound_floor(&normalized.scenario))
}

/// Floor for the named forged-sender compounds (see `forged_sender_compounds`
/// in evidence_clusters). Their inputs are observation-only, so the compound
/// usually arrives with no evidence cluster at all; without this floor the
/// combination stays Safe. A link or authentication compound is a Low review
/// finding; an account lure or independent corroboration makes it Medium.
fn forged_sender_compound_floor(scenario: &ScenarioContext) -> f64 {
    let admitted = |name: &str| scenario.admitted_categories.contains(name);
    if admitted(FORGED_SENDER_ACCOUNT_LURE) || admitted(FORGED_SENDER_LINK_LURE_CORROBORATED) {
        0.40
    } else if admitted(FORGED_SENDER_LINK_LURE) || admitted(FORGED_SENDER_UNAUTHENTICATED) {
        0.20
    } else {
        0.0
    }
}

pub(super) fn compute_pillar_scores(
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

pub(super) fn apply_context_adjustments(
    clusters: &mut [ClusterEvidence],
    normalized: &NormalizedEvidence,
) {
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
        && social_raw < 0.45
        && !has_qualified_gateway_credential_target(&normalized.scenario);

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
            let adjusted = score.clamp(0.0, cluster.id.score_cap());
            let factor = if cluster.score > 1e-12 {
                adjusted / cluster.score
            } else {
                0.0
            };
            for atom in &mut cluster.causal_atoms {
                atom.score = (atom.score * factor).clamp(0.0, cluster.id.score_cap());
            }
            cluster.score = adjusted;
        }
    }
}

pub(super) fn apply_cluster_floors_and_caps_with_config(
    mut risk: f64,
    clusters: &[ClusterEvidence],
    normalized: &NormalizedEvidence,
    config: &VerdictConfig,
) -> FloorCapResult {
    let score_map: HashMap<EvidenceClusterId, f64> = clusters
        .iter()
        .map(|cluster| {
            (
                cluster.id,
                cluster
                    .causal_atoms
                    .iter()
                    .map(|atom| atom.score)
                    .fold(0.0, f64::max),
            )
        })
        .collect();
    let identity = score_of(&score_map, EvidenceClusterId::SenderIdentityAuthenticity);
    let link = score_of(&score_map, EvidenceClusterId::LinkAndHtmlDeception);
    let payload = score_of(&score_map, EvidenceClusterId::PayloadMalware);
    let external = score_of(&score_map, EvidenceClusterId::ExternalReputationIoc);
    let social = score_of(&score_map, EvidenceClusterId::SocialEngineeringIntent);
    let business = score_of(&score_map, EvidenceClusterId::BusinessSensitivity);
    let inherited = score_of(&score_map, EvidenceClusterId::InheritedGatewayPrior);
    let delivery = score_of(&score_map, EvidenceClusterId::DeliveryIntegrity);
    let has_cross_locale_lure_signal =
        normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| {
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
    let credential_brand_policy = credential_brand_target_scenario_policy();
    let structural_credential_lure =
        normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| {
                category == "aitm_hosted_credential_lure"
                    || credential_brand_policy
                        .as_ref()
                        .is_some_and(|policy| category == &policy.credential_link_category)
            });
    let gateway_unwrapped_target_lure =
        has_qualified_gateway_credential_target(&normalized.scenario);
    let image_only_active_target = normalized.scenario.image_only_layout_observed
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| {
                matches!(
                    category.as_str(),
                    "ip_url"
                        | "javascript_uri"
                        | "data_uri"
                        | "at_sign_obfuscation"
                        | "idn_homograph"
                        | "mixed_script_domain"
                )
            });
    let image_only_dga_asset = normalized.scenario.image_only_layout_observed
        && !normalized.scenario.sender_alignment_verified
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "dga_random_domain")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "suspicious_tld");

    // ── Phase 1: Scenario-specific floors (hand-written rules) ──────────
    if let Some(policy) = credential_brand_policy.as_ref()
        && normalized.scenario.qualified_credential_brand_target
        && normalized.scenario.has_account_security_signal
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_high_risk_credential_target_signal
        && normalized.scenario.has_brand_sender_target_mismatch_signal
        && identity >= policy.minimum_identity_score
        && link >= policy.minimum_link_score
        && social >= policy.minimum_social_score
    {
        // This is the strength of one admitted native relation. The CTA,
        // target and identity aliases are not three convergence votes.
        risk = risk.max(policy.verdict_floor);
    }
    if let Some(policy) = credential_brand_policy.as_ref()
        && gateway_unwrapped_target_lure
        && link >= policy.minimum_redirect_link_score
    {
        risk = risk.max(policy.redirect_target_floor);
    }
    if payload >= 0.75 {
        risk = risk.max(payload.clamp(0.75, 0.90));
    }
    if identity >= 0.40
        && link >= 0.45
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SenderIdentityAuthenticity, 0.40),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.45),
            ],
        )
    {
        risk = risk.max(((identity + link) / 2.0).max(0.65));
    }
    if payload >= 0.45
        && external >= 0.45
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::PayloadMalware, 0.45),
                (EvidenceClusterId::ExternalReputationIoc, 0.45),
            ],
        )
    {
        risk = risk.max(0.70);
    }
    if social >= 0.55
        && link >= 0.10
        && external >= 0.20
        && normalized.scenario.has_account_security_signal
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SocialEngineeringIntent, 0.55),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.10),
                (EvidenceClusterId::ExternalReputationIoc, 0.20),
            ],
        )
    {
        risk = risk.max(0.68);
    }
    if social >= 0.30
        && link >= 0.08
        && external >= 0.12
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SocialEngineeringIntent, 0.30),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.08),
                (EvidenceClusterId::ExternalReputationIoc, 0.12),
            ],
        )
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
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SenderIdentityAuthenticity, 0.10),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.08),
                (EvidenceClusterId::ExternalReputationIoc, 0.12),
            ],
        )
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
        && (social >= 0.24 || structural_credential_lure)
        && link >= 0.08
    {
        let account_floor = if (identity >= 0.15
            || external >= 0.15
            || normalized.scenario.has_structural_threat_signal)
            && independent_cluster_sources(
                clusters,
                &[
                    (EvidenceClusterId::SenderIdentityAuthenticity, 0.15),
                    (EvidenceClusterId::ExternalReputationIoc, 0.15),
                    (EvidenceClusterId::SocialEngineeringIntent, 0.24),
                    (EvidenceClusterId::LinkAndHtmlDeception, 0.08),
                ],
            ) {
            0.56
        } else {
            0.48
        };
        risk = risk.max(account_floor);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized.scenario.has_account_security_signal
        && social >= 0.35
    {
        // The content module can produce a Medium account-security result
        // without a credential URL (for example, a direct password request).
        // Its social cluster is still actionable evidence; do not let DS
        // dilution turn that explicit Medium finding into a Low verdict.
        // Subject-only observations have no social cluster and therefore do
        // not enter this floor.
        risk = risk.max(0.40);
    }
    // Named forged-sender compounds; DSN, auto-reply and gateway caps below
    // still apply to them.
    risk = risk.max(forged_sender_compound_floor(&normalized.scenario));
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "aitm_hosted_credential_lure")
        && normalized.scenario.has_credential_link_signal
        && link >= 0.20
    {
        risk = risk.max(0.48);
    }
    if image_only_active_target && link >= 0.16 {
        risk = risk.max(0.48);
    }
    if image_only_dga_asset {
        // A text-empty remote-image message plus both a DGA-shaped host and a
        // high-risk TLD is a named delivery compound, not three independent
        // votes.  Require unverified alignment so legitimate authenticated
        // marketing/CDN mail does not inherit this floor.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "invoice_fraud")
    {
        // `invoice_fraud` is a named obfuscated-invoice + off-platform-contact
        // compound.  It is distinct from the non-threat `invoice_spam`
        // observation and must remain at least Medium for inline quarantine.
        risk = risk.max(0.48);
    }
    if normalized
        .scenario
        .qualified_link_compounds
        .contains("qr_ip_login_chain")
        && link >= 0.20
    {
        // A decoded QR target is still only an observation in isolation. The
        // named compound requires an explicit scan lure, an IP-literal host,
        // and a login/auth path; once the link cluster confirms that chain it
        // must not be diluted below the MTA quarantine threshold.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .qualified_link_compounds
        .contains("ip_action_target")
        && link >= 0.20
    {
        // Public IP + auth/action path + recipient CTA is a named landing
        // target chain. It must not remain below the MTA quarantine floor
        // merely because the body language is otherwise neutral.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| {
            matches!(
                category.as_str(),
                "shared_hosted_redirect_lure"
                    | "embedded_image_qr_lure"
                    | "embedded_iframe_auth_lure"
                    | "office_active_content_lure"
            )
        })
    {
        // These are structural compounds emitted only after their embedded
        // target/document and recipient-facing context have both matched.
        // Keep them at the named Medium floor so a single high-quality signal
        // is not diluted below quarantine by unrelated safe pillars.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "toad_callback_verb")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "toad_phone_present")
    {
        // Callback verb + callable phone is the irreducible TOAD compound;
        // urgency and brand cues are corroboration, not prerequisites for
        // keeping this concrete social-engineering signal at Medium.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "subject_account_expiry_lure")
        && social >= 0.12
    {
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| {
            matches!(
                category.as_str(),
                "authority_display_name_lure" | "authority_localpart_lure"
            )
        })
    {
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "mailbox_enumeration_probe")
    {
        // The anomaly module emits this only for the complete
        // external-sender -> single-internal-recipient -> exact generated
        // subject/local-part composite. Keep the promotion named so a lone
        // random sender or ordinary account identifier remains below Medium.
        risk = risk.max(0.40);
    }
    if let Some(policy) = image_only_phishing_medium_policy()
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == &policy.trigger_category)
        && social >= policy.minimum_social_score
        && (!policy.require_unverified_sender || !normalized.scenario.sender_alignment_verified)
    {
        // `image_only_phishing` is already a composite detector result: the
        // short image-dominant layout must contain a parser-marked suspicious
        // clickable link. Keep the promotion named and policy-controlled so
        // the ordinary `image_only_layout_observed` observation stays below
        // Medium and global fusion parameters remain unchanged.
        risk = risk.max(policy.verdict_floor);
    }
    if let Some(policy) = high_confidence_link_impersonation_policy()
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| {
                policy
                    .trigger_categories
                    .iter()
                    .any(|trigger| trigger == category)
            })
    {
        // These categories are emitted only for an official-domain anchor
        // mismatch, the sender's exact domain grafted onto an unrelated
        // registered host, or userinfo that makes the browser connect to a
        // different host than the authority appears to show. Generic href
        // mismatches retain their existing lower score and do not receive
        // this floor.
        risk = risk.max(policy.verdict_floor);
    }
    if let Some(policy) = obfuscated_domain_lure_verdict_policy()
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == &policy.result_category)
        && social >= policy.minimum_social_score
    {
        // Content detectors emit this named compound only for a lure plus a
        // destination obfuscation: either an alphanumeric CJK dot-word target
        // or an action-bearing bare host with a confusable common suffix.
        // Neither the lure nor destination observation enters fusion alone.
        risk = risk.max(policy.verdict_floor);
    }
    if identity >= 0.35
        && social >= 0.40
        && business >= 0.35
        && normalized.scenario.has_payment_change_signal
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SenderIdentityAuthenticity, 0.35),
                (EvidenceClusterId::SocialEngineeringIntent, 0.40),
                (EvidenceClusterId::BusinessSensitivity, 0.35),
            ],
        )
    {
        risk = risk.max(0.60);
    }
    // A payment-account-change signal standing on its own (single
    // BusinessSensitivity cluster, no identity/link/IOC corroboration) is
    // still concrete BEC evidence. D-S fusion can dilute one capped
    // (0.45) cluster below Medium — do not let a pure-text payment-change
    // mail fall under 0.40.
    if normalized.scenario.has_payment_change_signal
        && business >= 0.35
        && !normalized.scenario.sender_alignment_verified
    {
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "bec_payment_change")
        && normalized.scenario.has_payment_change_signal
        && business >= 0.25
        && !normalized.scenario.sender_alignment_verified
    {
        // The content detector already required an external sender, a
        // payment-account-change cue, and either two supporting dimensions or
        // a paired action request. Preserve that named BEC compound when one
        // fusion cluster is otherwise diluted below Medium.
        risk = risk.max(0.40);
    }
    if normalized.scenario.has_account_security_signal
        && normalized.scenario.has_payment_change_signal
        && has_cross_locale_lure_signal
        && social >= 0.18
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SocialEngineeringIntent, 0.18),
                (EvidenceClusterId::BusinessSensitivity, 0.00),
            ],
        )
    {
        risk = risk.max(0.68);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "gateway_pre_classified")
        && normalized.scenario.gateway_banner_polluted
        && social >= 0.10
    {
        // A gateway/banner prefix must not erase a complete recipient-facing
        // account lure. This floor is scoped to the named sanitizer-evasion
        // compound; it does not alter the global gateway or account threshold.
        risk = risk.max(0.40);
    }
    if social >= 0.40
        && link >= 0.28
        && external >= 0.35
        && normalized.scenario.has_credential_link_signal
        && normalized.scenario.has_malicious_ioc_signal
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SocialEngineeringIntent, 0.40),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.28),
                (EvidenceClusterId::ExternalReputationIoc, 0.35),
            ],
        )
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
            && independent_cluster_sources(
                clusters,
                &[
                    (EvidenceClusterId::SocialEngineeringIntent, 0.01),
                    (EvidenceClusterId::LinkAndHtmlDeception, 0.20),
                    (EvidenceClusterId::ExternalReputationIoc, 0.20),
                ],
            ) {
            0.74
        } else {
            0.48
        };
        risk = risk.max(subsidy_floor);
    }
    let qualified_attachment_container =
        normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| {
                matches!(
                    category.as_str(),
                    "attachment_credential_form" | "nested_message_phishing"
                )
            });
    if normalized.scenario.has_attachment_phishing_signal
        && normalized.scenario.has_structural_threat_signal
        && qualified_attachment_container
        && link >= 0.30
        && !normalized.scenario.dsn_like_system_mail
        && !normalized.scenario.auto_reply_like
    {
        risk = risk.max(0.56);
    }
    if normalized.scenario.has_attachment_phishing_signal
        && payload >= 0.24
        && (link >= 0.16 || normalized.scenario.has_high_risk_attachment_content)
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::PayloadMalware, 0.24),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.16),
            ],
        )
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
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "dangerous_extension")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| matches!(category.as_str(), "mime_mismatch" | "type_mismatch"))
        && payload >= 0.24
    {
        // Executable extension plus a MIME mismatch is a concrete disguise
        // signal. Keep it distinct from a generic MIME mismatch so ordinary
        // document/attachment type drift is not promoted.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "dangerous_container_lure")
        && payload >= 0.24
    {
        risk = risk.max(0.48);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| {
            matches!(
                category.as_str(),
                "polyglot_container"
                    | "executable_delivery_lure"
                    | "external_executable_attachment"
            )
        })
        && payload >= 0.24
    {
        // These categories are admitted only after structural attachment
        // evidence; keep a concrete executable/container delivery above the
        // inline quarantine boundary without changing unrelated attachment
        // or global severity thresholds.
        risk = risk.max(0.48);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "html_smuggling")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "active_content" || category == "html_active_content")
    {
        // An HTML attachment carrying an embedded active payload is a
        // concrete smuggling path, not a generic HTML document observation.
        risk = risk.max(0.60);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "pdf_active_payload")
        && payload >= 0.18
    {
        // Generic PDF JavaScript and form/navigation actions are observations.
        // Only separately qualified script behavior or a Launch action gets
        // the active-payload floor needed to survive DS dilution.
        risk = risk.max(0.48);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "toad_combo")
    {
        // The TOAD module only emits this compound after callback language,
        // a callable number, and urgency/brand context agree. Keep that
        // named pure-text attack above the inline quarantine boundary without
        // promoting ordinary phone signatures or callback words alone.
        risk = risk.max(0.48);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| {
            if matches!(
                category.as_str(),
                "external_action_link_lure" | "pii_collection_lure"
            ) {
                return normalized
                    .scenario
                    .qualified_content_compounds
                    .contains(category);
            }
            matches!(
                category.as_str(),
                "base_href_action_lure"
                    | "social_trust_lure"
                    | "targeted_recruitment_lure"
                    | "image_alt_phishing"
                    | "attachment_contact_redirect"
                    | "external_reply_to_social_engineering"
                    | "external_identity_consent_lure"
                    | "external_internal_service_link"
                    | "hidden_external_action_lure"
                    | "credential_exfiltration_lure"
            )
        })
    {
        // These are named multi-signal compounds: destination structure or
        // image-alt content is admitted only after the detector has already
        // required external provenance and independent semantic cues.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "bec_external_compound")
    {
        // Only the external, multi-dimension BEC compound receives this
        // floor. A generic `bec` category can be ordinary internal business
        // prose and must not turn a routine message into Medium.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized.scenario.has_admitted_content_account_signal
        && (normalized
            .scenario
            .qualified_link_compounds
            .contains("ip_action_target")
            || normalized
                .scenario
                .qualified_link_compounds
                .contains("qr_ip_login_chain"))
        && link >= 0.16
    {
        // Account-security action plus an IP-literal destination is a named
        // inline credential-phishing compound. It is scoped to the account
        // detector and target shape, so a generic IP link remains advisory.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized.scenario.has_admitted_content_account_signal
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "phishing")
    {
        // The content detector has already established both an account
        // threat/action pair and a phishing corroborator. Keep this named
        // cross-module compound at the inline boundary when DS dilution
        // would otherwise turn a complete account lure into Low.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "aitm_brand_subdomain")
    {
        // A brand-aligned subdomain is not enough by itself; paired with the
        // named account-security detector it is a complete authentication
        // lure and receives the same scoped floor.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "qr_text_lure")
    {
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| {
            matches!(
                category.as_str(),
                "protocol_execution_lure"
                    | "attachment_delivery_lure"
                    | "security_rule_archive_lure"
                    | "svg_active_content"
                    | "rmm_high_risk_remote_access_lure"
                    | "attachment_payment_lure"
            )
        })
    {
        // These categories are emitted only after an external-origin and
        // multi-signal compound has been established. Hidden-link evidence is
        // intentionally excluded: its category is observational until the
        // exact hidden-anchor relation is independently established, so a
        // stale category cannot create an unconditional Medium floor.
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "clickfix_lure")
    {
        risk = risk.max(0.60);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "ics_url_credential_lure")
        || (normalized
            .scenario
            .admitted_categories
            .iter()
            .any(|category| category == "attachment_meta_refresh")
            && normalized
                .scenario
                .admitted_categories
                .iter()
                .any(|category| category == "attachment_phishing_url"))
    {
        risk = risk.max(0.40);
    }
    if normalized
        .scenario
        .admitted_categories
        .iter()
        .any(|category| category == "dangerous_document_lure")
        && payload >= 0.40
    {
        // A dangerous attachment whose decoded filename impersonates an
        // ordinary business document is a named social-delivery compound.
        // This preserves quarantine for RFC 2231 filename evasions without
        // treating generic executable MIME or PE structure as malicious.
        risk = risk.max(0.40);
    }
    if normalized.scenario.has_payment_change_signal
        && normalized.scenario.has_credential_link_signal
        && (normalized.scenario.has_malicious_ioc_signal
            || normalized.scenario.has_structural_threat_signal)
        && (external >= 0.20 || link >= 0.18)
        && (link >= 0.18 || social >= 0.20 || business >= 0.18)
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::BusinessSensitivity, 0.18),
                (EvidenceClusterId::LinkAndHtmlDeception, 0.18),
                (EvidenceClusterId::SocialEngineeringIntent, 0.20),
                (EvidenceClusterId::ExternalReputationIoc, 0.20),
            ],
        )
    {
        risk = risk.max(0.72);
    }
    // Sensitive-data hits belong to data_security. They cannot raise threat
    // even when an independently malicious attachment is also present.
    if normalized.scenario.has_crypto_wallet_signal && business >= 0.24 {
        let wallet_floor = if (social >= 0.30 || external >= 0.20 || payload >= 0.25)
            && independent_cluster_sources(
                clusters,
                &[
                    (EvidenceClusterId::BusinessSensitivity, 0.24),
                    (EvidenceClusterId::SocialEngineeringIntent, 0.30),
                    (EvidenceClusterId::ExternalReputationIoc, 0.20),
                    (EvidenceClusterId::PayloadMalware, 0.25),
                ],
            ) {
            0.64
        } else {
            0.40
        };
        risk = risk.max(wallet_floor);
    }
    if normalized.scenario.has_header_spoof_signal
        && identity >= 0.35
        && business >= 0.18
        && independent_cluster_sources(
            clusters,
            &[
                (EvidenceClusterId::SenderIdentityAuthenticity, 0.35),
                (EvidenceClusterId::BusinessSensitivity, 0.18),
            ],
        )
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
    // ── Phase 2: Generic cluster-level circuit breaker ──────────────────
    //
    // Safety net for scenarios not covered by hand-written floor rules.
    // When a single admitted source view has a strong score (>= 0.55), decent confidence
    // (>= 0.70), and an independently strong anchor, D-S fusion should not
    // dilute it below a minimum floor. Repeated structural URL heuristics are
    // intentionally ineligible even if their aggregate score is high.
    //
    // Thresholds:
    //   - source-view score >= 0.55 (meaningful threat signal)
    //   - confidence >= 0.70 (not speculative)
    //   - floor = score * configured alert_floor_factor. Configuration
    //     validation guarantees the factor never discounts evidence (< 1.0).
    let mut cb_info: Option<CircuitBreakerInfo> = None;
    for cluster in clusters {
        for atom in &cluster.causal_atoms {
            if atom.breaker_eligible && atom.score >= 0.55 && atom.confidence >= 0.70 {
                let floor = (atom.score * config.alert_floor_factor).clamp(0.0, 1.0);
                if risk < floor {
                    cb_info = Some(CircuitBreakerInfo {
                        trigger_module_id: cluster.id.label().to_string(),
                        trigger_belief: atom.score,
                        floor_value: floor,
                        original_risk: risk,
                    });
                    risk = floor;
                }
            }
        }
    }

    // ── Phase 3: Cluster convergence breaker ────────────────────────────
    //
    // When the configured number of independent runtime sources have a
    // score at or above the configured threshold, their convergence is
    // strong evidence of a real
    // threat even if no single cluster is dominant. D-S fusion can dilute
    // many weak signals to Safe — this breaker prevents that.
    //
    // The base floor and minimum causal-source count are configuration-driven;
    // each additional independent causal key adds 0.05, capped 0.15 above the base.
    let mut conv_info: Option<ConvergenceBreakerInfo> = None;
    let qualified_sources = clusters
        .iter()
        .flat_map(|cluster| {
            cluster
                .causal_atoms
                .iter()
                .filter(|atom| {
                    atom.score >= config.convergence_belief_threshold
                        && is_runtime_causal_key(&atom.causal_key)
                })
                .map(move |atom| (cluster.id, atom))
        })
        .collect::<Vec<_>>();
    let active_count = qualified_sources
        .iter()
        .map(|(_, atom)| &atom.causal_key)
        .collect::<BTreeSet<_>>()
        .len();
    let minimum_sources = config.convergence_min_modules as usize;
    let family_count = qualified_sources
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>()
        .len();
    let has_native_actionable_evidence = qualified_sources
        .iter()
        .any(|(_, atom)| atom.breaker_eligible);

    // Qualified source membership is only a candidate set. A convergence
    // floor requires at least two independent causal keys, distinct evidence
    // clusters, and one native actionable anchor. This prevents one URL from
    // contributing DGA/path/TLD/Intel as four "independent" sources and keeps
    // two weak contextual observations below Medium.
    let convergence_eligible = minimum_sources > 0
        && active_count >= minimum_sources
        && active_count >= 2
        && family_count >= 2
        && has_native_actionable_evidence;
    if convergence_eligible {
        let additional_sources = active_count.saturating_sub(minimum_sources) as f64;
        let convergence_cap = (config.convergence_base_floor + 0.15).min(0.85);
        let convergence_floor =
            (config.convergence_base_floor + 0.05 * additional_sources).min(convergence_cap);
        if risk < convergence_floor {
            let flagged_clusters: Vec<String> = qualified_sources
                .iter()
                .map(|(id, _)| id.label().to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            conv_info = Some(ConvergenceBreakerInfo {
                modules_flagged: active_count as u32,
                floor_value: convergence_floor,
                original_risk: risk,
                flagged_modules: flagged_clusters,
            });
            risk = convergence_floor;
        }
    }

    // Two low-confidence contextual observations must not become a Medium
    // verdict when the sender's authentication/alignment is verified. This is
    // common for ordinary vendor questionnaires: a foreign-language body and
    // a coverage/MIME note are useful context, but neither is actionable threat
    // evidence. Explicit credential, payment, fraud, spoofing, IOC, and
    // attachment-phishing signals are excluded from this cap.
    let contextual_convergence_only = conv_info.is_some()
        && active_count <= 2
        && normalized.scenario.sender_alignment_verified
        && !normalized.scenario.has_header_spoof_signal
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
        && !normalized.scenario.has_payment_change_signal
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
        && !normalized.scenario.has_attachment_phishing_signal
        && !normalized.scenario.has_high_risk_attachment_content
        && !normalized.scenario.has_structural_threat_signal
        && normalized.categories.iter().all(|category| {
            matches!(
                category.as_str(),
                "foreign_to_cn_corp"
                    | "japanese_to_cn_corp"
                    | "japanese_unexpected"
                    | "nonsensical_spam"
                    | "mime_mismatch"
                    | "ocr_unavailable"
                    | "attachment_inspection_limited"
                    | "attachment_qr_inspection_limited"
                    | "encrypted_attachment"
                    | "inspection_incomplete"
                    | "inspection_coverage_incomplete"
                    | "inspection_execution_incomplete"
            )
        });
    if contextual_convergence_only {
        risk = risk.min(0.35);
        // Do not report a breaker that was subsequently suppressed; the
        // persisted fusion explanation should match the delivered severity.
        conv_info = None;
    }

    let named_gateway_account_lure = normalized
        .categories
        .iter()
        .any(|category| category == "account_security_phishing")
        && normalized
            .categories
            .iter()
            .any(|category| category == "gateway_pre_classified")
        && normalized.scenario.gateway_banner_polluted;

    let image_layout_context_only = normalized.scenario.image_only_layout_observed
        && !image_only_active_target
        && normalized.categories.iter().all(|category| {
            matches!(
                category.as_str(),
                "image_only_layout_observed"
                    | "suspicious_params"
                    | "redirect_url"
                    | "excessive_links"
                    | "url_shortener"
                    | "random_domain"
            )
        });
    if image_layout_context_only {
        risk = risk.min(0.35);
        conv_info = None;
    }

    // ── Phase 4: Scenario-specific caps (suppress false positives) ──────
    let only_contextual = inherited > 0.0
        && link < 0.30
        && payload < 0.30
        && external < 0.40
        && identity < 0.35
        && social < 0.40
        && !gateway_unwrapped_target_lure;
    if only_contextual
        && !structural_credential_phish
        && !payment_redirect_lure
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
        && !named_gateway_account_lure
    {
        risk = risk.min(0.35);
    }

    let intel_only =
        external > 0.0 && identity < 0.25 && link < 0.30 && payload < 0.30 && social < 0.30;
    if intel_only
        && !structural_credential_phish
        && !payment_redirect_lure
        && !gateway_unwrapped_target_lure
        && !named_gateway_account_lure
    {
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
        && !named_gateway_account_lure
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

    let semantic_notice_only = social > 0.0
        && identity < 0.25
        && link < 0.25
        && payload < 0.25
        && external < 0.25
        // A BusinessSensitivity cluster (payment-change / banking evidence)
        // is not NLP notice noise — a body or transaction signal standing
        // next to the NLP echo must not be flattened below its Phase-1 floor.
        && business < 0.20;
    if (normalized.scenario.notice_banner_polluted
        || normalized.scenario.auto_reply_like
        || normalized.scenario.dsn_like_system_mail)
        && semantic_notice_only
        && !normalized.scenario.has_account_security_signal
        && !normalized.scenario.has_credential_link_signal
        && !normalized.scenario.has_malicious_ioc_signal
        && !gateway_unwrapped_target_lure
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
        && !normalized.scenario.has_payment_change_signal
        && !normalized.scenario.has_crypto_wallet_signal
    {
        risk = risk.min(0.12);
    }

    if normalized.scenario.dsn_like_system_mail
        && payload < 0.45
        && link < 0.45
        && external < 0.55
        && !normalized.scenario.has_subsidy_fraud_signal
        && !normalized.scenario.has_invoice_spam_signal
        && !gateway_unwrapped_target_lure
        && !named_gateway_account_lure
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
        && !gateway_unwrapped_target_lure
        && !named_gateway_account_lure
    {
        risk = risk.min(0.12);
    }

    // A subject-only off-platform contact lure corroborated by sender
    // identity randomness is a concrete low-risk finding. Apply this after
    // gateway/notice caps so an upstream banner cannot erase it. Keep the
    // floor below Medium and do not make it a hard circuit-breaker anchor.
    if normalized
        .categories
        .iter()
        .any(|category| category == "subject_contact_lure")
        && normalized
            .categories
            .iter()
            .any(|category| category == "random_sender")
    {
        risk = risk.max(0.15);
    }

    // The upstream banner proves only that another filter inspected the mail.
    // When the first captured hop already carries it (the external hop was not
    // observed), banner scaling plus the prior-only noise cap can turn an
    // independent cross-locale lure — Japanese card-issuer phishing sent to a
    // Chinese mailbox — into Safe. Keep such a lure visible at Low.
    if normalized.scenario.gateway_banner_polluted && has_cross_locale_lure_signal && social > 0.0 {
        risk = risk.max(0.15);
    }

    // This category is emitted only by a named compound detector: an
    // external recipient-bound target plus an authentication action.  It is
    // stronger than URL shape evidence and must survive the generic caps;
    // otherwise D-S conflict can turn a complete credential chain into Low.
    if normalized
        .categories
        .iter()
        .any(|category| category == "targeted_credential_phishing")
        && link >= 0.12
    {
        risk = risk.max(0.56);
    }

    FloorCapResult {
        risk: risk.clamp(0.0, 0.99),
        circuit_breaker: cb_info,
        convergence_breaker: conv_info,
    }
}

// Most tests below cover the established scenario floors/caps and must
// exercise the exact production breaker semantics, so the helper delegates to
// the production `VerdictConfig::default()` values (alert_floor_factor=1.0,
// convergence_min_modules=2, convergence_base_floor=0.40,
// convergence_belief_threshold=0.10 — the same values `VerdictConfig::validate`
// enforces). Dedicated configuration tests call the production helper directly
// so changes to persisted knobs are observable.
#[cfg(test)]
fn apply_cluster_floors_and_caps(
    risk: f64,
    clusters: &[ClusterEvidence],
    normalized: &NormalizedEvidence,
) -> FloorCapResult {
    let config = VerdictConfig::default();
    // These numeric floor fixtures explicitly model already-admitted native
    // inputs. Admission regressions use the production normalizer/helper.
    let mut admitted_fixture = normalized.clone();
    admitted_fixture
        .scenario
        .admitted_categories
        .extend(normalized.categories.iter().cloned());
    admitted_fixture.scenario.qualified_link_compounds.extend(
        normalized
            .categories
            .iter()
            .filter(|category| {
                matches!(category.as_str(), "ip_action_target" | "qr_ip_login_chain")
            })
            .cloned(),
    );
    apply_cluster_floors_and_caps_with_config(risk, clusters, &admitted_fixture, &config)
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
        || has_qualified_gateway_credential_target(scenario)
        || payload >= 0.45
        || external >= 0.35
        || identity >= 0.45
}

fn has_qualified_gateway_credential_target(scenario: &ScenarioContext) -> bool {
    scenario.has_gateway_unwrapped_risky_target_signal
        && (scenario.has_account_security_signal || scenario.has_credential_link_signal)
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

pub(super) fn build_clustered_summary(
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
        | "webshell"
        | "weaponized_lnk_execution" => 120,
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
        | "official_domain_text_mismatch"
        | "sender_domain_nested_in_untrusted_host"
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
    use super::super::clustered_ds_v2::aggregate_clustered_ds_v2;
    use super::super::evidence_clusters::{
        CausalAtom, ClusterEvidence, EvidenceClusterId, NormalizedEvidence, ScenarioContext,
    };
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    use vigilyx_core::security::Pillar;

    fn make_cluster(id: EvidenceClusterId, score: f64, confidence: f64) -> ClusterEvidence {
        ClusterEvidence {
            id,
            score,
            confidence,
            breaker_eligible: true,
            causal_keys: vec![format!("body_relation:fixture-{}", id.label())],
            causal_atoms: vec![CausalAtom {
                causal_key: format!("body_relation:fixture-{}", id.label()),
                score,
                confidence,
                breaker_eligible: true,
            }],
            modules: vec![],
            key_factors: vec![],
        }
    }

    fn set_causes(cluster: &mut ClusterEvidence, keys: Vec<String>) {
        cluster.causal_keys = keys.clone();
        cluster.causal_atoms = keys
            .into_iter()
            .map(|causal_key| CausalAtom {
                causal_key,
                score: cluster.score,
                confidence: cluster.confidence,
                breaker_eligible: cluster.breaker_eligible,
            })
            .collect();
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
    fn production_breakers_consume_validated_verdict_configuration() {
        let strong = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.60,
            0.80,
        )];
        let strong_normalized = make_normalized(&strong);
        let factor_config = VerdictConfig {
            alert_floor_factor: 1.20,
            ..VerdictConfig::default()
        };
        let factor_result = apply_cluster_floors_and_caps_with_config(
            0.10,
            &strong,
            &strong_normalized,
            &factor_config,
        );
        assert!((factor_result.risk - 0.72).abs() < 1e-9);

        let converging = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::PayloadMalware, 0.20, 0.30),
        ];
        let converging_normalized = make_normalized(&converging);
        let convergence_config = VerdictConfig {
            convergence_min_modules: 2,
            convergence_base_floor: 0.45,
            convergence_belief_threshold: 0.19,
            ..VerdictConfig::default()
        };
        let convergence_result = apply_cluster_floors_and_caps_with_config(
            0.10,
            &converging,
            &converging_normalized,
            &convergence_config,
        );
        assert!((convergence_result.risk - 0.45).abs() < 1e-9);
        assert_eq!(
            convergence_result
                .convergence_breaker
                .expect("configured convergence breaker should fire")
                .modules_flagged,
            2
        );
    }

    #[test]
    fn test_generic_cluster_floor_fires_for_strong_identity() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.65,
            0.80,
        )];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // floor = 0.65 * 1.0 = 0.65 (production alert_floor_factor never discounts)
        assert!(
            (result.risk - 0.65).abs() < 1e-9,
            "risk should be 0.65, got {}",
            result.risk
        );
        assert!(result.circuit_breaker.is_some());
        let cb = result.circuit_breaker.unwrap();
        assert_eq!(cb.trigger_module_id, "sender_identity_authenticity");
        assert!((cb.trigger_belief - 0.65).abs() < 1e-9);
        assert!((cb.floor_value - 0.65).abs() < 1e-9);
        assert!((cb.original_risk - 0.10).abs() < 1e-9);
    }

    #[test]
    fn subject_contact_lure_with_identity_anomaly_has_low_floor_not_medium() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.11, 0.80),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.05, 0.70),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec![
            "subject_contact_lure".to_string(),
            "random_sender".to_string(),
        ];

        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);

        assert!(result.risk >= 0.15);
        assert!(result.risk < 0.40);
        assert!(result.circuit_breaker.is_none());
    }

    #[test]
    fn test_generic_cluster_floor_rejects_weak_correlated_link_heuristics() {
        let mut weak_link = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.90, 0.79);
        weak_link.breaker_eligible = false;
        weak_link.causal_atoms[0].breaker_eligible = false;
        let clusters = vec![weak_link];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec![
            "redirect_url".to_string(),
            "recipient_in_url".to_string(),
            "long_url".to_string(),
            "suspicious_params".to_string(),
        ];

        let result = apply_cluster_floors_and_caps(0.48, &clusters, &normalized);

        assert_eq!(result.risk, 0.48);
        assert!(result.circuit_breaker.is_none());
        assert!(!normalized.scenario.has_credential_link_signal);
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
        // floor = 0.60 * 1.0 = 0.60, but risk = 0.70 > 0.60
        let result = apply_cluster_floors_and_caps(0.70, &clusters, &normalized);
        assert!(
            (result.risk - 0.70).abs() < 1e-9,
            "risk should remain 0.70, got {}",
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
        // production min_modules=2 → floor = 0.40 + 0.05 * (3 - 2) = 0.45
        assert!(
            (result.risk - 0.45).abs() < 1e-9,
            "risk should be 0.45, got {}",
            result.risk
        );
        assert_eq!(ThreatLevel::from_score(result.risk), ThreatLevel::Medium);
        assert!(result.convergence_breaker.is_some());
        let conv = result.convergence_breaker.unwrap();
        assert_eq!(conv.modules_flagged, 3);
        assert!((conv.floor_value - 0.45).abs() < 1e-9);
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
        // production min_modules=2 → floor = 0.40 + 0.05 * (5 - 2) = 0.55
        assert!(
            (result.risk - 0.55).abs() < 1e-9,
            "risk should be 0.55, got {}",
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
        // production: floor = 0.40 + 0.05 * (8 - 2) = 0.70, capped at base+0.15 = 0.55
        assert!(
            (result.risk - 0.55).abs() < 1e-9,
            "risk should be 0.55 (convergence capped), got {}",
            result.risk
        );
        assert!(result.convergence_breaker.is_some());
        assert_eq!(result.convergence_breaker.unwrap().modules_flagged, 8);
    }

    #[test]
    fn test_convergence_floor_fires_for_2_clusters() {
        // Production convergence_min_modules=2: two independent clusters at or
        // above the belief threshold are already convergence evidence.
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
        ];
        let normalized = make_normalized(&clusters);
        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);
        // floor = 0.40 + 0.05 * (2 - 2) = 0.40 (exactly the Medium boundary)
        assert!(
            (result.risk - 0.40).abs() < 1e-9,
            "risk should be 0.40, got {}",
            result.risk
        );
        assert_eq!(ThreatLevel::from_score(result.risk), ThreatLevel::Medium);
        assert!(result.convergence_breaker.is_some());
        assert_eq!(result.convergence_breaker.unwrap().modules_flagged, 2);
    }

    #[test]
    fn two_labels_for_one_content_compound_cannot_arm_convergence() {
        let mut link = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.80);
        let mut social = make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.80);
        set_causes(
            &mut link,
            vec!["compound_claim:one-request-and-destination".to_string()],
        );
        set_causes(&mut social, link.causal_keys.clone());
        let same_claim = vec![link.clone(), social.clone()];
        let normalized = make_normalized(&same_claim);
        let shared = apply_cluster_floors_and_caps(0.10, &same_claim, &normalized);
        assert!(shared.convergence_breaker.is_none());
        assert!(shared.risk < 0.40);

        set_causes(
            &mut social,
            vec!["compound_claim:independent-request-and-destination".to_string()],
        );
        let independent = vec![link, social];
        let normalized = make_normalized(&independent);
        let distinct = apply_cluster_floors_and_caps(0.10, &independent, &normalized);
        assert!(distinct.convergence_breaker.is_some());
        assert!(distinct.risk >= 0.40);
    }

    #[test]
    fn weak_multi_cause_bridge_preserves_independent_votes_and_floor() {
        let mut social = make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.45, 0.80);
        let mut external = make_cluster(EvidenceClusterId::ExternalReputationIoc, 0.45, 0.80);
        set_causes(&mut social, vec!["host:a.example".to_string()]);
        set_causes(&mut external, vec!["host:b.example".to_string()]);
        let control = vec![social.clone(), external.clone()];
        let control_floor =
            apply_cluster_floors_and_caps(0.10, &control, &make_normalized(&control));
        assert!(control_floor.convergence_breaker.is_some());

        let mut bridge = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.40, 0.80);
        bridge.causal_keys = vec!["host:a.example".to_string(), "host:b.example".to_string()];
        bridge.causal_atoms = bridge
            .causal_keys
            .iter()
            .map(|key| CausalAtom {
                causal_key: key.clone(),
                score: 0.20,
                confidence: 0.80,
                breaker_eligible: true,
            })
            .collect();
        let mut candidate = vec![social, external, bridge];
        for _ in 0..2 {
            let floor =
                apply_cluster_floors_and_caps(0.10, &candidate, &make_normalized(&candidate));
            assert_eq!(floor.risk, control_floor.risk);
            assert_eq!(floor.convergence_breaker.unwrap().modules_flagged, 2);
            assert!(independent_cluster_sources(
                &candidate,
                &[
                    (EvidenceClusterId::SocialEngineeringIntent, 0.40),
                    (EvidenceClusterId::ExternalReputationIoc, 0.40),
                    (EvidenceClusterId::LinkAndHtmlDeception, 0.30),
                ]
            ));
            candidate.reverse();
        }
    }

    #[test]
    fn same_cause_selects_complete_pair_and_unknown_has_no_vote() {
        let mut high_score = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.70, 0.55);
        let mut high_confidence =
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.40, 0.95);
        set_causes(&mut high_score, vec!["host:a.example".to_string()]);
        set_causes(&mut high_confidence, vec!["host:a.example".to_string()]);
        let mut unknown = make_cluster(EvidenceClusterId::DeliveryIntegrity, 0.10, 0.30);
        set_causes(&mut unknown, vec!["family:coverage-note".to_string()]);
        let clusters = vec![high_score, high_confidence, unknown];
        let floor = apply_cluster_floors_and_caps(0.10, &clusters, &make_normalized(&clusters));
        assert!(floor.convergence_breaker.is_none());
    }

    #[test]
    fn aggregate_diagnostic_cannot_lend_confidence_or_create_strong_source() {
        let mut cluster = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.90, 0.95);
        cluster.causal_atoms[0].score = 0.70;
        cluster.causal_atoms[0].confidence = 0.50;
        cluster.causal_atoms.push(CausalAtom {
            causal_key: "host:independent-weak.example".to_string(),
            score: 0.10,
            confidence: 0.95,
            breaker_eligible: false,
        });
        let result =
            apply_cluster_floors_and_caps(0.10, &[cluster.clone()], &make_normalized(&[cluster]));
        assert!(result.circuit_breaker.is_none());
        assert!(result.convergence_breaker.is_none());
        assert!(result.risk < 0.40);
    }

    #[test]
    fn retained_native_labels_cannot_borrow_an_unrelated_admitted_cluster() {
        let cluster = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.25, 0.85);
        let mut normalized = make_normalized(std::slice::from_ref(&cluster));
        for category in [
            "ip_action_target",
            "qr_ip_login_chain",
            "invoice_fraud",
            "clickfix_lure",
            "office_active_content_lure",
        ] {
            normalized.categories = vec![category.to_string(), "org_domain_mimicry".to_string()];
            normalized.scenario.admitted_categories =
                BTreeSet::from(["org_domain_mimicry".to_string()]);
            let result = apply_cluster_floors_and_caps_with_config(
                0.15,
                std::slice::from_ref(&cluster),
                &normalized,
                &VerdictConfig::default(),
            );
            assert!(
                result.risk < 0.40,
                "retained {category} cannot arm a native floor: {}",
                result.risk
            );
        }
    }

    #[test]
    fn unknown_and_shared_causes_cannot_arm_generic_or_phase_one_floors() {
        let mut identity = make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.45, 0.85);
        let mut link = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.48, 0.85);
        for keys in [
            vec!["host:one.example".to_string()],
            vec!["family:identity".to_string()],
            vec!["unknown".to_string()],
            vec!["url:unknown".to_string()],
            vec![],
        ] {
            set_causes(&mut identity, keys.clone());
            set_causes(&mut link, keys);
            let clusters = vec![identity.clone(), link.clone()];
            let result =
                apply_cluster_floors_and_caps(0.20, &clusters, &make_normalized(&clusters));
            assert!(result.convergence_breaker.is_none());
            assert!(
                result.risk < 0.40,
                "a duplicated or unproved source cannot promote: {}",
                result.risk
            );
        }
        set_causes(
            &mut identity,
            vec!["header_identity:independent".to_string()],
        );
        set_causes(&mut link, vec!["host:one.example".to_string()]);
        let distinct = vec![identity, link];
        let result = apply_cluster_floors_and_caps(0.20, &distinct, &make_normalized(&distinct));
        assert!(result.risk >= 0.65);
    }

    #[test]
    fn convergence_requires_independent_causal_keys_and_native_anchor() {
        let mut same_url_a =
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30);
        let mut same_url_b = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.30);
        set_causes(&mut same_url_a, vec!["host:target.example".to_string()]);
        set_causes(&mut same_url_b, vec!["host:target.example".to_string()]);
        let normalized = make_normalized(&[same_url_a.clone(), same_url_b.clone()]);
        let result = apply_cluster_floors_and_caps(0.10, &[same_url_a, same_url_b], &normalized);
        assert!(result.convergence_breaker.is_none());

        let mut weak_a = make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.20, 0.30);
        let mut weak_b = make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.20, 0.30);
        weak_a.breaker_eligible = false;
        weak_a.causal_atoms[0].breaker_eligible = false;
        weak_b.breaker_eligible = false;
        weak_b.causal_atoms[0].breaker_eligible = false;
        let normalized = make_normalized(&[weak_a.clone(), weak_b.clone()]);
        let result = apply_cluster_floors_and_caps(0.10, &[weak_a, weak_b], &normalized);
        assert!(result.convergence_breaker.is_none());
    }

    #[test]
    fn verified_sender_context_does_not_reach_medium_convergence_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::PayloadMalware, 0.20, 0.30),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.20, 0.30),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.sender_alignment_verified = true;
        normalized.categories = vec![
            "foreign_to_cn_corp".to_string(),
            "mime_mismatch".to_string(),
            "inspection_coverage_incomplete".to_string(),
        ];

        let result = apply_cluster_floors_and_caps(0.10, &clusters, &normalized);

        assert!((result.risk - 0.35).abs() < 1e-9);
        assert_eq!(ThreatLevel::from_score(result.risk), ThreatLevel::Low);
        assert!(result.convergence_breaker.is_none());
    }

    #[test]
    fn test_convergence_floor_does_not_fire_below_min_modules() {
        // A single weak cluster is not convergence, whatever its score.
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.20,
            0.30,
        )];
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
        // Convergence floor = 0.40 + 0.05 * (3 - 2) = 0.45, then only_contextual cap → 0.35
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
    fn test_gateway_banner_noise_does_not_create_invoice_spam_threat() {
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
            (result.risk - 0.18).abs() < 1e-9,
            "invoice-spam observations must not create a threat floor, got {}",
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
    fn test_invoice_spam_signal_does_not_get_threat_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.44,
            0.88,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_invoice_spam_signal = true;

        let result = apply_cluster_floors_and_caps(0.16, &clusters, &normalized);

        assert!(
            (result.risk - 0.16).abs() < 1e-9,
            "invoice-spam observations must not force Medium, got {}",
            result.risk
        );
    }

    #[test]
    fn test_invoice_fraud_signal_gets_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.44,
            0.88,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec!["invoice_spam".to_string(), "invoice_fraud".to_string()];
        normalized.scenario.has_invoice_spam_signal = true;

        let result = apply_cluster_floors_and_caps(0.16, &clusters, &normalized);

        assert_eq!(
            result.risk, 0.48,
            "the named invoice-fraud compound must stay at the Medium floor"
        );
    }

    #[test]
    fn sensitive_data_cannot_raise_attachment_threat_but_native_malware_keeps_high() {
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
            (result.risk - 0.42).abs() < 1e-9,
            "sensitive-data observations cannot promote threat, got {}",
            result.risk
        );
        normalized.scenario.has_attachment_sensitive_data_signal = false;
        let without_dlp = apply_cluster_floors_and_caps(0.42, &clusters, &normalized);
        assert_eq!(result.risk, without_dlp.risk);
        let malware = vec![make_cluster(EvidenceClusterId::PayloadMalware, 0.80, 0.99)];
        let malignant = apply_cluster_floors_and_caps(0.42, &malware, &make_normalized(&malware));
        assert!(
            malignant.risk >= 0.75,
            "a genuine native malicious payload retains High independently: {}",
            malignant.risk
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
    fn html_credential_attachment_keeps_quarantine_floor_without_auth_diagnostic_cluster() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.36,
            0.88,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_attachment_phishing_signal = true;
        normalized.scenario.has_structural_threat_signal = true;
        normalized.categories.extend([
            "attachment_credential_form".to_string(),
            "attachment_phishing_url".to_string(),
        ]);

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            result.risk >= 0.56,
            "qualified credential-form attachment must not depend on an auth diagnostic cluster, got {}",
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
    fn test_body_account_security_medium_result_does_not_dilute_to_low() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.44,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized
            .categories
            .push("account_security_phishing".to_string());
        normalized.scenario.has_account_security_signal = true;

        let result = apply_cluster_floors_and_caps(0.195, &clusters, &normalized);

        assert!(
            result.risk >= 0.40,
            "an explicit body account-security Medium result must remain Medium after fusion, got {}",
            result.risk
        );
    }

    #[test]
    fn test_neutral_structural_credential_lure_gets_medium_floor_without_nlp_cluster() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.36,
            0.82,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_account_security_signal = true;
        normalized.scenario.has_credential_link_signal = true;
        normalized
            .categories
            .push("credential_link_lure".to_string());

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            result.risk >= 0.48,
            "the AI-disabled structural credential lure must not remain Safe/Low, got {}",
            result.risk
        );
    }

    #[test]
    fn credential_brand_target_triad_gets_policy_high_floor() {
        let policy = credential_brand_target_scenario_policy()
            .expect("the embedded compound policy must validate");
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.22, 0.82),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.30, 0.86),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.24, 0.76),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.categories.extend([
            policy.credential_link_category.clone(),
            policy.high_risk_target_category.clone(),
            policy.brand_mismatch_category.clone(),
        ]);
        normalized.scenario.has_account_security_signal = true;
        normalized.scenario.has_credential_link_signal = true;
        normalized.scenario.has_high_risk_credential_target_signal = true;
        normalized.scenario.has_brand_sender_target_mismatch_signal = true;
        normalized.scenario.qualified_credential_brand_target = true;

        let result = apply_cluster_floors_and_caps(0.20, &clusters, &normalized);

        assert!(
            result.risk >= policy.verdict_floor,
            "the complete CTA/target/brand triad must honor the policy high floor: {}",
            result.risk
        );
    }

    #[test]
    fn gateway_unwrapped_risky_target_gets_configured_medium_floor() {
        let policy = credential_brand_target_scenario_policy()
            .expect("the embedded gateway target policy must validate");
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.24,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized
            .scenario
            .has_gateway_unwrapped_risky_target_signal = true;
        normalized.scenario.has_credential_link_signal = true;

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);
        assert!(
            (result.risk - policy.redirect_target_floor).abs() < 1e-9,
            "a qualified gateway-unwrapped target must honor the configured Medium floor: {}",
            result.risk
        );
        assert_eq!(ThreatLevel::from_score(result.risk), ThreatLevel::Medium);

        let mut unqualified = make_normalized(&clusters);
        unqualified
            .scenario
            .has_gateway_unwrapped_risky_target_signal = true;
        let weak_result = apply_cluster_floors_and_caps(0.18, &clusters, &unqualified);
        assert!(
            weak_result.risk < policy.redirect_target_floor,
            "gateway metadata without account/CTA context must not manufacture the Medium floor: {}",
            weak_result.risk
        );
    }

    #[test]
    fn hosted_form_credential_lure_keeps_quarantine_floor_without_auth_diagnostic_cluster() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.36,
            0.82,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_credential_link_signal = true;
        normalized
            .categories
            .push("aitm_hosted_credential_lure".to_string());

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            result.risk >= 0.48,
            "qualified hosted-form lure must not depend on an auth diagnostic cluster, got {}",
            result.risk
        );
    }

    #[test]
    fn image_only_phish_requires_active_target_for_quarantine_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.12, 0.80),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.22, 0.84),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.image_only_layout_observed = true;
        normalized.categories.push("ip_url".to_string());

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            result.risk >= 0.48,
            "image-only lure with an active IP target must quarantine, got {}",
            result.risk
        );

        normalized.categories = vec!["suspicious_params".to_string()];
        let contextual = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);
        assert!(
            contextual.risk < 0.40,
            "ordinary image mail with contextual query metadata must stay below quarantine, got {}",
            contextual.risk
        );
    }

    #[test]
    fn unverified_image_observations_cannot_manufacture_a_native_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.22,
            0.82,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.image_only_layout_observed = true;
        normalized.categories = vec![
            "image_only_layout_observed".to_string(),
            "dga_random_domain".to_string(),
            "suspicious_tld".to_string(),
        ];

        let result = apply_cluster_floors_and_caps_with_config(
            0.0,
            &clusters,
            &normalized,
            &VerdictConfig::default(),
        );
        assert!(result.risk < 0.40);

        normalized.categories = vec![
            "image_only_layout_observed".to_string(),
            "suspicious_tld".to_string(),
        ];
        let one_url_observation = apply_cluster_floors_and_caps_with_config(
            0.0,
            &clusters,
            &normalized,
            &VerdictConfig::default(),
        );
        assert!(one_url_observation.risk < 0.40);

        normalized.categories.push("dga_random_domain".to_string());
        normalized.scenario.sender_alignment_verified = true;
        let verified_sender = apply_cluster_floors_and_caps_with_config(
            0.0,
            &clusters,
            &normalized,
            &VerdictConfig::default(),
        );
        assert!(verified_sender.risk < 0.40);
    }

    #[test]
    fn zero_cluster_image_observations_stay_safe_and_native_payload_keeps_high() {
        let session = make_test_session("Image notice", "", "sender@source.invalid");
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_test_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Safe,
                &["image_only_layout_observed"],
                0.0,
            ),
        );
        results.insert(
            "link_content".to_string(),
            make_test_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::Medium,
                &["dga_random_domain", "suspicious_tld"],
                0.42,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe, "{verdict:?}");
        assert!(
            verdict
                .fusion_details
                .as_ref()
                .is_some_and(|details| details.risk_single < 0.40)
        );
        let mut native_payload = make_test_result(
            "av_attach_scan",
            Pillar::Attachment,
            ThreatLevel::Critical,
            &["virus_detected"],
            0.98,
        );
        native_payload.confidence = 0.99;
        native_payload.details["infected_files"] = json!(["payload.exe"]);
        native_payload.details["scanned_count"] = json!(1);
        results.insert("av_attach_scan".to_string(), native_payload);
        let attack = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            attack.threat_level >= ThreatLevel::High,
            "a genuine native malicious payload keeps its strength: {attack:?}"
        );
    }

    #[test]
    fn image_only_phishing_category_gets_named_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.12,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec!["image_only_phishing".to_string()];

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert_eq!(
            ThreatLevel::from_score(result.risk),
            ThreatLevel::Medium,
            "the parser-suspicious-link image-only positive neighbor must reach Medium: {}",
            result.risk
        );
        assert!((result.risk - 0.40).abs() < 1e-9);
    }

    #[test]
    fn official_domain_link_impersonation_gets_named_medium_floor() {
        let policy = high_confidence_link_impersonation_policy()
            .expect("the link impersonation policy must validate");
        let clusters = vec![make_cluster(
            EvidenceClusterId::LinkAndHtmlDeception,
            0.18,
            0.78,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec!["official_domain_text_mismatch".to_string()];

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert_eq!(
            ThreatLevel::from_score(result.risk),
            ThreatLevel::Medium,
            "an official-domain target mismatch must not remain Low: {}",
            result.risk
        );
        assert!((result.risk - policy.verdict_floor).abs() < 1e-9);
    }

    #[test]
    fn obfuscated_domain_lure_gets_named_medium_floor() {
        let policy = obfuscated_domain_lure_verdict_policy()
            .expect("the embedded obfuscated-domain verdict policy must validate");
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.42,
            0.76,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories.push(policy.result_category.clone());

        let result = apply_cluster_floors_and_caps(0.26, &clusters, &normalized);

        assert!(
            result.risk >= policy.verdict_floor,
            "the complete configured compound must not remain Low, got {}",
            result.risk
        );
    }

    #[test]
    fn mailbox_enumeration_probe_gets_named_medium_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SenderIdentityAuthenticity,
            0.22,
            0.70,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec!["mailbox_enumeration_probe".to_string()];

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert_eq!(
            ThreatLevel::from_score(result.risk),
            ThreatLevel::Medium,
            "the complete mailbox-enumeration probe must not remain Low: {}",
            result.risk
        );
        assert!((result.risk - 0.40).abs() < 1e-9);
    }

    #[test]
    fn verified_sender_does_not_get_image_only_phishing_floor() {
        let clusters = vec![make_cluster(
            EvidenceClusterId::SocialEngineeringIntent,
            0.12,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.categories = vec!["image_only_phishing".to_string()];
        normalized.scenario.sender_alignment_verified = true;

        let result = apply_cluster_floors_and_caps(0.18, &clusters, &normalized);

        assert!(
            result.risk < 0.40,
            "verified sender alignment must not arm the image-only heuristic floor: {}",
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
        normalized.categories.extend([
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
    fn test_coverage_only_encrypted_attachment_does_not_add_threat_floor() {
        let clusters = vec![
            make_cluster(EvidenceClusterId::PayloadMalware, 0.16, 0.82),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.34, 0.80),
        ];
        let normalized = make_normalized(&clusters);

        let result = apply_cluster_floors_and_caps(0.26, &clusters, &normalized);

        assert!(
            result.risk < 0.56,
            "coverage-only encrypted attachment must not add a threat floor, got {}",
            result.risk
        );
    }

    // ── PoC regressions: plain-text BEC + forged Auto-Submitted bypass ─────

    fn make_test_session(subject: &str, body: &str, sender: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some(sender.to_string());
        session.content = EmailContent {
            body_text: Some(body.to_string()),
            ..Default::default()
        };
        session
    }

    fn make_test_result(
        module_id: &str,
        pillar: Pillar,
        threat_level: ThreatLevel,
        categories: &[&str],
        score: f64,
    ) -> ModuleResult {
        ModuleResult {
            module_id: module_id.to_string(),
            module_name: module_id.to_string(),
            pillar,
            threat_level,
            confidence: 0.85,
            categories: categories.iter().map(|c| (*c).to_string()).collect(),
            summary: "test".to_string(),
            evidence: vec![],
            details: json!({ "score": score }),
            duration_ms: 5,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        }
    }

    #[test]
    fn standalone_type_mismatch_does_not_produce_low_threat_verdict() {
        let session = make_test_session(
            "Synthetic contract delivery",
            "The requested contract documents are attached.",
            "sender@vendor.example",
        );
        let results = HashMap::from([(
            "attach_scan".to_string(),
            make_test_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::Low,
                &["type_mismatch"],
                0.30,
            ),
        )]);

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe, "{verdict:?}");
        assert_eq!(verdict.modules_flagged, 0, "{verdict:?}");
        assert!(
            verdict.categories.contains(&"type_mismatch".to_string()),
            "the format observation should remain visible: {verdict:?}"
        );
    }

    #[test]
    fn declared_executable_without_malicious_anchor_stays_below_medium() {
        let session = make_test_session(
            "Vendor driver package",
            "Please find the requested driver installer attached.",
            "sender@example.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "attach_scan".to_string(),
            make_test_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::Low,
                &["dangerous_extension"],
                0.35,
            ),
        );
        results.insert(
            "yara_scan".to_string(),
            make_test_result(
                "yara_scan",
                Pillar::Attachment,
                ThreatLevel::Low,
                &["executable_attachment", "structural_payload_validation"],
                0.25,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "declared executable policy risk must not become a malware quarantine verdict: {verdict:?}"
        );
        assert_eq!(verdict.threat_type, None);
        assert_eq!(verdict.modules_flagged, 1);
        assert!(
            verdict
                .categories
                .contains(&"dangerous_extension".to_string())
        );
        assert!(
            verdict
                .categories
                .contains(&"executable_attachment".to_string())
        );
    }

    #[test]
    fn governed_weaponized_lnk_cannot_fuse_to_safe_or_low() {
        let session = make_test_session(
            "Is this you???",
            "Please see the attached picture.",
            "unknown@external.example",
        );
        let results = HashMap::from([(
            "yara_scan".to_string(),
            make_test_result(
                "yara_scan",
                Pillar::Attachment,
                ThreatLevel::High,
                &[
                    "evasion_technique",
                    "yara_match",
                    "weaponized_lnk_execution",
                ],
                0.75,
            ),
        )]);

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::High,
            "a format-anchored LNK launcher/execution/delivery chain must not reproduce the historical Safe verdict: {verdict:?}"
        );
        let fusion = verdict.fusion_details.as_ref().expect("fusion details");
        assert!(
            fusion
                .engine_details
                .iter()
                .any(|detail| detail.engine_id == EvidenceClusterId::PayloadMalware.label()),
            "the admitted rule must enter the payload-malware evidence cluster: {verdict:?}"
        );
        assert!(
            fusion.circuit_breaker.is_some(),
            "the governed native anchor should preserve its single-cluster floor: {verdict:?}"
        );
    }

    #[test]
    fn document_lure_executable_gets_named_medium_floor() {
        let session = make_test_session("对账单", "请查收附件。", "sender@example.invalid");
        let mut results = HashMap::new();
        results.insert(
            "attach_scan".to_string(),
            make_test_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::Medium,
                &["dangerous_extension", "dangerous_document_lure"],
                0.60,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
        assert!(
            verdict
                .fusion_details
                .as_ref()
                .is_some_and(|details| details.risk_single >= 0.40)
        );
    }

    #[test]
    fn test_plain_text_bec_with_forged_auto_submitted_header_is_not_safe() {
        // Full attack PoC: a pure-text BEC email (payment account change, no
        // links/attachments/IOCs) plus one forged `Auto-Submitted` header line.
        // Before the fixes, content_scan's bec_payment_change /
        // bec_no_ioc_social categories were dropped without producing any
        // evidence cluster, and the lone forged header additionally triggered
        // the dsn/auto-reply suppression caps — the verdict came out Safe.
        let mut session = make_test_session(
            "付款账户变更通知",
            "请告知财务，原收款账户已停用，请将货款支付至新账户，此事保密。",
            "cfo@supplier-example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));

        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_test_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["bec_payment_change", "bec_no_ioc_social"],
                0.78,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "plain-text BEC must not be suppressed below Medium, got {:?} (summary: {})",
            verdict.threat_level,
            verdict.summary
        );
        let cluster_ids: Vec<String> = verdict
            .fusion_details
            .as_ref()
            .map(|details| {
                details
                    .engine_details
                    .iter()
                    .map(|engine| engine.engine_id.clone())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            cluster_ids
                .iter()
                .any(|id| id == EvidenceClusterId::BusinessSensitivity.label()),
            "verdict must contain a BusinessSensitivity cluster, got {cluster_ids:?}"
        );
        assert!(
            !verdict.summary.contains("dsn_like_system_mail")
                && !verdict.summary.contains("auto_reply_like"),
            "forged Auto-Submitted header must not tag scenario suppression: {}",
            verdict.summary
        );
    }

    #[test]
    fn test_genuine_dsn_with_corroborated_auto_submitted_still_suppresses() {
        // Control: a genuine DSN (Auto-Submitted + MAILER-DAEMON sender) with
        // only weak content signals must still be capped like before.
        let mut session = make_test_session(
            "Undelivered Mail Returned to Sender",
            "This message was generated by the mail system.",
            "MAILER-DAEMON@mail.example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));

        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_test_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Medium,
                &["phishing"],
                0.50,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "genuine DSN with weak content signal should stay capped, got {:?} (summary: {})",
            verdict.threat_level,
            verdict.summary
        );
    }

    #[test]
    fn test_payment_change_business_cluster_gets_medium_floor_without_identity() {
        // Round-2 PoC (cluster level): a standalone payment-change
        // BusinessSensitivity cluster (no identity/link/IOC corroboration)
        // used to fuse below Medium. The dedicated Phase 1 floor keeps a
        // strong payment-change signal at the Medium boundary.
        let clusters = vec![make_cluster(
            EvidenceClusterId::BusinessSensitivity,
            0.40,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_payment_change_signal = true;

        let result = apply_cluster_floors_and_caps(0.20, &clusters, &normalized);

        assert!(
            (result.risk - 0.40).abs() < 1e-9,
            "standalone payment-change cluster should floor at 0.40, got {}",
            result.risk
        );
        assert_eq!(ThreatLevel::from_score(result.risk), ThreatLevel::Medium);
    }

    #[test]
    fn test_payment_change_business_cluster_below_floor_threshold_stays_low() {
        // The floor must not manufacture Medium verdicts out of weak
        // business chatter: below the 0.35 cluster threshold nothing fires.
        let clusters = vec![make_cluster(
            EvidenceClusterId::BusinessSensitivity,
            0.30,
            0.80,
        )];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_payment_change_signal = true;

        let result = apply_cluster_floors_and_caps(0.20, &clusters, &normalized);

        assert!(
            (result.risk - 0.20).abs() < 1e-9,
            "weak payment-change cluster should keep fused risk, got {}",
            result.risk
        );
    }

    #[test]
    fn credential_brand_target_floor_requires_the_complete_json_managed_chain() {
        let policy = credential_brand_target_scenario_policy()
            .expect("embedded credential-brand-target policy must be valid");
        let clusters = vec![
            make_cluster(EvidenceClusterId::SenderIdentityAuthenticity, 0.30, 0.80),
            make_cluster(EvidenceClusterId::LinkAndHtmlDeception, 0.35, 0.80),
            make_cluster(EvidenceClusterId::SocialEngineeringIntent, 0.35, 0.80),
        ];
        let mut normalized = make_normalized(&clusters);
        normalized.scenario.has_account_security_signal = true;
        normalized.scenario.has_credential_link_signal = true;
        normalized.scenario.has_high_risk_credential_target_signal = true;
        normalized.scenario.has_brand_sender_target_mismatch_signal = true;
        normalized.scenario.qualified_credential_brand_target = true;

        let full = apply_cluster_floors_and_caps(0.25, &clusters, &normalized);
        assert!(
            (full.risk - policy.verdict_floor).abs() < 1e-9,
            "the complete compound chain must apply the configured floor: {}",
            full.risk
        );
        assert_eq!(ThreatLevel::from_score(full.risk), ThreatLevel::High);

        let mut missing_account = normalized.clone();
        missing_account.scenario.has_account_security_signal = false;
        let mut missing_cta = normalized.clone();
        missing_cta.scenario.has_credential_link_signal = false;
        let mut missing_target = normalized.clone();
        missing_target
            .scenario
            .has_high_risk_credential_target_signal = false;
        let mut missing_brand = normalized;
        missing_brand
            .scenario
            .has_brand_sender_target_mismatch_signal = false;

        for (label, candidate) in [
            ("account intent", missing_account),
            ("CTA correlation", missing_cta),
            ("risky effective target", missing_target),
            ("brand triad mismatch", missing_brand),
        ] {
            let result = apply_cluster_floors_and_caps(0.25, &clusters, &candidate);
            assert!(
                result.risk < policy.verdict_floor,
                "missing {label} must keep the new high floor disarmed: {}",
                result.risk
            );
        }
    }

    #[test]
    fn test_plain_text_payment_change_bec_from_forged_mailer_daemon_is_not_safe() {
        // Round-2 full attack PoC: a pure-text payment-account-change BEC
        // (no links/attachments/IOCs) with a forged MAILER-DAEMON envelope.
        // Before the fixes the lone system-sender trait triggered the
        // dsn_like suppression caps, and without identity corroboration the
        // single capped BusinessSensitivity cluster fused below Medium —
        // the verdict came out Low/Safe.
        let session = make_test_session(
            "付款账户变更通知",
            "请告知财务，原收款账户已停用，请将货款 58 万元紧急支付至新账户，此事保密。",
            "MAILER-DAEMON@evil-example.com",
        );

        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_test_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["bec_payment_change"],
                0.78,
            ),
        );
        results.insert(
            "transaction_correlation".to_string(),
            make_test_result(
                "transaction_correlation",
                Pillar::Semantic,
                ThreatLevel::Medium,
                &["payment_change"],
                0.70,
            ),
        );

        let verdict = aggregate_clustered_ds_v2(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "plain-text payment-change BEC with a forged MAILER-DAEMON envelope must reach Medium, got {:?} (summary: {})",
            verdict.threat_level,
            verdict.summary
        );
        assert!(
            !verdict.summary.contains("dsn_like_system_mail")
                && !verdict.summary.contains("auto_reply_like"),
            "forged MAILER-DAEMON envelope must not tag scenario suppression: {}",
            verdict.summary
        );
    }
}
