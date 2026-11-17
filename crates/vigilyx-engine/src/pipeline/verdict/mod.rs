//! Verdict aggregation: dispatches to one of several fusion strategies.

mod clustered_ds_v2;
mod evidence_clusters;
mod noisy_or;
mod relational_v2;
mod risk_constraints;
mod tbm;
mod weighted_max;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::models::{EmailSession, SessionSource};
use vigilyx_core::security::{
    ModuleResult, ThreatLevel, classify_email_classification, classify_verdict_threat_type,
};

// Re-export for backward compatibility
pub use evidence_clusters::{
    ScenarioPatternLists, runtime_scenario_patterns, set_runtime_scenario_patterns,
};
pub use vigilyx_core::security::{EngineBpaDetail, FusionDetails, SecurityVerdict};

use crate::config::VerdictConfig;

/// Categories that describe the mail class without asserting an actionable
/// malicious threat.  Fusion strategies may intentionally omit these from a
/// Safe verdict because they are not threat evidence; retain them separately
/// so the operator-facing classification survives persistence and API reads.
const MAIL_CLASSIFICATION_OBSERVATION_CATEGORIES: &[&str] = &[
    "spam",
    "gateway_spam_classified",
    "nlp_spam",
    "nonsensical_spam",
    "invoice_spam",
    "spam_cannon",
    "transactional_notice",
    "delivery_report",
    "password_reset_notice",
    "marketing",
    "preference_link",
    "campaign",
];

// Aggregation dispatcher

/// Aggregate module results into a final verdict.
pub fn aggregate_verdict(
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    aggregate_verdict_with_session(None, session_id, results, config)
}

/// Aggregate module results into a final verdict with optional session context.
pub fn aggregate_verdict_with_session(
    session: Option<&EmailSession>,
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    // A parser/capture gap must not let safe module BPA values dilute a real
    // threat signal. Keep threat-bearing module results, but turn safe results
    // into vacuous evidence until the missing bytes are replayed.
    let adjusted_results = if let Some(session) = session
        && session.content.has_inspection_coverage_gap()
    {
        let mut adjusted = results.clone();
        let reason = if !session.content.is_complete {
            "message body or MIME entity was not retained"
        } else {
            "parser or detector coverage was limited"
        };
        for result in adjusted.values_mut() {
            result.mark_inspection_incomplete(reason);
        }
        Some(adjusted)
    } else {
        None
    };
    let results = adjusted_results
        .as_ref()
        .map_or(results, |adjusted| adjusted);

    let mut verdict = match config.aggregation.as_str() {
        "tbm_v5" => tbm::aggregate_tbm_v5(session_id, results, config),
        "weighted_max" => weighted_max::aggregate_weighted_max(session_id, results, config),
        "noisy_or" => noisy_or::aggregate_noisy_or(session_id, results, config),
        _ => clustered_ds_v2::aggregate_clustered_ds_v2(session, session_id, results, config),
    };

    // Coverage and disposition never change the evidence-based threat family.
    let evidence_threat_level = verdict.threat_level;
    if verdict.inspection_coverage == vigilyx_core::security::InspectionCoverage::Unknown {
        verdict.inspection_coverage = if results.is_empty() {
            vigilyx_core::security::InspectionCoverage::Unknown
        } else {
            vigilyx_core::security::InspectionCoverage::Complete
        };
    }

    // Inspection coverage and threat evidence are different dimensions. A
    // normal capture/parse gap lowers confidence but is not malicious evidence
    // and must never inflate the threat level. Content that was actually
    // omitted from inspection is different: it is an operational quarantine
    // condition because a clean result cannot account for those bytes.
    if let Some(session) = session
        && session.has_analyzable_content()
        && !session.content.is_complete
    {
        apply_incomplete_inspection_policy(
            &mut verdict,
            session.source,
            "inspection_incomplete",
            "message capture or parsing was incomplete",
        );
    }

    // Detector-controlled resource limits and transient scanner failures are
    // also inspection completeness failures. These modules intentionally emit
    // vacuous/low-confidence evidence; fusion alone may dilute it below the
    // MTA quarantine threshold, so enforce the same invariant here.
    const INCOMPLETE_COVERAGE_CATEGORIES: &[&str] = &[
        "inspection_coverage_incomplete",
        "scan_incomplete",
        "scan_skipped_size_limit",
        "attachment_inspection_limited",
        "attachment_qr_inspection_limited",
        "semantic_ai_inspection_limited",
        "semantic_inspection_limited",
        "encrypted_attachment",
        "recipient_metadata_incomplete",
        "missing_content_type",
        "missing_from",
        "missing_to",
        "ocr_unavailable",
        // The DOM projection can be empty while the rendered email contains
        // text painted into an image/SVG/canvas/CSS visual carrier.  This is
        // an inspection-coverage gap until the visual asset is rendered and
        // OCR'd; it is not threat evidence and must not be treated as a
        // complete clean scan.
        "html_visual_text_uncovered",
        "html_external_visual_unresolved",
    ];
    const QUARANTINE_REQUIRED_CATEGORIES: &[&str] = &[
        "scan_incomplete",
        "scan_skipped_size_limit",
        "attachment_inspection_limited",
        "attachment_qr_inspection_limited",
        "semantic_ai_inspection_limited",
        "semantic_inspection_limited",
        "encrypted_attachment",
    ];
    let mut incomplete_modules = results
        .values()
        .filter(|result| {
            result
                .categories
                .iter()
                .any(|category| INCOMPLETE_COVERAGE_CATEGORIES.contains(&category.as_str()))
        })
        .map(|result| result.module_id.as_str())
        .collect::<Vec<_>>();
    for category in results
        .values()
        .flat_map(|result| &result.categories)
        .filter(|category| INCOMPLETE_COVERAGE_CATEGORIES.contains(&category.as_str()))
    {
        if !verdict.coverage_reasons.contains(category) {
            verdict.coverage_reasons.push(category.clone());
        }
    }
    incomplete_modules.sort_unstable();
    incomplete_modules.dedup();

    let mut quarantine_modules = results
        .values()
        .filter(|result| {
            result.categories.iter().any(|category| {
                QUARANTINE_REQUIRED_CATEGORIES.contains(&category.as_str())
                    || (category == "ocr_unavailable"
                        && result
                            .details
                            .get("ocr_fail_closed_count")
                            .and_then(serde_json::Value::as_u64)
                            .is_some_and(|count| count > 0))
            })
        })
        .map(|result| result.module_id.as_str())
        .collect::<Vec<_>>();
    quarantine_modules.sort_unstable();
    quarantine_modules.dedup();

    if !incomplete_modules.is_empty() {
        let reason = format!(
            "detector coverage incomplete: {}",
            incomplete_modules.join(", ")
        );
        if let Some(session) = session {
            apply_incomplete_inspection_policy(
                &mut verdict,
                session.source,
                "inspection_coverage_incomplete",
                &reason,
            );
        } else {
            annotate_incomplete_inspection(&mut verdict, "inspection_coverage_incomplete", &reason);
        }
    }

    let parser_content_gap = session.map(|session| {
        session.content.truncated
            || session.content.dropped_attachments > 0
            || session.content.links_truncated
    }) == Some(true);
    if parser_content_gap || !quarantine_modules.is_empty() {
        let mut reasons = Vec::new();
        if parser_content_gap {
            reasons.push("parser truncated or dropped message content/attachments".to_string());
        }
        if !quarantine_modules.is_empty() {
            reasons.push(format!(
                "mandatory attachment/content scan incomplete: {}",
                quarantine_modules.join(", ")
            ));
        }
        let reason = reasons.join("; ");
        // A passive mirror observes mail after delivery. Missing capture bytes
        // are an explicit coverage defect, but they are not threat evidence
        // and must not rewrite the displayed classification. The inline MTA
        // still needs the independent quarantine marker because it controls delivery. A
        // missing session keeps the conservative legacy behavior because its
        // source cannot be proven.
        if session.is_none_or(|session| session.source == SessionSource::MtaProxy) {
            enforce_quarantine_required_inspection(&mut verdict, &reason);
        } else {
            annotate_incomplete_inspection(&mut verdict, "inspection_coverage_incomplete", &reason);
        }
    }

    // Keep classification-only observations in the persisted top-level
    // category set when no actionable threat reached Medium. They do not
    // change the fused threat level or threat family. Without this bridge a
    // Safe spam result is reconstructed as
    // `undetermined` by the API because the database stores the top-level
    // categories rather than the in-memory module map.
    // Weak mail-class observations must not label an otherwise unclassified
    // native attack as spam or a routine notice. The module facts remain
    // available, while persistence reconstructs the native classification.
    if evidence_threat_level < ThreatLevel::Medium {
        for category in results
            .values()
            .flat_map(|result| result.categories.iter())
            .filter(|category| {
                MAIL_CLASSIFICATION_OBSERVATION_CATEGORIES.contains(&category.as_str())
            })
        {
            if !verdict.categories.contains(category) {
                verdict.categories.push(category.clone());
            }
        }
    }
    verdict.categories.sort();
    verdict.categories.dedup();

    let observed_content_labels =
        evidence_clusters::canonicalize_observed_attack_classification_categories(
            &mut verdict.categories,
            results,
            config,
        );
    if !observed_content_labels.is_empty() {
        verdict.summary =
            canonicalize_content_observation_summary(&verdict.summary, &observed_content_labels);
    }

    // Classification is a separate, operator-facing axis, but malicious
    // families are legal only when the evidence reaches the actionable
    // Medium threshold. Observation-only identity/URL categories remain
    // visible without producing a contradictory Safe + phishing row.
    verdict.threat_type = classify_verdict_threat_type(evidence_threat_level, &verdict.categories);
    verdict.classification = Some(classify_email_classification(&verdict.categories));

    verdict
}

fn canonicalize_content_observation_summary(
    summary: &str,
    observations: &std::collections::BTreeSet<String>,
) -> String {
    let mut canonical = summary.to_string();
    for category in observations {
        let mut output = String::with_capacity(canonical.len());
        let mut copied = 0;
        for (start, _) in canonical.match_indices(category.as_str()) {
            let end = start + category.len();
            let is_category_character =
                |character: char| character.is_ascii_alphanumeric() || character == '_';
            if canonical[..start]
                .chars()
                .next_back()
                .is_some_and(is_category_character)
                || canonical[end..]
                    .chars()
                    .next()
                    .is_some_and(is_category_character)
            {
                continue;
            }
            output.push_str(&canonical[copied..start]);
            output.push_str("generic_lure_observed");
            copied = end;
        }
        output.push_str(&canonical[copied..]);
        canonical = output;
    }
    canonical
}

/// Record incomplete coverage without manufacturing a threat finding. This is
/// the behavior for every ingestion source: retain the evidence-based threat
/// level, cap confidence, and surface a dedicated coverage category to
/// callers/UI. An inline MTA may independently tempfail delivery, but that
/// policy decision must not be represented as malicious evidence.
pub(crate) fn annotate_incomplete_inspection(
    verdict: &mut SecurityVerdict,
    category: &str,
    reason: &str,
) {
    verdict.inspection_coverage = vigilyx_core::security::InspectionCoverage::Limited;
    if !verdict
        .coverage_reasons
        .iter()
        .any(|existing| existing == category)
    {
        verdict.coverage_reasons.push(category.to_string());
    }
    verdict.confidence = verdict.confidence.min(0.50);
    if !verdict
        .categories
        .iter()
        .any(|existing| existing == category)
    {
        verdict.categories.push(category.to_string());
        verdict.summary = format!(
            "Inspection incomplete ({reason}); threat level reflects captured evidence only. {}",
            verdict.summary
        );
    }
}

/// Apply inspection coverage metadata without changing the evidence-based
/// classification. The source remains part of the signature so callers make
/// their ingestion context explicit; it never changes threat severity.
pub(crate) fn apply_incomplete_inspection_policy(
    verdict: &mut SecurityVerdict,
    _source: SessionSource,
    category: &str,
    reason: &str,
) {
    annotate_incomplete_inspection(verdict, category, reason);
}

/// Preserve the observed threat while asking the inline delivery policy to
/// quarantine incomplete mandatory inspection. Coverage is not attack evidence.
pub(crate) fn enforce_quarantine_required_inspection(verdict: &mut SecurityVerdict, reason: &str) {
    let evidence_confidence = verdict.confidence;
    annotate_incomplete_inspection(verdict, "inspection_quarantine_required", reason);
    if verdict.threat_level >= ThreatLevel::Medium {
        verdict.confidence = evidence_confidence;
    }
    verdict.summary = format!(
        "Quarantine required: inspection coverage omitted content ({reason}). {}",
        verdict.summary
    );
}

/// Whether a verdict carries incomplete-inspection metadata that an inline
/// delivery path must handle separately from threat severity.
pub(crate) fn has_incomplete_inspection(verdict: &SecurityVerdict) -> bool {
    verdict.has_incomplete_inspection()
}

// Shared helpers

fn empty_verdict(session_id: Uuid, now: DateTime<Utc>) -> SecurityVerdict {
    SecurityVerdict {
        inspection_coverage: Default::default(),
        coverage_reasons: vec![],
        id: Uuid::new_v4(),
        session_id,
        threat_level: ThreatLevel::Safe,
        threat_type: None,
        classification: None,
        confidence: 1.0,
        categories: vec![],
        summary: "No modules ran".to_string(),
        pillar_scores: HashMap::new(),
        modules_run: 0,
        modules_flagged: 0,
        total_duration_ms: 0,
        created_at: now,
        fusion_details: None,
    }
}

// YuanTest

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use super::aggregate_verdict_with_session;
    use super::noisy_or::aggregate_noisy_or;
    use super::tbm::aggregate_tbm_v5;
    use super::*;

    use crate::modules::content_scan::{
        KeywordCategoryOverride, KeywordOverrides, build_effective_keyword_lists,
    };
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol, SessionSource};
    use vigilyx_core::security::{EmailClassification, Pillar, ThreatType};

    static SCENARIO_PATTERNS_INIT: Once = Once::new();

    fn init_test_scenario_patterns() {
        SCENARIO_PATTERNS_INIT.call_once(|| {
            let system_seed = KeywordOverrides {
                gateway_banner_patterns: KeywordCategoryOverride {
                    added: vec![
                        "[注意风险邮件]".to_string(),
                        "[外部邮件]".to_string(),
                        "风险邮件".to_string(),
                        "外部邮件".to_string(),
                        "该邮件可能存在恶意内容".to_string(),
                        "this email may".to_string(),
                        "potentially malicious".to_string(),
                        "external email".to_string(),
                        "suspicious email".to_string(),
                    ],
                    removed: vec![],
                },
                notice_banner_patterns: KeywordCategoryOverride {
                    added: vec![
                        "无法扫描邮件附件".to_string(),
                        "请确认邮件来源以及真实性".to_string(),
                        "联系科技部网络安全管理员处置".to_string(),
                        "联系网络安全管理员处置".to_string(),
                        "unable to scan attachment".to_string(),
                        "unable to scan email attachment".to_string(),
                        "verify the sender and authenticity".to_string(),
                    ],
                    removed: vec![],
                },
                dsn_patterns: KeywordCategoryOverride {
                    added: vec![
                        "delivery status notification".to_string(),
                        "delivery failed".to_string(),
                        "undeliverable".to_string(),
                        "undelivered mail".to_string(),
                        "returned mail".to_string(),
                        "mail delivery subsystem".to_string(),
                        "failure notice".to_string(),
                        "退信".to_string(),
                        "投递失败".to_string(),
                    ],
                    removed: vec![],
                },
                auto_reply_patterns: KeywordCategoryOverride {
                    added: vec![
                        "自动回复".to_string(),
                        "自动答复".to_string(),
                        "auto reply".to_string(),
                        "autoreply".to_string(),
                        "automatic reply".to_string(),
                        "out of office".to_string(),
                        "vacation reply".to_string(),
                    ],
                    removed: vec![],
                },
                ..KeywordOverrides::default()
            };
            let effective =
                build_effective_keyword_lists(&system_seed, &KeywordOverrides::default());
            set_runtime_scenario_patterns(ScenarioPatternLists::from(&effective));
        });
    }

    fn make_result(
        module_id: &str,
        pillar: Pillar,
        score: f64,
        categories: Vec<&str>,
    ) -> ModuleResult {
        let threat_level = ThreatLevel::from_score(score);
        ModuleResult {
            module_id: module_id.to_string(),
            module_name: module_id.to_string(),
            pillar,
            threat_level,
            confidence: 0.80,
            categories: categories.into_iter().map(String::from).collect(),
            summary: String::new(),
            evidence: vec![],
            details: serde_json::json!({ "score": score }),
            duration_ms: 1,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        }
    }

    fn make_result_with_confidence(
        module_id: &str,
        pillar: Pillar,
        score: f64,
        confidence: f64,
        categories: Vec<&str>,
    ) -> ModuleResult {
        let mut result = make_result(module_id, pillar, score, categories);
        result.confidence = confidence;
        result
    }

    #[test]
    fn v2_is_the_authoritative_verdict_model() {
        let results = HashMap::from([(
            "identity_anomaly".to_string(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                0.25,
                vec!["random_domain"],
            ),
        )]);
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &VerdictConfig::default());
        let fusion = verdict.fusion_details.unwrap();
        assert_eq!(fusion.fusion_method.as_deref(), Some("clustered_ds_v2"));
        assert!(fusion.shadow_results.is_empty());
        let primary = fusion.primary_result.unwrap();
        assert_eq!(primary.risk_constrained, fusion.risk_single);
        assert_eq!(primary.fused_bpa, fusion.fused_bpa);
        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
        assert!(primary.risk_base < 0.40);
    }

    #[test]
    fn safe_spam_observation_survives_final_verdict_classification() {
        init_test_scenario_patterns();
        let session_id = Uuid::new_v4();
        let results = HashMap::from([(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.05,
                vec!["gateway_spam_classified"],
            ),
        )]);

        let verdict =
            aggregate_verdict_with_session(None, session_id, &results, &VerdictConfig::default());

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(verdict.threat_type, None);
        assert_eq!(verdict.classification, Some(EmailClassification::Spam));
        assert!(
            verdict
                .categories
                .contains(&"gateway_spam_classified".to_string())
        );
    }

    #[test]
    fn native_unknown_family_is_not_reclassified_by_weak_spam_observation() {
        init_test_scenario_patterns();
        let session_id = Uuid::new_v4();
        let config = VerdictConfig::default();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".to_string(),
            2525,
            "203.0.113.20".to_string(),
            25,
        );
        session.content.is_complete = true;
        session.content.body_text = Some("A complete retained message.".to_string());
        let mut native = make_result_with_confidence(
            "header_scan",
            Pillar::Package,
            0.90,
            0.99,
            vec!["sender_ip_malicious"],
        );
        // A native sender-IP IOC has an admitted default mapping while its
        // primary mail family remains unknown. The causal source is the
        // actual SMTP client, independent of the weak body-class observation.
        native.details["causal_findings"] = serde_json::json!([{
            "causal_key": format!("sender_ip:{}", session.client_ip),
            "categories": ["sender_ip_malicious"],
        }]);
        native.evidence = vec![vigilyx_core::security::Evidence {
            description: "SMTP client matched a native malicious-IP IOC".to_string(),
            location: Some("smtp:client_ip".to_string()),
            snippet: Some(session.client_ip.clone()),
        }];
        let observation = make_result(
            "semantic_scan",
            Pillar::Semantic,
            0.0,
            vec!["nonsensical_spam"],
        );
        let without = HashMap::from([("header_scan".to_string(), native.clone())]);
        let with = HashMap::from([
            ("header_scan".to_string(), native),
            ("semantic_scan".to_string(), observation.clone()),
        ]);
        let baseline =
            aggregate_verdict_with_session(Some(&session), session_id, &without, &config);
        let candidate = aggregate_verdict_with_session(Some(&session), session_id, &with, &config);
        assert!(
            candidate.threat_level >= ThreatLevel::Medium,
            "{candidate:?}"
        );
        assert_eq!(candidate.threat_level, baseline.threat_level);
        assert_eq!(
            candidate.fusion_details.as_ref().unwrap().risk_single,
            baseline.fusion_details.as_ref().unwrap().risk_single
        );
        assert_eq!(
            candidate.classification,
            Some(EmailClassification::Undetermined)
        );
        assert_eq!(candidate.classification, baseline.classification);
        assert!(
            !candidate
                .categories
                .contains(&"nonsensical_spam".to_string())
        );
        assert_eq!(
            classify_email_classification(&candidate.categories),
            EmailClassification::Undetermined
        );
        assert_eq!(
            with["semantic_scan"].categories,
            vec!["nonsensical_spam".to_string()]
        );

        let only_observation = HashMap::from([("semantic_scan".to_string(), observation)]);
        let benign = aggregate_verdict_with_session(None, session_id, &only_observation, &config);
        assert_eq!(benign.threat_level, ThreatLevel::Safe);
        assert_eq!(benign.classification, Some(EmailClassification::Spam));
        assert_eq!(
            classify_email_classification(&benign.categories),
            EmailClassification::Spam
        );
    }

    #[test]
    fn bank_like_generic_content_observation_does_not_persist_as_phishing() {
        init_test_scenario_patterns();
        for content_score in [0.08, 0.20] {
            let results = HashMap::from([
                (
                    "content_scan".to_string(),
                    make_result(
                        "content_scan",
                        Pillar::Content,
                        content_score,
                        vec!["phishing"],
                    ),
                ),
                (
                    "header_scan".to_string(),
                    make_result("header_scan", Pillar::Package, 0.15, vec!["stale_date"]),
                ),
            ]);
            let verdict = aggregate_verdict_with_session(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert!(verdict.threat_level < ThreatLevel::Medium, "{verdict:?}");
            assert_eq!(
                verdict.classification,
                Some(EmailClassification::Undetermined)
            );
            assert_eq!(verdict.threat_type, None);
            assert!(
                verdict
                    .categories
                    .contains(&"generic_lure_observed".to_string())
            );
            assert!(!verdict.categories.contains(&"phishing".to_string()));
            assert!(!verdict.summary.contains("(phishing"));
            // The database reconstructs classification from these canonical
            // categories, while analysts still have the original module fact.
            assert_eq!(
                classify_email_classification(&verdict.categories),
                EmailClassification::Undetermined
            );
            assert_eq!(
                results["content_scan"].categories,
                vec!["phishing".to_string()]
            );
        }
    }

    #[test]
    fn bank_like_content_and_identity_observations_do_not_reconstruct_as_attacks() {
        init_test_scenario_patterns();
        let results = HashMap::from([
            (
                "content_scan".to_string(),
                make_result("content_scan", Pillar::Content, 0.08, vec!["phishing"]),
            ),
            (
                "header_scan".to_string(),
                make_result("header_scan", Pillar::Package, 0.15, vec!["stale_date"]),
            ),
            (
                "identity_anomaly".to_string(),
                make_result(
                    "identity_anomaly",
                    Pillar::Semantic,
                    0.20,
                    vec!["display_name_spoof"],
                ),
            ),
        ]);
        let verdict = aggregate_verdict_with_session(
            None,
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(verdict.threat_level < ThreatLevel::Medium, "{verdict:?}");
        assert_eq!(
            verdict.classification,
            Some(EmailClassification::Undetermined)
        );
        assert_eq!(
            classify_email_classification(&verdict.categories),
            EmailClassification::Undetermined
        );
        assert!(!verdict.categories.contains(&"phishing".to_string()));
        assert!(
            !verdict
                .categories
                .contains(&"display_name_spoof".to_string())
        );
        assert!(
            verdict
                .categories
                .contains(&"generic_lure_observed".to_string())
        );
        assert_eq!(
            results["identity_anomaly"].categories,
            vec!["display_name_spoof".to_string()]
        );
    }

    #[test]
    fn admitted_authority_or_known_impersonation_anchor_keeps_identity_classification() {
        init_test_scenario_patterns();
        for anchor in ["authority_display_name_lure", "known_impersonation_domain"] {
            let results = HashMap::from([(
                "header_scan".to_string(),
                make_result(
                    "header_scan",
                    Pillar::Package,
                    0.75,
                    vec!["display_name_spoof", anchor],
                ),
            )]);
            let verdict = aggregate_verdict_with_session(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(
                verdict.classification,
                Some(EmailClassification::Impersonation),
                "{verdict:?}"
            );
            assert!(
                verdict
                    .categories
                    .contains(&"display_name_spoof".to_string())
            );
            assert!(verdict.categories.contains(&anchor.to_string()));
            assert_eq!(
                classify_email_classification(&verdict.categories),
                EmailClassification::Impersonation
            );
        }
    }

    #[test]
    fn declared_link_brand_observation_does_not_create_impersonation_classification() {
        init_test_scenario_patterns();
        let results = HashMap::from([(
            "link_reputation".to_string(),
            make_result(
                "link_reputation",
                Pillar::Link,
                0.30,
                vec!["brand_impersonation"],
            ),
        )]);
        let verdict = aggregate_verdict_with_session(
            None,
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.classification,
            Some(EmailClassification::Undetermined)
        );
        assert_eq!(
            verdict.categories,
            vec!["generic_lure_observed".to_string()]
        );
        assert_eq!(
            results["link_reputation"].categories,
            vec!["brand_impersonation".to_string()]
        );
    }

    #[test]
    fn subject_account_and_unqualified_content_labels_remain_observations_in_classification() {
        init_test_scenario_patterns();
        let mut content = make_result(
            "content_scan",
            Pillar::Content,
            0.30,
            vec!["account_security_phishing", "phishing"],
        );
        content.evidence.push(vigilyx_core::security::Evidence {
            description: "Synthetic subject observation".to_string(),
            location: Some("subject".to_string()),
            snippet: None,
        });
        let weak_link = make_result("link_scan", Pillar::Link, 0.30, vec!["href_text_mismatch"]);
        let results = HashMap::from([
            ("content_scan".to_string(), content),
            ("link_scan".to_string(), weak_link),
        ]);
        let verdict = aggregate_verdict_with_session(
            None,
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(verdict.threat_level < ThreatLevel::Medium, "{verdict:?}");
        assert_eq!(
            verdict.classification,
            Some(EmailClassification::Undetermined)
        );
        assert!(
            !verdict
                .categories
                .contains(&"account_security_phishing".to_string())
        );

        let results = HashMap::from([(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.60,
                vec![
                    "external_action_link_lure",
                    "pii_collection_lure",
                    "phishing",
                ],
            ),
        )]);
        let verdict = aggregate_verdict_with_session(
            None,
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(verdict.threat_level < ThreatLevel::Medium, "{verdict:?}");
        assert_eq!(
            verdict.classification,
            Some(EmailClassification::Undetermined)
        );
        assert_eq!(
            verdict.categories,
            vec!["generic_lure_observed".to_string()]
        );
    }

    #[test]
    fn native_pii_reply_harvest_keeps_phishing_compatibility_classification() {
        init_test_scenario_patterns();
        for score in [0.30, 0.75] {
            let results = HashMap::from([(
                "content_scan".to_string(),
                make_result(
                    "content_scan",
                    Pillar::Content,
                    score,
                    vec!["pii_reply_harvest_lure", "phishing"],
                ),
            )]);
            let verdict = aggregate_verdict_with_session(
                None,
                Uuid::new_v4(),
                &results,
                &VerdictConfig::default(),
            );
            assert_eq!(verdict.classification, Some(EmailClassification::Phishing));
            assert!(verdict.categories.contains(&"phishing".to_string()));
            assert!(
                verdict
                    .categories
                    .contains(&"pii_reply_harvest_lure".to_string())
            );
            assert_eq!(
                classify_email_classification(&verdict.categories),
                EmailClassification::Phishing
            );
        }
    }

    #[test]
    fn spam_classification_is_preserved_when_generic_phishing_is_only_observed() {
        init_test_scenario_patterns();
        let results = HashMap::from([(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.08,
                vec!["phishing", "gateway_spam_classified"],
            ),
        )]);
        let verdict = aggregate_verdict_with_session(
            None,
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(verdict.classification, Some(EmailClassification::Spam));
        assert!(
            verdict
                .categories
                .contains(&"gateway_spam_classified".to_string())
        );
        assert!(
            verdict
                .categories
                .contains(&"generic_lure_observed".to_string())
        );
    }

    #[test]
    fn disabled_or_vacuous_content_does_not_supply_an_attack_classification_alias() {
        init_test_scenario_patterns();
        for mode in 0..5 {
            let mut content = make_result(
                "content_scan",
                Pillar::Content,
                0.75,
                vec!["pii_reply_harvest_lure", "phishing"],
            );
            let mut config = VerdictConfig::default();
            match mode {
                0 => content.threat_level = ThreatLevel::Safe,
                1 => content.bpa = Some(vigilyx_core::security::Bpa::vacuous()),
                2 => {
                    config.weights.insert("content_scan".to_string(), 0.0);
                }
                3 => content.details["score"] = serde_json::json!(0.0),
                _ => content.confidence = 0.0,
            }
            let results = HashMap::from([("content_scan".to_string(), content)]);
            let verdict = aggregate_verdict_with_session(None, Uuid::new_v4(), &results, &config);
            assert_eq!(
                verdict.classification,
                Some(EmailClassification::Undetermined),
                "mode {mode}: {verdict:?}"
            );
            assert!(
                !verdict.categories.contains(&"phishing".to_string()),
                "mode {mode}"
            );
            assert!(
                results["content_scan"]
                    .categories
                    .contains(&"phishing".to_string()),
                "mode {mode}"
            );
        }
    }

    #[test]
    fn canonical_observation_summary_does_not_rewrite_a_named_attack_category() {
        let summary =
            "Low risk (phishing, targeted_credential_phishing, account_security_phishing)";
        let observations = std::collections::BTreeSet::from(["phishing".to_string()]);
        let canonical = canonicalize_content_observation_summary(summary, &observations);
        assert_eq!(
            canonical,
            "Low risk (generic_lure_observed, targeted_credential_phishing, account_security_phishing)"
        );
    }

    #[test]
    fn incomplete_passive_capture_does_not_inflate_threat_level() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session
            .content
            .headers
            .push(("Subject".to_string(), "Partial capture".to_string()));
        session.content.is_complete = false;

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::new(),
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_incomplete")
        );
        assert!(verdict.confidence <= 0.50);
        assert!(verdict.summary.contains("captured evidence only"));
    }

    #[test]
    fn incomplete_mta_capture_does_not_manufacture_threat() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session
            .content
            .headers
            .push(("Subject".to_string(), "Partial inline message".to_string()));
        session.content.is_complete = false;

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::new(),
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(verdict.summary.contains("captured evidence only"));
        assert!(has_incomplete_inspection(&verdict));
    }

    #[test]
    fn coverage_gap_does_not_let_safe_module_bpa_dilute_threat_evidence() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.headers.push((
            "Subject".to_string(),
            "Synthetic threat regression".to_string(),
        ));
        session.content.is_complete = false;
        session.content.truncated = true;

        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.65,
                vec!["account_security_phishing"],
            ),
        );
        results.insert(
            "empty_content_scan".to_string(),
            make_result("empty_content_scan", Pillar::Content, 0.0, vec![]),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );
        let fusion = verdict.fusion_details.as_ref().unwrap();

        assert!(has_incomplete_inspection(&verdict));
        assert!(
            fusion.fused_bpa.b > 0.0,
            "coverage gap must not erase independent threat evidence"
        );
        assert!(
            verdict.summary.contains("captured evidence only")
                || verdict.summary.contains("Inspection incomplete")
        );
    }

    #[test]
    fn incomplete_detector_execution_is_coverage_metadata_for_passive_analysis() {
        init_test_scenario_patterns();
        let session_id = Uuid::new_v4();
        let mut verdict = empty_verdict(session_id, Utc::now());

        annotate_incomplete_inspection(
            &mut verdict,
            "inspection_execution_incomplete",
            "module timeout: content_scan",
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_execution_incomplete")
        );
        assert!(verdict.summary.contains("module timeout: content_scan"));
        assert!(verdict.confidence <= 0.50);
    }

    #[test]
    fn scanner_coverage_gap_requires_review_without_threat_inflation() {
        init_test_scenario_patterns();
        let session_id = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(
            "av_eml_scan".to_string(),
            make_result(
                "av_eml_scan",
                Pillar::Attachment,
                0.08,
                vec!["scan_incomplete"],
            ),
        );

        let verdict =
            aggregate_verdict_with_session(None, session_id, &results, &VerdictConfig::default());

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_coverage_incomplete")
        );
        assert!(verdict.summary.contains("av_eml_scan"));
        assert!(verdict.confidence <= 0.50);
        assert!(verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn skipped_attachment_scan_requires_quarantine_without_threat_inflation() {
        init_test_scenario_patterns();
        let session_id = Uuid::new_v4();
        let mut results = HashMap::new();
        results.insert(
            "av_attach_scan".to_string(),
            make_result(
                "av_attach_scan",
                Pillar::Attachment,
                0.08,
                vec!["scan_skipped_size_limit"],
            ),
        );

        let verdict =
            aggregate_verdict_with_session(None, session_id, &results, &VerdictConfig::default());

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(has_incomplete_inspection(&verdict));
        assert!(verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn scanner_coverage_gap_requires_mta_quarantine_without_threat_inflation() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session
            .content
            .headers
            .push(("Subject".to_string(), "Inline scan".to_string()));
        session.content.is_complete = true;
        let mut results = HashMap::new();
        results.insert(
            "av_eml_scan".to_string(),
            make_result(
                "av_eml_scan",
                Pillar::Attachment,
                0.08,
                vec!["scan_incomplete"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(has_incomplete_inspection(&verdict));
        assert!(verdict.confidence <= 0.50);
        assert!(verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn attachment_content_coverage_is_not_mirror_threat_but_requires_mta_quarantine() {
        init_test_scenario_patterns();
        let results = HashMap::from([(
            String::from("attach_content"),
            make_result(
                "attach_content",
                Pillar::Attachment,
                0.0,
                vec!["attachment_inspection_limited"],
            ),
        )]);

        let mirror_session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        let mirror_verdict = aggregate_verdict_with_session(
            Some(&mirror_session),
            mirror_session.id,
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(mirror_verdict.threat_level, ThreatLevel::Safe);
        assert!(has_incomplete_inspection(&mirror_verdict));
        assert!(!mirror_verdict.summary.contains("Quarantine required"));

        let mut mta_session = mirror_session.clone();
        mta_session.source = SessionSource::MtaProxy;
        let mta_verdict = aggregate_verdict_with_session(
            Some(&mta_session),
            mta_session.id,
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(mta_verdict.threat_level, ThreatLevel::Safe);
        assert!(has_incomplete_inspection(&mta_verdict));
        assert!(mta_verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn mta_quarantine_does_not_create_threat_type_from_coverage_categories() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session.content.is_complete = true;
        session.content.truncated = true;

        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                0.20,
                vec!["envelope_spoofing"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(has_incomplete_inspection(&verdict));
        assert_eq!(verdict.threat_type, None);
    }

    #[test]
    fn link_extractor_gap_survives_without_semantic_scan() {
        let mut result = make_result(
            "link_content",
            Pillar::Content,
            0.0,
            vec!["inspection_coverage_incomplete"],
        );
        result.bpa = Some(vigilyx_core::security::Bpa::vacuous());
        result.confidence = 0.0;
        let verdict = aggregate_verdict(
            Uuid::new_v4(),
            &HashMap::from([("link_content".to_string(), result)]),
            &VerdictConfig::default(),
        );
        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(
            verdict
                .coverage_reasons
                .contains(&"inspection_coverage_incomplete".to_string())
        );
        assert!(has_incomplete_inspection(&verdict));
        assert_eq!(verdict.threat_type, None);
        assert_eq!(
            vigilyx_core::security::VerdictDisposition::from_threat_and_coverage(
                verdict.threat_level,
                verdict.has_incomplete_inspection(),
                ThreatLevel::Medium,
                ThreatLevel::Critical,
            ),
            vigilyx_core::security::VerdictDisposition::Quarantine,
        );
    }

    #[test]
    fn large_image_ocr_gap_requires_quarantine_but_small_gap_does_not() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session.content.is_complete = true;

        let mut large_result = make_result(
            "attach_scan",
            Pillar::Attachment,
            0.0,
            vec!["ocr_unavailable"],
        );
        large_result.details["ocr_fail_closed_count"] = serde_json::json!(1);
        let large_verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::from([(String::from("attach_scan"), large_result)]),
            &VerdictConfig::default(),
        );
        assert_eq!(large_verdict.threat_level, ThreatLevel::Safe);
        assert!(large_verdict.summary.contains("Quarantine required"));

        let mut small_result = make_result(
            "attach_scan",
            Pillar::Attachment,
            0.0,
            vec!["ocr_unavailable"],
        );
        small_result.details["ocr_fail_closed_count"] = serde_json::json!(0);
        let small_verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::from([(String::from("attach_scan"), small_result)]),
            &VerdictConfig::default(),
        );
        assert!(small_verdict.threat_level < ThreatLevel::Medium);
        assert!(!small_verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn html_visual_text_gap_is_incomplete_but_not_threat_evidence() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session.content.is_complete = true;

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::from([(
                String::from("content_scan"),
                make_result(
                    "content_scan",
                    Pillar::Content,
                    0.0,
                    vec!["html_visual_text_uncovered"],
                ),
            )]),
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(has_incomplete_inspection(&verdict));
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_coverage_incomplete")
        );
        assert!(!verdict.summary.contains("Quarantine required"));
        assert!(verdict.confidence <= 0.50);
    }

    #[test]
    fn semantic_ai_coverage_gap_requires_mta_quarantine_floor() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session.content.is_complete = true;
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".to_string(),
            make_result(
                "semantic_scan",
                Pillar::Content,
                0.0,
                vec!["semantic_ai_inspection_limited"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(has_incomplete_inspection(&verdict));
        assert!(verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn semantic_ai_coverage_gap_is_not_passive_threat_evidence() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.is_complete = true;
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".to_string(),
            make_result(
                "semantic_scan",
                Pillar::Content,
                0.0,
                vec!["semantic_ai_inspection_limited"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(has_incomplete_inspection(&verdict));
        assert!(!verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn scanner_coverage_gap_in_passive_mirror_preserves_evidence_threat() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session
            .content
            .headers
            .push(("Subject".to_string(), "Incomplete PDF capture".to_string()));
        session.content.is_complete = false;
        let mut results = HashMap::new();
        results.insert(
            "yara_scan".to_string(),
            make_result(
                "yara_scan",
                Pillar::Attachment,
                0.10,
                vec!["attachment_inspection_limited"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_coverage_incomplete")
        );
        assert!(
            !verdict
                .categories
                .iter()
                .any(|category| category == "inspection_quarantine_required")
        );
        assert!(verdict.confidence <= 0.50);
        assert!(!verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn passive_parser_truncation_is_coverage_not_threat() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session
            .content
            .headers
            .push(("Subject".to_string(), "Partial mirror capture".to_string()));
        session.content.is_complete = false;
        session.content.truncated = true;
        session.content.dropped_attachments = 1;

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::new(),
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert!(has_incomplete_inspection(&verdict));
        assert!(
            !verdict
                .categories
                .iter()
                .any(|category| category == "inspection_quarantine_required")
        );
        assert!(!verdict.summary.contains("Quarantine required"));
    }

    #[test]
    fn truncated_mta_attachment_requires_quarantine_even_with_no_detector_finding() {
        init_test_scenario_patterns();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.source = SessionSource::MtaProxy;
        session.content.truncated = true;
        session.content.dropped_attachments = 1;

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            session.id,
            &HashMap::new(),
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
        assert_eq!(
            verdict.inspection_coverage,
            vigilyx_core::security::InspectionCoverage::Limited
        );
        assert!(has_incomplete_inspection(&verdict));
        assert!(
            verdict
                .categories
                .iter()
                .any(|category| category == "inspection_quarantine_required")
        );
        assert!(verdict.confidence <= 0.50);
        assert!(verdict.summary.contains("Quarantine required"));
    }

    // Noisy-OR tests (preserved)

    #[test]
    fn test_single_weak_signal_stays_low() {
        let mut results = HashMap::new();
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.20, vec!["missing_date"]),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "DSN/system mail should not escalate beyond Low: {:?}",
            verdict.threat_level
        );
        assert!(verdict.pillar_scores["package"] > 0.19);
    }

    #[test]
    fn test_noisy_or_accumulates_within_pillar() {
        let mut results = HashMap::new();
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.15, vec![]),
        );
        results.insert(
            "mime_scan".into(),
            make_result("mime_scan", Pillar::Package, 0.15, vec![]),
        );
        results.insert(
            "anomaly_detect".into(),
            make_result("anomaly_detect", Pillar::Package, 0.15, vec![]),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert!(
            verdict.pillar_scores["package"] > 0.38,
            "Noisy-OR should accumulate: got {}",
            verdict.pillar_scores["package"]
        );
    }

    #[test]
    fn test_cross_pillar_fusion() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.30, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.25, vec!["ip_url"]),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn test_critical_not_downgraded() {
        let mut results = HashMap::new();
        results.insert(
            "attach_hash".into(),
            make_result(
                "attach_hash",
                Pillar::Attachment,
                0.90,
                vec!["malware_hash"],
            ),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert_eq!(verdict.threat_level, ThreatLevel::Critical);
    }

    #[test]
    fn test_dangerous_combo_headroom() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.25, vec!["phishing"]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.20, vec!["spoofing"]),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn test_all_safe_stays_safe() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_weighted_max_backward_compat() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.30, vec!["phishing"]),
        );

        let config = VerdictConfig {
            aggregation: "weighted_max".to_string(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &config);
        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "DSN/system mail should not escalate beyond Low: {:?}",
            verdict.threat_level
        );
    }

    #[test]
    fn test_sub_threshold_accumulation() {
        let mut results = HashMap::new();
        for (i, pillar) in [
            Pillar::Content,
            Pillar::Attachment,
            Pillar::Link,
            Pillar::Package,
            Pillar::Semantic,
        ]
        .iter()
        .enumerate()
        {
            results.insert(
                format!("mod_{}", i),
                make_result(&format!("mod_{}", i), *pillar, 0.12, vec!["suspicious"]),
            );
        }

        let config = VerdictConfig {
            aggregation: "noisy_or".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_noisy_or(Uuid::new_v4(), &results, &config);
        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Sub-threshold signals across 5 pillars should accumulate to Medium+, got {:?}",
            verdict.threat_level
        );
    }

    // Authoritative D-S V2 dispatch and established behavioral regressions

    #[test]
    fn test_aggregate_verdict_dispatches_clustered_default() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.8,
                vec!["account_security_phishing"],
            ),
        );

        let config = VerdictConfig::default(); // authoritative V2
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &config);
        assert!(verdict.threat_level >= ThreatLevel::Medium, "{verdict:?}");
        assert!(verdict.fusion_details.is_some());
        assert_eq!(
            verdict
                .fusion_details
                .as_ref()
                .and_then(|details| details.fusion_method.as_deref()),
            Some("clustered_ds_v2")
        );
        assert_eq!(verdict.threat_type, Some(ThreatType::Phishing));
    }

    #[test]
    fn observation_only_spoof_does_not_create_safe_phishing_classification() {
        let results = HashMap::from([(
            "identity_anomaly".to_string(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                0.30,
                vec!["display_name_spoof", "first_contact"],
            ),
        )]);

        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &VerdictConfig::default());

        assert_eq!(verdict.threat_level, ThreatLevel::Safe, "{verdict:?}");
        assert_eq!(verdict.threat_type, None, "{verdict:?}");
        assert_eq!(
            verdict.classification,
            Some(EmailClassification::Undetermined),
            "{verdict:?}"
        );
        assert!(
            verdict
                .categories
                .contains(&"generic_lure_observed".to_string()),
            "canonical observation must remain analyst-visible: {verdict:?}"
        );
        assert!(
            !verdict
                .categories
                .contains(&"display_name_spoof".to_string())
        );
        assert!(
            results["identity_anomaly"]
                .categories
                .contains(&"display_name_spoof".to_string())
        );
        assert!(
            results["identity_anomaly"]
                .categories
                .contains(&"first_contact".to_string())
        );
    }

    fn make_session(subject: &str, body: &str, mail_from: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.10".to_string(),
            34567,
            "10.0.0.20".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some(mail_from.to_string());
        session.content = EmailContent {
            headers: vec![],
            body_text: Some(body.to_string()),
            body_html: None,
            attachments: vec![],
            links: vec![],
            raw_size: body.len(),
            is_complete: true,
            raw_mime: None,
            is_encrypted: false,
            truncated: false,
            dropped_attachments: 0,
            links_truncated: false,
            link_index: std::collections::HashSet::new(),
            smtp_dialog: vec![],
        };
        session
    }

    fn make_domain_verify_result(alignment_score: f64) -> ModuleResult {
        let mut result = ModuleResult::safe_analyzed(
            "domain_verify",
            "domain_verify",
            Pillar::Package,
            "sender alignment verified",
            1,
        );
        result.details = serde_json::json!({
            "verified": alignment_score >= 0.55,
            "alignment_score": alignment_score,
            "trust_score": alignment_score
        });
        result
    }

    /// A scored intent-model hit enters fusion: alone, next to clean modules,
    /// it requires Medium review without treating the model score as probability.
    #[test]
    fn scored_intent_model_hit_alone_requires_medium_review() {
        init_test_scenario_patterns();
        let session = make_session(
            "季度会议安排",
            "请各位同事于周五前确认参会时间，会议室预订详情见内网。",
            "colleague@corp-example.com",
        );
        let mut results = HashMap::from([(
            "semantic_scan".to_string(),
            make_result_with_confidence(
                "semantic_scan",
                Pillar::Semantic,
                0.40,
                0.55,
                vec![crate::semantic::INTENT_MODEL_CATEGORY],
            ),
        )]);
        for (module, pillar) in [
            ("content_scan", Pillar::Content),
            ("link_scan", Pillar::Link),
            ("header_scan", Pillar::Package),
            ("attach_scan", Pillar::Attachment),
        ] {
            results.insert(
                module.to_string(),
                ModuleResult::safe_analyzed(module, module, pillar, "clean", 1),
            );
        }
        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.threat_level,
            ThreatLevel::Medium,
            "risk {:?}: {}",
            verdict
                .fusion_details
                .as_ref()
                .map(|details| details.risk_single),
            verdict.summary
        );
    }

    #[test]
    fn test_clustered_gateway_banner_pollution_capped_low() {
        init_test_scenario_patterns();
        let session = make_session(
            "[外部邮件] Monthly report",
            "This email may be malicious. Please use caution.",
            "alerts@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.32,
                vec!["gateway_pre_classified"],
            ),
        );
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.58,
                vec!["nlp_phishing", "nlp_scam", "nonsensical_spam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "DSN/system mail should not escalate beyond Low: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("gateway_banner_polluted"),
            "Expected gateway banner context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.35,
            "Gateway-polluted verdict should be capped to Low"
        );
    }

    #[test]
    fn test_clustered_gateway_prior_only_noise_drops_to_safe() {
        init_test_scenario_patterns();
        let session = make_session(
            "[注意风险邮件]合成月度业务报告",
            "该邮件可能存在恶意内容，请谨慎甄别邮件，不要在外网电脑单击任何链接。\n检测结果：垃圾邮件。\n\n本测试邮件及其附件含有示例机构的保密信息。",
            "trust@identity.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.32,
                vec!["gateway_pre_classified"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.threat_level,
            ThreatLevel::Safe,
            "Gateway prior alone should collapse to safe noise: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("gateway_banner_polluted"),
            "Expected gateway banner context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.12,
            "Gateway-only prior should be capped to safe noise"
        );
    }

    #[test]
    fn dsn_context_cannot_bypass_explicit_random_domain_review_minimum() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "Delivery Status Notification (Failure)",
            "Returned mail: see transcript for details.",
            "MAILER-DAEMON@ddei2.example",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));

        let mut results = HashMap::new();
        results.insert(
            "header_scan".into(),
            make_result(
                "header_scan",
                Pillar::Package,
                0.52,
                vec!["no_auth_results", "no_received"],
            ),
        );
        results.insert(
            "identity_anomaly".into(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                0.44,
                vec!["random_domain"],
            ),
        );
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.41,
                vec!["foreign_to_cn_corp", "nonsensical_spam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Explicit random-domain review policy must survive DSN context: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("dsn_like_system_mail"),
            "Expected DSN context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.40,
            "Explicit identity review minimum supersedes the DSN contextual cap"
        );
    }

    #[test]
    fn test_clustered_notice_banner_nlp_only_drops_to_safe() {
        init_test_scenario_patterns();
        // Round-4 change: notice-banner pollution now requires the banner in
        // the BODY (a subject-only tag is a one-line forgery and no longer
        // suppresses). This genuine notice scenario therefore carries the
        // banner line in the body as a real gateway-injected notice would.
        let session = make_session(
            "[警告：无法扫描邮件附件 - 请确认邮件来源以及真实性 / 或联系科技部网络安全管理员处置]5c2c3f14d027a237283ad8d35936ca5b",
            "发自我的iPhone\n\n警告：无法扫描邮件附件 - 请确认邮件来源以及真实性，或联系科技部网络安全管理员处置",
            "fixture-notice@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.58,
                vec!["nlp_bec", "nlp_phishing", "nlp_scam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.threat_level,
            ThreatLevel::Safe,
            "Notice-banner NLP noise should be suppressed to Safe: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("notice_banner_polluted"),
            "Expected notice banner context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.12,
            "Notice-banner NLP-only signal should be capped to Safe"
        );
    }

    // ─── Round-4 PoC: forged notice tag must not flatten payment-change BEC ─

    #[test]
    fn test_clustered_subject_only_notice_tag_cannot_cap_payment_change_bec() {
        // Attack PoC (round 4): a pure-text payment-change BEC mail whose
        // subject carries a forged gateway notice tag, plus an NLP echo.
        // Before the fix the subject-only tag marked notice_banner_polluted
        // and Phase 4 (semantic_notice_only → min(0.12)) pushed the mail back
        // to Safe, erasing the Phase-1 0.40 payment-change floor.
        init_test_scenario_patterns();
        let session = make_session(
            "[警告：无法扫描邮件附件 - 请确认邮件来源以及真实性]付款账户变更通知",
            "王总要求今天内把货款打到新账户，原收款账户已停用，请勿声张。",
            "cfo@supplier-example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.78,
                vec!["bec_payment_change"],
            ),
        );
        results.insert(
            "semantic_scan".into(),
            make_result("semantic_scan", Pillar::Semantic, 0.60, vec!["nlp_bec"]),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Forged subject-only notice tag must not suppress payment-change BEC: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.40,
            "Payment-change floor (0.40) must survive a forged subject notice tag, risk={}",
            verdict.fusion_details.as_ref().unwrap().risk_single
        );
        assert!(
            !verdict.summary.contains("notice_banner_polluted"),
            "Subject-only notice tag must not mark notice_banner_polluted: {}",
            verdict.summary
        );
    }

    #[test]
    fn test_clustered_body_notice_banner_cannot_cap_payment_change_bec() {
        // Defense in depth: even when the notice banner genuinely pollutes the
        // body (notice_banner_polluted = true), a payment-change business
        // signal must exempt the verdict from the semantic_notice_only cap.
        init_test_scenario_patterns();
        let session = make_session(
            "付款账户变更通知",
            "王总要求今天内把货款打到新账户，原收款账户已停用，请勿声张。\n\n警告：无法扫描邮件附件 - 请确认邮件来源以及真实性，或联系科技部网络安全管理员处置",
            "cfo@supplier-example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.78,
                vec!["bec_payment_change"],
            ),
        );
        results.insert(
            "semantic_scan".into(),
            make_result("semantic_scan", Pillar::Semantic, 0.60, vec!["nlp_bec"]),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.summary.contains("notice_banner_polluted"),
            "Body-carried notice banner should still mark notice_banner_polluted: {}",
            verdict.summary
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Payment-change signal must exempt the semantic_notice_only cap: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.40,
            "Payment-change floor (0.40) must survive body notice pollution, risk={}",
            verdict.fusion_details.as_ref().unwrap().risk_single
        );
    }

    #[test]
    fn test_clustered_auto_reply_nlp_only_drops_to_safe() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "自动回复：季度运营检查通知",
            "谢谢来信，我已收到。",
            "fixture-auto-reply@qq.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-replied".to_string()));
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.56,
                vec!["nlp_bec", "nlp_phishing", "nlp_scam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.threat_level,
            ThreatLevel::Safe,
            "Auto-reply NLP-only signal should be suppressed to Safe: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("auto_reply_like"),
            "Expected auto-reply context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.12,
            "Auto-reply NLP-only signal should be capped to Safe"
        );
    }

    #[test]
    fn test_clustered_semantic_nlp_only_signal_capped_to_safe() {
        init_test_scenario_patterns();
        let session = make_session(
            "关于示例集团开立银行账户不可归集情况说明",
            "请查收相关说明材料。",
            "fixture-semantic@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.62,
                vec!["nlp_phishing", "nlp_scam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level <= ThreatLevel::Safe,
            "NLP-only signal without corroboration should be Safe: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.14,
            "NLP-only signal should be capped to Safe floor (0.14)"
        );
        assert!(
            verdict.summary.contains("semantic_nlp_only_signal"),
            "Expected semantic-only context in summary: {}",
            verdict.summary
        );
    }

    #[test]
    fn test_clustered_transcript_like_structure_semantic_noise_soft_capped() {
        init_test_scenario_patterns();
        let session = make_session(
            "\"文件传输助手\"和\"坐看云舒\"的聊天记录",
            "李华 15:20\n资料发你了\n王强 15:21\n收到，谢谢\n李华 15:22\n明天再看",
            "fixture-transcript@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.61,
                vec!["nlp_bec", "nlp_phishing", "nlp_scam"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "Chat transcript NLP-only signal should stay low or below: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("transcript_like_structure"),
            "Expected transcript structure context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.18,
            "Transcript-like semantic noise should be softly capped"
        );
    }

    #[test]
    fn dsn_random_domain_respects_operator_medium_review_policy() {
        init_test_scenario_patterns();
        let session = make_session(
            "Undelivered Mail Returned to Sender",
            "This is the mail system at host example.com.",
            "MAILER-DAEMON@example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "identity_anomaly".into(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                0.29,
                vec!["random_domain"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert_eq!(
            verdict.threat_level,
            ThreatLevel::Medium,
            "Random-domain policy requires Medium even with DSN context: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("dsn_like_system_mail"),
            "Expected DSN context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.40,
            "Random-domain policy must preserve the 0.40 minimum"
        );
    }

    // These synthetic producer results represent one observed request/URL
    // and a separate SMTP-client IOC. Derivative body/link categories share
    // the same cause; they do not acquire independent votes in the fixture.
    fn qualify_credential_relation_fixture(
        session: &mut EmailSession,
        results: &mut HashMap<String, ModuleResult>,
    ) {
        let target = "https://capture.attacker.example/login";
        let body = session.content.body_text.get_or_insert_with(String::new);
        body.push(' ');
        body.push_str(target);
        let start = body.rfind('\n').map_or(0, |index| index + 1);
        let claim = serde_json::json!({
            "source_span_id": format!("plain_text:{start}:{}", body.len()),
            "source_part": "plain_text", "span": {"start_byte": start, "end_byte": body.len()},
            "actor_role": "sender", "target_role": "recipient", "speech_act": "request",
            "polarity": "action", "quote_or_forward_status": "original",
            "actions": ["click"], "objects": ["link"], "link_ids": ["link:credential-fixture"],
            "counter_context_ids": [], "confidence": 0.85, "causal_key": "host:capture.attacker.example"
        });
        if let Some(result) = results.get_mut("link_content") {
            result.details["qualified_link_compounds"] = serde_json::json!(result.categories.iter()
                .filter(|category| category.as_str() == "targeted_credential_phishing")
                .map(|category| serde_json::json!({
                    "category": category, "claim": claim,
                    "original_url": target, "effective_url": target, "link_extraction_source": "plain_text",
                    "causal_key": "host:capture.attacker.example", "link_transport_status": "not_attempted",
                    "link_content_status": "not_observed", "link_ownership_status": "unknown",
                    "coverage_reason": "fixture retains an observed URL without a fetched landing page"
                })).collect::<Vec<_>>());
        }
        if let Some(result) = results.get_mut("content_scan") {
            result.details["causal_findings"] = serde_json::json!([{
                "causal_key": "host:capture.attacker.example", "categories": result.categories
            }]);
        }
        if let Some(result) = results.get_mut("header_scan")
            && result
                .categories
                .iter()
                .any(|category| category == "ioc_ip_hit")
        {
            result.details["causal_findings"] = serde_json::json!([{
                "causal_key": format!("sender_ip:{}", session.client_ip), "categories": ["ioc_ip_hit"]
            }]);
        }
    }

    #[test]
    fn test_clustered_targeted_credential_combo_reaches_high() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "Apple ID security alert",
            "Please verify your account immediately.",
            "notifications@id.apple.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "header_scan".into(),
            make_result(
                "header_scan",
                Pillar::Package,
                0.62,
                vec!["brand_spoof_reply_to", "domain_mismatch"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result(
                "link_content",
                Pillar::Link,
                0.82,
                vec![
                    "at_sign_obfuscation",
                    "recipient_in_url",
                    "targeted_credential_phishing",
                ],
            ),
        );
        results.insert(
            "content_scan".into(),
            make_result(
                "content_scan",
                Pillar::Content,
                0.58,
                vec!["account_security_phishing"],
            ),
        );

        qualify_credential_relation_fixture(&mut session, &mut results);
        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level >= ThreatLevel::High,
            "Identity + targeted link phishing should remain High: {:?}",
            verdict.threat_level
        );
    }

    #[test]
    fn test_new_device_login_lure_with_recipient_url_reaches_medium() {
        init_test_scenario_patterns();
        let session = make_session(
            "[注意风险邮件]新设备登录提醒",
            "新设备登录提醒，请查看登录详情。",
            "security-center@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result_with_confidence(
                "content_scan",
                Pillar::Content,
                0.73,
                0.85,
                vec![
                    "gateway_pre_classified",
                    "phishing",
                    "phishing_subject",
                    "account_security_phishing",
                ],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence(
                "link_content",
                Pillar::Link,
                0.35,
                0.75,
                vec!["recipient_in_url"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "new-device login lure plus personalized untrusted URL must not remain Low: {:?}",
            verdict.threat_level
        );
        assert!(verdict.fusion_details.as_ref().unwrap().risk_single >= 0.40);
    }

    #[test]
    fn test_recipient_url_without_account_lure_requires_medium_review() {
        init_test_scenario_patterns();
        let session = make_session(
            "August newsletter",
            "Read this month's product newsletter.",
            "newsletter@example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result_with_confidence(
                "content_scan",
                Pillar::Content,
                0.05,
                0.85,
                vec!["gateway_pre_classified"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence(
                "link_content",
                Pillar::Link,
                0.35,
                0.75,
                vec!["recipient_in_url"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert_eq!(verdict.threat_level, ThreatLevel::Medium);
    }

    #[test]
    fn test_marketing_residuals_stay_low_without_breaker() {
        init_test_scenario_patterns();
        let session = make_session(
            "八月合规资讯",
            "本月聚焦合规与监管要求，欢迎报名示例课程并管理通讯偏好。",
            "newsletter@campaign.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert("domain_verify".into(), make_domain_verify_result(0.75));
        results.insert(
            "link_scan".into(),
            make_result_with_confidence(
                "link_scan",
                Pillar::Link,
                0.08,
                0.85,
                vec!["excessive_links"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence("link_content", Pillar::Link, 0.10, 0.75, vec!["long_url"]),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        let details = verdict.fusion_details.as_ref().expect("fusion details");

        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "marketing-only residual heuristics must not become actionable: {:?} / {}",
            verdict.threat_level,
            details.risk_single
        );
        assert!(details.circuit_breaker.is_none());
        assert!(!verdict.summary.contains("credential_link_signal"));
    }

    #[test]
    fn test_clustered_aligned_credential_phish_with_ioc_reaches_high() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "[注意风险邮件]请尽快更新密码以确保账户安全",
            "请点击链接更新密码以确保账户安全。",
            "sender@mailer.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert("domain_verify".into(), make_domain_verify_result(0.75));
        results.insert(
            "content_scan".into(),
            make_result_with_confidence(
                "content_scan",
                Pillar::Content,
                0.99,
                0.85,
                vec![
                    "account_security_phishing",
                    "bec",
                    "gateway_pre_classified",
                    "phishing",
                ],
            ),
        );
        results.insert(
            "header_scan".into(),
            make_result_with_confidence(
                "header_scan",
                Pillar::Package,
                0.40,
                0.80,
                vec!["ioc_ip_hit"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence(
                "link_content",
                Pillar::Link,
                0.35,
                0.85,
                vec!["targeted_credential_phishing"],
            ),
        );

        qualify_credential_relation_fixture(&mut session, &mut results);
        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        let social_cluster = verdict
            .fusion_details
            .as_ref()
            .and_then(|details| {
                details
                    .engine_details
                    .iter()
                    .find(|detail| detail.engine_id == "social_engineering_intent")
            })
            .expect("social cluster should exist");

        assert!(
            verdict.threat_level >= ThreatLevel::High,
            "Credential phishing with malicious IOC and credential-bearing link should reach High even when sender alignment exists: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.65,
            "Credential phishing triad should stay above High threshold"
        );
        assert!(
            verdict.summary.contains("account_security_phishing"),
            "High-risk summary should foreground credential-phishing evidence: {}",
            verdict.summary
        );
        assert!(
            !verdict.summary.contains("gateway_pre_classified"),
            "High-risk summary should not foreground weak gateway priors: {}",
            verdict.summary
        );
        assert!(
            social_cluster.key_factors.iter().any(|factor| factor
                .to_ascii_lowercase()
                .contains("account_security_phishing")),
            "Social cluster factors should reflect credential-phishing evidence, not gateway-banner noise: {:?}",
            social_cluster.key_factors
        );
        assert!(
            social_cluster
                .key_factors
                .iter()
                .any(|factor| factor == "content_scan:bec"),
            "V2 diagnostic factors must preserve the exact registered category: {:?}",
            social_cluster.key_factors
        );
    }

    #[test]
    fn test_clustered_credential_link_and_malicious_ioc_reaches_medium_without_account_theme() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "[注意风险邮件]账号即将到期，立即采取行动",
            "请点击链接完成处理。",
            "sender@mailer.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert("domain_verify".into(), make_domain_verify_result(0.72));
        results.insert(
            "content_scan".into(),
            make_result_with_confidence(
                "content_scan",
                Pillar::Content,
                0.62,
                0.72,
                vec!["bec", "phishing"],
            ),
        );
        results.insert(
            "header_scan".into(),
            make_result_with_confidence(
                "header_scan",
                Pillar::Package,
                0.36,
                0.73,
                vec!["ioc_ip_hit"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence(
                "link_content",
                Pillar::Link,
                0.35,
                0.85,
                vec!["targeted_credential_phishing"],
            ),
        );

        qualify_credential_relation_fixture(&mut session, &mut results);
        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Credential-link + malicious IOC phishing should not stay Low: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.56,
            "Credential-link + IOC floor should lift generic phishing above Medium"
        );
    }

    #[test]
    fn test_clustered_gateway_polluted_structural_phish_stays_medium() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "[注意风险邮件]密码快到期，请尽快确认您的信息",
            "该邮件可能存在恶意内容，请谨慎甄别邮件，不要在外网电脑单击任何链接。\n请点击链接处理。",
            "sender@newsletter.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert("domain_verify".into(), make_domain_verify_result(0.75));
        results.insert(
            "content_scan".into(),
            make_result_with_confidence(
                "content_scan",
                Pillar::Content,
                0.35,
                0.85,
                vec!["bec", "gateway_pre_classified"],
            ),
        );
        results.insert(
            "identity_anomaly".into(),
            make_result_with_confidence(
                "identity_anomaly",
                Pillar::Semantic,
                0.25,
                0.70,
                vec!["random_domain"],
            ),
        );
        results.insert(
            "header_scan".into(),
            make_result_with_confidence(
                "header_scan",
                Pillar::Package,
                0.40,
                0.80,
                vec!["ioc_ip_hit"],
            ),
        );
        results.insert(
            "link_content".into(),
            make_result_with_confidence(
                "link_content",
                Pillar::Link,
                0.35,
                0.85,
                vec!["targeted_credential_phishing"],
            ),
        );

        qualify_credential_relation_fixture(&mut session, &mut results);
        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );

        assert!(
            verdict.threat_level >= ThreatLevel::Medium,
            "Gateway-polluted credential phish with IOC and sender anomaly should not collapse to Safe: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single >= 0.48,
            "Structural phishing triad should hold a Medium floor even when social evidence is weak"
        );
        assert!(
            verdict.summary.contains("credential_link_signal"),
            "Summary should retain credential-link context for analyst review: {}",
            verdict.summary
        );
    }

    #[test]
    fn test_clustered_business_sensitivity_with_trust_stays_low() {
        init_test_scenario_patterns();
        let session = make_session(
            "Quarterly settlement notice",
            "Attached are account updates and payment references.",
            "service@internal.example",
        );
        let mut results = HashMap::new();
        results.insert("domain_verify".into(), make_domain_verify_result(0.82));
        results.insert(
            "transaction_correlation".into(),
            make_result(
                "transaction_correlation",
                Pillar::Semantic,
                0.58,
                vec![
                    "bank_account_detected",
                    "multi_financial_entities",
                    "urgency_financial_combo",
                ],
            ),
        );
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.45, vec!["dlp_api_key"]),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level <= ThreatLevel::Low,
            "Trusted transactional sensitivity should not escalate into Medium/High: {:?}",
            verdict.threat_level
        );
    }

    #[test]
    fn test_clustered_intel_only_signal_cannot_reach_high() {
        let session = make_session(
            "Marketing campaign",
            "View the latest offer online.",
            "marketing@campaign.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert(
            "link_reputation".into(),
            make_result(
                "link_reputation",
                Pillar::Link,
                0.72,
                vec!["intel_malicious"],
            ),
        );
        results.insert(
            "header_scan".into(),
            make_result(
                "header_scan",
                Pillar::Package,
                0.46,
                vec!["sender_ip_suspicious"],
            ),
        );

        let verdict = aggregate_verdict_with_session(
            Some(&session),
            Uuid::new_v4(),
            &results,
            &VerdictConfig::default(),
        );
        assert!(
            verdict.threat_level <= ThreatLevel::Medium,
            "Intel-only signals should not reach High without payload/link deception corroboration: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.55,
            "Intel-only path should be capped below High threshold"
        );
    }

    // TBM v5 tests

    #[test]
    fn test_tbm_v5_basic_threat() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.70, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.60, vec!["ip_url"]),
        );

        let config = VerdictConfig {
            aggregation: "tbm_v5".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_tbm_v5(Uuid::new_v4(), &results, &config);

        assert!(verdict.threat_level >= ThreatLevel::Medium);
        assert!(verdict.fusion_details.is_some());
        let fd = verdict.fusion_details.as_ref().unwrap();
        assert_eq!(fd.fusion_method.as_deref(), Some("tbm_v5"));
        assert!(fd.risk_single > 0.3);
        assert!(fd.novelty.is_some());
        assert!(fd.k_cross.is_some());
        assert!(fd.betp.is_some());
    }

    #[test]
    fn test_tbm_v5_dispatcher() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.5, vec!["phishing"]),
        );

        let config = VerdictConfig {
            aggregation: "tbm_v5".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &config);
        assert!(verdict.fusion_details.is_some());
        let fd = verdict.fusion_details.as_ref().unwrap();
        assert_eq!(fd.fusion_method.as_deref(), Some("tbm_v5"));
    }

    #[test]
    fn test_tbm_v5_novelty_from_epsilon() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.50, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.40, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.30, vec![]),
        );

        let config = VerdictConfig {
            aggregation: "tbm_v5".into(),
            default_epsilon: 0.1,
            ..VerdictConfig::default()
        };
        let verdict = aggregate_tbm_v5(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
        // With 3 engines reporting ~0.1, Novelty = 1 - 0.9^3 0.271
        assert!(
            fd.novelty.unwrap() > 0.1,
            "Novelty should be significant with ε=0.1: got {:.3}",
            fd.novelty.unwrap()
        );
    }

    #[test]
    fn test_tbm_v5_backward_compat_safe() {
        // All safe modules -> Safe verdict
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );

        let config = VerdictConfig {
            aggregation: "tbm_v5".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_tbm_v5(Uuid::new_v4(), &results, &config);

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
    }

    // Circuit breaker tests

    #[test]
    fn test_tbm_v5_cross_layer_fusion() {
        // Both tech and blind-spot modules present
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.60, vec!["phishing"]),
        );
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.70,
                vec!["social_engineering"],
            ),
        );

        let config = VerdictConfig {
            aggregation: "tbm_v5".into(),
            ..VerdictConfig::default()
        };
        let verdict = aggregate_tbm_v5(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
        // K_cross should be computed (tech vs blind)
        assert!(fd.k_cross.is_some());
        // BetP should be in [0, 1]
        let betp = fd.betp.unwrap();
        assert!((0.0..=1.0).contains(&betp), "BetP out of range: {}", betp);
    }
}
