//! Verdict aggregation: dispatches to one of several fusion strategies.

mod clustered_ds_v1;
mod ds_murphy;
mod evidence_clusters;
mod noisy_or;
mod tbm;
mod weighted_max;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{ModuleResult, ThreatLevel};

// Re-export for backward compatibility
pub use vigilyx_core::security::{EngineBpaDetail, FusionDetails, SecurityVerdict};
pub use evidence_clusters::{ScenarioPatternLists, set_runtime_scenario_patterns};

use crate::config::VerdictConfig;


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
    match config.aggregation.as_str() {
        "tbm_v5" => tbm::aggregate_tbm_v5(session_id, results, config),
        "weighted_max" => weighted_max::aggregate_weighted_max(session_id, results, config),
        "noisy_or" => noisy_or::aggregate_noisy_or(session_id, results, config),
        "legacy_ds_murphy" => ds_murphy::aggregate_ds_murphy(session_id, results, config),
        "clustered_ds_v1" | "ds_murphy" => {
            clustered_ds_v1::aggregate_clustered_ds_v1(session, session_id, results, config)
        }
        _ => clustered_ds_v1::aggregate_clustered_ds_v1(session, session_id, results, config),
    }
}


// Shared helpers


fn empty_verdict(session_id: Uuid, now: DateTime<Utc>) -> SecurityVerdict {
    SecurityVerdict {
        id: Uuid::new_v4(),
        session_id,
        threat_level: ThreatLevel::Safe,
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
    use super::ds_murphy::aggregate_ds_murphy;
    use super::noisy_or::aggregate_noisy_or;
    use super::tbm::aggregate_tbm_v5;
    use super::*;

    use crate::modules::content_scan::{
        KeywordCategoryOverride, KeywordOverrides, build_effective_keyword_lists,
    };
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    use vigilyx_core::security::Pillar;

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

   // D-S Murphy tests (new)

    #[test]
    fn test_ds_murphy_basic_threat() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.70, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.60, vec!["ip_url"]),
        );

        let config = VerdictConfig::default(); // ds_murphy
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        assert!(verdict.threat_level >= ThreatLevel::Medium);
        assert!(verdict.fusion_details.is_some());
        let fd = verdict.fusion_details.as_ref().unwrap();
        assert!(fd.risk_single > 0.3);
        assert!(fd.k_conflict < 0.5);
    }

    #[test]
    fn test_ds_murphy_all_safe() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        assert_eq!(verdict.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_ds_murphy_uncertainty_raises_risk() {
       // Low-confidence modules -> high uncertainty -> pushes risk up
        let mut results = HashMap::new();
       // score=0.3 but confidence=0.2 -> b=0.06, d=0.14, u=0.8
       // risk(=0.30) = 0.06 + 0.30*0.8 = 0.30
       // (bare belief=0.06, so =0.30 raises risk ~5x above bare belief)
        let mut r = make_result("content_scan", Pillar::Content, 0.30, vec!["suspicious"]);
        r.confidence = 0.2;
        results.insert("content_scan".into(), r);

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

       // With =0.30, high uncertainty should still raise risk above bare belief (0.06)
        let fd = verdict.fusion_details.as_ref().unwrap();
        assert!(
            fd.risk_single > 0.15,
            "High uncertainty with η=0.30 should raise risk above bare belief: got {:.3}",
            fd.risk_single
        );
    }

    #[test]
    fn test_ds_murphy_engine_grouping() {
       // Two modules in same engine (B) should be pre-fused
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.5, vec!["phishing"]),
        );
        results.insert(
            "html_scan".into(),
            make_result("html_scan", Pillar::Content, 0.4, vec!["xss"]),
        );

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
       // Should have 1 engine (B) not 2
        assert_eq!(
            fd.engine_details.len(),
            1,
            "Both modules should group into engine B"
        );
        assert_eq!(fd.engine_details[0].engine_id, "content_analysis");
        assert_eq!(fd.engine_details[0].modules.len(), 2);
    }

    #[test]
    fn test_ds_murphy_multi_engine_reinforcement() {
       // Multiple engines with clear threat signals -> should reinforce
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.8, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.7, vec!["suspicious_url"]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.6, vec!["spoofing"]),
        );

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
        assert_eq!(fd.engine_details.len(), 3); // B, D, E
        assert!(
            fd.risk_single > 0.5,
            "Multi-engine threat signals should produce elevated risk: {:.3}",
            fd.risk_single
        );
    }

    #[test]
    fn test_ds_murphy_credibility_weights_sum() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.5, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.3, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.2, vec![]),
        );

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
        let sum: f64 = fd.credibility_weights.values().sum();
        assert!(
            (sum - 1.0).abs() < 0.01,
            "Credibility weights should sum to ~1.0: got {:.3}",
            sum
        );
    }

    #[test]
    fn test_aggregate_verdict_dispatches_clustered_default() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.5, vec!["phishing"]),
        );

        let config = VerdictConfig::default(); // "ds_murphy"
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &config);
        assert!(verdict.fusion_details.is_some());
        assert_eq!(
            verdict
                .fusion_details
                .as_ref()
                .and_then(|details| details.fusion_method.as_deref()),
            Some("clustered_ds_v1")
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
            is_encrypted: false,
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
            "alignment_score": alignment_score,
            "trust_score": alignment_score
        });
        result
    }

    #[test]
    fn test_clustered_gateway_banner_pollution_capped_low() {
        init_test_scenario_patterns();
        let session = make_session(
            "[外部邮件] Monthly report",
            "This email may be malicious. Please use caution.",
            "alerts@qq.com",
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
            "[注意风险邮件]长盈聚金白金专属系列年定开场内电子数据20260409",
            "该邮件可能存在恶意内容，请谨慎甄别邮件，不要在外网电脑单击任何链接。\n检测结果：垃圾邮件。\n\n本邮件及其附件含有中信建投证券股份有限公司的保密信息。",
            "trustdata@csc.com.cn",
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
    fn test_clustered_dsn_like_system_mail_capped_low() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "Delivery Status Notification (Failure)",
            "Returned mail: see transcript for details.",
            "MAILER-DAEMON@ddei2.localdomain",
        );
        session.content.headers.push((
            "Auto-Submitted".to_string(),
            "auto-generated".to_string(),
        ));

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
            verdict.threat_level <= ThreatLevel::Low,
            "DSN/system mail should not escalate beyond Low: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("dsn_like_system_mail"),
            "Expected DSN context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.30,
            "DSN/system mail should remain capped below Medium"
        );
    }

    #[test]
    fn test_clustered_notice_banner_nlp_only_drops_to_safe() {
        init_test_scenario_patterns();
        let session = make_session(
            "[警告：无法扫描邮件附件 - 请确认邮件来源以及真实性 / 或联系科技部网络安全管理员处置]5c2c3f14d027a237283ad8d35936ca5b",
            "发自我的iPhone",
            "1738338551@qq.com",
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

    #[test]
    fn test_clustered_auto_reply_nlp_only_drops_to_safe() {
        init_test_scenario_patterns();
        let mut session = make_session(
            "CFP 自动回复: 西安经开区支行关于2026年一季度110报警测试专项检查的通报",
            "谢谢来信，我已收到。",
            "engram@yeah.net",
        );
        session.content.headers.push((
            "Auto-Submitted".to_string(),
            "auto-replied".to_string(),
        ));
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
    fn test_clustered_semantic_nlp_only_signal_capped_to_low_floor() {
        init_test_scenario_patterns();
        let session = make_session(
            "关于陕西交控投资集团有限公司开立银行账户不可归集情况说明",
            "请查收相关说明材料。",
            "hao0821@vip.qq.com",
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
            verdict.threat_level <= ThreatLevel::Low,
            "Single-cluster NLP signal should not float near Medium: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.24,
            "Single-cluster NLP signal should be capped to the low floor"
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
            "zuokanyunshu@qq.com",
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
    fn test_clustered_dsn_identity_only_drops_to_safe() {
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
            ThreatLevel::Safe,
            "DSN identity-only signal should be suppressed to Safe: {:?}",
            verdict.threat_level
        );
        assert!(
            verdict.summary.contains("dsn_like_system_mail"),
            "Expected DSN context in summary: {}",
            verdict.summary
        );
        assert!(
            verdict.fusion_details.as_ref().unwrap().risk_single <= 0.12,
            "DSN identity-only signal should be capped to Safe"
        );
    }

    #[test]
    fn test_clustered_targeted_credential_combo_reaches_high() {
        init_test_scenario_patterns();
        let session = make_session(
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
    fn test_clustered_aligned_credential_phish_with_ioc_reaches_high() {
        init_test_scenario_patterns();
        let session = make_session(
            "[注意风险邮件]请尽快更新密码以确保账户安全",
            "请点击链接更新密码以确保账户安全。",
            "jiajia@change-meme.com",
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
            "link_scan".into(),
            make_result_with_confidence(
                "link_scan",
                Pillar::Link,
                0.15,
                0.85,
                vec!["suspicious_params"],
            ),
        );

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
            social_cluster
                .key_factors
                .iter()
                .any(|factor| factor.to_ascii_lowercase().contains("account security phishing")),
            "Social cluster factors should reflect credential-phishing evidence, not gateway-banner noise: {:?}",
            social_cluster.key_factors
        );
        assert!(
            social_cluster
                .key_factors
                .iter()
                .any(|factor| factor.contains("Business Email Compromise")),
            "Acronym-style factors should be humanized for analyst readability: {:?}",
            social_cluster.key_factors
        );
    }

    #[test]
    fn test_clustered_credential_link_and_malicious_ioc_reaches_medium_without_account_theme() {
        init_test_scenario_patterns();
        let session = make_session(
            "[注意风险邮件]账号即将到期，立即采取行动",
            "请点击链接完成处理。",
            "jiajia@change-meme.com",
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
            "link_scan".into(),
            make_result_with_confidence(
                "link_scan",
                Pillar::Link,
                0.15,
                0.85,
                vec!["suspicious_params"],
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
        let session = make_session(
            "[注意风险邮件]密码快到期，请尽快确认您的信息",
            "该邮件可能存在恶意内容，请谨慎甄别邮件，不要在外网电脑单击任何链接。\n请点击链接处理。",
            "jiajia@fsroushi.com",
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
            "link_scan".into(),
            make_result_with_confidence(
                "link_scan",
                Pillar::Link,
                0.15,
                0.85,
                vec!["suspicious_params"],
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
            "service@ccabchina.com",
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
            make_result(
                "content_scan",
                Pillar::Content,
                0.45,
                vec!["dlp_api_key"],
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
            "Trusted transactional sensitivity should not escalate into Medium/High: {:?}",
            verdict.threat_level
        );
    }

    #[test]
    fn test_clustered_intel_only_signal_cannot_reach_high() {
        let session = make_session(
            "Marketing campaign",
            "View the latest offer online.",
            "marketing@mkt.aishu.cn",
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
    fn test_ds_murphy_circuit_breaker_lone_dissenter() {
       // Scenario: 1 Module Critical (score=0.95, b=0.76) + 4 Safe Engine
       // Murphy -> risk 0
       // Break/JudgeRoadhandler: floor = 0.76 * 1.0 = 0.76 -> High
        let mut results = HashMap::new();

       // link_reputation: score=0.95, conf=0.80 -> b=0.76 (Engine D)
        results.insert(
            "link_reputation".into(),
            make_result("link_reputation", Pillar::Link, 0.95, vec!["malicious_url"]),
        );
       // 4 SameEngineof Safe Module
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );
        results.insert(
            "domain_verify".into(),
            make_result("domain_verify", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "anomaly_detect".into(),
            make_result("anomaly_detect", Pillar::Semantic, 0.0, vec![]),
        );

        let config = VerdictConfig::default(); // threshold=0.20, factor=1.0
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
       // Break/JudgeRoadhandler When (b=0.76>= threshold=0.20)
        assert!(
            fd.circuit_breaker.is_some(),
            "Circuit breaker should fire when lone dissenter has b=0.76"
        );
        let cb = fd.circuit_breaker.as_ref().unwrap();
        assert_eq!(cb.trigger_module_id, "link_reputation");
        assert!((cb.trigger_belief - 0.76).abs() < 0.01);
       // floor = 0.76 * 1.0 * 0.30 (: 1 Engine Signal ->)
       // After consensus gating floor 0.228, max(0.228, 0.15) = 0.228
        assert!(
            (cb.floor_value - 0.228).abs() < 0.05,
            "Floor should be ~0.228 (b * factor * consensus=0.30), got {:.3}",
            cb.floor_value
        );
        assert!(
            cb.original_risk < cb.floor_value,
            "Original risk ({:.3}) should be below floor ({:.3})",
            cb.original_risk,
            cb.floor_value
        );
       // After consensus gating: Signal Low District (0.15-0.40)
       // of Target: prevent Module Critical
        assert!(
            fd.risk_single >= 0.15,
            "Risk should be at least Low (0.15): got {:.3}",
            fd.risk_single
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Low,
            "Lone dissenter with consensus gating should be at least Low: got {:?}",
            verdict.threat_level
        );
    }

    #[test]
    fn test_ds_murphy_circuit_breaker_not_triggered_when_fusion_agrees() {
       // Scenario: Engineall -> Result already High -> Break/JudgeRoadhandler
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.80, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.70, vec!["suspicious_url"]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.60, vec!["spoofing"]),
        );

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
       // Result already High,Break/JudgeRoadhandler
        assert!(
            fd.circuit_breaker.is_none(),
            "Circuit breaker should NOT fire when fusion already agrees: risk={:.3}",
            fd.risk_single
        );
    }

    #[test]
    fn test_ds_murphy_circuit_breaker_disabled_when_threshold_zero() {
       // lone_dissenter SameScenario,But threshold=0.0 -> Break/JudgeRoadhandler
        let mut results = HashMap::new();
        results.insert(
            "link_reputation".into(),
            make_result("link_reputation", Pillar::Link, 0.95, vec!["malicious_url"]),
        );
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );
        results.insert(
            "domain_verify".into(),
            make_result("domain_verify", Pillar::Content, 0.0, vec![]),
        );

        let config = VerdictConfig {
            alert_belief_threshold: 0.0, // Break/JudgeRoadhandler
            ..VerdictConfig::default()
        };
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
        assert!(
            fd.circuit_breaker.is_none(),
            "Circuit breaker should be disabled when threshold=0.0"
        );
    }

    #[test]
    fn test_ds_murphy_circuit_breaker_configurable() {
       // Threshold: threshold=0.80, factor=0.30
       // link_reputation b=0.76 <0.80 -> Do not trigger
        let mut results = HashMap::new();
        results.insert(
            "link_reputation".into(),
            make_result("link_reputation", Pillar::Link, 0.95, vec!["malicious_url"]),
        );
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.0, vec![]),
        );
        results.insert(
            "header_scan".into(),
            make_result("header_scan", Pillar::Package, 0.0, vec![]),
        );

        let config = VerdictConfig {
            alert_belief_threshold: 0.80, // High Default
            alert_floor_factor: 0.30,
            ..VerdictConfig::default()
        };
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);

        let fd = verdict.fusion_details.as_ref().unwrap();
       // b=0.76 <threshold=0.80 -> Do not trigger
        assert!(
            fd.circuit_breaker.is_none(),
            "Circuit breaker should NOT fire: b=0.76 < threshold=0.80"
        );
    }

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

    
   // Multi-signal convergence breaker tests
    

   /// 3 ModuleMark Low (belief>= 0.20) + Safe Module
   /// -> D-S Safe -> ConvergeBreak/JudgeRoadhandler
   /// : content_scan(0.32) + link_scan(0.28) + link_reputation(0.28) + Safe
   /// belief: 0.32*0.80=0.256, 0.28*0.80=0.224, 0.28*0.80=0.224,>= 0.20
    #[test]
    fn test_convergence_breaker_3_low_modules() {
        let mut results = HashMap::new();
       // 3 Low Module (SameEngine),belief All>= 0.20
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.32, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.28, vec!["redirect_url"]),
        );
        results.insert(
            "link_reputation".into(),
            make_result(
                "link_reputation",
                Pillar::Link,
                0.28,
                vec!["suspicious_tld"],
            ),
        );
       // Safe Module Engine
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("attach_scan", Pillar::Attachment),
            ("attach_content", Pillar::Attachment),
            ("attach_hash", Pillar::Attachment),
            ("link_content", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("header_scan", Pillar::Package),
            ("mime_scan", Pillar::Package),
            ("semantic_scan", Pillar::Semantic),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

       // ConvergeBreak/JudgeRoadhandler
        assert!(
            fd.convergence_breaker.is_some(),
            "Convergence breaker should activate with 3 modules having belief >= 0.20"
        );
        let cb = fd.convergence_breaker.as_ref().unwrap();
        assert_eq!(cb.modules_flagged, 3);
       // 3 ModuleConverge + boost: 0.40 * (1 + 0.15 * (3-2)) = 0.46
       // : 3 Module Butpossibly 1-2 Engine -> CheckEngine
       // TestMedium 3 Module (content_scan, link_scan, link_reputation) 2 Engine
       // (content_analysis, url_analysis) -> supporting=2 -> consensus=0.75
       // floor = 0.46 * 0.75 = 0.345, max(0.345, 0.15) = 0.345
        assert!(
            cb.floor_value >= 0.15,
            "Floor after consensus gating should be >= 0.15 (Safe threshold), got {:.4}",
            cb.floor_value,
        );
        assert!(
            cb.original_risk < cb.floor_value,
            "Original risk {:.4} should be < floor {:.4} (D-S fusion suppressed it)",
            cb.original_risk,
            cb.floor_value
        );

       // After consensus gating: ConvergeSignal But waitlevel
        assert!(
            fd.risk_single >= 0.15,
            "Risk should be at least Low (0.15), got {:.4}",
            fd.risk_single
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Low,
            "Convergence with consensus gating should be at least Low, got {:?}",
            verdict.threat_level
        );
    }

   /// 3 ModuleMark But belief AllLow -> ConvergeBreak/JudgeRoadhandler ()
   /// : LegitimateemailMedium content_scan detectMobile phoneNumber (score=0.16, belief=0.128)
   /// + semantic_scan verdict (score=0.20, belief=0.160)
   /// + transaction_correlation Signal (score=0.18, belief=0.144)
   /// All threat_level> Safe,But belief All <0.20, ConvergeBreak/JudgeRoadhandler
    #[test]
    fn test_convergence_breaker_skips_low_belief_modules() {
        let mut results = HashMap::new();
       // 3 Low belief Module (Legitimateemailof)
       // belief All <0.10 (convergence_belief_threshold), Converge
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.06, vec!["phone_in_body"]),
        );
        results.insert(
            "semantic_scan".into(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                0.08,
                vec!["nlp_suspicious"],
            ),
        );
        results.insert(
            "transaction_correlation".into(),
            make_result(
                "transaction_correlation",
                Pillar::Semantic,
                0.07,
                vec!["iban_detected"],
            ),
        );
       // Safe Module
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("attach_scan", Pillar::Attachment),
            ("link_scan", Pillar::Link),
            ("link_reputation", Pillar::Link),
            ("link_content", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("header_scan", Pillar::Package),
            ("mime_scan", Pillar::Package),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

       // ConvergeBreak/JudgeRoadhandler: 3 Module threat_level> Safe,
       // But belief All <0.10 (convergence_belief_threshold)
        assert!(
            fd.convergence_breaker.is_none(),
            "Convergence breaker should NOT activate when module beliefs are all below threshold. \
             This scenario represents legitimate emails with weak false signals (phone numbers, \
             borderline NLP classification). Risk: {:.4}",
            fd.risk_single
        );
    }

   /// 1 ModuleMark -> full convergence_min_modules=2 -> Do not trigger
    #[test]
    fn test_convergence_breaker_not_triggered_below_threshold() {
        let mut results = HashMap::new();
       // only 1 Low Module
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.32, vec!["phishing"]),
        );
       // Safe Module
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("link_scan", Pillar::Link),
            ("attach_scan", Pillar::Attachment),
            ("link_content", Pillar::Link),
            ("link_reputation", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("semantic_scan", Pillar::Semantic),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

       // ConvergeBreak/JudgeRoadhandler (only 1 Module, Need/Require 2)
        assert!(
            fd.convergence_breaker.is_none(),
            "Convergence breaker should NOT activate with only 1 flagged module"
        );
    }

   /// convergence_min_modules=0
    #[test]
    fn test_convergence_breaker_disabled_when_zero() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.32, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.28, vec!["redirect_url"]),
        );
        results.insert(
            "link_reputation".into(),
            make_result(
                "link_reputation",
                Pillar::Link,
                0.28,
                vec!["suspicious_tld"],
            ),
        );
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("attach_scan", Pillar::Attachment),
            ("link_content", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("semantic_scan", Pillar::Semantic),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig {
            convergence_min_modules: 0,
            ..VerdictConfig::default()
        };
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

        assert!(
            fd.convergence_breaker.is_none(),
            "Convergence breaker should be disabled when convergence_min_modules=0"
        );
    }

   /// ConvergeBreak/JudgeRoadhandlerRecording of flagged_modules List (belief>= ofModule)
    #[test]
    fn test_convergence_breaker_records_flagged_modules() {
        let mut results = HashMap::new();
       // belief: 0.32*0.80=0.256, 0.28*0.80=0.224, 0.28*0.80=0.224
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.32, vec!["phishing"]),
        );
        results.insert(
            "link_scan".into(),
            make_result("link_scan", Pillar::Link, 0.28, vec!["redirect_url"]),
        );
        results.insert(
            "link_reputation".into(),
            make_result(
                "link_reputation",
                Pillar::Link,
                0.28,
                vec!["suspicious_tld"],
            ),
        );
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("attach_scan", Pillar::Attachment),
            ("link_content", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("semantic_scan", Pillar::Semantic),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

        let cb = fd.convergence_breaker.as_ref().unwrap();
        let mut flagged = cb.flagged_modules.clone();
        flagged.sort();
        assert!(flagged.contains(&"content_scan".to_string()));
        assert!(flagged.contains(&"link_scan".to_string()));
        assert!(flagged.contains(&"link_reputation".to_string()));
        assert_eq!(flagged.len(), 3);
    }

    
   // Break/JudgeRoadhandler: Low High belief Module
    

   /// Scenario: Phishingemail
   /// - link_content: score=0.70, conf=0.75 -> b=0.525 (High belief But conf <0.80)
   /// - content_scan: score=0.55, conf=0.85 -> b=0.4675 (Low belief But conf>= 0.80)
   /// - transaction_correlation: score=0.33, conf=0.75 -> b=0.2475
   /// - semantic_scan (NLP): score=0.15, conf=0.60 -> b=0.09 (Exclude: nlp_ first)
   /// - Module Safe
    
   /// first: Break/JudgeRoadhandlerTrace link_content (b=0.525, conf=0.75),conf <0.80 -> Do not trigger.
   /// : Break/JudgeRoadhandlerTrace content_scan (b=0.4675, conf=0.85), floor=0.4675*1.15=0.54.
    #[test]
    fn test_circuit_breaker_low_confidence_high_belief_does_not_shadow() {
        let mut results = HashMap::new();

       // link_content: High belief But confidence (0.75 <0.80)
        let mut link_content = make_result(
            "link_content",
            Pillar::Link,
            0.70,
            vec!["at_sign_obfuscation"],
        );
        link_content.confidence = 0.75;
        results.insert("link_content".into(), link_content);

       // content_scan: Low belief But confidence (0.85>= 0.80)
        let mut content_scan = make_result(
            "content_scan",
            Pillar::Content,
            0.55,
            vec!["account_security_phishing", "phishing_subject"],
        );
        content_scan.confidence = 0.85;
        results.insert("content_scan".into(), content_scan);

       // transaction_correlation: Low, confidence 0.75
        let mut tx_corr = make_result(
            "transaction_correlation",
            Pillar::Semantic,
            0.33,
            vec!["urgency_financial_combo"],
        );
        tx_corr.confidence = 0.75;
        results.insert("transaction_correlation".into(), tx_corr);

       // semantic_scan (NLP): Exclude Break/JudgeRoadhandlerAndConverge (nlp_ first)
        let mut nlp = make_result(
            "semantic_scan",
            Pillar::Semantic,
            0.15,
            vec!["nlp_phishing", "nlp_scam"],
        );
        nlp.confidence = 0.60;
        results.insert("semantic_scan".into(), nlp);

       // Safe Module
        for safe_mod in &[
            ("html_scan", Pillar::Content),
            ("attach_scan", Pillar::Attachment),
            ("attach_content", Pillar::Attachment),
            ("attach_hash", Pillar::Attachment),
            ("link_scan", Pillar::Link),
            ("link_reputation", Pillar::Link),
            ("anomaly_detect", Pillar::Package),
            ("domain_verify", Pillar::Package),
            ("header_scan", Pillar::Package),
            ("mime_scan", Pillar::Package),
            ("identity_anomaly", Pillar::Semantic),
        ] {
            results.insert(
                safe_mod.0.into(),
                make_result(safe_mod.0, safe_mod.1, 0.0, vec![]),
            );
        }

        let config = VerdictConfig::default();
        let verdict = aggregate_ds_murphy(Uuid::new_v4(), &results, &config);
        let fd = verdict.fusion_details.as_ref().unwrap();

       // Break/JudgeRoadhandler By content_scan (b=0.4675, conf=0.85), link_content
        assert!(
            fd.circuit_breaker.is_some(),
            "Circuit breaker should fire via content_scan (b=0.47, conf=0.85). \
             link_content (b=0.53, conf=0.75) must not shadow it. Risk: {:.4}",
            fd.risk_single,
        );
        let cb = fd.circuit_breaker.as_ref().unwrap();
        assert_eq!(
            cb.trigger_module_id, "content_scan",
            "Should be triggered by content_scan, not link_content"
        );
        assert!(
            (cb.trigger_belief - 0.4675).abs() < 0.01,
            "Trigger belief should be ~0.4675, got {:.4}",
            cb.trigger_belief
        );

       // After consensus gating: Signal (1 Engine) -> consensus=0.30
       // floor = 0.4675 * 1.0 * 0.30 0.14, max(0.14, 0.15) = 0.15
       // Butif Converge large (convergence_flagged>= 3),floor High
       // Risk At least Low
        assert!(
            fd.risk_single >= 0.15,
            "Risk should be at least Low (0.15) after consensus-gated breaker: got {:.4}",
            fd.risk_single,
        );
        assert!(
            verdict.threat_level >= ThreatLevel::Low,
            "Should be at least Low with consensus gating: got {:?}",
            verdict.threat_level,
        );
    }
}
