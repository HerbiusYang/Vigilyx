//! Verdict aggregation: dispatches to one of four fusion strategies.

mod ds_murphy;
mod noisy_or;
mod tbm;
mod weighted_max;

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::security::{ModuleResult, ThreatLevel};

// Re-export for backward compatibility
pub use vigilyx_core::security::{EngineBpaDetail, FusionDetails, SecurityVerdict};

use crate::config::VerdictConfig;


// Aggregation dispatcher


/// Aggregate module results into a final verdict.
pub fn aggregate_verdict(
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    match config.aggregation.as_str() {
        "tbm_v5" => tbm::aggregate_tbm_v5(session_id, results, config),
        "weighted_max" => weighted_max::aggregate_weighted_max(session_id, results, config),
        "noisy_or" => noisy_or::aggregate_noisy_or(session_id, results, config),
        _ => ds_murphy::aggregate_ds_murphy(session_id, results, config),
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
    use super::ds_murphy::aggregate_ds_murphy;
    use super::noisy_or::aggregate_noisy_or;
    use super::tbm::aggregate_tbm_v5;
    use super::*;

    use vigilyx_core::security::Pillar;

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
        assert_eq!(verdict.threat_level, ThreatLevel::Low);
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
        assert_eq!(verdict.threat_level, ThreatLevel::Low);
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
    fn test_aggregate_verdict_dispatches_ds_murphy() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".into(),
            make_result("content_scan", Pillar::Content, 0.5, vec!["phishing"]),
        );

        let config = VerdictConfig::default(); // "ds_murphy"
        let verdict = aggregate_verdict(Uuid::new_v4(), &results, &config);
        assert!(verdict.fusion_details.is_some());
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
