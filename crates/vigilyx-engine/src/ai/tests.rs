//! Existing AI sampling and model-consistency regressions.

use crate::module::ThreatLevel;
use vigilyx_core::models::{EmailSession, Protocol};

use super::nlp::{
    NLP_BODY_MAX_BYTES, NlpSignalProfile, complete_nlp_request, fine_tuned_nlp_is_actionable,
    start_nlp_request, truncate_body_for_nlp, zero_shot_nlp_is_actionable,
};
use super::remote::RemoteModuleProxy;

fn session() -> EmailSession {
    EmailSession::new(
        Protocol::Smtp,
        "203.0.113.10".to_string(),
        25_000,
        "192.0.2.10".to_string(),
        25,
    )
}

#[tokio::test]
async fn disabled_ai_does_not_prepare_input_or_modify_existing_evidence() {
    let request = start_nlp_request(None, &session(), None, "Please send your password to me.");
    assert!(request.handle.is_none());
    assert!(request.sampled_body.is_none());
    assert_eq!(request.request_status.nlp_status, "disabled");

    let mut score = 0.3;
    let mut categories = vec!["existing_native_evidence".to_string()];
    let mut evidence = Vec::new();
    let outcome = complete_nlp_request(
        request.handle,
        true,
        request.request_status,
        &mut score,
        &mut categories,
        &mut evidence,
    )
    .await;
    assert!(!outcome.nlp_used);
    assert!(!outcome.nlp_contributed);
    assert_eq!(outcome.request_status.nlp_status, "disabled");
    assert_eq!(score, 0.3);
    assert_eq!(categories, vec!["existing_native_evidence".to_string()]);
    assert!(evidence.is_empty());
}

#[tokio::test]
async fn cooling_ai_retains_retry_status_without_scheduling_a_request() {
    let remote = RemoteModuleProxy::new("http://127.0.0.1:9".to_string());
    remote.note_timeout();
    let request = start_nlp_request(Some(&remote), &session(), None, "Quarterly report.");
    assert!(request.handle.is_none());
    assert!(request.sampled_body.is_none());
    assert_eq!(request.request_status.nlp_status, "cooldown");
    assert!(request.request_status.nlp_skipped_temporarily);
    assert!(request.request_status.nlp_retry_after_secs.is_some());
    assert!(request.request_status.nlp_status_message.is_some());
}

/// RT-010: long AI bodies must retain distributed coverage and stay on
/// UTF-8 boundaries instead of dropping the entire suffix.
#[test]
fn nlp_body_truncation_respects_utf8_boundary() {
    let body = format!("{}{}", "测".repeat(12_000), "尾".repeat(4_000));
    assert!(body.len() > NLP_BODY_MAX_BYTES);
    let truncated = truncate_body_for_nlp(&body);
    assert!(truncated.ends_with("尾尾"));
    assert!(truncated.len() <= NLP_BODY_MAX_BYTES);
}

/// RT-010: real phishing prose past the old prefix cap is sampled; short
/// bodies still pass through untouched.
#[test]
fn nlp_body_truncation_real_corpus() {
    let payload = "mailbox deactivation: send password and OTP to admin@evil.example";
    let body = format!("{}{}{}", "A".repeat(25_000), payload, "B".repeat(4_000));
    let truncated = truncate_body_for_nlp(&body);
    assert!(truncated.len() <= NLP_BODY_MAX_BYTES);
    assert!(truncated.contains(payload));
    assert!(truncated.starts_with('A'));
    assert!(truncated.ends_with('B'));

    let short = "请于周五前提交季度报表。";
    assert_eq!(truncate_body_for_nlp(short), short);
}

#[test]
fn zero_shot_nlp_requires_rule_corroboration() {
    let profile = NlpSignalProfile {
        model_type: Some("zero-shot".to_string()),
        top_label: Some("scam".to_string()),
        top_score: 0.91,
        malicious_probability: 0.96,
        legitimate_probability: 0.02,
        phishing_probability: 0.0,
    };

    assert!(!zero_shot_nlp_is_actionable(&profile, false));
}

#[test]
fn zero_shot_legitimate_top_label_stays_advisory() {
    let profile = NlpSignalProfile {
        model_type: Some("zero-shot".to_string()),
        top_label: Some("legitimate".to_string()),
        top_score: 0.62,
        malicious_probability: 0.83,
        legitimate_probability: 0.58,
        phishing_probability: 0.0,
    };

    assert!(!zero_shot_nlp_is_actionable(&profile, true));
}

#[test]
fn zero_shot_strong_corroborated_signal_is_actionable() {
    let profile = NlpSignalProfile {
        model_type: Some("zero-shot".to_string()),
        top_label: Some("phishing".to_string()),
        top_score: 0.72,
        malicious_probability: 0.91,
        legitimate_probability: 0.08,
        phishing_probability: 0.0,
    };

    assert!(zero_shot_nlp_is_actionable(&profile, true));
}

// ─── Fine-tuned consistency gate (R4 遗留1) ───
//
// Before the gate, a fine-tuned malicious verdict contributed up to 0.22
// unconditionally; an adversarially steered or self-inconsistent model
// (top label "legitimate" but verdict High) scored directly. Now the
// verdict must agree with the model's own label distribution.

#[test]
fn fine_tuned_nlp_bypasses_zero_shot_gate_but_not_consistency_gate() {
    // 语义更新说明：此测试原名 fine_tuned_nlp_can_contribute_without_zero_shot_gate。
    // zero-shot 门控对 fine-tuned 仍然放行（保持不变），但新增的一致性门控
    // 会拦截 top_score < 0.5 的弱信号——该 profile 现在属于 advisory-only。
    let profile = NlpSignalProfile {
        model_type: Some("fine-tuned".to_string()),
        top_label: Some("phishing".to_string()),
        top_score: 0.34,
        malicious_probability: 0.62,
        legitimate_probability: 0.28,
        phishing_probability: 0.0,
    };

    assert!(zero_shot_nlp_is_actionable(&profile, false));
    // Legacy 2-class profile without phishing_probability is treated as
    // inconsistent (advisory-only).
    assert!(!fine_tuned_nlp_is_actionable(&profile, ThreatLevel::High));
}

#[test]
fn fine_tuned_5class_consistent_malicious_signal_is_actionable() {
    let profile = NlpSignalProfile {
        model_type: Some("fine-tuned-5class".to_string()),
        top_label: Some("phishing".to_string()),
        top_score: 0.81,
        malicious_probability: 0.9,
        legitimate_probability: 0.1,
        phishing_probability: 0.0,
    };

    assert!(fine_tuned_nlp_is_actionable(&profile, ThreatLevel::High));
}

#[test]
fn fine_tuned_5class_low_top_score_is_advisory_only() {
    // Verdict claims High but the top class only reached 0.34 — weak,
    // easily steered by adversarial phrasing; must not score directly.
    let profile = NlpSignalProfile {
        model_type: Some("fine-tuned-5class".to_string()),
        top_label: Some("phishing".to_string()),
        top_score: 0.34,
        malicious_probability: 0.62,
        legitimate_probability: 0.28,
        phishing_probability: 0.0,
    };

    assert!(!fine_tuned_nlp_is_actionable(&profile, ThreatLevel::High));
}

#[test]
fn fine_tuned_5class_legitimate_top_label_is_advisory_only() {
    // Adversarial inconsistency: verdict High while the model's own top
    // label is "legitimate".
    let profile = NlpSignalProfile {
        model_type: Some("fine-tuned-5class".to_string()),
        top_label: Some("legitimate".to_string()),
        top_score: 0.55,
        malicious_probability: 0.9,
        legitimate_probability: 0.45,
        phishing_probability: 0.0,
    };

    assert!(!fine_tuned_nlp_is_actionable(&profile, ThreatLevel::High));
}

#[test]
fn fine_tuned_2class_requires_malicious_band_probability() {
    // Legacy 2-class has no top_label; the phishing probability must sit
    // in the malicious band the verdict claims (>= 0.40 per the Python
    // band mapping).
    let consistent = NlpSignalProfile {
        model_type: Some("fine-tuned".to_string()),
        phishing_probability: 0.72,
        ..Default::default()
    };
    let inconsistent = NlpSignalProfile {
        model_type: Some("fine-tuned".to_string()),
        phishing_probability: 0.21,
        ..Default::default()
    };

    assert!(fine_tuned_nlp_is_actionable(&consistent, ThreatLevel::High));
    assert!(!fine_tuned_nlp_is_actionable(
        &inconsistent,
        ThreatLevel::High
    ));
}

#[test]
fn fine_tuned_gate_ignores_safe_verdicts_and_other_models() {
    let safe_profile = NlpSignalProfile {
        model_type: Some("fine-tuned-5class".to_string()),
        top_label: Some("legitimate".to_string()),
        top_score: 0.9,
        ..Default::default()
    };
    // Safe/Low verdicts never score; gate must not interfere.
    assert!(fine_tuned_nlp_is_actionable(
        &safe_profile,
        ThreatLevel::Safe
    ));
    assert!(fine_tuned_nlp_is_actionable(
        &safe_profile,
        ThreatLevel::Low
    ));

    let zero_shot_profile = NlpSignalProfile {
        model_type: Some("zero-shot".to_string()),
        ..Default::default()
    };
    // Zero-shot has its own gate; the fine-tuned gate leaves it alone.
    assert!(fine_tuned_nlp_is_actionable(
        &zero_shot_profile,
        ThreatLevel::High
    ));
}
