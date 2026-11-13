//! Bounded Python NLP request views, response gates, and completion handling.

use std::time::Duration;

use tracing::{debug, warn};
use vigilyx_core::models::EmailSession;

use crate::module::{Evidence, ThreatLevel};

use super::remote::{AiAnalysisResponse, ContentAnalysisRequest, RemoteError, RemoteModuleProxy};
/// NLP remote timeout. Semantic NLP is supplementary; a long wait should not
/// stall the whole verdict path when the AI side is overloaded.
/// Raised from 4s → 8s because the 55-core server under load regularly
/// exceeds 4s, causing unnecessary backoff escalation.
pub(crate) const NLP_TIMEOUT: Duration = Duration::from_secs(8);

/// Match the Python default aggregate budget (8 x 3000-character windows)
/// without cloning a parser-sized body into the HTTP request.
pub(crate) const NLP_BODY_MAX_BYTES: usize = 24_000;
const NLP_BODY_SAMPLE_WINDOWS: usize = 8;
const NLP_OMISSION_MARKER: &str = "\n[... omitted ...]\n";

/// Build a bounded, UTF-8-safe AI request view with windows distributed over
/// the complete body. The caller must separately surface the coverage gap.
pub(crate) fn truncate_body_for_nlp(body: &str) -> String {
    if body.len() <= NLP_BODY_MAX_BYTES {
        return body.to_string();
    }

    let separator_budget = NLP_OMISSION_MARKER.len() * (NLP_BODY_SAMPLE_WINDOWS - 1);
    let content_budget = NLP_BODY_MAX_BYTES - separator_budget;
    let base_window = content_budget / NLP_BODY_SAMPLE_WINDOWS;
    let remainder = content_budget % NLP_BODY_SAMPLE_WINDOWS;
    let mut sampled = String::with_capacity(NLP_BODY_MAX_BYTES);

    for index in 0..NLP_BODY_SAMPLE_WINDOWS {
        if index > 0 {
            sampled.push_str(NLP_OMISSION_MARKER);
        }
        let window_budget = base_window + if index < remainder { 1 } else { 0 };
        let (start, end) = if index == NLP_BODY_SAMPLE_WINDOWS - 1 {
            let start = ceil_char_boundary(body, body.len().saturating_sub(window_budget));
            (start, body.len())
        } else {
            let span = body.len().saturating_sub(window_budget);
            let desired_start = index * span / (NLP_BODY_SAMPLE_WINDOWS - 1);
            let start = floor_char_boundary(body, desired_start);
            let end = floor_char_boundary(body, (start + window_budget).min(body.len()));
            (start, end)
        };
        sampled.push_str(body.get(start..end).unwrap_or_default());
    }

    sampled
}

#[derive(Debug, Default, Clone)]
pub(crate) struct NlpSignalProfile {
    pub(crate) model_type: Option<String>,
    pub(crate) top_label: Option<String>,
    pub(crate) top_score: f64,
    pub(crate) malicious_probability: f64,
    pub(crate) legitimate_probability: f64,
    /// Legacy 2-class fine-tuned models expose `phishing_probability`
    /// instead of top_label/top_score.
    pub(crate) phishing_probability: f64,
}

fn summarize_nlp_signal(details: &serde_json::Value) -> NlpSignalProfile {
    let probabilities = details.get("probabilities");
    NlpSignalProfile {
        model_type: details
            .get("model_type")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        top_label: details
            .get("top_label")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        top_score: details
            .get("top_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        malicious_probability: details
            .get("malicious_probability")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        legitimate_probability: probabilities
            .and_then(|v| v.get("legitimate"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        phishing_probability: details
            .get("phishing_probability")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
    }
}

/// Malicious fine-tuned 5-class labels (mirror of Python
/// FINETUNED_LABEL_NAMES minus "legitimate").
const FINETUNED_MALICIOUS_LABELS: &[&str] =
    &["phishing", "spoofing", "social_engineering", "other_threat"];

/// Consistency gate for fine-tuned NLP signals. Unlike zero-shot (which has
/// its own advisory gate), a fine-tuned verdict previously contributed up to
/// 0.22 unconditionally; an adversarially steered or inconsistent model
/// (e.g. top label "legitimate" while the verdict claims High) could push
/// score directly. Now a malicious fine-tuned verdict must be backed by a
/// coherent label distribution, otherwise it degrades to advisory-only.
pub(crate) fn fine_tuned_nlp_is_actionable(
    profile: &NlpSignalProfile,
    threat: ThreatLevel,
) -> bool {
    let is_fine_tuned = matches!(
        profile.model_type.as_deref(),
        Some("fine-tuned") | Some("fine-tuned-5class")
    );
    if !is_fine_tuned || threat < ThreatLevel::Medium {
        // Non-fine-tuned models use their own gates; Safe/Low verdicts never
        // score anyway.
        return true;
    }
    match profile.model_type.as_deref() {
        Some("fine-tuned-5class") => {
            let label_is_malicious = profile
                .top_label
                .as_deref()
                .map(|label| FINETUNED_MALICIOUS_LABELS.contains(&label))
                .unwrap_or(false);
            label_is_malicious && profile.top_score >= 0.5
        }
        // Legacy 2-class: no top_label; require the phishing probability to
        // actually sit in the malicious band the verdict claims.
        _ => profile.phishing_probability >= 0.40,
    }
}

pub(crate) fn zero_shot_nlp_is_actionable(
    profile: &NlpSignalProfile,
    has_rule_corroboration: bool,
) -> bool {
    if profile.model_type.as_deref() != Some("zero-shot") {
        return true;
    }
    if !has_rule_corroboration {
        return false;
    }
    if profile.top_label.as_deref() == Some("legitimate") {
        return false;
    }
    if profile.top_score < 0.45 {
        return false;
    }
    if profile.malicious_probability < 0.80 {
        return false;
    }
    if profile.legitimate_probability > 0.0
        && profile.top_score <= profile.legitimate_probability + 0.10
    {
        return false;
    }
    true
}

pub(crate) type NlpHandle = tokio::task::JoinHandle<Result<AiAnalysisResponse, RemoteError>>;

pub(crate) struct NlpRequestStatus {
    pub(crate) nlp_status: &'static str,
    pub(crate) nlp_skipped_temporarily: bool,
    pub(crate) nlp_retry_after_secs: Option<u64>,
    pub(crate) nlp_status_message: Option<String>,
}

pub(crate) struct NlpRequest {
    pub(crate) handle: Option<NlpHandle>,
    pub(crate) sampled_body: Option<String>,
    pub(crate) request_status: NlpRequestStatus,
}

/// Start AI work concurrently with local analysis. The caller retains ownership
/// of local evidence qualification and coverage reporting for omitted input.
pub(crate) fn start_nlp_request(
    remote: Option<&RemoteModuleProxy>,
    session: &EmailSession,
    subject: Option<&str>,
    body: &str,
) -> NlpRequest {
    let mut request = NlpRequest {
        handle: None,
        sampled_body: None,
        request_status: NlpRequestStatus {
            nlp_status: "disabled",
            nlp_skipped_temporarily: false,
            nlp_retry_after_secs: None,
            nlp_status_message: Some(
                "AI/NLP service is not configured; using rule-based analysis only".to_string(),
            ),
        },
    };
    let Some(remote) = remote else {
        return request;
    };
    if !remote.is_request_available() {
        let retry_after_secs = remote.cooldown_remaining_secs();
        request.request_status = NlpRequestStatus {
            nlp_status: "cooldown",
            nlp_skipped_temporarily: true,
            nlp_retry_after_secs: Some(retry_after_secs),
            nlp_status_message: Some(format!(
                "AI/NLP service is temporarily unavailable; retry after about {retry_after_secs}s"
            )),
        };
        debug!(
            retry_after_secs,
            "Skipping NLP request while AI remote is in cooldown"
        );
        return request;
    }

    let nlp_body = truncate_body_for_nlp(body);
    request.sampled_body = Some(nlp_body.clone());
    request.request_status.nlp_status = "pending";
    request.request_status.nlp_status_message = None;
    let input = ContentAnalysisRequest {
        session_id: session.id.to_string(),
        subject: subject.map(str::to_string),
        body_text: Some(nlp_body),
        body_html: None,
        mail_from: session.mail_from.clone(),
        rcpt_to: session.rcpt_to.clone(),
        // The transport attaches configured LLM second-opinion settings.
        llm: None,
    };
    debug!("Firing NLP request first (most time-consuming)");
    let remote = remote.clone();
    request.handle = Some(tokio::spawn(async move {
        match tokio::time::timeout(NLP_TIMEOUT, remote.analyze_content(&input)).await {
            Ok(result) => result,
            Err(_) => {
                remote.note_timeout();
                Err(RemoteError::Timeout)
            }
        }
    }));
    request
}

pub(crate) struct NlpOutcome {
    pub(crate) nlp_used: bool,
    pub(crate) nlp_contributed: bool,
    pub(crate) nlp_contribution_score: f64,
    pub(crate) nlp_reported_coverage_limited: bool,
    pub(crate) nlp_details: serde_json::Value,
    pub(crate) nlp_observed_categories: Vec<String>,
    pub(crate) nlp_scored_categories: Vec<String>,
    pub(crate) request_status: NlpRequestStatus,
}

/// Await the already-started request and apply the existing contribution gates.
pub(crate) async fn complete_nlp_request(
    nlp_handle: Option<NlpHandle>,
    has_rule_corroboration: bool,
    request_status: NlpRequestStatus,
    score: &mut f64,
    categories: &mut Vec<String>,
    evidence: &mut Vec<Evidence>,
) -> NlpOutcome {
    let NlpRequestStatus {
        mut nlp_status,
        mut nlp_skipped_temporarily,
        mut nlp_retry_after_secs,
        mut nlp_status_message,
    } = request_status;
    let mut nlp_used = false;
    let mut nlp_contributed = false;
    let mut nlp_contribution_score = 0.0;
    let mut nlp_reported_coverage_limited = false;
    let mut nlp_details = serde_json::Value::Null;
    let mut nlp_observed_categories = Vec::<String>::new();
    let mut nlp_scored_categories = Vec::<String>::new();
    if let Some(handle) = nlp_handle {
        match handle.await {
            Ok(Ok(ai_resp)) => {
                nlp_used = true;
                nlp_observed_categories = ai_resp.categories.clone();
                if ai_resp
                    .categories
                    .iter()
                    .any(|category| category == "nlp_spam")
                {
                    categories.push("nlp_spam".to_string());
                }
                let nlp_threat = ai_resp.to_threat_level();
                let nlp_confidence = ai_resp.confidence;
                // Captured before `details` is moved out below: the
                // Python LLM second opinion flags forged/injected
                // verdicts here instead of rendering them.
                let llm_injection_suspected = ai_resp.llm_injection_suspected();
                nlp_details = ai_resp.details.unwrap_or(serde_json::Value::Null);
                nlp_reported_coverage_limited = nlp_details
                    .get("coverage_limited")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let signal_profile = summarize_nlp_signal(&nlp_details);
                let zero_shot_advisory_only = signal_profile.model_type.as_deref()
                    == Some("zero-shot")
                    && !zero_shot_nlp_is_actionable(&signal_profile, has_rule_corroboration);
                let fine_tuned_advisory_only =
                    !fine_tuned_nlp_is_actionable(&signal_profile, nlp_threat);

                let mut nlp_evidence_description = format!(
                    "NLP model verdict: {} (confidence {:.1}%) — {}",
                    ai_resp.threat_level,
                    nlp_confidence * 100.0,
                    ai_resp.summary,
                );
                if zero_shot_advisory_only {
                    nlp_evidence_description
                        .push_str(" (zero-shot advisory only; not used for scoring)");
                }
                if fine_tuned_advisory_only {
                    nlp_evidence_description.push_str(
                        " (fine-tuned verdict inconsistent with its own label distribution; advisory only)",
                    );
                }
                if !has_rule_corroboration {
                    nlp_evidence_description.push_str(
                        " (no independently admitted native semantic relation; advisory only)",
                    );
                }
                evidence.push(Evidence {
                    description: nlp_evidence_description,
                    location: Some("body:nlp".to_string()),
                    snippet: None,
                });

                let nlp_base = match (signal_profile.model_type.as_deref(), nlp_threat) {
                    (_, ThreatLevel::Safe | ThreatLevel::Low) => 0.0,
                    (Some("zero-shot"), ThreatLevel::Medium) => 0.05,
                    (Some("zero-shot"), ThreatLevel::High) => 0.08,
                    (Some("zero-shot"), ThreatLevel::Critical) => 0.10,
                    (_, ThreatLevel::Medium) => 0.10,
                    (_, ThreatLevel::High) => 0.15,
                    (_, ThreatLevel::Critical) => 0.20,
                };

                let nlp_has_attack_label = ai_resp.categories.iter().any(|category| {
                    matches!(category.as_str(), "nlp_phishing" | "nlp_bec" | "nlp_scam")
                });
                let nlp_score = if !has_rule_corroboration
                    || !nlp_has_attack_label
                    || zero_shot_advisory_only
                    || fine_tuned_advisory_only
                {
                    0.0
                } else if signal_profile.model_type.as_deref() == Some("zero-shot") {
                    if nlp_confidence >= 0.80 && nlp_threat >= ThreatLevel::High {
                        (nlp_base + nlp_confidence * 0.03).min(0.12)
                    } else {
                        nlp_base
                    }
                } else if nlp_confidence >= 0.70 && nlp_threat >= ThreatLevel::High {
                    (nlp_base + nlp_confidence * 0.08).min(0.22)
                } else {
                    nlp_base
                };

                if nlp_score > 0.0 {
                    nlp_contributed = true;
                    nlp_contribution_score = nlp_score;
                    *score += nlp_score;
                    nlp_status = "ok";
                    nlp_status_message = Some(
                        "AI/NLP analysis completed and provided corroborating evidence".to_string(),
                    );
                    nlp_scored_categories = ai_resp
                        .categories
                        .iter()
                        .filter(|category| {
                            matches!(category.as_str(), "nlp_phishing" | "nlp_bec" | "nlp_scam")
                        })
                        .cloned()
                        .collect();
                    categories.extend(nlp_scored_categories.clone());
                } else {
                    nlp_status = "ok";
                    nlp_status_message = Some(
                        "AI/NLP analysis completed but remained advisory-only; rule engine stayed primary"
                            .to_string(),
                    );
                }

                if llm_injection_suspected {
                    // Dropping an out-of-whitelist model response is an
                    // integrity diagnostic, not native attack evidence.
                    categories.push("llm_injection_suspected".to_string());
                    evidence.push(Evidence {
                        description: "LLM second opinion returned a verdict outside the allowed whitelist (likely injected via email content); forged verdict was dropped".to_string(),
                        location: Some("body:llm".to_string()),
                        snippet: None,
                    });
                }
            }
            Ok(Err(RemoteError::TemporarilyUnavailable { retry_after_secs })) => {
                nlp_skipped_temporarily = true;
                nlp_status = "cooldown";
                nlp_retry_after_secs = Some(retry_after_secs);
                nlp_status_message = Some(format!(
                    "AI/NLP service is temporarily unavailable; retry after about {}s",
                    retry_after_secs
                ));
                warn!(
                    retry_after_secs,
                    "NLP service temporarily unavailable, skipping semantic NLP"
                );
                evidence.push(Evidence {
                    description: format!(
                        "NLP service temporarily unavailable (retry after ~{}s); falling back to rule-based detection",
                        retry_after_secs
                    ),
                    location: Some("body:nlp".to_string()),
                    snippet: None,
                });
            }
            Ok(Err(RemoteError::Timeout)) => {
                nlp_status = "timeout";
                nlp_status_message = Some(format!(
                    "AI/NLP request timed out after {}s; using rule-based analysis only",
                    NLP_TIMEOUT.as_secs()
                ));
                warn!(
                    "NLP service timeout ({}s), falling back to rule-based",
                    NLP_TIMEOUT.as_secs()
                );
                evidence.push(Evidence {
                    description: format!(
                        "NLP service timeout ({}s) (falling back to rule-based detection)",
                        NLP_TIMEOUT.as_secs()
                    ),
                    location: Some("body:nlp".to_string()),
                    snippet: None,
                });
            }
            Ok(Err(e)) => {
                nlp_status = "error";
                nlp_status_message = Some(format!(
                    "AI/NLP request failed: {}; using rule-based analysis only",
                    e
                ));
                warn!("NLP service error: {}, falling back to rule-based", e);
                evidence.push(Evidence {
                    description: format!(
                        "NLP service call failed: {} (falling back to rule-based detection)",
                        e
                    ),
                    location: Some("body:nlp".to_string()),
                    snippet: None,
                });
            }
            Err(e) => {
                nlp_status = "error";
                nlp_status_message = Some(format!(
                    "AI/NLP task terminated unexpectedly: {}; using rule-based analysis only",
                    e
                ));
                warn!("NLP task panicked: {}, falling back to rule-based", e);
                evidence.push(Evidence {
                    description: format!(
                        "NLP task abnormal: {} (falling back to rule-based detection)",
                        e
                    ),
                    location: Some("body:nlp".to_string()),
                    snippet: None,
                });
            }
        }
    }

    NlpOutcome {
        nlp_used,
        nlp_contributed,
        nlp_contribution_score,
        nlp_reported_coverage_limited,
        nlp_details,
        nlp_observed_categories,
        nlp_scored_categories,
        request_status: NlpRequestStatus {
            nlp_status,
            nlp_skipped_temporarily,
            nlp_retry_after_secs,
            nlp_status_message,
        },
    }
}

fn floor_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn ceil_char_boundary(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}
