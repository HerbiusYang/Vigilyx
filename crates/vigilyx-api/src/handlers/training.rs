//! NLP model training API handlers
//!
//! - GET /admin/nlp/samples - List training samples
//! - DELETE /admin/nlp/samples/{id} - Delete a training sample
//! - PUT /admin/nlp/samples/{id} - Update a training sample label
//! - GET /admin/nlp/samples/export - Export the complete training dataset
//! - GET /admin/nlp/stats - Training data statistics
//! - POST /admin/nlp/train - Trigger NLP model fine-tuning
//! - POST /admin/nlp/approve - Approve a staged (pending) trained model
//! - GET /admin/nlp/status - NLP training status
//! - GET /admin/nlp/progress - Training progress

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::IntoResponse,
};
use sha2::{Digest, Sha256};
use std::sync::{Arc, OnceLock};
use vigilyx_core::{
    DEFAULT_INTERNAL_SERVICE_HOSTS, security::LABEL_NAMES, validate_internal_service_url,
};

use super::{ApiResponse, PaginationParams, spawn_audit_log};
use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::training_redaction::{REDACTION_PROFILE, RedactionKey, Redactor, mark_raw_payload};

const MIN_TRAINING_SAMPLES: u64 = 30;
const MAX_TRAINING_REQUEST_SAMPLES: u64 = 10_000;
const MAX_TRAINING_SUBJECT_CHARS: usize = 500;
const MAX_TRAINING_BODY_CHARS: usize = 20_000;
const MAX_TRAINING_ADDRESS_CHARS: usize = 320;
const MAX_TRAINING_COMMENT_CHARS: usize = 2_000;
const MAX_TRAINING_RECIPIENTS: usize = 100;
const TRAINING_DATASET_SCHEMA: &str = "vigilyx.email_training.v1";
const MAX_TRAINING_TEXT_CHARS: usize = 3_000;

#[derive(Debug, Default, serde::Deserialize)]
pub struct TrainingExportParams {
    /// Safe by default. `false` is an explicit administrator opt-out from
    /// privacy transformation and is confirmed in the UI.
    redact: Option<bool>,
}

// Handlers

/// List training samples (paginated)
pub async fn get_training_samples(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.limit.min(200);
    let offset = params.page.saturating_sub(1) * limit; // use clamped `limit`, not raw input

    match state.engine_db.list_training_samples(limit, offset).await {
        Ok(samples) => ApiResponse::ok(serde_json::to_value(samples).unwrap_or_default()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

/// Export the complete bounded training dataset as JSONL.
///
/// This endpoint is intentionally separate from the paginated list endpoint:
/// the UI only displays recent samples, while an administrator may need every
/// labeled sample for an AI training hand-off or an auditable backup. SQL
/// bounds each content field and the JSONL response is marked as a download so
/// browsers do not render stored email HTML as a page. Each record also carries
/// a canonical `text` field that can be consumed by standard text-classification
/// tooling without reimplementing the Rust/Python field-selection rules.
pub async fn export_training_samples(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Query(params): Query<TrainingExportParams>,
) -> axum::response::Response {
    let redacted = params.redact.unwrap_or(true);
    let redaction_key = redacted.then(RedactionKey::from_env);
    let samples = match state.engine_db.get_all_training_samples_for_export().await {
        Ok(samples) => samples,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(
                &error,
                "Failed to load training samples for export",
            )
            .into_response();
        }
    };

    let mut body = Vec::new();
    for sample in &samples {
        let payload =
            match training_sample_export_payload_with_redaction(sample, redaction_key.as_ref()) {
                Ok(payload) => payload,
                Err(error) => return ApiResponse::<serde_json::Value>::err(error).into_response(),
            };
        if let Err(error) = serde_json::to_writer(&mut body, &payload) {
            return ApiResponse::<serde_json::Value>::internal_err(
                &error,
                "Failed to serialize training sample export",
            )
            .into_response();
        }
        body.push(b'\n');
    }

    let content_length = body.len().to_string();
    let dataset_sha256 = Sha256::digest(&body)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    spawn_audit_log(
        state.engine_db.clone(),
        user.username,
        if redacted {
            "export_training_dataset_redacted"
        } else {
            "export_training_dataset_raw"
        },
        Some("training_dataset"),
        None,
        Some(format!(
            "redacted={redacted}; count={}; schema={TRAINING_DATASET_SCHEMA}; sha256={dataset_sha256}",
            samples.len()
        )),
    );
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")
        .header(
            header::CONTENT_DISPOSITION,
            if redacted {
                "attachment; filename=\"vigilyx-training-dataset-v1-redacted.jsonl\""
            } else {
                "attachment; filename=\"vigilyx-training-dataset-v1-raw.jsonl\""
            },
        )
        .header(header::CONTENT_LENGTH, content_length)
        .header("x-vigilyx-dataset-schema", TRAINING_DATASET_SCHEMA)
        .header("x-vigilyx-dataset-count", samples.len().to_string())
        .header("x-vigilyx-dataset-sha256", dataset_sha256)
        .header(
            "x-vigilyx-redacted",
            if redacted { "true" } else { "false" },
        )
        .header(
            "x-vigilyx-redaction-profile",
            if redacted { REDACTION_PROFILE } else { "none" },
        )
        .header(header::CACHE_CONTROL, "no-store, no-cache")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(body))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal error"))
                .expect("fallback response")
        })
        .into_response()
}

/// Delete a training sample
pub async fn delete_training_sample(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.engine_db.delete_training_sample(&id).await {
        Ok(true) => ApiResponse::ok(serde_json::json!({ "deleted": true })).into_response(),
        Ok(false) => {
            ApiResponse::<serde_json::Value>::not_found("Sample not found").into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Get training data statistics (label counts + Python model status)
pub async fn get_training_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let label_counts = match state.engine_db.get_training_sample_counts().await {
        Ok(c) => c,
        Err(e) => return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    };
    // `label_name` is NOT NULL, so the grouped counts are an exact total. This
    // avoids a second full-table COUNT on every settings-page load.
    let total_samples: u64 = label_counts.values().copied().sum();

    let min_samples_required = MIN_TRAINING_SAMPLES;

    // Do not probe a deliberately disabled optional service. Apart from being
    // unnecessary work, a failed Docker-network connection used to make this
    // otherwise local page wait for the full HTTP timeout.
    let ai_config = get_ai_service_config(&state).await;
    let model_status = if ai_config.enabled {
        let url = match build_ai_service_endpoint(&ai_config.service_url, "training/status") {
            Ok(url) => url,
            Err(error) => {
                return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed");
            }
        };

        let client = &state.http_client;
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.get(&url).send()).await
        {
            Ok(Ok(resp)) => resp.json::<serde_json::Value>().await.ok(),
            _ => None,
        }
    } else {
        None
    };

    // Training cannot start without a reachable AI service.  Returning this
    // explicitly prevents the UI from presenting a misleading "base" model
    // and an actionable training button when the optional AI container is off.
    let ai_service_available = model_status.is_some();

    // Inference availability does not imply that the service supports training.
    let training_enabled = model_status
        .as_ref()
        .and_then(|s| s.get("training_enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let is_training = model_status
        .as_ref()
        .and_then(|s| s.get("is_training"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let can_train = ai_service_available
        && training_enabled
        && total_samples >= min_samples_required
        && !is_training;

    let mut result = serde_json::json!({
        "total_samples": total_samples,
        "label_counts": label_counts,
        "min_samples_required": min_samples_required,
        "can_train": can_train,
        "ai_service_available": ai_service_available,
        "training_enabled": training_enabled,
    });

    if let Some(status) = model_status
        && let Some(obj) = result.as_object_mut()
    {
        obj.insert(
            "model_version".to_string(),
            status
                .get("model_version")
                .cloned()
                .unwrap_or(serde_json::json!("base")),
        );
        obj.insert(
            "has_finetuned".to_string(),
            status
                .get("has_finetuned")
                .cloned()
                .unwrap_or(serde_json::json!(false)),
        );
        obj.insert(
            "is_training".to_string(),
            status
                .get("is_training")
                .cloned()
                .unwrap_or(serde_json::json!(false)),
        );
        obj.insert(
            "last_trained".to_string(),
            status
                .get("last_trained")
                .cloned()
                .unwrap_or(serde_json::json!(null)),
        );
    }

    ApiResponse::ok(result)
}

/// Trigger NLP model fine-tuning.
///
/// Loads training samples from DB and sends them to the Python AI service.
pub async fn trigger_nlp_training(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // 1. Check sample count before loading and serializing training data.
    let total_samples = match state.engine_db.count_training_samples().await {
        Ok(n) => n,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::internal_err(
                &e,
                "Failed to count training samples",
            );
        }
    };

    if total_samples < MIN_TRAINING_SAMPLES {
        return ApiResponse::<serde_json::Value>::err(format!(
            "Insufficient training samples: {}/{}",
            total_samples, MIN_TRAINING_SAMPLES
        ));
    }

    if total_samples > MAX_TRAINING_REQUEST_SAMPLES {
        return ApiResponse::<serde_json::Value>::err(format!(
            "Too many training samples for one training request: {}/{}",
            total_samples, MAX_TRAINING_REQUEST_SAMPLES
        ));
    }

    // 2. Load training samples from DB.
    let samples = match state
        .engine_db
        .get_training_samples_for_export(MAX_TRAINING_REQUEST_SAMPLES as u32)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::internal_err(
                &e,
                "Failed to load training samples",
            );
        }
    };

    // 3. Build bounded payload and send to Python AI service.
    let payload: Vec<serde_json::Value> = match samples
        .iter()
        .map(training_sample_training_payload)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(payload) => payload,
        Err(error) => return ApiResponse::<serde_json::Value>::err(error),
    };

    let ai_url = get_ai_service_url(&state).await;
    let url = match build_ai_service_endpoint(&ai_url, "training/train") {
        Ok(url) => url,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed");
        }
    };

    let client = &state.http_client;
    // CPU-intensive training; 24h timeout (Python handles progress internally)
    match tokio::time::timeout(
        std::time::Duration::from_secs(86400),
        client
            .post(&url)
            .json(&serde_json::json!({ "samples": payload }))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => match resp.json::<serde_json::Value>().await {
            Ok(body) => ApiResponse::ok(body),
            Err(e) => {
                tracing::error!(error = %e, "Failed to parse AI training response");
                ApiResponse::<serde_json::Value>::err("AI service returned an invalid response")
            }
        },
        Ok(Err(e)) => {
            tracing::error!(error = %e, "AI training service connection failed");
            ApiResponse::<serde_json::Value>::err("AI service is unavailable")
        }
        Err(_) => ApiResponse::<serde_json::Value>::err("Training timed out"),
    }
}

/// Approve a staged (pending) trained model via the Python AI service.
///
/// Proxies POST /model/approve. A successful training run only STAGES the
/// model; it goes live solely through this explicit operator approval.
/// Python rejects with 404 (nothing staged), 409 (staged record changed
/// between review and approval), or 410 (staged model directory missing) —
/// those statuses are forwarded so the UI can react accordingly.
pub async fn approve_nlp_model(State(state): State<Arc<AppState>>) -> axum::response::Response {
    let ai_url = get_ai_service_url(&state).await;
    let url = match build_ai_service_endpoint(&ai_url, "model/approve") {
        Ok(url) => url,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed")
                .into_response();
        }
    };

    let client = &state.http_client;
    // Hot-swapping reloads model weights; allow a generous timeout.
    match tokio::time::timeout(
        std::time::Duration::from_secs(120),
        client.post(&url).send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            let status = resp.status();
            match resp.json::<serde_json::Value>().await {
                Ok(body) if status.is_success() => ApiResponse::ok(body).into_response(),
                Ok(body) => {
                    let detail = body
                        .get("detail")
                        .and_then(|d| d.as_str())
                        .unwrap_or("AI service rejected the approval");
                    tracing::warn!(%status, detail, "AI model approval rejected");
                    (
                        status,
                        Json(ApiResponse::<serde_json::Value> {
                            success: false,
                            data: None,
                            error: Some(detail.to_string()),
                            error_code: None,
                        }),
                    )
                        .into_response()
                }
                Err(e) => {
                    tracing::error!(error = %e, "Failed to parse AI approval response");
                    ApiResponse::<serde_json::Value>::err("AI service returned an invalid response")
                        .into_response()
                }
            }
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "AI approval service connection failed");
            ApiResponse::<serde_json::Value>::err("AI service is unavailable").into_response()
        }
        Err(_) => {
            ApiResponse::<serde_json::Value>::err("AI service not responding").into_response()
        }
    }
}

fn limit_optional_json_string(value: Option<&str>, max_chars: usize) -> serde_json::Value {
    match value {
        Some(text) => serde_json::Value::String(limit_text(text, max_chars)),
        None => serde_json::Value::Null,
    }
}

fn limit_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value.chars().take(max_chars).collect()
    }
}

fn limit_recipient_json_array(recipients: &[String]) -> serde_json::Value {
    serde_json::Value::Array(
        recipients
            .iter()
            .take(MAX_TRAINING_RECIPIENTS)
            .map(|recipient| {
                serde_json::Value::String(limit_text(recipient, MAX_TRAINING_ADDRESS_CHARS))
            })
            .collect(),
    )
}

fn validate_training_label(sample: &vigilyx_core::security::TrainingSample) -> Result<(), String> {
    let expected = usize::try_from(sample.label)
        .ok()
        .and_then(|index| LABEL_NAMES.get(index).copied())
        .ok_or_else(|| {
            format!(
                "Invalid training label {} for sample {}",
                sample.label, sample.id
            )
        })?;

    if sample.label_name != expected {
        return Err(format!(
            "Training label mismatch for sample {}: label {} must be '{}' (got '{}')",
            sample.id, sample.label, expected, sample.label_name
        ));
    }

    Ok(())
}

/// Normalize a stored email into the single text feature used by the NLP model.
///
/// The order intentionally matches the AI service contract: prefer parsed plain
/// text, fall back to HTML, retain sender/subject headers, strip HTML-only
/// presentation, decode entities, collapse whitespace, then apply the same
/// 3,000-character training budget. The raw fields remain in the payload for
/// audit and reproducibility, while `text` is the model-ready feature.
fn canonical_training_text(
    sample: &vigilyx_core::security::TrainingSample,
) -> (String, &'static str, bool) {
    let (body, source) = match sample
        .body_text
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(body) => (body, "body_text"),
        None => match sample
            .body_html
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            Some(body) => (body, "body_html"),
            None => ("", "empty"),
        },
    };

    let mut parts = Vec::new();
    if let Some(mail_from) = sample
        .mail_from
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("From: {mail_from}"));
    }
    if let Some(subject) = sample.subject.as_deref().filter(|value| !value.is_empty()) {
        parts.push(format!("Subject: {subject}"));
    }
    if !body.is_empty() {
        parts.push(clean_training_body(body));
    }

    let combined = parts.join("\n");
    let truncated = combined.chars().count() > MAX_TRAINING_TEXT_CHARS;
    (
        limit_text(&combined, MAX_TRAINING_TEXT_CHARS),
        source,
        truncated,
    )
}

fn clean_training_body(value: &str) -> String {
    static SCRIPT_STYLE_RE: OnceLock<regex::Regex> = OnceLock::new();
    static COMMENT_RE: OnceLock<regex::Regex> = OnceLock::new();
    static TAG_RE: OnceLock<regex::Regex> = OnceLock::new();

    let without_blocks = SCRIPT_STYLE_RE
        .get_or_init(|| {
            regex::Regex::new(r"(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>")
                .expect("valid HTML block regex")
        })
        .replace_all(value, " ");
    let without_comments = COMMENT_RE
        .get_or_init(|| regex::Regex::new(r"(?s)<!--.*?-->").expect("valid HTML comment regex"))
        .replace_all(&without_blocks, " ");
    let without_tags = TAG_RE
        .get_or_init(|| regex::Regex::new(r"(?s)<[^>]+>").expect("valid HTML tag regex"))
        .replace_all(&without_comments, " ");
    let decoded = html_escape::decode_html_entities(&without_tags);

    decoded.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Keep the export schema explicit instead of serializing the database model
/// wholesale. This makes the bounds part of the API contract and keeps the
/// export aligned with the payload sent to the AI training service.
fn training_sample_training_payload(
    sample: &vigilyx_core::security::TrainingSample,
) -> Result<serde_json::Value, String> {
    validate_training_label(sample)?;
    let (text, text_source, text_truncated) = canonical_training_text(sample);

    Ok(serde_json::json!({
        "schema_version": TRAINING_DATASET_SCHEMA,
        "id": sample.id,
        "session_id": sample.session_id,
        "label": sample.label,
        "label_name": sample.label_name,
        "label_source": if sample.label_source.is_empty() {
            "analyst_feedback".to_string()
        } else {
            sample.label_source.clone()
        },
        "source_threat_type": sample.source_threat_type,
        "text": text,
        "text_source": text_source,
        "text_truncated": text_truncated,
        "subject": limit_optional_json_string(sample.subject.as_deref(), MAX_TRAINING_SUBJECT_CHARS),
        "body_text": limit_optional_json_string(sample.body_text.as_deref(), MAX_TRAINING_BODY_CHARS),
        "body_html": limit_optional_json_string(sample.body_html.as_deref(), MAX_TRAINING_BODY_CHARS),
        "mail_from": limit_optional_json_string(sample.mail_from.as_deref(), MAX_TRAINING_ADDRESS_CHARS),
        "rcpt_to": limit_recipient_json_array(&sample.rcpt_to),
        "analyst_comment": limit_optional_json_string(sample.analyst_comment.as_deref(), MAX_TRAINING_COMMENT_CHARS),
        "original_threat_level": sample.original_threat_level,
        "verdict_id": sample.verdict_id,
        "created_at": sample.created_at,
    }))
}

fn training_sample_export_payload_with_redaction(
    sample: &vigilyx_core::security::TrainingSample,
    redaction_key: Option<&RedactionKey>,
) -> Result<serde_json::Value, String> {
    let payload = training_sample_training_payload(sample)?;
    Ok(match redaction_key {
        Some(key) => Redactor::new(key.clone()).redact_payload(payload),
        None => mark_raw_payload(payload),
    })
}

/// Query NLP model status from Python AI service
pub async fn get_nlp_training_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ai_url = get_ai_service_url(&state).await;
    let url = match build_ai_service_endpoint(&ai_url, "training/status") {
        Ok(url) => url,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed");
        }
    };

    let client = &state.http_client;
    match tokio::time::timeout(std::time::Duration::from_secs(5), client.get(&url).send()).await {
        Ok(Ok(resp)) => match resp.json::<serde_json::Value>().await {
            Ok(body) => ApiResponse::ok(body),
            Err(e) => {
                tracing::error!(error = %e, "Failed to parse AI training status response");
                ApiResponse::<serde_json::Value>::err("AI service returned an invalid response")
            }
        },
        Ok(Err(e)) => {
            tracing::error!(error = %e, "AI training status connection failed");
            ApiResponse::<serde_json::Value>::err("AI service is unavailable")
        }
        Err(_) => ApiResponse::<serde_json::Value>::err("AI service not responding"),
    }
}

/// Query training progress from Python AI service
pub async fn get_training_progress(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ai_url = get_ai_service_url(&state).await;
    let url = match build_ai_service_endpoint(&ai_url, "training/progress") {
        Ok(url) => url,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed");
        }
    };

    let client = &state.http_client;
    match tokio::time::timeout(std::time::Duration::from_secs(3), client.get(&url).send()).await {
        Ok(Ok(resp)) => match resp.json::<serde_json::Value>().await {
            Ok(body) => ApiResponse::ok(body),
            Err(e) => {
                tracing::error!(error = %e, "Failed to parse AI training progress response");
                ApiResponse::<serde_json::Value>::err("AI service returned an invalid response")
            }
        },
        Ok(Err(e)) => {
            tracing::error!(error = %e, "AI training progress connection failed");
            ApiResponse::<serde_json::Value>::err("AI service is unavailable")
        }
        Err(_) => ApiResponse::<serde_json::Value>::err("AI service not responding"),
    }
}

pub async fn update_training_sample(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let label_name = match body.get("label_name").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return ApiResponse::<serde_json::Value>::bad_request("Missing label_name field")
                .into_response();
        }
    };

    let (label, label_name) = match vigilyx_core::security::feedback_type_to_label(label_name) {
        Some(pair) => pair,
        None => {
            return ApiResponse::<serde_json::Value>::bad_request(format!(
                "Invalid label name: {}",
                label_name
            ))
            .into_response();
        }
    };

    match state
        .engine_db
        .update_training_sample_label(&id, label, label_name)
        .await
    {
        Ok(true) => ApiResponse::ok(serde_json::json!({
            "updated": true,
            "label": label,
            "label_name": label_name,
        }))
        .into_response(),
        Ok(false) => {
            ApiResponse::<serde_json::Value>::not_found("Sample not found").into_response()
        }
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Get AI service URL from DB, with runtime allowlist validation (CWE-918).
/// Falls back to default if DB value fails validation (DB poisoning protection).
fn build_ai_service_endpoint(base_url: &str, endpoint: &str) -> Result<String, String> {
    let base = url::Url::parse(base_url).map_err(|e| format!("Invalid AI service URL: {e}"))?;
    base.join(endpoint)
        .map(|url| url.to_string())
        .map_err(|e| format!("Failed to build AI service endpoint: {e}"))
}

async fn get_ai_service_url(state: &AppState) -> String {
    get_ai_service_config(state).await.service_url
}

async fn get_ai_service_config(state: &AppState) -> vigilyx_engine::config::AiServiceConfig {
    let default_url = vigilyx_engine::config::AiServiceConfig::default().service_url;
    let mut config = match state.engine_db.get_config("ai_service_config").await {
        Ok(Some(json)) => {
            match serde_json::from_str::<vigilyx_engine::config::AiServiceConfig>(&json) {
                Ok(cfg) => cfg,
                Err(_) => {
                    return vigilyx_engine::config::AiServiceConfig {
                        service_url: default_url,
                        ..vigilyx_engine::config::AiServiceConfig::default()
                    };
                }
            }
        }
        _ => {
            return vigilyx_engine::config::AiServiceConfig {
                service_url: default_url,
                ..vigilyx_engine::config::AiServiceConfig::default()
            };
        }
    };

    // SEC: Validate URL allowlist at runtime - same as API save-time check
    if validate_internal_service_url(&config.service_url, DEFAULT_INTERNAL_SERVICE_HOSTS).is_ok() {
        return config;
    }

    tracing::warn!(
        url = %config.service_url,
        "SEC: AI service URL from DB failed runtime allowlist, using default"
    );
    config.service_url = default_url;
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn training_payload_limiter_preserves_utf8_boundaries() {
        assert_eq!(limit_text("测试abc", 3), "测试a");
        assert_eq!(
            limit_optional_json_string(Some("测试abc"), 2),
            serde_json::json!("测试")
        );
        assert_eq!(limit_optional_json_string(None, 2), serde_json::Value::Null);
    }

    #[test]
    fn training_payload_limiter_caps_recipient_list() {
        let recipients: Vec<String> = (0..150)
            .map(|idx| format!("{}@example.com", "a".repeat(400 + idx)))
            .collect();

        let value = limit_recipient_json_array(&recipients);
        let array = value.as_array().expect("recipient list should be an array");

        assert_eq!(array.len(), MAX_TRAINING_RECIPIENTS);
        assert!(array.iter().all(|item| {
            item.as_str()
                .map(|text| text.chars().count() <= MAX_TRAINING_ADDRESS_CHARS)
                .unwrap_or(false)
        }));
    }

    #[test]
    fn training_export_payload_keeps_metadata_and_bounds_content() {
        let sample = vigilyx_core::security::TrainingSample {
            id: Uuid::nil(),
            session_id: Uuid::nil(),
            label: 1,
            label_name: "phishing".to_string(),
            subject: Some("主题".repeat(MAX_TRAINING_SUBJECT_CHARS + 1)),
            body_text: Some("正文".repeat(MAX_TRAINING_BODY_CHARS + 1)),
            body_html: None,
            mail_from: Some("sender@example.invalid".to_string()),
            rcpt_to: vec!["recipient@example.invalid".to_string(); MAX_TRAINING_RECIPIENTS + 1],
            analyst_comment: Some("备注".repeat(MAX_TRAINING_COMMENT_CHARS + 1)),
            original_threat_level: "medium".to_string(),
            verdict_id: None,
            created_at: Utc::now(),
            label_source: "analyst_feedback".to_string(),
            source_threat_type: None,
        };

        let payload = training_sample_export_payload_with_redaction(&sample, None)
            .expect("valid training sample");
        assert_eq!(payload["label_name"], "phishing");
        assert_eq!(payload["schema_version"], TRAINING_DATASET_SCHEMA);
        assert_eq!(payload["text_source"], "body_text");
        assert_eq!(payload["text_truncated"], true);
        assert!(payload["text"].as_str().unwrap().chars().count() <= MAX_TRAINING_TEXT_CHARS);
        assert_eq!(
            payload["subject"].as_str().unwrap().chars().count(),
            MAX_TRAINING_SUBJECT_CHARS
        );
        assert_eq!(
            payload["body_text"].as_str().unwrap().chars().count(),
            MAX_TRAINING_BODY_CHARS
        );
        assert_eq!(
            payload["analyst_comment"].as_str().unwrap().chars().count(),
            MAX_TRAINING_COMMENT_CHARS
        );
        assert_eq!(
            payload["rcpt_to"].as_array().unwrap().len(),
            MAX_TRAINING_RECIPIENTS
        );
    }

    #[test]
    fn canonical_training_text_prefers_plain_text_and_cleans_html() {
        let sample = vigilyx_core::security::TrainingSample {
            id: Uuid::nil(),
            session_id: Uuid::nil(),
            label: 1,
            label_name: "phishing".to_string(),
            subject: Some("Verify".to_string()),
            body_text: None,
            body_html: Some("<p>Hello&nbsp;world</p><script>ignore()</script>".to_string()),
            mail_from: Some("sender@example.invalid".to_string()),
            rcpt_to: vec![],
            analyst_comment: None,
            original_threat_level: "high".to_string(),
            verdict_id: None,
            created_at: Utc::now(),
            label_source: "analyst_feedback".to_string(),
            source_threat_type: None,
        };

        let (text, source, truncated) = canonical_training_text(&sample);
        assert_eq!(source, "body_html");
        assert!(!truncated);
        assert!(text.contains("From: sender@example.invalid"));
        assert!(text.contains("Subject: Verify"));
        assert!(text.contains("Hello world"));
        assert!(!text.contains("<p>"));
        assert!(!text.contains("ignore"));
    }

    #[test]
    fn training_payload_rejects_label_name_mismatch() {
        let sample = vigilyx_core::security::TrainingSample {
            id: Uuid::nil(),
            session_id: Uuid::nil(),
            label: 1,
            label_name: "legitimate".to_string(),
            subject: None,
            body_text: Some("text".to_string()),
            body_html: None,
            mail_from: None,
            rcpt_to: vec![],
            analyst_comment: None,
            original_threat_level: "safe".to_string(),
            verdict_id: None,
            created_at: Utc::now(),
            label_source: "analyst_feedback".to_string(),
            source_threat_type: None,
        };

        assert!(training_sample_export_payload_with_redaction(&sample, None).is_err());
    }
}
