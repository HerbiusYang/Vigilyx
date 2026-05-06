//! NLP model training API handlers
//!
//! - GET /admin/nlp/samples - List training samples
//! - DELETE /admin/nlp/samples/{id} - Delete a training sample
//! - PUT /admin/nlp/samples/{id} - Update a training sample label
//! - GET /admin/nlp/stats - Training data statistics
//! - POST /admin/nlp/train - Trigger NLP model fine-tuning
//! - GET /admin/nlp/status - NLP training status
//! - GET /admin/nlp/progress - Training progress

use axum::{
    Json,
    extract::{Path, Query, State},
    response::IntoResponse,
};
use std::sync::Arc;
use vigilyx_core::{DEFAULT_INTERNAL_SERVICE_HOSTS, validate_internal_service_url};

use super::{ApiResponse, PaginationParams};
use crate::AppState;

const MIN_TRAINING_SAMPLES: u64 = 30;
const MAX_TRAINING_REQUEST_SAMPLES: u64 = 10_000;
const MAX_TRAINING_SUBJECT_CHARS: usize = 500;
const MAX_TRAINING_BODY_CHARS: usize = 20_000;
const MAX_TRAINING_ADDRESS_CHARS: usize = 320;
const MAX_TRAINING_RECIPIENTS: usize = 100;

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
    let total_samples = match state.engine_db.count_training_samples().await {
        Ok(n) => n,
        Err(e) => return ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    };

    let min_samples_required = MIN_TRAINING_SAMPLES;

    // Fetch model status from Python AI service
    let ai_url = get_ai_service_url(&state).await;
    let url = match build_ai_service_endpoint(&ai_url, "training/status") {
        Ok(url) => url,
        Err(error) => {
            return ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed");
        }
    };

    let client = &state.http_client;
    let model_status = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.get(&url).send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp.json::<serde_json::Value>().await.ok(),
        _ => None,
    };

    // can_train: enough samples and not currently training
    let is_training = model_status
        .as_ref()
        .and_then(|s| s.get("is_training"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let can_train = total_samples >= min_samples_required && !is_training;

    let mut result = serde_json::json!({
        "total_samples": total_samples,
        "label_counts": label_counts,
        "min_samples_required": min_samples_required,
        "can_train": can_train,
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
            return ApiResponse::<serde_json::Value>::err(format!(
                "Failed to count training samples: {}",
                e
            ));
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
            return ApiResponse::<serde_json::Value>::err(format!(
                "Failed to load training samples: {}",
                e
            ));
        }
    };

    // 3. Build bounded payload and send to Python AI service.
    let payload: Vec<serde_json::Value> = samples
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id": s.session_id.to_string(),
                "label": s.label,
                "subject": limit_optional_json_string(s.subject.as_deref(), MAX_TRAINING_SUBJECT_CHARS),
                "body_text": limit_optional_json_string(s.body_text.as_deref(), MAX_TRAINING_BODY_CHARS),
                "body_html": limit_optional_json_string(s.body_html.as_deref(), MAX_TRAINING_BODY_CHARS),
                "mail_from": limit_optional_json_string(s.mail_from.as_deref(), MAX_TRAINING_ADDRESS_CHARS),
                "rcpt_to": limit_recipient_json_array(&s.rcpt_to),
            })
        })
        .collect();

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
            Err(e) => ApiResponse::<serde_json::Value>::err(format!(
                "Failed to parse training response: {}",
                e
            )),
        },
        Ok(Err(e)) => ApiResponse::<serde_json::Value>::err(format!(
            "AI service connection failed ({}): {}",
            ai_url, e
        )),
        Err(_) => ApiResponse::<serde_json::Value>::err("Training timed out"),
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
            Err(e) => ApiResponse::<serde_json::Value>::err(format!(
                "Failed to parse status response: {}",
                e
            )),
        },
        Ok(Err(e)) => {
            ApiResponse::<serde_json::Value>::err(format!("AI service connection failed: {}", e))
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
            Err(e) => ApiResponse::<serde_json::Value>::err(format!(
                "Failed to parse progress response: {}",
                e
            )),
        },
        Ok(Err(e)) => {
            ApiResponse::<serde_json::Value>::err(format!("AI service connection failed: {}", e))
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
    let default_url = vigilyx_engine::config::AiServiceConfig::default().service_url;
    let url = match state.engine_db.get_config("ai_service_config").await {
        Ok(Some(json)) => {
            match serde_json::from_str::<vigilyx_engine::config::AiServiceConfig>(&json) {
                Ok(cfg) => cfg.service_url,
                Err(_) => return default_url,
            }
        }
        _ => return default_url,
    };

    // SEC: Validate URL allowlist at runtime - same as API save-time check
    if validate_internal_service_url(&url, DEFAULT_INTERNAL_SERVICE_HOSTS).is_ok() {
        return url;
    }

    tracing::warn!(
        url,
        "SEC: AI service URL from DB failed runtime allowlist, using default"
    );
    default_url
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
