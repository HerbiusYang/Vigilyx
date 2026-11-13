//! Security, Statistics, Process

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header::HeaderName},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use vigilyx_core::security::DeliveryRiskDetailItem;
use vigilyx_core::security::SecurityStats;
use vigilyx_db::DeliveryRiskDetailKind;
use vigilyx_db::cache::{CacheDataset, CacheEnvelope, CacheKey};
use vigilyx_db::{VigilDb, cache::ReadCacheClient};

use super::super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;
use crate::error_codes;
use crate::metrics;

fn feedback_error_response(error: &anyhow::Error) -> axum::response::Response {
    let message = error.to_string();
    if message == vigilyx_engine::feedback::FEEDBACK_RATE_LIMIT_ERROR {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some("Too many feedback submissions; try again later".to_string()),
                error_code: Some(error_codes::AUTH_RATE_LIMITED.to_string()),
            }),
        )
            .into_response();
    }
    if message == vigilyx_engine::feedback::FEEDBACK_DUPLICATE_ERROR
        || message == vigilyx_engine::feedback::FEEDBACK_STALE_VERDICT_ERROR
    {
        return (
            StatusCode::CONFLICT,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some(message),
                error_code: Some(error_codes::RESOURCE_CONFLICT.to_string()),
            }),
        )
            .into_response();
    }
    if message == "Session verdict not found"
        || message.starts_with("Invalid feedback_type:")
        || message.starts_with("Invalid corrected_threat_level")
        || message.starts_with("Invalid feedback:")
        || message.starts_with("Feedback module_id exceeds")
        || message.starts_with("Feedback comment exceeds")
    {
        return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
    }

    ApiResponse::<serde_json::Value>::server_error(error, "Feedback operation failed")
        .into_response()
}

fn security_stats_response(stats: SecurityStats, cache_layer: &'static str) -> Response {
    let data_as_of = if stats.delivery_stats_as_of.is_empty() {
        chrono::Utc::now().to_rfc3339()
    } else {
        stats.delivery_stats_as_of.clone()
    };
    let mut response =
        ApiResponse::ok(serde_json::to_value(stats).unwrap_or_default()).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("x-vigilyx-cache"),
        HeaderValue::from_static(cache_layer),
    );
    if let Ok(value) = HeaderValue::from_str(&data_as_of) {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-vigilyx-data-as-of"), value);
    }
    response
}

fn stale_security_stats_response(stats: SecurityStats) -> Response {
    let mut response = security_stats_response(stats, "l2-stale");
    response.headers_mut().insert(
        HeaderName::from_static("warning"),
        HeaderValue::from_static("110 - \"Response is stale\""),
    );
    response
}

/// Refresh one security aggregate in the background after serving a value
/// that is past Fresh TTL but still inside Hard TTL. The distributed lease
/// prevents duplicate database refreshes across API instances.
async fn refresh_security_stats_l2(engine_db: VigilDb, read_cache: ReadCacheClient) {
    let dataset = CacheDataset::SecurityOverview24h;
    let cache_key = CacheKey::security_overview();
    let token = Uuid::new_v4().to_string();
    let lease = match read_cache
        .try_acquire_refresh_lease(cache_key, &token)
        .await
    {
        Ok(true) => true,
        Ok(false) => {
            metrics::READ_CACHE_LOCK_CONTENTION_TOTAL
                .with_label_values(&[metrics::cache_dataset_label(dataset)])
                .inc();
            metrics::record_cache_request(dataset, "refresh", "lease_contention");
            false
        }
        Err(error) => {
            metrics::record_cache_request(dataset, "refresh", "lease_error");
            metrics::record_cache_refresh_failure(dataset, &error);
            false
        }
    };
    if !lease {
        return;
    }

    let refresh_started = std::time::Instant::now();
    let result = engine_db.get_security_stats().await;
    if let Ok(stats) = result {
        let envelope = CacheEnvelope::for_dataset(
            dataset,
            stats.clone(),
            Some(stats.delivery_stats_as_of.clone()),
        );
        match read_cache.set(cache_key, &envelope).await {
            Ok(payload_bytes) => {
                metrics::record_cache_request(dataset, "refresh", "write");
                metrics::READ_CACHE_REFRESH_DURATION_SECONDS
                    .with_label_values(&[metrics::cache_dataset_label(dataset)])
                    .observe(refresh_started.elapsed().as_secs_f64());
                metrics::READ_CACHE_ENTRY_BYTES
                    .with_label_values(&[metrics::cache_dataset_label(dataset)])
                    .set(payload_bytes as f64);
                metrics::record_cache_observation(dataset, envelope.generated_at);
            }
            Err(error) => {
                metrics::record_cache_refresh_failure(dataset, &error);
                metrics::record_cache_fallback(dataset, metrics::cache_error_reason(&error));
            }
        }
    } else {
        metrics::record_cache_request(dataset, "refresh", "postgres_error");
    }

    if let Err(error) = read_cache.release_refresh_lease(cache_key, &token).await {
        tracing::debug!(%error, "Security read-cache stale refresh lease release failed");
    }
}

// Security Query

/// Get session security analysis. Analysis metadata remains visible in
/// privacy mode; message content is projected by the session handler.
pub async fn get_session_verdict(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    _user: AuthenticatedUser,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    match state.engine_db.get_verdict_by_session(session_id).await {
        Ok(Some(verdict)) => ApiResponse::ok(verdict).into_response(),
        Ok(None) => ApiResponse::ok(serde_json::json!(null)).into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

/// Get per-module security analysis. Module evidence is security metadata,
/// not the original message body, so it remains available in privacy mode.
pub async fn get_session_security_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    _user: AuthenticatedUser,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    match state
        .engine_db
        .get_module_results_by_session(session_id)
        .await
    {
        Ok(results) => ApiResponse::ok(results).into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed").into_response()
        }
    }
}

// risk table (+ metadata)

#[derive(Debug, Deserialize)]
pub struct VerdictListParams {
    #[serde(default = "default_verdict_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
    pub threat_level: Option<String>,
}

fn default_verdict_limit() -> u32 {
    30
}

#[derive(Debug, Deserialize)]
pub struct DeliveryRiskDetailParams {
    pub kind: String,
    pub snapshot_at: String,
    pub server_ip: Option<String>,
    #[serde(default = "default_delivery_detail_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_delivery_detail_limit() -> u32 {
    30
}

fn redact_delivery_detail(mut item: DeliveryRiskDetailItem) -> DeliveryRiskDetailItem {
    item.mail_from = item
        .mail_from
        .as_deref()
        .map(super::super::privacy::mask_email_address);
    item.rcpt_to = item
        .rcpt_to
        .iter()
        .map(|address| super::super::privacy::mask_email_address(address))
        .collect();
    item.subject = item
        .subject
        .as_deref()
        .map(super::super::privacy::mask_subject);
    item.message_id = None;
    item
}

/// List the exact mail/hop observations behind one clickable delivery-risk
/// counter. The caller supplies the timestamp returned by `/security/stats`,
/// so pagination uses the same complete historical snapshot without a start date.
pub async fn list_delivery_risk_details(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<DeliveryRiskDetailParams>,
) -> axum::response::Response {
    let Some(kind) = DeliveryRiskDetailKind::parse(params.kind.trim()) else {
        return ApiResponse::<serde_json::Value>::bad_request("Invalid delivery detail kind")
            .into_response();
    };
    let snapshot_at = match chrono::DateTime::parse_from_rfc3339(params.snapshot_at.trim()) {
        Ok(value) if value <= chrono::Utc::now() + chrono::Duration::minutes(5) => value,
        _ => {
            return ApiResponse::<serde_json::Value>::bad_request(
                "Invalid delivery detail snapshot_at",
            )
            .into_response();
        }
    };
    if kind.requires_node() {
        let Some(server_ip) = params.server_ip.as_deref() else {
            return ApiResponse::<serde_json::Value>::bad_request(
                "server_ip is required for node detail",
            )
            .into_response();
        };
        if server_ip.parse::<std::net::IpAddr>().is_err() {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid server_ip")
                .into_response();
        }
    }

    params.limit = params.limit.clamp(1, 100);
    let snapshot_at = snapshot_at.to_rfc3339();
    match state
        .engine_db
        .list_delivery_risk_details(
            kind,
            params.server_ip.as_deref(),
            &snapshot_at,
            params.limit,
            params.offset,
        )
        .await
    {
        Ok((mut items, total)) => {
            let scopes = super::super::privacy::default_scopes(&state).await;
            if !scopes.contains("headers") {
                items = items.into_iter().map(redact_delivery_detail).collect();
            }
            ApiResponse::ok(serde_json::json!({
                "items": items,
                "total": total,
                "limit": params.limit,
                "offset": params.offset,
                "snapshot_at": snapshot_at,
                "scope": "all_history",
                "kind": kind.as_str(),
                "server_ip": params.server_ip,
            }))
            .into_response()
        }
        Err(error) => ApiResponse::<serde_json::Value>::server_error(
            &error,
            "Delivery risk detail query failed",
        )
        .into_response(),
    }
}

/// Security (metadata)
pub async fn list_recent_verdicts(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<VerdictListParams>,
) -> impl IntoResponse {
    params.limit = params.limit.clamp(1, 1000);
    match state
        .engine_db
        .list_recent_verdicts(params.threat_level.as_deref(), params.limit, params.offset)
        .await
    {
        Ok((items, total)) => ApiResponse::ok(serde_json::json!({
            "items": items,
            "total": total,
            "limit": params.limit,
            "offset": params.offset,
        })),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

// Statistics monitor

/// GetSecurityStatistics
pub async fn get_security_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let dataset = CacheDataset::SecurityOverview24h;
    let cache_key = CacheKey::security_overview();
    let mut lease_token = None;
    let mut cache_write_succeeded = false;

    if let Some(read_cache) = state.cache.read_cache.as_ref() {
        let cache_enabled = read_cache.config().enabled(dataset);
        let cache_write_enabled = read_cache.config().shadow_write_enabled(dataset);

        if cache_enabled {
            match read_cache.get::<SecurityStats>(cache_key).await {
                Ok(Some(envelope)) if envelope.is_fresh(chrono::Utc::now()) => {
                    metrics::record_cache_request(dataset, "l2", "fresh_hit");
                    metrics::record_cache_observation(dataset, envelope.generated_at);
                    return security_stats_response(envelope.data, "l2-fresh");
                }
                Ok(Some(envelope)) => {
                    metrics::record_cache_request(dataset, "l2", "stale");
                    metrics::record_cache_observation(dataset, envelope.generated_at);
                    metrics::READ_CACHE_STALE_SERVED_TOTAL
                        .with_label_values(&[metrics::cache_dataset_label(dataset)])
                        .inc();
                    let engine_db = state.engine_db.clone();
                    let read_cache = read_cache.clone();
                    tokio::spawn(async move {
                        refresh_security_stats_l2(engine_db, read_cache).await;
                    });
                    return stale_security_stats_response(envelope.data);
                }
                Ok(None) => metrics::record_cache_request(dataset, "l2", "miss"),
                Err(error) => {
                    metrics::record_cache_request(dataset, "l2", "error");
                    metrics::record_cache_fallback(dataset, metrics::cache_error_reason(&error));
                    tracing::warn!(%error, "Security read-cache read failed; using PostgreSQL");
                }
            }
        }

        if cache_enabled || cache_write_enabled {
            let token = Uuid::new_v4().to_string();
            match read_cache
                .try_acquire_refresh_lease(cache_key, &token)
                .await
            {
                Ok(true) => lease_token = Some(token),
                Ok(false) => {
                    metrics::READ_CACHE_LOCK_CONTENTION_TOTAL
                        .with_label_values(&[metrics::cache_dataset_label(dataset)])
                        .inc();
                    // Another API instance is refreshing. Give it one short
                    // bounded chance to publish before falling back to the
                    // existing PostgreSQL/L1 path.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    if cache_enabled
                        && let Ok(Some(envelope)) = read_cache.get::<SecurityStats>(cache_key).await
                        && envelope.is_fresh(chrono::Utc::now())
                    {
                        metrics::record_cache_request(dataset, "l2", "fresh_hit_after_wait");
                        metrics::record_cache_observation(dataset, envelope.generated_at);
                        return security_stats_response(envelope.data, "l2-fresh");
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "Security read-cache lease unavailable; using PostgreSQL");
                }
            }
        }

        let refresh_started = std::time::Instant::now();
        let database_result = state.engine_db.get_security_stats().await;
        if let Ok(stats) = &database_result {
            if lease_token.is_some() && (cache_enabled || cache_write_enabled) {
                let envelope = CacheEnvelope::for_dataset(
                    dataset,
                    stats.clone(),
                    Some(stats.delivery_stats_as_of.clone()),
                );
                match read_cache.set(cache_key, &envelope).await {
                    Ok(payload_bytes) => {
                        cache_write_succeeded = true;
                        metrics::READ_CACHE_REFRESH_DURATION_SECONDS
                            .with_label_values(&[metrics::cache_dataset_label(dataset)])
                            .observe(refresh_started.elapsed().as_secs_f64());
                        metrics::READ_CACHE_ENTRY_BYTES
                            .with_label_values(&[metrics::cache_dataset_label(dataset)])
                            .set(payload_bytes as f64);
                        metrics::record_cache_observation(dataset, envelope.generated_at);
                        metrics::record_cache_request(dataset, "l2", "write");
                    }
                    Err(error) => {
                        metrics::record_cache_refresh_failure(dataset, &error);
                        metrics::record_cache_fallback(
                            dataset,
                            metrics::cache_error_reason(&error),
                        );
                        tracing::warn!(%error, "Security read-cache write failed; PostgreSQL remains authoritative");
                    }
                }
            }
            if let Some(token) = lease_token
                && let Err(error) = read_cache.release_refresh_lease(cache_key, &token).await
            {
                tracing::debug!(%error, "Security read-cache lease release failed");
            }
        } else if let Some(token) = lease_token
            && let Err(error) = read_cache.release_refresh_lease(cache_key, &token).await
        {
            tracing::debug!(%error, "Security read-cache lease release failed");
        }

        return match database_result {
            Ok(stats) => security_stats_response(
                stats,
                if cache_write_succeeded {
                    "postgres-shadow-write"
                } else {
                    "postgres-fallback"
                },
            ),
            Err(error) => {
                metrics::record_cache_fallback(dataset, "postgres_error");
                ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed")
                    .into_response()
            }
        };
    }

    match state.engine_db.get_security_stats().await {
        Ok(stats) => security_stats_response(stats, "postgres"),
        Err(error) => ApiResponse::<serde_json::Value>::internal_err(&error, "Operation failed")
            .into_response(),
    }
}

/// GetEngine status

/// DataSource Level:
/// 1. Redis TTL key (engine heartbeat)
/// 2. In-memory cache (engine_status RwLock)
/// 3. Fallback -> running: false
pub async fn get_engine_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(snapshot) = super::load_engine_status_snapshot(&state).await
        && snapshot.heartbeat_secs < 30
    {
        return ApiResponse::ok(super::normalize_engine_status_payload(snapshot.status));
    }

    ApiResponse::ok(super::default_engine_status_payload())
}

pub async fn submit_feedback(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(req): Json<vigilyx_engine::feedback::SubmitFeedbackRequest>,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    let feedback_mgr = vigilyx_engine::feedback::FeedbackManager::new(
        state.engine_db.clone(),
        state.managers.ioc_manager.clone(),
    );

    let can_save_training_sample = user.has_permission("ai.training");
    let can_adjust_ioc = user.has_permission("security.ioc.manage");
    match feedback_mgr
        .submit(
            session_id,
            &req,
            &user.username,
            can_save_training_sample,
            can_adjust_ioc,
        )
        .await
    {
        Ok(result) => {
            // Every new vote may invalidate an older sample through conflict
            // or missing evidence. The dataset independently enforces the
            // submit-time training permission before admitting any label.
            {
                let learning_state = Arc::clone(&state);
                tokio::spawn(async move {
                    match vigilyx_engine::ds_learning::refresh_candidate(&learning_state.engine_db)
                        .await
                    {
                        Ok(()) => {
                            super::publish_engine_reload(&learning_state, "ds_learning").await
                        }
                        Err(error) => {
                            tracing::error!(%error, "DS candidate refresh failed; feedback remains recorded")
                        }
                    }
                });
            }
            {
                let db = state.engine_db.clone();
                let username = user.username.clone();
                tokio::spawn(async move {
                    if let Err(e) = db
                        .write_audit_log(
                            &username,
                            "feedback_recorded",
                            Some("ds_learning"),
                            Some(&session_id.to_string()),
                            None,
                            None,
                        )
                        .await
                    {
                        tracing::error!(error = %e, "Audit: failed to write feedback audit log");
                    }
                });
            }
            ApiResponse::ok(serde_json::to_value(result).unwrap_or_default()).into_response()
        }
        Err(e) => feedback_error_response(&e),
    }
}

pub async fn get_session_feedback(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    _user: AuthenticatedUser,
) -> Response {
    let Ok(session_id) = Uuid::parse_str(&id) else {
        return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID").into_response();
    };
    match state.engine_db.session_feedback_history(session_id).await {
        Ok(history) => ApiResponse::ok(history).into_response(),
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Feedback history unavailable")
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DsLearningSamplesParams {
    #[serde(default = "default_verdict_limit")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

/// Hashed, content-free immutable snapshots require the training permission.
/// This is an analyst-labelled candidate dataset, never a holdout export.
pub async fn get_ds_learning_samples(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Query(params): Query<DsLearningSamplesParams>,
) -> Response {
    if !user.has_permission("ai.training") {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse::<serde_json::Value> {
                success: false,
                data: None,
                error: Some("AI training permission required".to_string()),
                error_code: Some(error_codes::AUTH_FORBIDDEN.to_string()),
            }),
        )
            .into_response();
    }
    match state
        .engine_db
        .ds_learning_samples_page(params.limit.clamp(1, 1_000), params.offset)
        .await
    {
        Ok(dataset) => {
            let db = state.engine_db.clone();
            let count = dataset["cases"].as_array().map_or(0, Vec::len);
            tokio::spawn(async move {
                let detail = format!(
                    "content_free=true; samples={count}; offset={}",
                    params.offset
                );
                if let Err(error) = db
                    .write_audit_log(
                        &user.username,
                        "export_ds_learning_samples",
                        Some("ds_learning"),
                        None,
                        Some(&detail),
                        None,
                    )
                    .await
                {
                    tracing::error!(%error, "Failed to audit DS sample export");
                }
            });
            ApiResponse::ok(dataset).into_response()
        }
        Err(error) => {
            ApiResponse::<serde_json::Value>::server_error(&error, "Learning samples unavailable")
                .into_response()
        }
    }
}

/// Get Statistics
pub async fn get_feedback_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.engine_db.get_feedback_stats().await {
        Ok(stats) => ApiResponse::ok(serde_json::to_value(stats).unwrap_or_default()),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_feedback_is_a_conflict_and_inconsistent_severity_is_bad_request() {
        let stale = anyhow::anyhow!(vigilyx_engine::feedback::FEEDBACK_STALE_VERDICT_ERROR);
        assert_eq!(
            feedback_error_response(&stale).status(),
            StatusCode::CONFLICT
        );
        let invalid = anyhow::anyhow!("Invalid corrected_threat_level for feedback classification");
        assert_eq!(
            feedback_error_response(&invalid).status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn historical_delivery_payload_rejects_legacy_rolling_cache_data() {
        let mut payload = serde_json::json!({
            "total_scanned": 0, "level_counts": {}, "high_threats_24h": 0, "ioc_count": 0,
            "delivery_stats_scope": "all_history", "first_hop_emails_total": 400,
        });
        let stats: SecurityStats = serde_json::from_value(payload.clone()).unwrap();
        assert_eq!(stats.first_hop_emails_total, 400);
        payload
            .as_object_mut()
            .unwrap()
            .remove("delivery_stats_scope");
        payload["first_hop_emails_24h"] = serde_json::json!(10);
        assert!(serde_json::from_value::<SecurityStats>(payload).is_err());
    }
}
