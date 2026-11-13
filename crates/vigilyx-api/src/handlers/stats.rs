//! Statistics handlers: traffic stats, external login stats

use axum::{
    extract::State,
    http::{HeaderValue, header::HeaderName},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use vigilyx_core::{ExternalLoginStats, TrafficStats};
use vigilyx_db::cache::{CacheDataset, CacheKey};

use super::ApiResponse;
use crate::AppState;
use crate::metrics;

fn aggregate_response<T: serde::Serialize>(
    data: T,
    cache_layer: &'static str,
    generated_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Response {
    let mut response = ApiResponse::ok(data).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("x-vigilyx-cache"),
        HeaderValue::from_static(cache_layer),
    );
    if let Some(generated_at) = generated_at
        && let Ok(value) = HeaderValue::from_str(&generated_at.to_rfc3339())
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-vigilyx-data-as-of"), value);
    }
    response
}

fn merge_live_rates(state: &AppState, stats: &mut TrafficStats) {
    stats.packets_per_second = f64::from_bits(
        state
            .monitoring
            .latest_pps
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    stats.bytes_per_second = f64::from_bits(
        state
            .monitoring
            .latest_bps
            .load(std::sync::atomic::Ordering::Relaxed),
    );
}

fn l1_is_within_hard_ttl(created_at: std::time::Instant, dataset: CacheDataset) -> bool {
    created_at.elapsed() < std::time::Duration::from_secs(dataset.hard_ttl_secs())
}

async fn refresh_traffic_l1(state: &AppState) -> Result<TrafficStats, anyhow::Error> {
    let _guard = state.cache.traffic_stats_refresh_lock.lock().await;
    if let Some((created_at, stats)) = state.cache.traffic_stats.read().await.as_ref()
        && l1_is_within_hard_ttl(*created_at, CacheDataset::SessionCounts)
    {
        return Ok(stats.clone());
    }
    let stats = state.db.get_stats().await?;
    *state.cache.traffic_stats.write().await = Some((std::time::Instant::now(), stats.clone()));
    Ok(stats)
}

async fn refresh_login_l1(state: &AppState) -> Result<ExternalLoginStats, anyhow::Error> {
    let _guard = state.cache.login_stats_refresh_lock.lock().await;
    if let Some((created_at, stats)) = state.cache.login_stats.read().await.as_ref()
        && l1_is_within_hard_ttl(*created_at, CacheDataset::ExternalLogin24h)
    {
        return Ok(stats.clone());
    }
    let stats = state.db.get_external_login_stats().await?;
    *state.cache.login_stats.write().await = Some((std::time::Instant::now(), stats.clone()));
    Ok(stats)
}

/// Get statistics (DB stored values + sniffer real-time rates merged)
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Response {
    let dataset = CacheDataset::SessionCounts;
    let cache_key = CacheKey::session_counts();

    if let Some(read_cache) = state.cache.read_cache.as_ref()
        && read_cache.config().enabled(dataset)
    {
        match read_cache.get::<TrafficStats>(cache_key).await {
            Ok(Some(envelope)) if envelope.is_fresh(chrono::Utc::now()) => {
                metrics::record_cache_request(dataset, "l2", "fresh_hit");
                metrics::record_cache_observation(dataset, envelope.generated_at);
                let mut stats = envelope.data;
                merge_live_rates(&state, &mut stats);
                return aggregate_response(stats, "l2-fresh", Some(envelope.generated_at));
            }
            Ok(Some(envelope)) => {
                metrics::record_cache_request(dataset, "l2", "stale");
                metrics::record_cache_observation(dataset, envelope.generated_at);
            }
            Ok(None) => metrics::record_cache_request(dataset, "l2", "miss"),
            Err(error) => {
                metrics::record_cache_request(dataset, "l2", "error");
                metrics::record_cache_fallback(dataset, metrics::cache_error_reason(&error));
            }
        }
    }

    // The process-local snapshot remains the first fallback. It is refreshed
    // by the background task and avoids turning a temporary L2 miss into a DB
    // query on every API request.
    if let Some((created_at, mut stats)) = state.cache.traffic_stats.read().await.clone()
        && l1_is_within_hard_ttl(created_at, dataset)
    {
        metrics::record_cache_fallback(dataset, "l1");
        merge_live_rates(&state, &mut stats);
        return aggregate_response(stats, "l1", Some(chrono::Utc::now()));
    }

    match refresh_traffic_l1(&state).await {
        Ok(mut stats) => {
            metrics::record_cache_fallback(dataset, "postgres");
            merge_live_rates(&state, &mut stats);
            aggregate_response(stats, "postgres", Some(chrono::Utc::now()))
        }
        Err(error) => {
            metrics::record_cache_fallback(dataset, "postgres_error");
            ApiResponse::<TrafficStats>::internal_err(&error, "Operation failed").into_response()
        }
    }
}

/// Get external login statistics (last 24h, grouped by hour)

/// Uses background cache: raw query ~29s, cached <1ms
pub async fn get_external_login_stats(State(state): State<Arc<AppState>>) -> Response {
    let dataset = CacheDataset::ExternalLogin24h;
    let cache_key = CacheKey::external_login();

    if let Some(read_cache) = state.cache.read_cache.as_ref()
        && read_cache.config().enabled(dataset)
    {
        match read_cache.get::<ExternalLoginStats>(cache_key).await {
            Ok(Some(envelope)) if envelope.is_fresh(chrono::Utc::now()) => {
                metrics::record_cache_request(dataset, "l2", "fresh_hit");
                metrics::record_cache_observation(dataset, envelope.generated_at);
                return aggregate_response(envelope.data, "l2-fresh", Some(envelope.generated_at));
            }
            Ok(Some(envelope)) => {
                metrics::record_cache_request(dataset, "l2", "stale");
                metrics::record_cache_observation(dataset, envelope.generated_at);
            }
            Ok(None) => metrics::record_cache_request(dataset, "l2", "miss"),
            Err(error) => {
                metrics::record_cache_request(dataset, "l2", "error");
                metrics::record_cache_fallback(dataset, metrics::cache_error_reason(&error));
            }
        }
    }

    if let Some((created_at, data)) = state.cache.login_stats.read().await.clone()
        && l1_is_within_hard_ttl(created_at, dataset)
    {
        metrics::record_cache_fallback(dataset, "l1");
        return aggregate_response(data, "l1", Some(chrono::Utc::now()));
    }

    match refresh_login_l1(&state).await {
        Ok(stats) => {
            metrics::record_cache_fallback(dataset, "postgres");
            aggregate_response(stats, "postgres", Some(chrono::Utc::now()))
        }
        Err(error) => {
            metrics::record_cache_fallback(dataset, "postgres_error");
            ApiResponse::<ExternalLoginStats>::internal_err(&error, "Operation failed")
                .into_response()
        }
    }
}
