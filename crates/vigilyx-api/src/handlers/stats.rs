//! Statistics handlers: traffic stats, external login stats

use axum::{extract::State, response::IntoResponse};
use std::sync::Arc;
use vigilyx_core::{ExternalLoginStats, TrafficStats};

use super::ApiResponse;
use crate::AppState;

/// Get statistics (DB stored values + sniffer real-time rates merged)
pub async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_stats().await {
        Ok(mut stats) => {
           // Merge sniffer-pushed real-time rates (DB stores cumulative values only, not rates)
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
            ApiResponse::ok(stats)
        }
        Err(e) => ApiResponse::<TrafficStats>::internal_err(&e, "Operation failed"),
    }
}

/// Get external login statistics (last 24h, grouped by hour)

/// Uses background cache: raw query ~29s, cached <1ms
pub async fn get_external_login_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
   // Prefer reading from cache
    {
        let cache = state.cache.login_stats.read().await;
        if let Some((_, data)) = &*cache {
            return ApiResponse::ok(data.clone());
        }
    }
   // Cache not ready (service just started, background task hasn't completed first refresh yet)
    match state.db.get_external_login_stats().await {
        Ok(stats) => ApiResponse::ok(stats),
        Err(e) => ApiResponse::<ExternalLoginStats>::internal_err(&e, "Operation failed"),
    }
}
