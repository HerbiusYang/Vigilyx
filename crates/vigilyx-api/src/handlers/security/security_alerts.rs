//! P0-P3 Security Alert API (security_alerts table)

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

const DEFAULT_ALERT_LIMIT: u32 = 50;
const MAX_ALERT_LIMIT: u32 = 500;

/// Query parameters for GET /security/alerts
#[derive(Debug, Deserialize)]
pub struct AlertListQuery {
    pub alert_level: Option<String>,
    pub acknowledged: Option<bool>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Validate the optional alert_level filter (P0|P1|P2|P3).
fn validate_alert_level(level: Option<&str>) -> Result<Option<String>, String> {
    match level {
        None => Ok(None),
        Some(raw) => {
            let normalized = raw.trim().to_uppercase();
            match normalized.as_str() {
                "P0" | "P1" | "P2" | "P3" => Ok(Some(normalized)),
                _ => Err("Invalid alert_level (expected P0|P1|P2|P3)".to_string()),
            }
        }
    }
}

/// GET /security/alerts
pub async fn list_security_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertListQuery>,
) -> axum::response::Response {
    let level_filter = match validate_alert_level(query.alert_level.as_deref()) {
        Ok(level) => level,
        Err(msg) => {
            return ApiResponse::<serde_json::Value>::bad_request(msg).into_response();
        }
    };
    let limit = query
        .limit
        .unwrap_or(DEFAULT_ALERT_LIMIT)
        .clamp(1, MAX_ALERT_LIMIT);
    let offset = query.offset.unwrap_or(0);

    let alerts = match state
        .engine_db
        .list_alerts(level_filter.as_deref(), query.acknowledged, limit, offset)
        .await
    {
        Ok(alerts) => alerts,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Failed to list alerts")
                .into_response();
        }
    };
    let total = match state
        .engine_db
        .count_alerts(level_filter.as_deref(), query.acknowledged)
        .await
    {
        Ok(total) => total,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Failed to count alerts")
                .into_response();
        }
    };

    ApiResponse::ok(serde_json::json!({
        "alerts": alerts,
        "total": total,
    }))
    .into_response()
}

/// POST /security/alerts/{id}/acknowledge
pub async fn acknowledge_security_alert(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> axum::response::Response {
    // SEC: Use authenticated username from JWT, never trust client-supplied operator
    let acknowledged_by = user.username.clone();

    let alert_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid ID").into_response();
        }
    };

    match state
        .engine_db
        .acknowledge_alert(alert_id, &acknowledged_by)
        .await
    {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                acknowledged_by,
                "acknowledge_security_alert",
                Some("security"),
                Some(id),
                None,
            );
            ApiResponse::ok(serde_json::json!({ "success": true })).into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("Alert not found").into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::server_error(&e, "Failed to acknowledge alert")
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_alert_level;

    #[test]
    fn accepts_valid_levels_and_normalizes_case() {
        assert_eq!(validate_alert_level(None), Ok(None));
        assert_eq!(validate_alert_level(Some("P0")), Ok(Some("P0".to_string())));
        assert_eq!(validate_alert_level(Some("p2")), Ok(Some("P2".to_string())));
        assert_eq!(
            validate_alert_level(Some(" p3 ")),
            Ok(Some("P3".to_string()))
        );
    }

    #[test]
    fn rejects_invalid_levels() {
        assert!(validate_alert_level(Some("P4")).is_err());
        assert!(validate_alert_level(Some("high")).is_err());
        assert!(validate_alert_level(Some("")).is_err());
    }
}
