//! Process: Kubernetes liveness / readiness

//! - `GET /health/live` - (process,, <10ms)
//! - `GET /health/ready` - (Processrequest: DB + Redis + Engine)
//! - `GET /health` -, liveness

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;


#[derive(Debug, Serialize)]
pub struct CheckResult {
   /// "up" | "down" | "degraded"
    pub status: &'static str,
   /// ()
    pub latency_ms: u64,
   /// Failed (status != "up" ; internal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Engine (ContainsHeartbeatinfo)
#[derive(Debug, Serialize)]
pub struct EngineCheckResult {
   /// "up" | "down" | "degraded"
    pub status: &'static str,
   /// (None = From Received)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_secs: Option<i64>,
}

/// Readiness response
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
   /// "ready" | "not_ready"
    pub status: &'static str,
    pub checks: ReadinessChecks,
}

/// Public readiness response
#[derive(Debug, Serialize)]
pub struct PublicReadinessResponse {
   /// "ready" | "not_ready"
    pub status: &'static str,
}

/// Comment retained in English.
#[derive(Debug, Serialize)]
pub struct ReadinessChecks {
    pub database: CheckResult,
    pub redis: CheckResult,
    pub engine: EngineCheckResult,
}

/// Liveness response
#[derive(Debug, Serialize)]
pub struct LivenessResponse {
    pub status: &'static str,
}


// Handlers


/// `GET /health/live` -

/// 200 table process,.
/// target: <1ms response.
pub async fn liveness() -> impl IntoResponse {
    Json(LivenessResponse { status: "alive" })
}

/// `GET /health/ready` -

/// , 1failed 503 Service Unavailable.
/// All timeout,.
pub async fn readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (http_status, response) = build_readiness_response(&state).await;
    (http_status, Json(response))
}

/// `GET /health/ready` (public) - aggregate only
///
/// Public callers only need the overall readiness status. Detailed dependency
/// information is available on the internal-token protected route.
pub async fn public_readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (http_status, response) = build_readiness_response(&state).await;
    (
        http_status,
        Json(PublicReadinessResponse {
            status: response.status,
        }),
    )
}

async fn build_readiness_response(
    state: &Arc<AppState>,
) -> (StatusCode, ReadinessResponse) {
   // 1. Database check (5s timeout)
    let db_check = {
        let start = Instant::now();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(5), state.db.health_check()).await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(true)) => CheckResult {
                status: "up",
                latency_ms,
                message: None,
            },
            Ok(Ok(false)) => CheckResult {
                status: "down",
                latency_ms,
                message: Some("database query returned unexpected result".to_string()),
            },
            Ok(Err(e)) => {
                tracing::error!(error = %e, "readiness: database health check failed");
                CheckResult {
                    status: "down",
                    latency_ms,
                    message: Some("database connection failed".to_string()),
                }
            }
            Err(_) => CheckResult {
                status: "down",
                latency_ms,
                message: Some("database check timed out (5s)".to_string()),
            },
        }
    };

   // 2. Redis check (3s timeout)
    let redis_check = {
        let start = Instant::now();
        let result = if let Some(ref mq) = state.messaging.mq {
            tokio::time::timeout(std::time::Duration::from_secs(3), mq.is_connected()).await
        } else {
           // Redis not configured - still "up" in local mode (by design)
            Ok(false)
        };
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(true) => CheckResult {
                status: "up",
                latency_ms,
                message: None,
            },
            Ok(false) if state.messaging.mq.is_none() => {
               // No Redis configured - running in local/UDS mode, acceptable
                CheckResult {
                    status: "up",
                    latency_ms,
                    message: Some("local mode (no Redis configured)".to_string()),
                }
            }
            Ok(false) => CheckResult {
                status: "down",
                latency_ms,
                message: Some("redis PING failed".to_string()),
            },
            Err(_) => CheckResult {
                status: "down",
                latency_ms,
                message: Some("redis check timed out (3s)".to_string()),
            },
        }
    };

   // 3. Engine check (via cached heartbeat)
    let engine_check = {
        match crate::handlers::security::load_engine_status_snapshot(state).await {
            Some(snapshot) => {
                let engine_status = match snapshot.heartbeat_secs {
                    age if age <= 60 => "up",
                    age if age <= 120 => "degraded",
                    _ => "down",
                };

                EngineCheckResult {
                    status: engine_status,
                    last_heartbeat_secs: Some(snapshot.heartbeat_secs),
                }
            }
            None => EngineCheckResult {
                status: "down",
                last_heartbeat_secs: None,
            },
        }
    };

   // Aggregate
    let all_up =
        db_check.status == "up" && redis_check.status == "up" && engine_check.status != "down";

    let response = ReadinessResponse {
        status: if all_up { "ready" } else { "not_ready" },
        checks: ReadinessChecks {
            database: db_check,
            redis: redis_check,
            engine: engine_check,
        },
    };

    let http_status = if all_up {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (http_status, response)
}


// Tests


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liveness_response_serializes_correctly() {
        let resp = LivenessResponse { status: "alive" };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "alive");
    }

    #[test]
    fn test_readiness_response_ready_serializes_correctly() {
        let resp = ReadinessResponse {
            status: "ready",
            checks: ReadinessChecks {
                database: CheckResult {
                    status: "up",
                    latency_ms: 2,
                    message: None,
                },
                redis: CheckResult {
                    status: "up",
                    latency_ms: 1,
                    message: None,
                },
                engine: EngineCheckResult {
                    status: "up",
                    last_heartbeat_secs: Some(5),
                },
            },
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "ready");
        assert_eq!(json["checks"]["database"]["status"], "up");
        assert_eq!(json["checks"]["database"]["latency_ms"], 2);
       // "message" should be absent when None (skip_serializing_if)
        assert!(json["checks"]["database"].get("message").is_none());
        assert_eq!(json["checks"]["redis"]["status"], "up");
        assert_eq!(json["checks"]["engine"]["status"], "up");
        assert_eq!(json["checks"]["engine"]["last_heartbeat_secs"], 5);
    }

    #[test]
    fn test_readiness_response_not_ready_serializes_correctly() {
        let resp = ReadinessResponse {
            status: "not_ready",
            checks: ReadinessChecks {
                database: CheckResult {
                    status: "down",
                    latency_ms: 5001,
                    message: Some("database check timed out (5s)".to_string()),
                },
                redis: CheckResult {
                    status: "up",
                    latency_ms: 1,
                    message: None,
                },
                engine: EngineCheckResult {
                    status: "down",
                    last_heartbeat_secs: None,
                },
            },
        };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "not_ready");
        assert_eq!(json["checks"]["database"]["status"], "down");
        assert_eq!(
            json["checks"]["database"]["message"],
            "database check timed out (5s)"
        );
        assert!(
            json["checks"]["engine"]
                .get("last_heartbeat_secs")
                .is_none()
        );
    }

    #[test]
    fn test_check_result_message_omitted_when_none() {
        let check = CheckResult {
            status: "up",
            latency_ms: 0,
            message: None,
        };
        let json = serde_json::to_string(&check).expect("serialize");
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_engine_check_degraded_status() {
        let check = EngineCheckResult {
            status: "degraded",
            last_heartbeat_secs: Some(90),
        };
        let json = serde_json::to_value(&check).expect("serialize");
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["last_heartbeat_secs"], 90);
    }

    #[test]
    fn test_public_readiness_response_serializes_without_checks() {
        let resp = PublicReadinessResponse { status: "ready" };
        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "ready");
        assert!(json.get("checks").is_none());
    }
}
