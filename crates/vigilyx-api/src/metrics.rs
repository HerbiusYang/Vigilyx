//! Prometheus

//! Vigilyx API For Prometheus:
//! - HTTP request delay (According to method / path / status)
//! - WebSocket Connection
//! - Process verdict
//! - EngineModule

//! `GET /api/metrics` `INTERNAL_API_TOKEN` authentication (SEC-M06).
//! Prometheus Configuration `X-Internal-Token` request.

//! **Road 1 **: UUID Road `:id`,
//! (high cardinality) Prometheus time.

use std::sync::LazyLock;
use std::time::Instant;

use axum::{
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, HistogramVec, TextEncoder, register_counter,
    register_counter_vec, register_gauge, register_histogram_vec,
};

// Metric definitions (global singletons via LazyLock)

/// HTTP request (According to method, path, status)
static HTTP_REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    )
    .expect("http_requests_total metric must register")
});

/// HTTP requestdelay () (According to method, path)

/// Bucket API delay:
/// - 1ms~10ms: /
/// - 10ms~100ms: DB Query
/// - 100ms~1s: Query
/// - 1s~10s: scan / analyze
static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )
    .expect("http_request_duration_seconds metric must register")
});

/// WebSocket Connection
pub static WS_CONNECTIONS_ACTIVE: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "ws_connections_active",
        "Number of active WebSocket connections"
    )
    .expect("ws_connections_active metric must register")
});

/// Process
pub static EMAILS_PROCESSED_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    register_counter!(
        "emails_processed_total",
        "Total number of emails analyzed by the engine"
    )
    .expect("emails_processed_total metric must register")
});

/// Verdict (According to threat_level: safe / low / medium / high / critical)
pub static VERDICTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "verdicts_total",
        "Total number of security verdicts by threat level",
        &["threat_level"]
    )
    .expect("verdicts_total metric must register")
});

/// EngineModule () (According to module_id)
pub static ENGINE_MODULE_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "engine_module_duration_seconds",
        "Engine module analysis duration in seconds",
        &["module_id"],
        vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ]
    )
    .expect("engine_module_duration_seconds metric must register")
});

// Path normalization (prevent high-cardinality labels)

/// 1 URL Road, UUID Road `:id`

/// - `/api/sessions/550e8400-e29b-41d4-a716-446655440000` -> `/api/sessions/:id`
/// - `/api/security/rules/42` -> `/api/security/rules/:id`
/// - `/api/sessions/abc-def/verdict` -> `/api/sessions/:id/verdict`
fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.is_empty() {
                return segment;
            }
            // UUID: 8-4-4-4-12 hex pattern (36 chars with dashes)
            if segment.len() == 36 && segment.chars().filter(|c| *c == '-').count() == 4 {
                let hex_only: String = segment.chars().filter(|c| *c != '-').collect();
                if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
                    return ":id";
                }
            }
            // Pure numeric segment
            if segment.chars().all(|c| c.is_ascii_digit()) {
                return ":id";
            }
            segment
        })
        .collect::<Vec<&str>>()
        .join("/")
}

// Middleware

/// Prometheus

/// record HTTP request delay.
/// `/api/metrics`.
pub async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();

    // metrics (request)
    if raw_path == "/api/metrics" {
        return next.run(req).await;
    }

    let path = normalize_path(&raw_path);
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[&method, &path, &status])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method, &path])
        .observe(duration);

    response
}

// Handler

/// `GET /api/metrics` - Prometheus (public, authentication)

/// text/plain format Prometheus exposition format.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(4096);
    // SAFETY: TextEncoder::encode only fails on I/O errors writing to Vec,
    // which cannot happen (Vec::write never fails).
    encoder
        .encode(&metric_families, &mut buffer)
        .expect("encoding to Vec<u8> is infallible");
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_uuid_replaced() {
        let path = "/api/sessions/550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(normalize_path(path), "/api/sessions/:id");
    }

    #[test]
    fn test_normalize_path_uuid_with_suffix() {
        let path = "/api/sessions/550e8400-e29b-41d4-a716-446655440000/verdict";
        assert_eq!(normalize_path(path), "/api/sessions/:id/verdict");
    }

    #[test]
    fn test_normalize_path_numeric_id() {
        let path = "/api/security/rules/42";
        assert_eq!(normalize_path(path), "/api/security/rules/:id");
    }

    #[test]
    fn test_normalize_path_no_dynamic_segments() {
        let path = "/api/security/pipeline";
        assert_eq!(normalize_path(path), "/api/security/pipeline");
    }

    #[test]
    fn test_normalize_path_empty() {
        assert_eq!(normalize_path("/"), "/");
    }

    #[test]
    fn test_normalize_path_root_api() {
        assert_eq!(normalize_path("/api/health"), "/api/health");
    }

    #[test]
    fn test_normalize_path_multiple_uuids() {
        let path =
            "/api/a/550e8400-e29b-41d4-a716-446655440000/b/660e8400-e29b-41d4-a716-446655440001";
        assert_eq!(normalize_path(path), "/api/a/:id/b/:id");
    }

    #[test]
    fn test_normalize_path_hex_but_not_uuid() {
        // 8 hex chars, not UUID format
        let path = "/api/sessions/abcdef12";
        assert_eq!(normalize_path(path), "/api/sessions/abcdef12");
    }

    #[test]
    fn test_normalize_path_preserves_query_segment_like_strings() {
        // Path segments that look like words should not be replaced
        let path = "/api/security/intel-whitelist";
        assert_eq!(normalize_path(path), "/api/security/intel-whitelist");
    }

    #[test]
    fn test_metrics_handler_returns_text_content() {
        // Force all LazyLock metrics to register by touching them
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/api/test", "200"])
            .inc();
        HTTP_REQUEST_DURATION_SECONDS
            .with_label_values(&["GET", "/api/test"])
            .observe(0.001);
        WS_CONNECTIONS_ACTIVE.inc();
        WS_CONNECTIONS_ACTIVE.dec();
        EMAILS_PROCESSED_TOTAL.inc();
        VERDICTS_TOTAL.with_label_values(&["safe"]).inc();
        ENGINE_MODULE_DURATION_SECONDS
            .with_label_values(&["test_module"])
            .observe(0.001);

        let encoder = TextEncoder::new();
        let families = prometheus::gather();
        let mut buf = Vec::new();
        encoder.encode(&families, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("http_requests_total"));
        assert!(output.contains("http_request_duration_seconds"));
        assert!(output.contains("ws_connections_active"));
        assert!(output.contains("emails_processed_total"));
        assert!(output.contains("verdicts_total"));
        assert!(output.contains("engine_module_duration_seconds"));
    }

    #[test]
    fn test_counter_increments() {
        let before = HTTP_REQUESTS_TOTAL
            .with_label_values(&["POST", "/api/metrics_test", "201"])
            .get();
        HTTP_REQUESTS_TOTAL
            .with_label_values(&["POST", "/api/metrics_test", "201"])
            .inc();
        let after = HTTP_REQUESTS_TOTAL
            .with_label_values(&["POST", "/api/metrics_test", "201"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_observes() {
        ENGINE_MODULE_DURATION_SECONDS
            .with_label_values(&["test_module"])
            .observe(0.042);
        let count = ENGINE_MODULE_DURATION_SECONDS
            .with_label_values(&["test_module"])
            .get_sample_count();
        assert!(count >= 1);
    }

    #[test]
    fn test_gauge_inc_dec() {
        let before = WS_CONNECTIONS_ACTIVE.get();
        WS_CONNECTIONS_ACTIVE.inc();
        assert!((WS_CONNECTIONS_ACTIVE.get() - before - 1.0).abs() < f64::EPSILON);
        WS_CONNECTIONS_ACTIVE.dec();
        assert!((WS_CONNECTIONS_ACTIVE.get() - before).abs() < f64::EPSILON);
    }

    #[test]
    fn test_verdicts_counter_by_threat_level() {
        VERDICTS_TOTAL.with_label_values(&["safe"]).inc();
        VERDICTS_TOTAL.with_label_values(&["low"]).inc();
        VERDICTS_TOTAL.with_label_values(&["medium"]).inc();
        VERDICTS_TOTAL.with_label_values(&["high"]).inc();
        VERDICTS_TOTAL.with_label_values(&["critical"]).inc();

        // All labels should have at least 1
        for level in &["safe", "low", "medium", "high", "critical"] {
            assert!(VERDICTS_TOTAL.with_label_values(&[level]).get() >= 1.0);
        }
    }
}
