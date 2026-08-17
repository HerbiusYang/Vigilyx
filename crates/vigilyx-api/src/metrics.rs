//! Prometheus

//! Vigilyx API For Prometheus:
//! - HTTP request delay (According to method / path / status)
//! - WebSocket Connection
//! - Process verdict
//! - EngineModule

//! `GET /api/metrics` `INTERNAL_API_TOKEN` authentication (SEC-M06).
//! Prometheus Configuration `X-Internal-Token` request.

//! **SEC-03**: path labels come from axum's `MatchedPath` route template
//! (unmatched requests use a constant `:unmatched` label), keeping the
//! Prometheus label cardinality bounded.

use std::sync::LazyLock;
use std::time::Instant;

use axum::{
    extract::MatchedPath,
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

// Path label selection (SEC-03: bounded label cardinality)

/// Label used for requests that did not match any route (SPA fallback / 404).
///
/// Keeping all unmatched traffic under a single constant label prevents an
/// attacker from exhausting Prometheus memory by scanning random paths.
const UNMATCHED_PATH_LABEL: &str = ":unmatched";

/// Select the Prometheus path label for a request.
///
/// SEC-03: prefer axum's `MatchedPath` route template (e.g. `/api/sessions/{id}`),
/// which is statically declared and therefore inherently bounded — the concrete
/// path parameters inside it never become label values. Requests that match no
/// route fall through to the SPA fallback and are labeled `:unmatched`; the raw
/// request path must never be used as a label value.
///
/// This middleware is mounted with `Router::layer`, which runs *after* routing
/// (axum >= 0.7), so `MatchedPath` is already present in the request extensions.
fn metrics_path_label(req: &Request<axum::body::Body>) -> String {
    req.extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_owned())
        .unwrap_or_else(|| UNMATCHED_PATH_LABEL.to_owned())
}

fn metrics_method_label(method: &axum::http::Method) -> &'static str {
    match *method {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PUT => "PUT",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        axum::http::Method::CONNECT => "CONNECT",
        axum::http::Method::TRACE => "TRACE",
        _ => ":other",
    }
}

// Middleware

/// Prometheus

/// record HTTP request delay.
/// `/api/metrics`.
pub async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    let method = metrics_method_label(req.method());
    let raw_path = req.uri().path().to_string();

    // metrics (request)
    if raw_path == "/api/metrics" {
        return next.run(req).await;
    }

    // Resolve the label before `next.run` consumes the request.
    let path = metrics_path_label(&req);
    let start = Instant::now();

    let response = next.run(req).await;

    let status = response.status().as_u16().to_string();
    let duration = start.elapsed().as_secs_f64();

    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, &path, &status])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, &path])
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
    use axum::{Router, body::Body, routing::get};
    use tower::ServiceExt;

    #[test]
    fn test_metrics_method_label_is_bounded() {
        let attacker_method = axum::http::Method::from_bytes(b"X-ATTACKER-123").unwrap();
        assert_eq!(metrics_method_label(&attacker_method), ":other");
        assert_eq!(metrics_method_label(&axum::http::Method::GET), "GET");
    }

    #[tokio::test]
    async fn test_metrics_label_uses_matched_path_template() {
        let app = Router::new()
            .route("/api/sessions/{id}", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(metrics_middleware));

        let before = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/api/sessions/{id}", "200"])
            .get();
        let request = Request::builder()
            .uri("/api/sessions/550e8400-e29b-41d4-a716-446655440000")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);

        let after = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/api/sessions/{id}", "200"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_metrics_label_unmatched_for_unknown_paths() {
        // Mirror main.rs: fallback registered before the metrics layer.
        let app = Router::new()
            .route("/api/health", get(|| async { "ok" }))
            .fallback(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") })
            .layer(axum::middleware::from_fn(metrics_middleware));

        let before = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", ":unmatched", "404"])
            .get();
        // Attacker-controlled garbage path must never become a label value.
        let request = Request::builder()
            .uri("/api/random-garbage-path-93ab71")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 404);

        let after = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", ":unmatched", "404"])
            .get();
        assert!((after - before - 1.0).abs() < f64::EPSILON);
        // The raw garbage path must not have been recorded as a label.
        assert_eq!(
            HTTP_REQUESTS_TOTAL
                .with_label_values(&["GET", "/api/random-garbage-path-93ab71", "404"])
                .get(),
            0.0
        );
    }

    #[tokio::test]
    async fn test_metrics_scrape_endpoint_not_recorded() {
        let app = Router::new()
            .route("/api/metrics", get(metrics_handler))
            .layer(axum::middleware::from_fn(metrics_middleware));

        let before = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/api/metrics", "200"])
            .get();
        let request = Request::builder()
            .uri("/api/metrics")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), 200);

        let after = HTTP_REQUESTS_TOTAL
            .with_label_values(&["GET", "/api/metrics", "200"])
            .get();
        assert!(
            (after - before).abs() < f64::EPSILON,
            "scrape traffic must not be recorded"
        );
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
