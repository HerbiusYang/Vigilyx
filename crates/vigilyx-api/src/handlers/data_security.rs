//! Data security API handlers.
//!
//! - GET /api/data-security/stats — Data security statistics
//! - GET /api/data-security/incidents — Incident list (paginated + filtered)
//! - GET /api/data-security/incidents/{id} — Incident detail
//! - GET /api/data-security/http-sessions/{id} — HTTP session detail
//! - POST /api/data-security/import/http-sessions — Import HTTP sessions (internal)

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::header,
    response::IntoResponse,
};
use regex::{Captures, Regex};
use serde::Deserialize;
use std::sync::Arc;
use std::sync::OnceLock;
use uuid::Uuid;
use vigilyx_core::{DataSecurityIncident, DataSecurityStats, HttpSession};

use super::{ApiResponse, PaginatedResponse};
use crate::AppState;


// Query parameters


/// Data security incident query parameters
#[derive(Debug, Deserialize)]
pub struct IncidentQueryParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
   /// Incident type: draft_box_abuse | file_transit_abuse | self_sending
    pub incident_type: Option<String>,
   /// Severity: info | low | medium | high | critical
    pub severity: Option<String>,
   /// Filter by client IP
    pub client_ip: Option<String>,
   /// Filter by user
    pub user: Option<String>,
   /// Filter by keyword (summary)
    pub keyword: Option<String>,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    50
}


// Statistics API


/// Get data security statistics
pub async fn get_data_security_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_data_security_stats().await {
        Ok(stats) => ApiResponse::ok(stats),
        Err(e) => ApiResponse::<DataSecurityStats>::internal_err(&e, "Operation failed"),
    }
}


// Incident API


/// Validate incident type parameter
fn validate_incident_type(t: &str) -> bool {
    matches!(
        t,
        "draft_box_abuse"
            | "file_transit_abuse"
            | "self_sending"
            | "volume_anomaly"
            | "jrt_compliance_violation"
    )
}

/// Validate severity parameter
fn validate_severity(s: &str) -> bool {
    matches!(s, "info" | "low" | "medium" | "high" | "critical")
}

/// List data security incidents (paginated + filtered)
pub async fn list_data_security_incidents(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<IncidentQueryParams>,
) -> axum::response::Response {
    params.limit = params.limit.clamp(1, 1000);
   // Validate parameters
    if let Some(ref t) = params.incident_type
        && !validate_incident_type(t)
    {
        return ApiResponse::<PaginatedResponse<DataSecurityIncident>>::bad_request(format!(
            "无效事件Type: {}",
            t
        ))
        .into_response();
    }
    if let Some(ref s) = params.severity
        && !validate_severity(s)
    {
        return ApiResponse::<PaginatedResponse<DataSecurityIncident>>::bad_request(format!(
            "无效严重程度: {}",
            s
        ))
        .into_response();
    }

    let offset = (params.page.saturating_sub(1)) * params.limit;

    match state
        .db
        .list_data_security_incidents(
            params.incident_type.as_deref(),
            params.severity.as_deref(),
            params.client_ip.as_deref(),
            params.user.as_deref(),
            params.keyword.as_deref(),
            params.limit,
            offset,
        )
        .await
    {
        Ok((incidents, total)) => {
            let total_pages = if params.limit > 0 {
                ((total as f64) / (params.limit as f64)).ceil() as u32
            } else {
                0
            };
            ApiResponse::ok(PaginatedResponse {
                items: incidents,
                total,
                page: params.page,
                limit: params.limit,
                total_pages,
            })
            .into_response()
        }
        Err(e) => ApiResponse::<PaginatedResponse<DataSecurityIncident>>::server_error(
            &e,
            "Operation failed",
        )
        .into_response(),
    }
}

/// Get data security incident detail
pub async fn get_data_security_incident(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                ApiResponse::<DataSecurityIncident>::err("Invalid UUID"),
            );
        }
    };

    match state.db.get_data_security_incident(uuid).await {
        Ok(Some(incident)) => (axum::http::StatusCode::OK, ApiResponse::ok(incident)),
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            ApiResponse::err("Incident not found"),
        ),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::internal_err(&e, "Operation failed"),
        ),
    }
}


// HTTP Session API


/// HTTP session list query parameters
#[derive(Debug, Deserialize)]
pub struct HttpSessionQueryParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
   /// Client IP (filter)
    pub client_ip: Option<String>,
   /// User (filter)
    pub user: Option<String>,
   /// HTTP method: GET | POST | PUT | DELETE
    pub method: Option<String>,
   /// URL keyword (filter)
    pub keyword: Option<String>,
}

/// List HTTP sessions (paginated + filtered)
pub async fn list_http_sessions(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<HttpSessionQueryParams>,
) -> impl IntoResponse {
    params.limit = params.limit.clamp(1, 1000);
    let offset = (params.page.saturating_sub(1)) * params.limit;

   // Build filters
    let filters = vigilyx_db::HttpSessionFilters {
        client_ip: params.client_ip.filter(|s| !s.is_empty()),
        user: params.user.filter(|s| !s.is_empty()),
        method: params.method.filter(|s| !s.is_empty()),
        keyword: params.keyword.filter(|s| !s.is_empty()),
    };

    match state
        .db
        .list_http_sessions_filtered(&filters, params.limit, offset)
        .await
    {
        Ok((sessions, total)) => {
            let total_pages = if params.limit > 0 {
                ((total as f64) / (params.limit as f64)).ceil() as u32
            } else {
                0
            };
            ApiResponse::ok(PaginatedResponse {
                items: sessions,
                total,
                page: params.page,
                limit: params.limit,
                total_pages,
            })
        }
        Err(e) => {
            ApiResponse::<PaginatedResponse<HttpSession>>::internal_err(&e, "Operation failed")
        }
    }
}

/// Get HTTP session detail
pub async fn get_http_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                ApiResponse::<HttpSession>::err("Invalid UUID"),
            );
        }
    };

    match state.db.get_http_session(uuid).await {
        Ok(Some(mut session)) => {
           // SEC: Redact password-like fields from request_body before API delivery (CWE-312)
            if let Some(ref body) = session.request_body {
                session.request_body =
                    Some(redact_request_body(body, session.content_type.as_deref()));
            }
            (axum::http::StatusCode::OK, ApiResponse::ok(session))
        }
        Ok(None) => (
            axum::http::StatusCode::NOT_FOUND,
            ApiResponse::err("HTTP session not found"),
        ),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::internal_err(&e, "Operation failed"),
        ),
    }
}


// HTTP session import (internal / sniffer)


/// Import HTTP sessions (internal).
///
/// Accepts sessions from the sniffer or external parsers.
/// Triggers data security engine analysis.
pub async fn import_http_sessions(
    State(state): State<Arc<AppState>>,
    Json(mut sessions): Json<Vec<HttpSession>>,
) -> impl IntoResponse {
    // SEC: strip externally supplied body_temp_file values to prevent path-traversal reads of arbitrary files (CWE-22).
    // Only temp paths generated by the server-side sniffer are allowed; external imports must not specify file paths.
    for session in &mut sessions {
        session.body_temp_file = None;
    }

    let total = sessions.len();
    let mut success_count = 0u64;

    for session in &sessions {
       // Save HTTP session
        if let Err(e) = state.db.insert_http_session(session).await {
            tracing::warn!(session_id = %session.id, "保存 HTTP Session 失败: {}", e);
            continue;
        }
        success_count += 1;
    }

    ApiResponse::ok(serde_json::json!({
        "imported": success_count,
        "total": total
    }))
}

/// Get data security engine status.
///
/// Reads engine heartbeat from Redis/file and extracts DS counters.
pub async fn get_data_security_engine_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let engine_status = super::security::load_engine_status_snapshot(&state)
        .await
        .filter(|snapshot| snapshot.heartbeat_secs < 30)
        .map(|snapshot| snapshot.status);

    match engine_status.as_ref() {
        Some(status) => {
            let ds_sessions = status
                .get("ds_sessions_processed")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let ds_incidents = status
                .get("ds_incidents_detected")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            ApiResponse::ok(serde_json::json!({
                "running": true,
                "http_sessions_processed": ds_sessions,
                "incidents_detected": ds_incidents
            }))
        }
        None => ApiResponse::ok(serde_json::json!({
            "running": false,
            "http_sessions_processed": 0,
            "incidents_detected": 0
        })),
    }
}


// HTTP session body download


/// Download HTTP session body file.
///
/// Large bodies (>256KB) are stored by sniffer at data/tmp/http/{session_id}.bin.
/// Security analysis temp files are cleaned up after 2 hours.
pub async fn download_http_session_body(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
   // Validate UUID
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "Invalid UUID").into_response(),
    };

   // Query session to get body_temp_file path
    let session = match state.db.get_http_session(uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (axum::http::StatusCode::NOT_FOUND, "Session not found").into_response();
        }
        Err(e) => {
            tracing::error!(session_id = %uuid, "查询 HTTP Session 失败: {}", e);
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
            )
                .into_response();
        }
    };

   // File path: prefer body_temp_file, fallback to convention
    let file_path = session
        .body_temp_file
        .unwrap_or_else(|| format!("data/tmp/http/{}.bin", uuid));

   // Security: ensure path stays within data/tmp/http/ (path traversal guard)
    let canonical = match std::path::Path::new(&file_path).canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (axum::http::StatusCode::NOT_FOUND, "Body file not found").into_response();
        }
    };
    let allowed_dir = match std::path::Path::new("data/tmp/http").canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                "Temp directory not found",
            )
                .into_response();
        }
    };
    if !canonical.starts_with(&allowed_dir) {
        tracing::warn!(
            session_id = %uuid,
            path = %file_path,
            "路径遍历攻击: 文件不在允许目录下"
        );
        return (axum::http::StatusCode::FORBIDDEN, "Access denied").into_response();
    }

   // Read file
    let raw_data = match tokio::fs::read(&canonical).await {
        Ok(d) => d,
        Err(_) => {
            return (axum::http::StatusCode::NOT_FOUND, "Body file not found").into_response();
        }
    };

    let raw_ct = session
        .content_type
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let data = match build_redacted_download_payload(
        &raw_data,
        Some(&raw_ct),
        session.body_is_binary,
    ) {
        Ok(data) => data,
        Err(message) => {
            tracing::warn!(
                session_id = %uuid,
                body_is_binary = session.body_is_binary,
                content_type = %raw_ct,
                "Blocked unsafe HTTP body download: {}",
                message
            );
            return (axum::http::StatusCode::FORBIDDEN, message).into_response();
        }
    };
    let download_name =
        build_redacted_download_name(session.uploaded_filename.as_deref(), &uuid.to_string());

    axum::http::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", download_name),
        )
        .body(Body::from(data))
        .unwrap_or_else(|_| {
            axum::http::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Failed to build response"))
                .expect("fallback response")
        })
        .into_response()
}

const REDACTED_VALUE: &str = "[REDACTED]";
const SENSITIVE_KEY_EXACT: &[&str] = &["auth", "otp", "pass", "pwd", "secret", "token"];
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "accesstoken",
    "apikey",
    "authorization",
    "clientsecret",
    "credential",
    "passwd",
    "passcode",
    "passphrase",
    "password",
    "refreshtoken",
    "sessiontoken",
    "verificationcode",
];

fn redact_request_body(body: &str, content_type: Option<&str>) -> String {
    let ct = content_type.map(|value| value.to_ascii_lowercase());
    let trimmed = body.trim_start();

    if (ct
        .as_deref()
        .is_some_and(|value| value.contains("json") || value.ends_with("+json"))
        || trimmed.starts_with('{')
        || trimmed.starts_with('['))
        && let Some(redacted) = redact_json_credentials(body)
    {
        return redacted;
    }

    let mut redacted = redact_key_value_credentials(body);
    if ct
        .as_deref()
        .is_some_and(|value| value.contains("xml") || value.ends_with("+xml"))
        || trimmed.starts_with('<')
    {
        redacted = redact_xml_tag_credentials(&redacted);
    }
    redacted
}

fn redact_json_credentials(body: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(body).ok()?;
    redact_json_value(&mut value);
    serde_json::to_string(&value).ok()
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if is_sensitive_key(key) {
                   *item = serde_json::Value::String(REDACTED_VALUE.to_string());
                } else {
                    redact_json_value(item);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

fn redact_key_value_credentials(body: &str) -> String {
    key_value_regex()
        .replace_all(body, |caps: &Captures<'_>| {
            let key = caps
                .name("dkey")
                .or_else(|| caps.name("skey"))
                .or_else(|| caps.name("bare"))
                .map(|m| m.as_str())
                .unwrap_or_default();

            if !is_sensitive_key(key) {
                return caps[0].to_string();
            }

            let prefix = caps.name("prefix").map(|m| m.as_str()).unwrap_or_default();
            let value = caps.name("value").map(|m| m.as_str()).unwrap_or_default();
            format!("{prefix}{}", redacted_literal(value, prefix))
        })
        .into_owned()
}

fn redact_xml_tag_credentials(body: &str) -> String {
    xml_tag_regex()
        .replace_all(body, |caps: &Captures<'_>| {
            let tag = caps.name("tag").map(|m| m.as_str()).unwrap_or_default();
            if !is_sensitive_key(tag.rsplit(':').next().unwrap_or(tag)) {
                return caps[0].to_string();
            }

            let open = caps.name("open").map(|m| m.as_str()).unwrap_or_default();
            let close = caps.name("close").map(|m| m.as_str()).unwrap_or_default();
            format!("{open}{REDACTED_VALUE}{close}")
        })
        .into_owned()
}

fn redacted_literal(value: &str, prefix: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0] as char;
        let last = value.as_bytes()[value.len() - 1] as char;
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            return format!("{first}{REDACTED_VALUE}{last}");
        }
    }

    if prefix.contains(':') {
        format!("\"{REDACTED_VALUE}\"")
    } else {
        REDACTED_VALUE.to_string()
    }
}

fn build_redacted_download_payload(
    raw_data: &[u8],
    content_type: Option<&str>,
    body_is_binary: bool,
) -> Result<Vec<u8>, &'static str> {
    if body_is_binary {
        return Err("出于安全考虑，二进制请求体的原始下载已禁用");
    }

    let body = std::str::from_utf8(raw_data)
        .map_err(|_| "请求体不是可安全导出的 UTF-8 文本内容")?;

    Ok(redact_request_body(body, content_type).into_bytes())
}

fn build_redacted_download_name(raw_name: Option<&str>, fallback_stem: &str) -> String {
    let safe_name: String = raw_name
        .unwrap_or("http-request-body")
        .chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '/' && *c != '\\')
        .take(180)
        .collect();

    let safe_name = if safe_name.trim().is_empty() {
        fallback_stem.to_string()
    } else {
        safe_name
    };

    format!("{safe_name}.redacted.txt")
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>();

    SENSITIVE_KEY_EXACT.iter().any(|item| normalized == *item)
        || SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|item| normalized.contains(item))
}

fn key_value_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?P<prefix>
                (?:
                    "(?P<dkey>[^"]+)"
                    |
                    '(?P<skey>[^']+)'
                    |
                    (?P<bare>[A-Za-z0-9_.:-]+)
                )
                \s*[:=]\s*
            )
            (?P<value>
                "(?:\\.|[^"])*"
                |
                '(?:\\.|[^'])*'
                |
                [^,&;\s}\]\r\n]+
            )
            "#,
        )
        .expect("valid key/value redaction regex")
    })
}

fn xml_tag_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?isx)
            (?P<open><(?P<tag>[A-Za-z0-9_.:-]+)[^>]*>)
            (?P<value>[^<]*)
            (?P<close></[A-Za-z0-9_.:-]+\s*>)
            "#,
        )
        .expect("valid XML redaction regex")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_redacted_download_name, build_redacted_download_payload, redact_request_body,
    };
    use serde_json::Value;

    #[test]
    fn redacts_form_credentials() {
        let redacted = redact_request_body(
            "username=alice&password=secret&token=abc123",
            Some("application/x-www-form-urlencoded"),
        );

        assert_eq!(
            redacted,
            "username=alice&password=[REDACTED]&token=[REDACTED]"
        );
    }

    #[test]
    fn redacts_json_credentials() {
        let redacted = redact_request_body(
            r#"{"username":"alice","password":"secret","nested":{"access_token":"abc"}}"#,
            Some("application/json"),
        );
        let value: Value = serde_json::from_str(&redacted).expect("valid json");

        assert_eq!(value["username"], "alice");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["nested"]["access_token"], "[REDACTED]");
    }

    #[test]
    fn redacts_xml_credentials() {
        let redacted = redact_request_body(
            r#"<login password="secret"><username>alice</username><password>secret</password></login>"#,
            Some("application/xml"),
        );

        assert!(redacted.contains("<password>[REDACTED]</password>"));
        assert!(redacted.contains(r#"password="[REDACTED]""#));
    }

    #[test]
    fn redacts_javascript_style_credentials() {
        let redacted = redact_request_body(
            r#"const payload = { password: "secret", apiKey: tokenValue };"#,
            Some("application/javascript"),
        );

        assert!(redacted.contains(r#"password: "[REDACTED]""#));
        assert!(redacted.contains(r#"apiKey: "[REDACTED]""#));
    }

    #[test]
    fn redacts_json_credentials_when_content_type_is_generic() {
        let redacted = redact_request_body(
            r#"{"username":"alice","password":"secret","nested":{"access_token":"abc"}}"#,
            Some("application/octet-stream"),
        );
        let value: Value = serde_json::from_str(&redacted).expect("valid json");

        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["nested"]["access_token"], "[REDACTED]");
    }

    #[test]
    fn blocks_binary_body_downloads() {
        let result = build_redacted_download_payload(b"\x89PNG\r\n", Some("image/png"), true);
        assert!(result.is_err());
    }

    #[test]
    fn exports_redacted_text_body_downloads() {
        let result = build_redacted_download_payload(
            b"username=alice&password=secret",
            Some("application/octet-stream"),
            false,
        )
        .expect("utf8 text payload");

        assert_eq!(
            String::from_utf8(result).expect("utf8"),
            "username=alice&password=[REDACTED]"
        );
    }

    #[test]
    fn marks_download_name_as_redacted() {
        let filename = build_redacted_download_name(Some("invoice.pdf"), "fallback");
        assert_eq!(filename, "invoice.pdf.redacted.txt");
    }
}
