//! Session Process: table,, EML, Session

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use std::sync::Arc;
use uuid::Uuid;
use vigilyx_core::{EmailContent, EmailSession};

use super::{ApiResponse, PaginatedResponse, PaginationParams, clamp_limit};
use crate::AppState;

const MAX_EML_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;
const MAX_ATTACHMENT_DOWNLOAD_BYTES: usize = 25 * 1024 * 1024;

fn redact_related_session_content(mut session: EmailSession) -> EmailSession {
    session.content = EmailContent {
        is_complete: session.content.is_complete,
        is_encrypted: session.content.is_encrypted,
        ..EmailContent::default()
    };
    session
}

fn redact_attachment_payloads(mut session: EmailSession) -> EmailSession {
    for attachment in &mut session.content.attachments {
        attachment.content_base64 = None;
    }
    session
}

/// GetSession table
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<PaginationParams>,
) -> impl IntoResponse {
    params.limit = clamp_limit(params.limit);
    let offset = (params.page.saturating_sub(1)) * params.limit;

    match state
        .db
        .list_sessions(
            params.limit,
            offset,
            params.protocol.as_deref(),
            params.status.as_deref(),
            params.since.as_deref(),
            params.content_filter.as_deref(),
            params.auth_filter.as_deref(),
            params.source_ips.as_deref(),
            params.dest_ips.as_deref(),
            params.search.as_deref(),
            &[],
            params.skip_count,
        )
        .await
    {
        Ok((sessions, total)) => {
            let total_pages = (total as f64 / params.limit as f64).ceil() as u32;
            ApiResponse::ok(PaginatedResponse {
                items: sessions,
                total,
                page: params.page,
                limit: params.limit,
                total_pages,
            })
        }
        Err(e) => {
            ApiResponse::<PaginatedResponse<EmailSession>>::internal_err(&e, "Operation failed")
        }
    }
}

/// Get Session
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                ApiResponse::<EmailSession>::err("Invalid UUID"),
            );
        }
    };

    match state.db.get_session_without_attachment_content(uuid).await {
        Ok(Some(session)) => (
            StatusCode::OK,
            ApiResponse::ok(redact_attachment_payloads(session)),
        ),
        Ok(None) => (StatusCode::NOT_FOUND, ApiResponse::err("Session not found")),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::internal_err(&e, "Operation failed"),
        ),
    }
}

/// Session attachment download.
pub async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path((id, index)): Path<(String, usize)>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::header;

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid UUID").into_response(),
    };

    let session = match state.db.get_session(uuid).await {
        Ok(Some(session)) => session,
        Ok(None) => return (StatusCode::NOT_FOUND, "Session not found").into_response(),
        Err(e) => {
            tracing::error!("Attachment download session lookup failed: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let Some(attachment) = session.content.attachments.get(index) else {
        return (StatusCode::NOT_FOUND, "Attachment not found").into_response();
    };
    if attachment.size > MAX_ATTACHMENT_DOWNLOAD_BYTES {
        tracing::warn!(
            session_id = %session.id,
            attachment_index = index,
            size = attachment.size,
            max_size = MAX_ATTACHMENT_DOWNLOAD_BYTES,
            "Blocked oversized attachment download"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Attachment download too large",
        )
            .into_response();
    }

    let Some(content_base64) = attachment.content_base64.as_deref() else {
        return (StatusCode::NOT_FOUND, "Attachment content unavailable").into_response();
    };
    let estimated_bytes = content_base64.len().saturating_mul(3) / 4;
    if estimated_bytes > MAX_ATTACHMENT_DOWNLOAD_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Attachment download too large",
        )
            .into_response();
    }

    let bytes = match BASE64_STANDARD.decode(content_base64) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(
                session_id = %session.id,
                attachment_index = index,
                error = %e,
                "Stored attachment content is not valid base64"
            );
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                "Attachment content invalid",
            )
                .into_response();
        }
    };
    if bytes.len() > MAX_ATTACHMENT_DOWNLOAD_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Attachment download too large",
        )
            .into_response();
    }

    let filename = sanitize_download_filename(&attachment.filename, "attachment.bin");
    let content_type = safe_content_type(&attachment.content_type);

    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(bytes))
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build response",
            )
                .into_response()
        })
}

/// Session EML File (RFC 2822 format)
pub async fn download_eml(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::header;

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UUID").into_response();
        }
    };

    match state.db.get_session(uuid).await {
        Ok(Some(session)) => {
            let estimated_size = session.estimated_reconstructed_eml_size();
            if estimated_size > MAX_EML_DOWNLOAD_BYTES {
                tracing::warn!(
                    session_id = %session.id,
                    estimated_size,
                    max_size = MAX_EML_DOWNLOAD_BYTES,
                    "Blocked oversized EML download"
                );
                return (StatusCode::PAYLOAD_TOO_LARGE, "EML download too large").into_response();
            }

            let Some(eml_bytes) = session.reconstruct_eml_limited(MAX_EML_DOWNLOAD_BYTES) else {
                tracing::warn!(
                    session_id = %session.id,
                    max_size = MAX_EML_DOWNLOAD_BYTES,
                    "Blocked oversized EML download after reconstruction"
                );
                return (StatusCode::PAYLOAD_TOO_LARGE, "EML download too large").into_response();
            };
            if eml_bytes.is_empty() {
                return (StatusCode::NOT_FOUND, "No email content to reconstruct").into_response();
            }

            // Sanitize filename from subject
            let filename = session
                .subject
                .as_deref()
                .unwrap_or("email")
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
                .take(50)
                .collect::<String>();
            let filename = if filename.trim().is_empty() {
                "email".to_string()
            } else {
                filename
            };

            axum::http::Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "message/rfc822")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}.eml\"", filename),
                )
                .body(Body::from(eml_bytes))
                .unwrap_or_else(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to build response",
                    )
                        .into_response()
                })
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Session not found").into_response(),
        // SEC-H06: client Data error (CWE-209)
        Err(e) => {
            tracing::error!("EML 下载failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}

/// Get Session(Message-ID)
pub async fn get_related_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                ApiResponse::<Vec<EmailSession>>::err("Invalid UUID"),
            );
        }
    };

    let session = match state.db.get_session_without_attachment_content(uuid).await {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, ApiResponse::err("Session not found")),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::internal_err(&e, "Operation failed"),
            );
        }
    };

    let mut related: Vec<EmailSession> = Vec::new();

    // Message-ID
    if let Some(ref mid) = session.message_id
        && !mid.is_empty()
        && let Ok(msg_related) = state
            .db
            .find_related_sessions_without_attachment_content(mid, uuid)
            .await
    {
        related = msg_related
            .into_iter()
            .map(redact_related_session_content)
            .collect();
    }

    related.sort_by_key(|s| s.started_at);
    (StatusCode::OK, ApiResponse::ok(related))
}

fn sanitize_download_filename(filename: &str, fallback: &str) -> String {
    let sanitized = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(120)
        .collect::<String>();
    let sanitized = sanitized.trim_start_matches('.').to_string();
    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

fn safe_content_type(content_type: &str) -> &str {
    if content_type.is_empty()
        || content_type
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b';')
    {
        "application/octet-stream"
    } else {
        content_type
    }
}

#[cfg(test)]
mod tests {
    use super::{
        redact_attachment_payloads, redact_related_session_content, safe_content_type,
        sanitize_download_filename,
    };
    use vigilyx_core::{EmailAttachment, EmailLink, EmailSession, Protocol, SmtpDialogEntry};

    #[test]
    fn related_session_redaction_drops_message_payload() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            25000,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.is_complete = true;
        session.content.is_encrypted = true;
        session.content.headers = vec![("Subject".to_string(), "hello".to_string())];
        session.content.body_text = Some("plain".to_string());
        session.content.body_html = Some("<p>html</p>".to_string());
        session.content.attachments = vec![EmailAttachment {
            filename: "a.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 5,
            hash: "abc".to_string(),
            content_base64: None,
        }];
        session.content.links = vec![EmailLink {
            url: "https://example.com".to_string(),
            text: Some("example".to_string()),
            suspicious: false,
        }];
        session.content.smtp_dialog = vec![SmtpDialogEntry {
            direction: vigilyx_core::Direction::Inbound,
            command: "DATA".to_string(),
            size: 4,
            timestamp: chrono::Utc::now(),
        }];

        let redacted = redact_related_session_content(session);

        assert!(redacted.content.is_complete);
        assert!(redacted.content.is_encrypted);
        assert!(redacted.content.headers.is_empty());
        assert!(redacted.content.body_text.is_none());
        assert!(redacted.content.body_html.is_none());
        assert!(redacted.content.attachments.is_empty());
        assert!(redacted.content.links.is_empty());
        assert!(redacted.content.smtp_dialog.is_empty());
    }

    #[test]
    fn session_detail_redaction_drops_attachment_payloads() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            25000,
            "10.0.0.2".to_string(),
            25,
        );
        session.content.attachments = vec![EmailAttachment {
            filename: "a.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 3,
            hash: "abc".to_string(),
            content_base64: Some("QUJD".to_string()),
        }];

        let redacted = redact_attachment_payloads(session);

        assert_eq!(redacted.content.attachments.len(), 1);
        assert!(redacted.content.attachments[0].content_base64.is_none());
    }

    #[test]
    fn download_headers_are_sanitized() {
        assert_eq!(
            sanitize_download_filename("../恶意\r\n.txt", "attachment.bin"),
            "txt"
        );
        assert_eq!(
            sanitize_download_filename("\r\n", "attachment.bin"),
            "attachment.bin"
        );
        assert_eq!(safe_content_type("text/plain"), "text/plain");
        assert_eq!(
            safe_content_type("text/plain\r\nx: y"),
            "application/octet-stream"
        );
        assert_eq!(
            safe_content_type("text/plain; charset=utf-8"),
            "application/octet-stream"
        );
    }
}
