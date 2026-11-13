//! Session Process: table,, EML, Session

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_CURSOR},
};
use std::sync::Arc;
use uuid::Uuid;
use vigilyx_core::{EmailContent, EmailSession};

use super::privacy;
use super::{ApiResponse, PaginationParams, clamp_limit};
use crate::AppState;
use crate::auth::AuthenticatedUser;

const MAX_EML_DOWNLOAD_BYTES: usize = 50 * 1024 * 1024;
const MAX_ATTACHMENT_DOWNLOAD_BYTES: usize = 25 * 1024 * 1024;

fn redact_related_session_content(mut session: EmailSession) -> EmailSession {
    session.mail_from = session
        .mail_from
        .as_deref()
        .map(privacy::mask_email_address);
    session.rcpt_to = session
        .rcpt_to
        .iter()
        .map(|address| privacy::mask_email_address(address))
        .collect();
    session.subject = None;
    session.message_id = None;
    session.auth_info = None;
    session.content = EmailContent {
        is_complete: session.content.is_complete,
        is_encrypted: session.content.is_encrypted,
        ..EmailContent::default()
    };
    session
}

fn project_session_content(
    mut session: EmailSession,
    scopes: &std::collections::HashSet<String>,
) -> EmailSession {
    let content = &session.content;
    let allow_body = scopes.contains("body");
    let allow_html = scopes.contains("html");
    let allow_headers = scopes.contains("headers");
    // Subject, envelope addresses, Message-ID, and SMTP AUTH identity are
    // message metadata.  Keep them behind the same explicit header scope so
    // a list/detail endpoint cannot become an indirect plaintext outlet.
    if !allow_headers {
        session.mail_from = session
            .mail_from
            .as_deref()
            .map(privacy::mask_email_address);
        session.rcpt_to = session
            .rcpt_to
            .iter()
            .map(|address| privacy::mask_email_address(address))
            .collect();
        session.subject = session.subject.as_deref().map(privacy::mask_subject);
        session.message_id = None;
        session.auth_info = None;
    }
    let attachments = content
        .attachments
        .iter()
        .cloned()
        .map(|mut attachment| {
            attachment.content_base64 = None;
            attachment
        })
        .collect();
    session.content = EmailContent {
        headers: if allow_headers {
            content.headers.clone()
        } else {
            Vec::new()
        },
        body_text: if allow_body {
            content.body_text.clone()
        } else {
            None
        },
        body_html: if allow_html {
            content.body_html.clone()
        } else {
            None
        },
        attachments,
        links: if allow_body || allow_html {
            content.links.clone()
        } else {
            Vec::new()
        },
        raw_size: content.raw_size,
        is_complete: content.is_complete,
        raw_mime: None,
        is_encrypted: content.is_encrypted,
        truncated: content.truncated,
        dropped_attachments: content.dropped_attachments,
        links_truncated: content.links_truncated,
        link_index: std::collections::HashSet::new(),
        smtp_dialog: if allow_headers {
            content.smtp_dialog.clone()
        } else {
            Vec::new()
        },
    };
    session
}

/// Add an explicit privacy state to detail responses so clients can distinguish
/// an intentionally redacted message from a session that was captured without
/// usable content.  The marker contains no message data and does not alter the
/// existing server-side scope checks.
fn project_session_content_payload(
    session: EmailSession,
    scopes: &std::collections::HashSet<String>,
) -> serde_json::Value {
    let revealed = scopes.contains("__privacy_disabled__")
        || scopes.contains("body")
        || scopes.contains("html")
        || scopes.contains("headers");
    let mut payload = serde_json::to_value(project_session_content(session, scopes))
        .unwrap_or_else(|_| serde_json::json!({}));
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "privacy".to_string(),
            serde_json::json!({ "state": if revealed { "revealed" } else { "redacted" } }),
        );
    }
    payload
}

#[derive(Debug, serde::Serialize)]
struct SessionPage {
    items: Vec<EmailSession>,
    total: u64,
    page: u32,
    limit: u32,
    total_pages: u32,
    has_more: bool,
    total_is_exact: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct SessionCountResponse {
    total: u64,
    total_pages: u32,
    counted_at: chrono::DateTime<chrono::Utc>,
    /// False when `total` is the planner estimate after the exact COUNT timed out.
    exact: bool,
}

/// Use one extra row instead of COUNT to distinguish a full final page from
/// a page that actually has a successor. All projected rows retain privacy.
fn project_session_page(
    mut sessions: Vec<EmailSession>,
    total: u64,
    params: &PaginationParams,
    scopes: &std::collections::HashSet<String>,
    next_cursor: Option<String>,
) -> SessionPage {
    let has_more = sessions.len() > params.limit as usize;
    sessions.truncate(params.limit as usize);
    SessionPage {
        items: sessions
            .into_iter()
            .map(|session| project_session_content(session, scopes))
            .collect(),
        total,
        page: params.page,
        limit: params.limit,
        total_pages: total
            .div_ceil(u64::from(params.limit))
            .min(u64::from(u32::MAX)) as u32,
        has_more,
        total_is_exact: !params.skip_count,
        next_cursor: if has_more { next_cursor } else { None },
    }
}

/// Count asynchronously on the same permission boundary as session rows.
/// A timeout is an explicit failure rather than a successful zero result.
pub async fn count_sessions(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<PaginationParams>,
) -> impl IntoResponse {
    params.limit = clamp_limit(params.limit);
    match state
        .db
        .count_sessions(
            params.protocol.as_deref(),
            params.status.as_deref(),
            params.since.as_deref(),
            params.content_filter.as_deref(),
            params.auth_filter.as_deref(),
            params.source_ips.as_deref(),
            params.dest_ips.as_deref(),
            params.search.as_deref(),
            &[],
        )
        .await
    {
        Ok(snapshot) => ApiResponse::ok(SessionCountResponse {
            total: snapshot.total,
            total_pages: snapshot
                .total
                .div_ceil(u64::from(params.limit))
                .min(u64::from(u32::MAX)) as u32,
            counted_at: snapshot.counted_at,
            exact: snapshot.exact,
        }),
        Err(error) => {
            ApiResponse::<SessionCountResponse>::internal_err(&error, "Session count unavailable")
        }
    }
}

fn decode_session_cursor(encoded: &str) -> Option<vigilyx_db::SessionListCursor> {
    if encoded.len() > 512 {
        return None;
    }
    let decoded = BASE64_CURSOR.decode(encoded).ok()?;
    let cursor: vigilyx_db::SessionListCursor = serde_json::from_slice(&decoded).ok()?;
    if cursor.started_at.len() > 64
        || chrono::DateTime::parse_from_rfc3339(&cursor.started_at).is_err()
    {
        return None;
    }
    Some(cursor)
}

/// GetSession table
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<PaginationParams>,
) -> impl IntoResponse {
    params.limit = clamp_limit(params.limit);
    params.page = params.page.max(1);
    let offset = params.page.saturating_sub(1).saturating_mul(params.limit);
    let after = match params.after.as_deref() {
        Some(encoded) => match decode_session_cursor(encoded) {
            Some(cursor) => Some(cursor),
            None => {
                return ApiResponse::<SessionPage>::bad_request("Invalid session cursor")
                    .into_response();
            }
        },
        None => None,
    };
    let scopes = privacy::default_scopes(&state).await;

    match state
        .db
        .list_session_entries(
            params.limit + 1,
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
            after.as_ref(),
        )
        .await
    {
        Ok((entries, total)) => {
            let cursor = entries
                .get(params.limit.saturating_sub(1) as usize)
                .and_then(|entry| serde_json::to_vec(&entry.cursor).ok())
                .map(|bytes| BASE64_CURSOR.encode(bytes));
            ApiResponse::ok(project_session_page(
                entries.into_iter().map(|entry| entry.session).collect(),
                total,
                &params,
                &scopes,
                cursor,
            ))
            .into_response()
        }
        Err(e) => ApiResponse::<SessionPage>::internal_err(&e, "Operation failed").into_response(),
    }
}

/// Get Session
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> impl IntoResponse {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                ApiResponse::<EmailSession>::err("Invalid UUID"),
            )
                .into_response();
        }
    };

    let scopes = match privacy::active_scopes(
        &state,
        &user,
        privacy::request_id_header(&headers),
        "session",
        &id,
    )
    .await
    {
        Ok(scopes) => scopes,
        Err(error) => {
            return ApiResponse::<EmailSession>::server_error(
                &error,
                "Privacy lease validation failed",
            )
            .into_response();
        }
    };

    match state.db.get_session_without_attachment_content(uuid).await {
        Ok(Some(session)) => (
            StatusCode::OK,
            ApiResponse::<serde_json::Value>::ok(project_session_content_payload(session, &scopes)),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            ApiResponse::<serde_json::Value>::err("Session not found"),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiResponse::<serde_json::Value>::internal_err(&e, "Operation failed"),
        )
            .into_response(),
    }
}

/// Session attachment download.
pub async fn download_attachment(
    State(state): State<Arc<AppState>>,
    Path((id, index)): Path<(String, usize)>,
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> axum::response::Response {
    use axum::body::Body;

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid UUID").into_response(),
    };

    let allowed = match privacy::consume_scope(
        &state,
        &user,
        privacy::request_id_header(&headers),
        "attachment",
        &format!("{id}:{index}"),
        "attachment_download",
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::error!(error = %error, "Privacy attachment lease validation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };
    if !allowed {
        return (StatusCode::FORBIDDEN, "Privacy approval required").into_response();
    }

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
        .header(header::CACHE_CONTROL, "no-store, no-cache")
        .header(header::PRAGMA, "no-cache")
        .header("x-content-type-options", "nosniff")
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
    headers: HeaderMap,
    user: AuthenticatedUser,
) -> axum::response::Response {
    use axum::body::Body;

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UUID").into_response();
        }
    };

    let allowed = match privacy::consume_scope(
        &state,
        &user,
        privacy::request_id_header(&headers),
        "session",
        &id,
        "eml_download",
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::error!(error = %error, "Privacy EML lease validation failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };
    if !allowed {
        return (StatusCode::FORBIDDEN, "Privacy approval required").into_response();
    }

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
                .header(header::CACHE_CONTROL, "no-store, no-cache")
                .header(header::PRAGMA, "no-cache")
                .header("x-content-type-options", "nosniff")
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
    let scopes = privacy::default_scopes(&state).await;

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
            .map(|session| {
                if privacy::is_privacy_disabled(&scopes) {
                    session
                } else {
                    redact_related_session_content(session)
                }
            })
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
        project_session_content, project_session_content_payload, project_session_page,
        redact_related_session_content, safe_content_type, sanitize_download_filename,
    };
    use base64::Engine as _;
    use std::collections::HashSet;
    use vigilyx_core::{
        EmailAttachment, EmailLink, EmailSession, Protocol, SmtpAuthInfo, SmtpDialogEntry,
    };

    fn populated_session() -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            25000,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("analyst@corp.example".to_string());
        session.rcpt_to = vec!["reviewer@corp.example".to_string()];
        session.subject = Some("Confidential subject".to_string());
        session.message_id = Some("<secret-message-id@example.com>".to_string());
        session.auth_info = Some(SmtpAuthInfo {
            auth_method: "PLAIN".to_string(),
            username: Some("confidential-user".to_string()),
            password: Some("confidential-password".to_string()),
            auth_success: Some(true),
        });
        session.content.headers = vec![("X-Internal-Token".to_string(), "secret".to_string())];
        session.content.body_text = Some("confidential plain body".to_string());
        session.content.body_html = Some("<p>confidential html body</p>".to_string());
        session.content.attachments = vec![EmailAttachment {
            filename: "evidence.txt".to_string(),
            content_type: "text/plain".to_string(),
            size: 3,
            hash: "abc".to_string(),
            content_base64: Some("QUJD".to_string()),
        }];
        session.content.links = vec![EmailLink {
            url: "https://example.com/secret".to_string(),
            text: Some("secret link".to_string()),
            suspicious: true,
        }];
        session.content.smtp_dialog = vec![SmtpDialogEntry {
            direction: vigilyx_core::Direction::Inbound,
            command: "AUTH confidential-user".to_string(),
            size: 20,
            timestamp: chrono::Utc::now(),
        }];
        session.content.raw_size = 1024;
        session.content.is_complete = true;
        session.content.is_encrypted = true;
        session.content.truncated = true;
        session.content.dropped_attachments = 2;
        session.content.links_truncated = true;
        session
    }

    fn scopes(values: &[&str]) -> HashSet<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn cursor_roundtrip_preserves_stored_timestamp_and_rejects_invalid_inputs() {
        let cursor = vigilyx_db::SessionListCursor {
            started_at: "2026-10-08T07:00:00.123456789+00:00".into(),
            id: uuid::Uuid::new_v4(),
        };
        let encoded = super::BASE64_CURSOR.encode(serde_json::to_vec(&cursor).unwrap());
        let decoded = super::decode_session_cursor(&encoded).unwrap();
        assert_eq!(decoded.started_at, cursor.started_at);
        assert_eq!(decoded.id, cursor.id);
        assert!(super::decode_session_cursor("not a cursor").is_none());
        let oversized = "A".repeat(513);
        assert!(super::decode_session_cursor(&oversized).is_none());
        let invalid_time = super::BASE64_CURSOR.encode(
            serde_json::to_vec(&serde_json::json!({
                "started_at": "invalid", "id": cursor.id,
            }))
            .unwrap(),
        );
        assert!(super::decode_session_cursor(&invalid_time).is_none());
    }

    #[test]
    fn counted_cursor_pages_use_rows_instead_of_a_stale_total_for_navigation() {
        let params: super::PaginationParams = serde_json::from_value(serde_json::json!({
            "page": 1, "limit": 2, "skip_count": false,
        }))
        .unwrap();
        let empty = project_session_page(
            Vec::new(),
            100,
            &params,
            &HashSet::new(),
            Some("unused".into()),
        );
        assert!(!empty.has_more);
        assert!(empty.next_cursor.is_none());
        let full_last = project_session_page(
            vec![populated_session(), populated_session()],
            100,
            &params,
            &HashSet::new(),
            Some("unused".into()),
        );
        assert!(!full_last.has_more);
        assert!(full_last.next_cursor.is_none());
        let newer_rows = project_session_page(
            vec![
                populated_session(),
                populated_session(),
                populated_session(),
            ],
            0,
            &params,
            &HashSet::new(),
            Some("boundary".into()),
        );
        assert!(newer_rows.has_more);
        assert_eq!(newer_rows.next_cursor.as_deref(), Some("boundary"));
        assert_eq!(newer_rows.items.len(), 2);
    }

    #[test]
    fn fast_pagination_distinguishes_a_full_final_page_and_preserves_privacy() {
        let params: super::PaginationParams = serde_json::from_value(serde_json::json!({
            "page": 2, "limit": 2, "skip_count": true,
        }))
        .unwrap();
        let final_page = project_session_page(
            vec![populated_session(), populated_session()],
            0,
            &params,
            &HashSet::new(),
            None,
        );
        assert_eq!(final_page.items.len(), 2);
        assert!(!final_page.has_more);
        assert!(!final_page.total_is_exact);
        let next_page = project_session_page(
            vec![
                populated_session(),
                populated_session(),
                populated_session(),
            ],
            0,
            &params,
            &HashSet::new(),
            None,
        );
        assert!(next_page.has_more);
        assert_eq!(next_page.items.len(), 2);
        assert!(next_page.items.iter().all(|row| row.auth_info.is_none()
            && row.content.body_text.is_none()
            && row.content.attachments[0].content_base64.is_none()));
        let empty = project_session_page(Vec::new(), 0, &params, &HashSet::new(), None);
        assert!(!empty.has_more);
        assert!(empty.items.is_empty());
    }

    #[test]
    fn default_session_projection_masks_identity_and_removes_message_content() {
        let projected = project_session_content(populated_session(), &HashSet::new());

        assert_eq!(projected.mail_from.as_deref(), Some("a****@corp.example"));
        assert_eq!(projected.rcpt_to, vec!["r****@corp.example"]);
        assert_eq!(projected.subject.as_deref(), Some("C******t"));
        assert!(projected.message_id.is_none());
        assert!(projected.auth_info.is_none());
        assert!(projected.content.headers.is_empty());
        assert!(projected.content.body_text.is_none());
        assert!(projected.content.body_html.is_none());
        assert!(projected.content.links.is_empty());
        assert!(projected.content.smtp_dialog.is_empty());
        assert_eq!(projected.content.attachments.len(), 1);
        assert!(projected.content.attachments[0].content_base64.is_none());
        assert!(projected.content.is_complete);
        assert!(projected.content.is_encrypted);
        assert!(projected.content.truncated);
        assert_eq!(projected.content.dropped_attachments, 2);
        assert!(projected.content.links_truncated);
    }

    #[test]
    fn body_scope_reveals_plaintext_and_links_only() {
        let projected = project_session_content(populated_session(), &scopes(&["body"]));

        assert_eq!(
            projected.content.body_text.as_deref(),
            Some("confidential plain body")
        );
        assert!(projected.content.body_html.is_none());
        assert!(projected.content.headers.is_empty());
        assert_eq!(projected.content.links.len(), 1);
        assert!(projected.content.smtp_dialog.is_empty());
        assert_eq!(projected.mail_from.as_deref(), Some("a****@corp.example"));
        assert_eq!(projected.subject.as_deref(), Some("C******t"));
    }

    #[test]
    fn html_scope_reveals_html_and_links_without_plaintext() {
        let projected = project_session_content(populated_session(), &scopes(&["html"]));

        assert!(projected.content.body_text.is_none());
        assert_eq!(
            projected.content.body_html.as_deref(),
            Some("<p>confidential html body</p>")
        );
        assert!(projected.content.headers.is_empty());
        assert_eq!(projected.content.links.len(), 1);
        assert!(projected.content.smtp_dialog.is_empty());
    }

    #[test]
    fn headers_scope_reveals_message_metadata_and_smtp_dialog_only() {
        let projected = project_session_content(populated_session(), &scopes(&["headers"]));

        assert_eq!(projected.mail_from.as_deref(), Some("analyst@corp.example"));
        assert_eq!(projected.rcpt_to, vec!["reviewer@corp.example"]);
        assert_eq!(projected.subject.as_deref(), Some("Confidential subject"));
        assert_eq!(
            projected.message_id.as_deref(),
            Some("<secret-message-id@example.com>")
        );
        let auth_info = projected
            .auth_info
            .as_ref()
            .expect("headers reveal auth info");
        assert_eq!(auth_info.auth_method, "PLAIN");
        assert_eq!(auth_info.username.as_deref(), Some("confidential-user"));
        assert_eq!(auth_info.password.as_deref(), Some("confidential-password"));
        assert_eq!(projected.content.headers.len(), 1);
        assert_eq!(projected.content.smtp_dialog.len(), 1);
        assert!(projected.content.body_text.is_none());
        assert!(projected.content.body_html.is_none());
        assert!(projected.content.links.is_empty());
    }

    #[test]
    fn complete_message_scopes_restore_views_but_never_attachment_bytes() {
        let projected =
            project_session_content(populated_session(), &scopes(&["body", "html", "headers"]));

        assert_eq!(projected.mail_from.as_deref(), Some("analyst@corp.example"));
        assert_eq!(
            projected.content.body_text.as_deref(),
            Some("confidential plain body")
        );
        assert_eq!(
            projected.content.body_html.as_deref(),
            Some("<p>confidential html body</p>")
        );
        assert_eq!(projected.content.headers.len(), 1);
        assert_eq!(projected.content.links.len(), 1);
        assert_eq!(projected.content.smtp_dialog.len(), 1);
        assert!(projected.content.attachments[0].content_base64.is_none());
    }

    #[test]
    fn detail_payload_marks_redacted_and_revealed_states_without_message_leakage() {
        let redacted = project_session_content_payload(populated_session(), &HashSet::new());
        assert_eq!(redacted["privacy"]["state"], "redacted");
        assert!(redacted["content"]["body_text"].is_null());

        let revealed = project_session_content_payload(populated_session(), &scopes(&["body"]));
        assert_eq!(revealed["privacy"]["state"], "revealed");
        assert_eq!(revealed["content"]["body_text"], "confidential plain body");
    }

    #[test]
    fn related_session_redaction_drops_message_payload() {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            25000,
            "10.0.0.2".to_string(),
            25,
        );
        session.mail_from = Some("analyst@corp.example".to_string());
        session.rcpt_to = vec!["reviewer@corp.example".to_string()];
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

        assert_eq!(redacted.mail_from.as_deref(), Some("a****@corp.example"));
        assert_eq!(redacted.rcpt_to, vec!["r****@corp.example"]);
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

        let redacted = project_session_content(session, &HashSet::new());

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
