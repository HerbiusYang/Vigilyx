//! API

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{Duration, Instant};
use tracing::warn;
use uuid::Uuid;
use vigilyx_core::security::ThreatLevel;
use vigilyx_db::mq::{RescanSessionReference, streams};
use vigilyx_db::security::quarantine::QuarantineEntry;
use vigilyx_mta::config::MtaConfig;
use vigilyx_mta::relay::downstream::{DownstreamRelay, RelayResult};
use vigilyx_parser::MimeParser;

use super::super::{ApiResponse, clamp_i64_pagination};
use crate::AppState;
use crate::auth::AuthenticatedUser;

#[derive(Debug, Deserialize)]
pub struct QuarantineListQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ReleaseRequest {
    /// Ignored - operator is extracted from JWT. Kept for backward API compatibility.
    #[serde(default)]
    pub _released_by: Option<String>,
}

const QUARANTINE_PREVIEW_MAX_CHARS: usize = 12_000;

#[derive(Debug, Serialize)]
struct QuarantineAttachmentPreview {
    filename: String,
    content_type: String,
    size: usize,
    hash: String,
}

#[derive(Debug, Serialize)]
struct QuarantinePreview {
    entry: QuarantineEntry,
    body_text: Option<String>,
    /// Returned as source text only. The frontend must never inject it as HTML.
    body_html_source: Option<String>,
    attachments: Vec<QuarantineAttachmentPreview>,
    parse_warning: Option<String>,
}

fn truncate_preview(value: &str) -> String {
    let mut chars = value.chars();
    let preview: String = chars.by_ref().take(QUARANTINE_PREVIEW_MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{preview}\n…")
    } else {
        preview
    }
}

fn release_requires_outbound_relay(entry: &QuarantineEntry) -> bool {
    // Current quarantine records do not persist direction. Outbound DLP entries are the
    // only ones that should bypass the inbound downstream relay, and they are tagged
    // with the canonical DLP reason prefix when stored by the MTA.
    entry
        .reason
        .as_deref()
        .is_some_and(|reason| reason.starts_with("DLP:"))
}

async fn load_release_relays() -> Result<(DownstreamRelay, Option<DownstreamRelay>), String> {
    let mut config =
        MtaConfig::from_env().map_err(|e| format!("Failed to load MTA release config: {e}"))?;
    let db_url = config.database_url.clone();
    if !db_url.is_empty()
        && let Err(error) = config.override_from_db(&db_url).await
    {
        warn!(error = %error, "Failed to load MTA DB overrides for quarantine release; falling back to env defaults");
    }

    let downstream = DownstreamRelay::new(&config.downstream)
        .await
        .map_err(|e| format!("Failed to initialize downstream relay: {e}"))?;
    let outbound = match config.outbound.as_ref() {
        Some(outbound_cfg) => Some(
            DownstreamRelay::new(outbound_cfg)
                .await
                .map_err(|e| format!("Failed to initialize outbound relay: {e}"))?,
        ),
        None => None,
    };

    Ok((downstream, outbound))
}

async fn relay_quarantine_release(
    entry: &QuarantineEntry,
    raw_eml: &[u8],
) -> Result<RelayResult, String> {
    let (downstream, outbound) = load_release_relays().await?;
    let relay = if release_requires_outbound_relay(entry) {
        outbound.as_ref().unwrap_or(&downstream)
    } else {
        &downstream
    };

    Ok(relay
        .relay_from(
            entry.mail_from.as_deref(),
            &entry.rcpt_to,
            raw_eml,
            entry.client_ip.as_deref(),
        )
        .await)
}

/// Default maximum time to wait for the pre-release rescan verdict before
/// failing closed. The full pipeline can spend ~8s on NLP alone, so this must
/// stay decoupled from the MTA inline budget. Override with
/// `RELEASE_RESCAN_TIMEOUT_SECS`.
const DEFAULT_RELEASE_RESCAN_TIMEOUT_SECS: u64 = 30;
/// Poll interval while waiting for the rescan verdict to be persisted.
const RELEASE_RESCAN_POLL_INTERVAL: Duration = Duration::from_millis(200);

fn parse_release_rescan_timeout(raw: Option<&str>) -> Duration {
    raw.and_then(|value| value.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(DEFAULT_RELEASE_RESCAN_TIMEOUT_SECS))
}

fn release_rescan_timeout() -> Duration {
    parse_release_rescan_timeout(std::env::var("RELEASE_RESCAN_TIMEOUT_SECS").ok().as_deref())
}

/// Outcome of the mandatory pre-release rescan of the stored raw message.
enum ReleaseScanOutcome {
    /// Rescan verdict is below High; carries the rescan verdict id for audit.
    Clear(String),
    /// Rescan verdict is High or above; the release must be blocked.
    Blocked(String),
}

/// Decide whether a rescan verdict allows the release to proceed.
fn release_scan_decision(verdict_id: Uuid, threat_level: ThreatLevel) -> ReleaseScanOutcome {
    if threat_level >= ThreatLevel::High {
        ReleaseScanOutcome::Blocked(format!("{threat_level} (verdict {verdict_id})"))
    } else {
        ReleaseScanOutcome::Clear(verdict_id.to_string())
    }
}

/// Re-run the engine on the exact stored message before any delivery.
///
/// Without this gate the quarantined raw_eml would reach the recipient inbox
/// with zero fresh analysis: an attacker only needs to social-engineer an
/// analyst into clicking "release". The rescan goes through the same Redis
/// rescan channel as the admin rescan API, but carries the quarantine id so
/// the engine re-parses the stored raw_eml — the exact bytes the relay would
/// deliver — instead of the persisted session row, which parser degradation
/// paths (attachment caps, size truncation) may have stripped, plus the
/// entry's client IP so IP-reputation signals survive the rescan (A5). The
/// handler then polls the verdict table until the new verdict lands.
///
/// Fail-closed: any channel/engine error, parse failure or timeout returns
/// `Err` and the caller must refuse the release.
async fn rescan_before_release(
    state: &AppState,
    entry: &QuarantineEntry,
) -> Result<ReleaseScanOutcome, String> {
    let session_id = Uuid::parse_str(&entry.session_id)
        .map_err(|_| "Quarantine entry has an invalid session id".to_string())?;

    let Some(mq) = state.messaging.mq.as_ref() else {
        return Err("Engine rescan channel is unavailable (Redis not connected)".to_string());
    };

    let previous_verdict_id = state
        .db
        .get_verdict_by_session(session_id)
        .await
        .map_err(|e| format!("Failed to load existing verdict before release rescan: {e}"))?
        .map(|verdict| verdict.id);

    mq.xadd(
        streams::RESCAN_REQUESTS,
        &RescanSessionReference::for_quarantine(
            session_id,
            entry.id.clone(),
            // A5: carry the real client IP so the rescan verdict keeps
            // IP-reputation signals and cannot degrade below the release gate.
            entry.client_ip.clone(),
        ),
    )
    .await
    .map_err(|e| format!("Failed to submit release rescan to engine: {e}"))?;

    // Note: if the asynchronous full-pipeline verdict of the original inline
    // analysis lands after this snapshot but before the rescan verdict, it may
    // be observed here first. That is safe: it analyzed the exact same stored
    // content, so the release decision is still based on a fresh engine verdict.
    let timeout = release_rescan_timeout();
    let deadline = Instant::now() + timeout;
    loop {
        let verdict = state
            .db
            .get_verdict_by_session(session_id)
            .await
            .map_err(|e| format!("Failed to poll release rescan verdict: {e}"))?;
        if let Some(verdict) = verdict
            && Some(verdict.id) != previous_verdict_id
        {
            return Ok(release_scan_decision(verdict.id, verdict.threat_level));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Engine rescan did not produce a verdict within {}s",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(RELEASE_RESCAN_POLL_INTERVAL).await;
    }
}

fn release_conflict_response(status: Option<&str>) -> Response {
    match status {
        None => ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
            .into_response(),
        Some("released") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err("Quarantine entry was already released"),
        )
            .into_response(),
        Some("releasing") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Quarantine entry is already being released by another request",
            ),
        )
            .into_response(),
        Some("release_blocked") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Release of this entry was blocked because the rescan verdict is High or above",
            ),
        )
            .into_response(),
        Some(_) => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Quarantine entry cannot be released from its current state",
            ),
        )
            .into_response(),
    }
}

async fn rollback_failed_release(state: &AppState, id: &str) -> Result<(), Response> {
    match state.db.quarantine_release_reset(id).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            let rollback_error =
                format!("Release rollback lost ownership for quarantine entry {id}");
            Err(ApiResponse::<serde_json::Value>::server_error(
                &rollback_error,
                "Failed to restore quarantine state after release relay failure",
            )
            .into_response())
        }
        Err(e) => Err(ApiResponse::<serde_json::Value>::server_error(
            &e,
            "Failed to restore quarantine state after release relay failure",
        )
        .into_response()),
    }
}

/// GET /security/quarantine
pub async fn list_quarantine(
    State(state): State<Arc<AppState>>,
    Query(params): Query<QuarantineListQuery>,
) -> impl IntoResponse {
    let (limit, offset) = clamp_i64_pagination(params.limit, params.offset, 50, 200);

    match state
        .db
        .quarantine_list(params.status.as_deref(), limit, offset)
        .await
    {
        Ok(entries) => ApiResponse::ok(serde_json::json!({
            "items": entries,
            "limit": limit,
            "offset": offset,
        }))
        .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::internal_err(&e, "Failed to list quarantine")
            .into_response(),
    }
}

/// GET /security/quarantine/stats
pub async fn quarantine_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let quarantined = state
        .db
        .quarantine_count(Some("quarantined"))
        .await
        .unwrap_or(0);
    let releasing = state
        .db
        .quarantine_count(Some("releasing"))
        .await
        .unwrap_or(0);
    let released = state
        .db
        .quarantine_count(Some("released"))
        .await
        .unwrap_or(0);
    let total = state.db.quarantine_count(None).await.unwrap_or(0);

    ApiResponse::ok(serde_json::json!({
        "quarantined": quarantined,
        "releasing": releasing,
        "released": released,
        "total": total,
    }))
}

/// GET /security/quarantine/:id/preview
///
/// Returns a bounded, non-executable preview for an administrator reviewing a
/// quarantined message. Attachment payloads are deliberately omitted.
pub async fn preview_quarantine(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    let (raw_eml, entry) = match state.db.quarantine_get_raw_eml(&id).await {
        Ok(Some(value)) => value,
        Ok(None) => {
            return ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
                .into_response();
        }
        Err(error) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &error,
                "Failed to load quarantine preview",
            )
            .into_response();
        }
    };

    let preview = match MimeParser::new().parse(&raw_eml) {
        Ok(content) => QuarantinePreview {
            entry,
            body_text: content.body_text.as_deref().map(truncate_preview),
            body_html_source: content.body_html.as_deref().map(truncate_preview),
            attachments: content
                .attachments
                .into_iter()
                .map(|attachment| QuarantineAttachmentPreview {
                    filename: attachment.filename,
                    content_type: attachment.content_type,
                    size: attachment.size,
                    hash: attachment.hash,
                })
                .collect(),
            parse_warning: None,
        },
        Err(_) => QuarantinePreview {
            entry,
            body_text: None,
            body_html_source: None,
            attachments: Vec::new(),
            parse_warning: Some(
                "The message could not be parsed safely; download is not exposed from preview"
                    .to_string(),
            ),
        },
    };

    ApiResponse::ok(preview).into_response()
}

/// POST /security/quarantine/:id/release
pub async fn release_quarantine(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    Json(_body): Json<ReleaseRequest>,
) -> impl IntoResponse {
    // SEC: Use authenticated username from JWT, never trust client-supplied released_by
    let released_by = user.username.clone();

    let (raw_eml, entry) = match state.db.quarantine_claim_release(&id).await {
        Ok(Some(entry)) => entry,
        Ok(None) => {
            let status = match state.db.quarantine_status(&id).await {
                Ok(status) => status,
                Err(e) => {
                    return ApiResponse::<serde_json::Value>::server_error(
                        &e,
                        "Failed to load quarantine release status",
                    )
                    .into_response();
                }
            };
            return release_conflict_response(status.as_deref());
        }
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(
                &e,
                "Failed to claim quarantine entry for release",
            )
            .into_response();
        }
    };

    // SEC: the stored raw message must pass a fresh engine verdict before it
    // is allowed anywhere near a recipient inbox — the release click is the
    // last enforcement point against social-engineered analysts. Fail-closed:
    // any engine/channel error or timeout returns the entry to `quarantined`
    // and refuses the release with 503.
    let rescan_verdict_id = match rescan_before_release(state.as_ref(), &entry).await {
        Ok(ReleaseScanOutcome::Clear(verdict_id)) => verdict_id,
        Ok(ReleaseScanOutcome::Blocked(reason)) => {
            match state.db.quarantine_mark_release_blocked(&id).await {
                Ok(true) => {}
                Ok(false) => {
                    return ApiResponse::<serde_json::Value>::server_error(
                        &"Release rollback lost ownership for quarantine entry",
                        "Failed to mark quarantine entry as release-blocked",
                    )
                    .into_response();
                }
                Err(e) => {
                    return ApiResponse::<serde_json::Value>::server_error(
                        &e,
                        "Failed to mark quarantine entry as release-blocked",
                    )
                    .into_response();
                }
            }
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                released_by.clone(),
                "release_quarantine_blocked",
                Some("security"),
                Some(id.clone()),
                Some(reason.clone()),
            );
            return (
                StatusCode::CONFLICT,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Release blocked: rescan verdict is {reason}"
                )),
            )
                .into_response();
        }
        Err(msg) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Release requires a fresh engine verdict, which is unavailable: {msg}"
                )),
            )
                .into_response();
        }
    };

    match relay_quarantine_release(&entry, &raw_eml).await {
        Ok(RelayResult::Accepted) => {}
        Ok(RelayResult::TempFail(msg)) | Ok(RelayResult::ConnError(msg)) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Failed to forward released message: {msg}"
                )),
            )
                .into_response();
        }
        Ok(RelayResult::PermFail(msg)) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::BAD_GATEWAY,
                ApiResponse::<serde_json::Value>::err(format!(
                    "Downstream relay rejected released message: {msg}"
                )),
            )
                .into_response();
        }
        Err(msg) => {
            if let Err(response) = rollback_failed_release(state.as_ref(), &id).await {
                return response;
            }
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiResponse::<serde_json::Value>::err(msg),
            )
                .into_response();
        }
    }

    match state.db.quarantine_finalize_release(&id, &released_by).await {
        Ok(true) => {
            // Best-effort: keep the entry's verdict reference pointing at the
            // rescan verdict that authorized this release (the rescan replaced
            // the session's verdict row, so the old id would dangle).
            if let Err(e) = state
                .db
                .quarantine_record_release_rescan(&id, &rescan_verdict_id)
                .await
            {
                warn!(error = %e, quarantine_id = %id, "Failed to record release rescan verdict id");
            }
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                released_by.clone(),
                "release_quarantine",
                Some("security"),
                Some(id.clone()),
                Some(format!("rescan_verdict_id={rescan_verdict_id}")),
            );
            (
                StatusCode::OK,
                ApiResponse::ok(serde_json::json!({
                    "id": id,
                    "status": "released",
                    "released_by": released_by,
                    "rescan_verdict_id": rescan_verdict_id,
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Message was forwarded, but release finalization failed; entry remains locked to prevent duplicate delivery",
            ),
        )
            .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::server_error(
            &e,
            "Released message was forwarded but database finalization failed; entry remains in releasing state",
        )
        .into_response(),
    }
}

/// DELETE /security/quarantine/:id
pub async fn delete_quarantine(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.quarantine_delete(&id).await {
        Ok(true) => {
            crate::handlers::spawn_audit_log(
                state.engine_db.clone(),
                user.username,
                "delete_quarantine",
                Some("security"),
                Some(id.clone()),
                None,
            );
            (
                StatusCode::OK,
                ApiResponse::ok(serde_json::json!({"id": id, "deleted": true})),
            )
                .into_response()
        }
        Ok(false) => ApiResponse::<serde_json::Value>::not_found("Quarantine entry not found")
            .into_response(),
        Err(e) if e.to_string().contains("currently being released") => (
            StatusCode::CONFLICT,
            ApiResponse::<serde_json::Value>::err(
                "Entry is currently being released and cannot be deleted",
            ),
        )
            .into_response(),
        Err(e) => ApiResponse::<serde_json::Value>::server_error(&e, "Failed to delete quarantine")
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_truncation_preserves_unicode_boundaries_and_marks_truncation() {
        let input = "测".repeat(QUARANTINE_PREVIEW_MAX_CHARS + 2);
        let preview = truncate_preview(&input);

        assert_eq!(
            preview
                .chars()
                .filter(|character| *character == '测')
                .count(),
            QUARANTINE_PREVIEW_MAX_CHARS
        );
        assert!(preview.ends_with('…'));
    }

    #[test]
    fn preview_truncation_does_not_modify_short_content() {
        assert_eq!(truncate_preview("short body"), "short body");
    }

    #[test]
    fn release_scan_decision_blocks_high_and_critical_verdicts() {
        // PoC: before the gate the release path relayed the stored raw_eml
        // with no verdict at all; now a High/Critical rescan verdict must
        // block the release instead of delivering the message.
        let verdict_id = Uuid::new_v4();
        for level in [ThreatLevel::High, ThreatLevel::Critical] {
            match release_scan_decision(verdict_id, level) {
                ReleaseScanOutcome::Blocked(reason) => {
                    assert!(reason.contains(&level.to_string()));
                    assert!(reason.contains(&verdict_id.to_string()));
                }
                ReleaseScanOutcome::Clear(_) => panic!("{level} verdict must block release"),
            }
        }
    }

    #[test]
    fn release_scan_decision_allows_clean_verdicts() {
        // Clean/low/medium rescan verdicts must release normally and carry
        // the rescan verdict id for the audit trail.
        let verdict_id = Uuid::new_v4();
        for level in [ThreatLevel::Safe, ThreatLevel::Low, ThreatLevel::Medium] {
            match release_scan_decision(verdict_id, level) {
                ReleaseScanOutcome::Clear(recorded) => {
                    assert_eq!(recorded, verdict_id.to_string());
                }
                ReleaseScanOutcome::Blocked(_) => panic!("{level} verdict must not block release"),
            }
        }
    }

    #[test]
    fn release_conflict_response_explains_release_blocked() {
        // A second release attempt on a blocked entry must explain why.
        let response = release_conflict_response(Some("release_blocked"));
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn release_rescan_timeout_defaults_to_30s() {
        // PoC for the systematic 503: an 8s ceiling could never fit the full
        // pipeline (NLP alone has an ~8s budget), so every release with a
        // healthy engine failed closed on timeout. The default must cover it.
        let timeout = parse_release_rescan_timeout(None);
        assert_eq!(timeout, Duration::from_secs(30));
        assert!(timeout > Duration::from_secs(8));
    }

    #[test]
    fn release_rescan_timeout_accepts_env_override_and_rejects_garbage() {
        assert_eq!(
            parse_release_rescan_timeout(Some("45")),
            Duration::from_secs(45)
        );
        // Invalid, zero and negative values must fall back to the default,
        // never disable the fail-closed gate.
        for garbage in ["abc", "0", "-5", "", "8.5"] {
            assert_eq!(
                parse_release_rescan_timeout(Some(garbage)),
                Duration::from_secs(30),
                "invalid override {garbage:?} must fall back to the default"
            );
        }
    }
}
