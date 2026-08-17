//! Rescan (re-analysis) handlers.

use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};
use std::sync::Arc;
use uuid::Uuid;

use vigilyx_db::mq::{RescanSessionReference, StreamClient, streams};

use super::super::ApiResponse;
use crate::AppState;
use crate::auth::AuthenticatedUser;

const RESCAN_BATCH_SIZE: usize = 200;

#[derive(sqlx::FromRow)]
struct SessionIdRow {
    id: String,
}

// Batch rescan

/// Trigger batch rescan
pub async fn trigger_rescan(
    State(state): State<Arc<AppState>>,
    user: AuthenticatedUser,
    Json(req): Json<vigilyx_engine::rescan::RescanRequest>,
) -> axum::response::Response {
    if let Err(message) = validate_rescan_request(&req) {
        return ApiResponse::<serde_json::Value>::bad_request(message).into_response();
    }
    // Freeze an unbounded request at acceptance time. Without this cutoff,
    // live SMTP inserts can move the OFFSET window and make an "all" task
    // chase newly arriving sessions indefinitely.
    let req = snapshot_rescan_request(req);

    if !rescan_channel_available(&state) {
        return ApiResponse::<serde_json::Value>::server_error(
            &"Redis 通道不可用",
            "无法连接分析引擎",
        )
        .into_response();
    }

    let total_sessions = match count_rescan_candidates(&state, &req).await {
        Ok(total) => total,
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    };

    let task_id = Uuid::new_v4();
    let detail = format!(
        "task_id={}, total_sessions={}, since={}, until={}, session_ids={}",
        task_id,
        total_sessions,
        req.since.as_deref().unwrap_or("n/a"),
        req.until.as_deref().unwrap_or("n/a"),
        req.session_ids.as_ref().map(|ids| ids.len()).unwrap_or(0)
    );

    let audit_db = state.engine_db.clone();
    let username = user.username.clone();
    tokio::spawn(async move {
        let task_id_str = task_id.to_string();
        if let Err(e) = audit_db
            .write_audit_log(
                &username,
                "trigger_rescan",
                Some("security"),
                Some(&task_id_str),
                Some(&detail),
                None,
            )
            .await
        {
            tracing::error!(error = %e, task_id = %task_id, "审计: 回溯扫描审计日志写入失败");
        }
    });

    if total_sessions == 0 {
        return ApiResponse::ok(serde_json::json!({
            "status": "accepted",
            "task_id": task_id.to_string(),
            "total_sessions": 0,
            "message": "No matching sessions found for re-analysis"
        }))
        .into_response();
    }

    let state_clone = Arc::clone(&state);
    let req_clone = req.clone();
    tokio::spawn(async move {
        run_rescan_task(state_clone, req_clone, task_id).await;
    });

    ApiResponse::ok(serde_json::json!({
        "status": "accepted",
        "task_id": task_id.to_string(),
        "total_sessions": total_sessions,
        "message": "Rescan task queued"
    }))
    .into_response()
}

/// Rescan a single session (submit to engine via Redis)
pub async fn rescan_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let session_id = match Uuid::parse_str(&id) {
        Ok(id) => id,
        Err(_) => {
            return ApiResponse::<serde_json::Value>::bad_request("Invalid session ID")
                .into_response();
        }
    };

    // Load session from database
    let session = match state.db.get_session(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return ApiResponse::<serde_json::Value>::not_found("Session not found")
                .into_response();
        }
        Err(e) => {
            return ApiResponse::<serde_json::Value>::server_error(&e, "Operation failed")
                .into_response();
        }
    };

    match submit_rescan_session(&state, session.id).await {
        Ok(path) => ApiResponse::ok(serde_json::json!({
            "status": "accepted",
            "session_id": session_id.to_string(),
            "message": format!("Session submitted for re-analysis via {path}")
        }))
        .into_response(),
        Err(e) => {
            ApiResponse::<serde_json::Value>::server_error(&e, "无法连接分析引擎").into_response()
        }
    }
}

async fn run_rescan_task(
    state: Arc<AppState>,
    req: vigilyx_engine::rescan::RescanRequest,
    task_id: Uuid,
) {
    let total_sessions = match count_rescan_candidates(&state, &req).await {
        Ok(total) => total,
        Err(e) => {
            tracing::error!(task_id = %task_id, "回溯扫描统计failed: {}", e);
            return;
        }
    };

    let mut submitted = 0u64;
    let mut failed = 0u64;
    let mut offset = 0usize;

    tracing::info!(
        task_id = %task_id,
        total_sessions,
        "开始执行回溯扫描任务"
    );

    loop {
        let ids = match fetch_rescan_candidate_ids(&state, &req, RESCAN_BATCH_SIZE, offset).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::error!(task_id = %task_id, offset, "回溯扫描读取批次failed: {}", e);
                break;
            }
        };
        if ids.is_empty() {
            break;
        }

        let batch_size = ids.len();
        match submit_rescan_batch(&state, &ids).await {
            Ok(count) => submitted += count as u64,
            Err(e) => {
                failed += batch_size as u64;
                tracing::warn!(
                    task_id = %task_id,
                    offset,
                    batch_size,
                    "回溯扫描批量提交failed: {}",
                    e
                );
            }
        }

        offset += batch_size;
    }

    tracing::info!(
        task_id = %task_id,
        total_sessions,
        submitted,
        failed,
        "回溯扫描任务结束"
    );
}

fn validate_rescan_request(req: &vigilyx_engine::rescan::RescanRequest) -> Result<(), String> {
    let since = req.since.as_deref().map(parse_rfc3339).transpose()?;
    let until = req.until.as_deref().map(parse_rfc3339).transpose()?;

    if let (Some(since), Some(until)) = (since, until)
        && since > until
    {
        return Err("since must be earlier than or equal to until".to_string());
    }

    if let Some(session_ids) = req.session_ids.as_ref() {
        for session_id in session_ids {
            Uuid::parse_str(session_id)
                .map_err(|_| format!("Invalid session ID in session_ids: {session_id}"))?;
        }
    }

    Ok(())
}

fn snapshot_rescan_request(
    mut req: vigilyx_engine::rescan::RescanRequest,
) -> vigilyx_engine::rescan::RescanRequest {
    if req.until.is_none() {
        req.until = Some(chrono::Utc::now().to_rfc3339());
    }
    req
}

fn parse_rfc3339(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| format!("Invalid RFC3339 timestamp: {value}"))
}

fn rescan_channel_available(state: &AppState) -> bool {
    state.messaging.mq.is_some()
}

async fn submit_rescan_session(state: &AppState, session_id: Uuid) -> Result<&'static str, String> {
    if let Some(ref mq) = state.messaging.mq {
        let reference = RescanSessionReference::new(session_id);
        match mq.xadd(streams::RESCAN_REQUESTS, &reference).await {
            Ok(_) => return Ok("Redis Stream"),
            Err(e) => {
                tracing::warn!(session_id = %session_id, "Redis Stream rescan failed: {}", e);
            }
        }
    }

    Err("Redis Stream not available for rescan".to_string())
}

async fn submit_rescan_batch(state: &AppState, session_ids: &[Uuid]) -> Result<usize, String> {
    if session_ids.is_empty() {
        return Ok(0);
    }
    let Some(mq) = state.messaging.mq.as_ref() else {
        return Err("Redis Stream not available for rescan".to_string());
    };
    let references = session_ids
        .iter()
        .copied()
        .map(RescanSessionReference::new)
        .collect::<Vec<_>>();
    let producer = StreamClient::new(mq.clone(), "vigilyx-api-rescan", "producer");
    producer
        .xadd_batch(streams::RESCAN_REQUESTS, &references)
        .await
        .map_err(|error| format!("Redis Stream rescan batch failed: {error}"))
}

async fn count_rescan_candidates(
    state: &AppState,
    req: &vigilyx_engine::rescan::RescanRequest,
) -> anyhow::Result<u64> {
    let (sql, params) = build_rescan_candidate_sql(req, RescanQueryMode::Count, None, None);
    let mut query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(sql.as_str()));
    for param in &params {
        query = query.bind(param);
    }
    let (count,) = query.fetch_one(state.db.pool()).await?;
    Ok(count.max(0) as u64)
}

async fn fetch_rescan_candidate_ids(
    state: &AppState,
    req: &vigilyx_engine::rescan::RescanRequest,
    limit: usize,
    offset: usize,
) -> anyhow::Result<Vec<Uuid>> {
    let (sql, params) =
        build_rescan_candidate_sql(req, RescanQueryMode::Ids, Some(limit), Some(offset));
    let mut query = sqlx::query_as::<_, SessionIdRow>(sqlx::AssertSqlSafe(sql.as_str()));
    for param in &params {
        query = query.bind(param);
    }

    let rows = query.fetch_all(state.db.pool()).await?;
    Ok(rows
        .into_iter()
        .filter_map(|row| Uuid::parse_str(&row.id).ok())
        .collect())
}

#[derive(Clone, Copy)]
enum RescanQueryMode {
    Count,
    Ids,
}

fn build_rescan_candidate_sql(
    req: &vigilyx_engine::rescan::RescanRequest,
    mode: RescanQueryMode,
    limit: Option<usize>,
    offset: Option<usize>,
) -> (String, Vec<String>) {
    let mut params = Vec::new();
    let mut conditions = vec![
        "status = 'Completed'".to_string(),
        "(COALESCE(jsonb_array_length(content->'headers'), 0) > 0 \
          OR content->>'body_text' IS NOT NULL \
          OR content->>'body_html' IS NOT NULL \
          OR COALESCE(jsonb_array_length(content->'attachments'), 0) > 0 \
          OR COALESCE(jsonb_array_length(content->'links'), 0) > 0 \
          OR COALESCE(error_reason, '') LIKE 'inspection:%')"
            .to_string(),
    ];
    let mut next_idx = 1usize;

    if let Some(since) = req.since.as_ref() {
        conditions.push(format!("started_at >= ${next_idx}"));
        params.push(since.clone());
        next_idx += 1;
    }

    if let Some(until) = req.until.as_ref() {
        conditions.push(format!("started_at <= ${next_idx}"));
        params.push(until.clone());
        next_idx += 1;
    }

    if let Some(session_ids) = req.session_ids.as_ref()
        && !session_ids.is_empty()
    {
        let placeholders = (next_idx..next_idx + session_ids.len())
            .map(|idx| format!("${idx}"))
            .collect::<Vec<_>>()
            .join(",");
        conditions.push(format!("id IN ({placeholders})"));
        params.extend(session_ids.iter().cloned());
    }

    let mut sql = match mode {
        RescanQueryMode::Count => "SELECT COUNT(*) FROM sessions".to_string(),
        RescanQueryMode::Ids => "SELECT id FROM sessions".to_string(),
    };

    if !conditions.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&conditions.join(" AND "));
    }

    if matches!(mode, RescanQueryMode::Ids) {
        sql.push_str(" ORDER BY started_at ASC");
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        if let Some(offset) = offset {
            sql.push_str(&format!(" OFFSET {offset}"));
        }
    }

    (sql, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rescan_reference_does_not_duplicate_email_content() {
        let reference = RescanSessionReference::new(Uuid::new_v4());
        let encoded = serde_json::to_vec(&reference).unwrap();
        assert!(encoded.len() < 80);
        assert!(!String::from_utf8_lossy(&encoded).contains("body"));
    }

    #[test]
    fn unbounded_rescan_is_frozen_to_an_acceptance_snapshot() {
        let req = vigilyx_engine::rescan::RescanRequest {
            since: None,
            until: None,
            session_ids: None,
        };

        let snapshot = snapshot_rescan_request(req);

        let until = snapshot.until.expect("snapshot cutoff must be populated");
        assert!(chrono::DateTime::parse_from_rfc3339(&until).is_ok());
    }

    #[test]
    fn rescan_query_matches_email_session_analyzable_content_contract() {
        let req = vigilyx_engine::rescan::RescanRequest {
            since: None,
            until: None,
            session_ids: None,
        };

        let (sql, _) = build_rescan_candidate_sql(&req, RescanQueryMode::Count, None, None);

        assert!(!sql.contains("mail_from"));
        assert!(sql.contains("content->'headers'"));
        assert!(sql.contains("content->'attachments'"));
        assert!(sql.contains("content->'links'"));
        assert!(sql.contains("error_reason, '') LIKE 'inspection:%'"));
    }
}
