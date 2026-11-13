//! Session CRUD operations

use anyhow::Result;
use sqlx::FromRow;
use uuid::Uuid;
use vigilyx_core::{
    EmailAttachment, EmailContent, EmailSession, Protocol, SessionSource, SessionStatus,
};

use crate::VigilDb;
use crate::security::threat_scene::{BounceMetadata, extract_bounce_metadata};

const SESSION_WITH_CONTENT_PREDICATE_TEMPLATE: &str = "(({prefix}content->>'is_encrypted') IS DISTINCT FROM 'true' \
      AND (({prefix}content->>'body_text') IS NOT NULL \
       OR ({prefix}content->>'body_html') IS NOT NULL \
       OR COALESCE(jsonb_array_length({prefix}content->'attachments'), 0) > 0 \
       OR COALESCE(jsonb_array_length({prefix}content->'headers'), 0) > 0 \
       OR COALESCE(jsonb_array_length({prefix}content->'links'), 0) > 0))";

pub(crate) fn session_with_content_predicate(prefix: &str) -> String {
    SESSION_WITH_CONTENT_PREDICATE_TEMPLATE.replace("{prefix}", prefix)
}

/// Trust predicate for first-contact history lookups (E2).
///
/// A session only counts as sender history when it was actually analyzed AND
/// came back below High:
/// - no verdict row → the "clean greeting" may never have been scanned (or
///   the scan failed) — counting it let a single warm-up mail permanently
///   disarm `first_contact` (-0.10) / `new_sender_on_known_domain` (-0.07)
///   and the `envelope_mismatch + random_domain + first_contact` composite
///   (+0.25) for every later attack from that domain;
/// - verdict high/critical → obviously not trust-building history.
///
/// References the `s` alias; callers must alias `sessions` accordingly.
const TRUSTED_HISTORY_VERDICT_PREDICATE: &str = "EXISTS(SELECT 1 FROM security_verdicts v \
     WHERE v.session_id = s.id AND lower(v.threat_level) NOT IN ('high', 'critical'))";

/// Shared EXISTS query for sender-history lookups: `$1` is the sender match
/// value, `$2` is the session id to exclude (the session being analyzed).
fn sender_history_exists_sql(match_predicate: &str) -> String {
    format!(
        "SELECT CASE WHEN EXISTS( \
            SELECT 1 FROM sessions s \
            WHERE {match_predicate} AND s.status = 'Completed' AND s.id != $2 \
              AND {TRUSTED_HISTORY_VERDICT_PREDICATE} \
            LIMIT 1 \
         ) THEN 1::BIGINT ELSE 0::BIGINT END"
    )
}

/// Experimental normal-evidence history query.
///
/// This is deliberately stricter than the legacy first-contact lookup:
/// imported mail is excluded, only prior sessions are eligible, only the
/// latest Safe/Low verdict counts, and recipient relationship support is
/// measured separately from mailbox history.
const SENDER_RELATIONSHIP_HISTORY_SQL: &str = r#"
    WITH eligible AS (
        SELECT
            s.started_at,
            EXISTS (
                SELECT 1
                FROM jsonb_array_elements_text(
                    COALESCE(NULLIF(s.rcpt_to, ''), '[]')::jsonb
                ) AS recipient(value)
                WHERE lower(recipient.value) = ANY($2::text[])
            ) AS recipient_match
        FROM sessions s
        WHERE lower(s.mail_from) = lower($1)
          AND s.status = 'Completed'
          AND s.source IN ('sniffer', 'mta_proxy')
          AND s.id != $3
          AND s.started_at < $4
          AND (
              SELECT lower(v.threat_level)
              FROM security_verdicts v
              WHERE v.session_id = s.id
              ORDER BY v.created_at DESC, v.id DESC
              LIMIT 1
          ) IN ('safe', 'low')
    )
    SELECT
        COUNT(*)::BIGINT,
        COUNT(DISTINCT LEFT(started_at, 10))::BIGINT,
        COUNT(*) FILTER (WHERE recipient_match)::BIGINT,
        COUNT(DISTINCT LEFT(started_at, 10))
            FILTER (WHERE recipient_match)::BIGINT
    FROM eligible
"#;

fn content_without_attachment_payload_sql(column: &str) -> String {
    format!(
        "CASE \
           WHEN {column} IS NULL THEN NULL \
           WHEN jsonb_typeof({column}->'attachments') = 'array' THEN \
             jsonb_set( \
               {column}, \
               '{{attachments}}', \
               COALESCE( \
                 (SELECT jsonb_agg(attachment.value - 'content_base64') \
                  FROM jsonb_array_elements({column}->'attachments') AS attachment(value)), \
                 '[]'::jsonb \
               ) \
             )::TEXT \
           ELSE {column}::TEXT \
         END"
    )
}

/// Session row (read from database - full version, includes content)
#[derive(Debug, FromRow)]
struct SessionRow {
    id: String,
    protocol: String,
    client_ip: String,
    client_port: i32,
    server_ip: String,
    server_port: i32,
    started_at: String,
    ended_at: Option<String>,
    status: String,
    packet_count: i32,
    total_bytes: i64,
    mail_from: Option<String>,
    rcpt_to: String,
    subject: Option<String>,
    content: Option<String>,
    email_count: Option<i32>,
    error_reason: Option<String>,
    message_id: Option<String>,
    auth_info: Option<String>,
    #[sqlx(default)]
    source: Option<String>,
}

/// Lightweight session row (for list queries - does not load large content field, only extracts summary)
#[derive(Debug, FromRow)]
struct SessionListRow {
    id: String,
    protocol: String,
    client_ip: String,
    client_port: i32,
    server_ip: String,
    server_port: i32,
    started_at: String,
    ended_at: Option<String>,
    status: String,
    packet_count: i32,
    total_bytes: i64,
    mail_from: Option<String>,
    rcpt_to: String,
    subject: Option<String>,
    // Lightweight alternative to content: only contains data needed for list rendering
    content_summary: Option<String>,
    email_count: Option<i32>,
    error_reason: Option<String>,
    message_id: Option<String>,
    auth_info: Option<String>,
    threat_level: Option<String>,
    threat_type: Option<String>,
    #[sqlx(default)]
    source: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SessionFilterQuery {
    where_clause: String,
    params: Vec<String>,
    next_param: usize,
}

/// One predicate builder keeps list rows and independent totals identical,
/// including the legacy JSON content fallback and bound search/IP values.
#[allow(clippy::too_many_arguments)]
fn session_filter_query(
    protocol: Option<&str>,
    status: Option<&str>,
    since: Option<&str>,
    content_filter: Option<&str>,
    auth_filter: Option<&str>,
    source_ips: Option<&str>,
    dest_ips: Option<&str>,
    search: Option<&str>,
    relay_ips: &[String],
) -> SessionFilterQuery {
    let mut conditions = Vec::new();
    let mut params: Vec<String> = Vec::new();
    // PostgreSQL uses $1, $2,... numbered placeholders
    // We track the next placeholder number with a counter
    let mut param_idx: usize = 1;

    if let Some(p) = protocol {
        if p.contains(',') {
            let protocols: Vec<&str> = p
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if !protocols.is_empty() {
                let placeholders = (param_idx..param_idx + protocols.len())
                    .map(|i| format!("${}", i))
                    .collect::<Vec<_>>()
                    .join(",");
                param_idx += protocols.len();
                conditions.push(format!("s.protocol IN ({})", placeholders));
                for proto in &protocols {
                    params.push(proto.to_string());
                }
            }
        } else {
            conditions.push(format!("s.protocol = ${}", param_idx));
            param_idx += 1;
            params.push(p.to_string());
        }
    }
    if let Some(s) = status {
        let normalized = {
            let mut c = s.chars();
            match c.next() {
                None => String::new(),
                Some(first) => first.to_uppercase().to_string() + &c.as_str().to_lowercase(),
            }
        };
        conditions.push(format!("s.status = ${}", param_idx));
        param_idx += 1;
        params.push(normalized);
    }
    if let Some(s) = since {
        conditions.push(format!("s.started_at >= ${}", param_idx));
        param_idx += 1;
        params.push(s.to_string());
    }

    match content_filter {
        Some("WITH_CONTENT") => {
            // Keep the original exact predicate for every row. The
            // server/content partial index can satisfy this condition
            // directly, while metadata remains an output optimization
            // for rows written after the trigger was installed.
            conditions.push(session_with_content_predicate("s."));
        }
        Some("ENCRYPTED") => {
            conditions.push(
                "((s.content->>'is_encrypted') = 'true' \
                 OR s.server_port IN (465, 993, 995))"
                    .to_string(),
            );
        }
        Some("NON_ENCRYPTED") => {
            conditions.push(
                "((s.content->>'is_encrypted') IS DISTINCT FROM 'true' \
                 AND s.server_port NOT IN (465, 993, 995))"
                    .to_string(),
            );
        }
        _ => {}
    }

    match auth_filter {
        Some("WITH_AUTH") => {
            conditions.push("s.auth_info IS NOT NULL".to_string());
        }
        Some("AUTH_SUCCESS") => {
            conditions.push(
                "(s.auth_info IS NOT NULL AND (s.auth_info->>'auth_success') = 'true')".to_string(),
            );
        }
        Some("AUTH_FAILED") => {
            conditions.push(
                "(s.auth_info IS NOT NULL AND (s.auth_info->>'auth_success') = 'false')"
                    .to_string(),
            );
        }
        _ => {}
    }

    if let Some(ips_str) = source_ips {
        let ips: Vec<&str> = ips_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !ips.is_empty() {
            let placeholders = (param_idx..param_idx + ips.len())
                .map(|i| format!("${}", i))
                .collect::<Vec<_>>()
                .join(",");
            param_idx += ips.len();
            conditions.push(format!("s.client_ip IN ({})", placeholders));
            for ip in &ips {
                params.push(ip.to_string());
            }
        }
    }

    if let Some(ips_str) = dest_ips {
        let ips: Vec<&str> = ips_str
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !ips.is_empty() {
            let placeholders = (param_idx..param_idx + ips.len())
                .map(|i| format!("${}", i))
                .collect::<Vec<_>>()
                .join(",");
            param_idx += ips.len();
            conditions.push(format!("s.server_ip IN ({})", placeholders));
            for ip in &ips {
                params.push(ip.to_string());
            }
        }
    }

    if let Some(q) = search {
        let q = q.trim();
        if !q.is_empty() {
            let like = format!("%{}%", q);
            let _search_parts_start = param_idx;
            let mut search_parts = vec![
                format!("s.client_ip LIKE ${}", param_idx),
                format!("s.server_ip LIKE ${}", param_idx + 1),
                format!("s.mail_from LIKE ${}", param_idx + 2),
                format!("s.rcpt_to LIKE ${}", param_idx + 3),
                format!("s.subject LIKE ${}", param_idx + 4),
            ];
            param_idx += 5;
            for _ in 0..5 {
                params.push(like.clone());
            }

            if !relay_ips.is_empty() {
                let client_ip_ph = (param_idx..param_idx + relay_ips.len())
                    .map(|i| format!("${}", i))
                    .collect::<Vec<_>>()
                    .join(",");
                param_idx += relay_ips.len();
                let server_ip_ph = (param_idx..param_idx + relay_ips.len())
                    .map(|i| format!("${}", i))
                    .collect::<Vec<_>>()
                    .join(",");
                param_idx += relay_ips.len();
                search_parts.push(format!("s.client_ip IN ({})", client_ip_ph));
                search_parts.push(format!("s.server_ip IN ({})", server_ip_ph));
                for ip in relay_ips {
                    params.push(ip.clone());
                }
                for ip in relay_ips {
                    params.push(ip.clone());
                }
            }

            conditions.push(format!("({})", search_parts.join(" OR ")));
        }
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    SessionFilterQuery {
        where_clause,
        params,
        next_param: param_idx,
    }
}

const SESSION_COUNT_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);
const SESSION_COUNT_FAILURE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const SESSION_COUNT_CACHE_CAPACITY: usize = 64;

/// Exact database ordering key. Keep the stored timestamp text rather than
/// reformatting it through chrono, which could change lexical comparisons.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionListCursor {
    pub started_at: String,
    pub id: Uuid,
}

pub struct SessionListEntry {
    pub session: EmailSession,
    pub cursor: SessionListCursor,
}

/// A count snapshot. `exact` is false when the bounded COUNT timed out and
/// `total` is the planner's row estimate for the same filter instead.
#[derive(Clone, Copy, Debug)]
pub struct SessionCountSnapshot {
    pub total: u64,
    pub counted_at: chrono::DateTime<chrono::Utc>,
    pub exact: bool,
}

type SessionCountEntries = std::collections::HashMap<
    SessionFilterQuery,
    (std::time::Instant, Option<SessionCountSnapshot>),
>;

/// Top-level `Plan Rows` of `EXPLAIN (FORMAT JSON)` output.
fn plan_row_estimate(plan: &serde_json::Value) -> Option<u64> {
    plan.get(0)?
        .get("Plan")?
        .get("Plan Rows")?
        .as_f64()
        .filter(|rows| rows.is_finite() && *rows >= 0.0)
        .map(|rows| rows.round() as u64)
}

#[derive(Default)]
pub(crate) struct SessionCountCache {
    // Cached counts can be read while another filter is being refreshed.
    entries: tokio::sync::Mutex<SessionCountEntries>,
    refresh_lock: tokio::sync::Mutex<()>,
}

impl SessionCountCache {
    async fn get(&self, filter: &SessionFilterQuery) -> Option<Result<SessionCountSnapshot>> {
        let mut entries = self.entries.lock().await;
        entries.retain(|_, (at, result)| {
            at.elapsed()
                < if result.is_some() {
                    SESSION_COUNT_CACHE_TTL
                } else {
                    SESSION_COUNT_FAILURE_TTL
                }
        });
        entries.get(filter).map(|(_, result)| {
            result.ok_or_else(|| anyhow::anyhow!("Session count temporarily unavailable"))
        })
    }

    async fn store(&self, filter: SessionFilterQuery, value: Option<SessionCountSnapshot>) {
        let mut entries = self.entries.lock().await;
        if entries.len() >= SESSION_COUNT_CACHE_CAPACITY
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(filter, (std::time::Instant::now(), value));
    }
}

impl VigilDb {
    /// Insert or update session (atomic UPSERT)
    pub async fn insert_session(&self, session: &EmailSession) -> Result<bool> {
        let id_str = session.id.to_string();

        let existing: Option<(String,)> = sqlx::query_as("SELECT id FROM sessions WHERE id = $1")
            .bind(&id_str)
            .fetch_optional(&self.pool)
            .await?;
        let is_new = existing.is_none();

        let rcpt_to = serde_json::to_string(&session.rcpt_to)?;
        // PostgreSQL JSONB \u0000 Unicode
        let content = {
            let raw = serde_json::to_string(&session.content)?;
            let sanitized = raw.replace("\\u0000", "");
            serde_json::from_str::<serde_json::Value>(&sanitized)?
        };

        let message_id = session.message_id.clone().or_else(|| {
            session
                .content
                .get_header("Message-ID")
                .map(|s| s.trim().to_string())
        });

        // Security: Password, skip_serializing (defense-in-depth)
        let auth_info = session.auth_info.as_ref().and_then(|a| {
            let mut safe = a.clone();
            safe.password = None;
            serde_json::to_value(&safe).ok()
        });

        // Extract domain from mail_from(Used forfirst communication detection index query)
        let sender_domain = session
            .mail_from
            .as_deref()
            .and_then(|m| m.split('@').nth(1))
            .map(|d| d.to_lowercase());
        let bounce_metadata = extract_bounce_metadata(
            session.mail_from.as_deref(),
            session.subject.as_deref(),
            session
                .content
                .body_text
                .as_deref()
                .or(session.content.body_html.as_deref()),
        );

        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, protocol, client_ip, client_port, server_ip, server_port,
                started_at, ended_at, started_at_ts, ended_at_ts, status, packet_count, total_bytes,
                mail_from, rcpt_to, subject, content, email_count, error_reason, message_id, auth_info,
                sender_domain, source, bounce_metadata_ready, bounce_candidate,
                bounce_reported_alert, bounce_target_addresses
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::timestamptz, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
            ON CONFLICT(id) DO UPDATE SET
                started_at_ts = COALESCE(sessions.started_at_ts, excluded.started_at_ts),
                ended_at = excluded.ended_at,
                ended_at_ts = excluded.ended_at_ts,
                status = excluded.status,
                packet_count = excluded.packet_count,
                total_bytes = excluded.total_bytes,
                mail_from = COALESCE(excluded.mail_from, sessions.mail_from),
                sender_domain = COALESCE(excluded.sender_domain, sessions.sender_domain),
                rcpt_to = excluded.rcpt_to,
                subject = COALESCE(excluded.subject, sessions.subject),
                content = CASE
                    WHEN sessions.content_has_body AND NOT excluded.content_has_body
                    THEN sessions.content
                    ELSE excluded.content
                END,
                email_count = excluded.email_count,
                error_reason = excluded.error_reason,
                message_id = COALESCE(excluded.message_id, sessions.message_id),
                auth_info = COALESCE(excluded.auth_info, sessions.auth_info),
                source = excluded.source,
                bounce_metadata_ready = excluded.bounce_metadata_ready,
                bounce_candidate = sessions.bounce_candidate OR excluded.bounce_candidate,
                bounce_reported_alert = sessions.bounce_reported_alert OR excluded.bounce_reported_alert,
                bounce_target_addresses = COALESCE(excluded.bounce_target_addresses, sessions.bounce_target_addresses)
            "#,
        )
        .bind(&id_str)
        .bind(match session.protocol { Protocol::Smtp => "SMTP", Protocol::Pop3 => "POP3", Protocol::Imap => "IMAP", Protocol::Http => "HTTP", Protocol::Unknown => "UNKNOWN" })
        .bind(&session.client_ip)
        .bind(session.client_port as i32)
        .bind(&session.server_ip)
        .bind(session.server_port as i32)
        .bind(session.started_at.to_rfc3339())
        .bind(session.ended_at.map(|t| t.to_rfc3339()))
        .bind(session.started_at.to_rfc3339())
        .bind(session.ended_at.map(|t| t.to_rfc3339()))
        .bind(format!("{:?}", session.status))
        .bind(session.packet_count as i32)
        .bind(session.total_bytes as i64)
        .bind(&session.mail_from)
        .bind(&rcpt_to)
        .bind(&session.subject)
        .bind(&content)
        .bind(session.email_count as i32)
        .bind(&session.error_reason)
        .bind(&message_id)
        .bind(&auth_info)
        .bind(&sender_domain)
        .bind(session.source.to_string())
        .bind(bounce_metadata.ready)
        .bind(bounce_metadata.candidate)
        .bind(bounce_metadata.reported_alert)
        .bind(&bounce_metadata.target_addresses_json)
        .execute(&self.pool)
        .await?;

        Ok(is_new)
    }

    /// Batch insert sessions (transaction + multi-row UPSERT)
    ///
    /// Use dynamic multi-row VALUES instead of row-by-row INSERT, reduce N DB round-trips to ceil(N/CHUNK).
    /// PostgreSQL parameter limit ~65535, 19 cols x 500 rows = 9500 params, within safe range.
    pub async fn insert_sessions_batch(
        &self,
        sessions: &[EmailSession],
    ) -> Result<(usize, Vec<bool>, Vec<EmailSession>)> {
        if sessions.is_empty() {
            return Ok((0, vec![], vec![]));
        }

        let ids: Vec<String> = sessions.iter().map(|s| s.id.to_string()).collect();
        let placeholders = (1..=ids.len())
            .map(|i| format!("${}", i))
            .collect::<Vec<_>>()
            .join(",");
        let query_str = format!("SELECT id FROM sessions WHERE id IN ({})", placeholders);
        let mut q = sqlx::query_as::<_, (String,)>(sqlx::AssertSqlSafe(query_str.as_str()));
        for id in &ids {
            q = q.bind(id);
        }
        let existing_rows = q.fetch_all(&self.pool).await?;
        let existing_ids: std::collections::HashSet<String> =
            existing_rows.into_iter().map(|(id,)| id).collect();

        // Preprocessing: serialize all params (avoid serde errors in SQL build loop)
        const COLS_PER_ROW: usize = 27;
        const BATCH_CHUNK_SIZE: usize = 500; // 500 x 27 = 13500 params, well under 65535

        struct PreparedSession {
            id_str: String,
            protocol: &'static str,
            client_ip: String,
            client_port: i32,
            server_ip: String,
            server_port: i32,
            started_at: String,
            ended_at: Option<String>,
            started_at_ts: String,
            ended_at_ts: Option<String>,
            status: String,
            packet_count: i32,
            total_bytes: i64,
            mail_from: Option<String>,
            rcpt_to: String,
            subject: Option<String>,
            content: serde_json::Value,
            email_count: i32,
            error_reason: Option<String>,
            message_id: Option<String>,
            auth_info: Option<serde_json::Value>,
            sender_domain: Option<String>,
            source: String,
            bounce_metadata: BounceMetadata,
        }

        let mut prepared: Vec<PreparedSession> = Vec::with_capacity(sessions.len());
        for session in sessions {
            let rcpt_to = serde_json::to_string(&session.rcpt_to)?;
            // PostgreSQL JSONB \u0000 Unicode
            let content = {
                let raw = serde_json::to_string(&session.content)?;
                let sanitized = raw.replace("\\u0000", "");
                serde_json::from_str::<serde_json::Value>(&sanitized)?
            };
            let message_id = session.message_id.clone().or_else(|| {
                session
                    .content
                    .get_header("Message-ID")
                    .map(|s| s.trim().to_string())
            });
            // Security: Password, skip_serializing (defense-in-depth)
            let auth_info = session.auth_info.as_ref().and_then(|a| {
                let mut safe = a.clone();
                safe.password = None;
                serde_json::to_value(&safe).ok()
            });
            prepared.push(PreparedSession {
                id_str: session.id.to_string(),
                protocol: match session.protocol {
                    Protocol::Smtp => "SMTP",
                    Protocol::Pop3 => "POP3",
                    Protocol::Imap => "IMAP",
                    Protocol::Http => "HTTP",
                    Protocol::Unknown => "UNKNOWN",
                },
                client_ip: session.client_ip.clone(),
                client_port: session.client_port as i32,
                server_ip: session.server_ip.clone(),
                server_port: session.server_port as i32,
                started_at: session.started_at.to_rfc3339(),
                ended_at: session.ended_at.map(|t| t.to_rfc3339()),
                started_at_ts: session.started_at.to_rfc3339(),
                ended_at_ts: session.ended_at.map(|t| t.to_rfc3339()),
                status: format!("{:?}", session.status),
                packet_count: session.packet_count as i32,
                total_bytes: session.total_bytes as i64,
                mail_from: session.mail_from.clone(),
                rcpt_to,
                subject: session.subject.clone(),
                content,
                email_count: session.email_count as i32,
                error_reason: session.error_reason.clone(),
                message_id,
                auth_info,
                sender_domain: session
                    .mail_from
                    .as_deref()
                    .and_then(|m| m.split('@').nth(1))
                    .map(|d| d.to_lowercase()),
                source: session.source.to_string(),
                bounce_metadata: extract_bounce_metadata(
                    session.mail_from.as_deref(),
                    session.subject.as_deref(),
                    session
                        .content
                        .body_text
                        .as_deref()
                        .or(session.content.body_html.as_deref()),
                ),
            });
        }

        let mut tx = self.pool.begin().await?;
        let is_new_vec: Vec<bool> = sessions
            .iter()
            .map(|s| !existing_ids.contains(&s.id.to_string()))
            .collect();

        for chunk in prepared.chunks(BATCH_CHUNK_SIZE) {
            let mut sql = String::from(
                "INSERT INTO sessions (\
                    id, protocol, client_ip, client_port, server_ip, server_port, \
                    started_at, ended_at, started_at_ts, ended_at_ts, status, packet_count, total_bytes, \
                    mail_from, rcpt_to, subject, content, email_count, error_reason, message_id, auth_info, \
                    sender_domain, source, bounce_metadata_ready, bounce_candidate,\
                    bounce_reported_alert, bounce_target_addresses\
                ) VALUES ",
            );

            let mut param_idx = 1u32;
            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    sql.push_str(", ");
                }
                sql.push('(');
                for col in 0..COLS_PER_ROW {
                    if col > 0 {
                        sql.push_str(", ");
                    }
                    sql.push('$');
                    // itoa would be faster but format! is fine for build-time SQL
                    sql.push_str(&(param_idx + col as u32).to_string());
                    if col == 8 || col == 9 {
                        sql.push_str("::timestamptz");
                    }
                }
                sql.push(')');
                param_idx += COLS_PER_ROW as u32;
            }

            sql.push_str(
                " ON CONFLICT(id) DO UPDATE SET \
                    started_at_ts = COALESCE(sessions.started_at_ts, excluded.started_at_ts), \
                    ended_at = excluded.ended_at, \
                    ended_at_ts = excluded.ended_at_ts, \
                    status = excluded.status, \
                    packet_count = excluded.packet_count, \
                    total_bytes = excluded.total_bytes, \
                    mail_from = COALESCE(excluded.mail_from, sessions.mail_from), \
                    sender_domain = COALESCE(excluded.sender_domain, sessions.sender_domain), \
                    rcpt_to = excluded.rcpt_to, \
                    subject = COALESCE(excluded.subject, sessions.subject), \
                    content = CASE \
                        WHEN sessions.content_has_body AND NOT excluded.content_has_body \
                        THEN sessions.content \
                        ELSE excluded.content \
                    END, \
                    email_count = excluded.email_count, \
                    error_reason = excluded.error_reason, \
                    message_id = COALESCE(excluded.message_id, sessions.message_id), \
                    auth_info = COALESCE(excluded.auth_info, sessions.auth_info), \
                    source = excluded.source, \
                    bounce_metadata_ready = excluded.bounce_metadata_ready, \
                    bounce_candidate = sessions.bounce_candidate OR excluded.bounce_candidate, \
                    bounce_reported_alert = sessions.bounce_reported_alert OR excluded.bounce_reported_alert, \
                    bounce_target_addresses = COALESCE(excluded.bounce_target_addresses, sessions.bounce_target_addresses)",
            );

            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()));
            for row in chunk {
                query = query
                    .bind(&row.id_str)
                    .bind(row.protocol)
                    .bind(&row.client_ip)
                    .bind(row.client_port)
                    .bind(&row.server_ip)
                    .bind(row.server_port)
                    .bind(&row.started_at)
                    .bind(&row.ended_at)
                    .bind(&row.started_at_ts)
                    .bind(&row.ended_at_ts)
                    .bind(&row.status)
                    .bind(row.packet_count)
                    .bind(row.total_bytes)
                    .bind(&row.mail_from)
                    .bind(&row.rcpt_to)
                    .bind(&row.subject)
                    .bind(&row.content)
                    .bind(row.email_count)
                    .bind(&row.error_reason)
                    .bind(&row.message_id)
                    .bind(&row.auth_info)
                    .bind(&row.sender_domain)
                    .bind(&row.source)
                    .bind(row.bounce_metadata.ready)
                    .bind(row.bounce_metadata.candidate)
                    .bind(row.bounce_metadata.reported_alert)
                    .bind(&row.bounce_metadata.target_addresses_json);
            }
            query.execute(&mut *tx).await?;
        }

        let count = prepared.len();

        // Commit write transaction first (release write lock), then read back merged version
        // This way read query wont be blocked by write lock for 3+ seconds
        tx.commit().await?;

        let merged_placeholders = (1..=ids.len())
            .map(|i| format!("${}", i))
            .collect::<Vec<_>>()
            .join(",");
        let merged_query_str = format!(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE id IN ({})",
            merged_placeholders
        );
        let mut mq =
            sqlx::query_as::<_, SessionRow>(sqlx::AssertSqlSafe(merged_query_str.as_str()));
        for id in &ids {
            mq = mq.bind(id);
        }
        let merged_rows: Vec<SessionRow> = mq.fetch_all(&self.pool).await?;
        let merged: Vec<EmailSession> = merged_rows
            .into_iter()
            .filter_map(|r| row_to_session(r).ok())
            .collect();

        Ok((count, is_new_vec, merged))
    }

    /// Get session list
    #[allow(clippy::too_many_arguments)]
    pub async fn list_sessions(
        &self,
        limit: u32,
        offset: u32,
        protocol: Option<&str>,
        status: Option<&str>,
        since: Option<&str>,
        content_filter: Option<&str>,
        auth_filter: Option<&str>,
        source_ips: Option<&str>,
        dest_ips: Option<&str>,
        search: Option<&str>,
        relay_ips: &[String],
        skip_count: bool,
    ) -> Result<(Vec<EmailSession>, u64)> {
        let (entries, total) = self
            .list_session_entries(
                limit,
                offset,
                protocol,
                status,
                since,
                content_filter,
                auth_filter,
                source_ips,
                dest_ips,
                search,
                relay_ips,
                skip_count,
                None,
            )
            .await?;
        Ok((
            entries.into_iter().map(|entry| entry.session).collect(),
            total,
        ))
    }

    /// Limit/offset or seek pagination happens before wide projection and risk
    /// enrichment. Skipped rows never pay a verdict lookup or JSON projection.
    #[allow(clippy::too_many_arguments)]
    pub async fn list_session_entries(
        &self,
        limit: u32,
        offset: u32,
        protocol: Option<&str>,
        status: Option<&str>,
        since: Option<&str>,
        content_filter: Option<&str>,
        auth_filter: Option<&str>,
        source_ips: Option<&str>,
        dest_ips: Option<&str>,
        search: Option<&str>,
        relay_ips: &[String],
        skip_count: bool,
        after: Option<&SessionListCursor>,
    ) -> Result<(Vec<SessionListEntry>, u64)> {
        let filter = session_filter_query(
            protocol,
            status,
            since,
            content_filter,
            auth_filter,
            source_ips,
            dest_ips,
            search,
            relay_ips,
        );
        let total = if skip_count {
            0
        } else {
            self.count_session_filter(&filter).await?.total
        };
        let mut where_clause = filter.where_clause.clone();
        let mut params = filter.params.clone();
        let mut next_param = filter.next_param;
        if let Some(cursor) = after {
            where_clause.push_str(if where_clause.is_empty() {
                " WHERE "
            } else {
                " AND "
            });
            where_clause.push_str(&format!(
                "(s.started_at <= ${0} AND (s.started_at < ${0} OR s.id < ${1}))",
                next_param,
                next_param + 1
            ));
            params.push(cursor.started_at.clone());
            params.push(cursor.id.to_string());
            next_param += 2;
        }

        // 2. PaginationDataQuery (: Load content, JSONB Extract metadata)
        // LEFT JOIN security_verdicts (threat_level)
        let limit_ph = format!("${}", next_param);
        next_param += 1;
        let offset_ph = format!("${}", next_param);
        // not needed after last use

        let content_projection = if content_filter == Some("WITH_CONTENT") {
            "CASE WHEN s.list_has_content THEN jsonb_build_object(\
                 'is_encrypted', CASE WHEN s.content_is_encrypted THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'attachment_count', s.content_attachment_count, \
                 'is_complete', CASE WHEN s.content_is_complete THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'has_body', CASE WHEN s.content_has_body THEN 1::BIGINT ELSE 0::BIGINT END\
             )::TEXT ELSE CASE WHEN s.content IS NOT NULL THEN \
               jsonb_build_object(\
                 'is_encrypted', CASE WHEN (s.content->>'is_encrypted') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'attachment_count', COALESCE(jsonb_array_length(s.content->'attachments'), 0), \
                 'is_complete', CASE WHEN (s.content->>'is_complete') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'has_body', CASE WHEN s.content->>'body_text' IS NOT NULL \
                   OR s.content->>'body_html' IS NOT NULL THEN 1::BIGINT ELSE 0::BIGINT END \
               )::TEXT \
             ELSE NULL END END"
        } else {
            "CASE WHEN s.content IS NOT NULL THEN \
               jsonb_build_object(\
                 'is_encrypted', CASE WHEN (s.content->>'is_encrypted') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'attachment_count', COALESCE(jsonb_array_length(s.content->'attachments'), 0), \
                 'is_complete', CASE WHEN (s.content->>'is_complete') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'has_body', CASE WHEN s.content->>'body_text' IS NOT NULL \
                   OR s.content->>'body_html' IS NOT NULL THEN 1::BIGINT ELSE 0::BIGINT END \
               )::TEXT \
             ELSE NULL END"
        };

        let data_query = format!(
            "WITH page AS MATERIALIZED ( \
               SELECT s.id, s.started_at FROM sessions s{where_clause} \
               ORDER BY s.started_at DESC, s.id DESC LIMIT {limit_ph} OFFSET {offset_ph} \
             ) SELECT s.id, s.protocol, s.client_ip, s.client_port, s.server_ip, s.server_port, \
             s.started_at, s.ended_at, s.status, s.packet_count, s.total_bytes, \
             s.mail_from, s.rcpt_to, s.subject, {content_projection} AS content_summary, \
             s.email_count, s.error_reason, s.message_id, s.auth_info::TEXT as auth_info, \
             v.threat_level, v.threat_type, s.source \
             FROM page JOIN sessions s ON s.id = page.id \
             LEFT JOIN security_verdicts v ON v.session_id = s.id \
             ORDER BY page.started_at DESC, page.id DESC"
        );

        let mut q = sqlx::query_as::<_, SessionListRow>(sqlx::AssertSqlSafe(data_query.as_str()));
        for p in &params {
            q = q.bind(p);
        }
        q = q.bind(i64::from(limit)).bind(if after.is_some() {
            0
        } else {
            i64::from(offset)
        });
        // Rare filters and arbitrary deep offsets can still be expensive.
        // Bound their execution at PostgreSQL rather than only the HTTP wait.
        let mut tx = tokio::time::timeout(std::time::Duration::from_secs(2), self.pool.begin())
            .await
            .map_err(|_| anyhow::anyhow!("Session page connection timeout"))??;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '8s'")
            .execute(&mut *tx)
            .await?;
        let rows: Vec<SessionListRow> = q.fetch_all(&mut *tx).await?;
        tx.commit().await?;
        let entries = rows
            .into_iter()
            .filter_map(|row| {
                let cursor = SessionListCursor {
                    started_at: row.started_at.clone(),
                    id: Uuid::parse_str(&row.id).ok()?,
                };
                list_row_to_session(row)
                    .ok()
                    .map(|session| SessionListEntry { session, cursor })
            })
            .collect();
        Ok((entries, total))
    }

    /// Exact total for the same filters as list_sessions, bounded separately
    /// from the page query so a large table cannot block the visible rows.
    #[allow(clippy::too_many_arguments)]
    pub async fn count_sessions(
        &self,
        protocol: Option<&str>,
        status: Option<&str>,
        since: Option<&str>,
        content_filter: Option<&str>,
        auth_filter: Option<&str>,
        source_ips: Option<&str>,
        dest_ips: Option<&str>,
        search: Option<&str>,
        relay_ips: &[String],
    ) -> Result<SessionCountSnapshot> {
        let filter = session_filter_query(
            protocol,
            status,
            since,
            content_filter,
            auth_filter,
            source_ips,
            dest_ips,
            search,
            relay_ips,
        );
        self.count_session_filter(&filter).await
    }

    async fn count_session_filter(
        &self,
        filter: &SessionFilterQuery,
    ) -> Result<SessionCountSnapshot> {
        if let Some(cached) = self.session_count_cache.get(filter).await {
            return cached;
        }
        // At most one COUNT holds a database connection; identical cold
        // requests recheck the completed snapshot instead of counting twice.
        let _refresh = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.session_count_cache.refresh_lock.lock(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Session count is busy"))?;
        if let Some(cached) = self.session_count_cache.get(filter).await {
            return cached;
        }

        // Acquisition has its own small budget. The database-side timeout
        // actually cancels a costly scan instead of merely dropping HTTP work.
        let result = async {
            let mut tx = tokio::time::timeout(std::time::Duration::from_secs(2), self.pool.begin())
                .await
                .map_err(|_| anyhow::anyhow!("Session count connection timeout"))??;
            sqlx::query("SET TRANSACTION READ ONLY")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL statement_timeout = '8s'")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL max_parallel_workers_per_gather = 0")
                .execute(&mut *tx)
                .await?;
            // The planner estimates the whole table for partial-index counts,
            // which triggers full JIT compilation that costs more than the scan.
            sqlx::query("SET LOCAL jit = off").execute(&mut *tx).await?;
            let sql = format!("SELECT COUNT(*) FROM sessions s{}", filter.where_clause);
            let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql.as_str()));
            for value in &filter.params {
                query = query.bind(value);
            }
            let total = query.fetch_one(&mut *tx).await?;
            tx.commit().await?;
            Ok::<SessionCountSnapshot, anyhow::Error>(SessionCountSnapshot {
                total: total as u64,
                counted_at: chrono::Utc::now(),
                exact: true,
            })
        }
        .await;
        // Unselective filters over the whole table cannot be counted within
        // the budget; the planner estimate is labelled, never passed as exact.
        let result = match result {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => match self.estimate_session_filter(filter).await {
                Ok(total) => Ok(SessionCountSnapshot {
                    total,
                    counted_at: chrono::Utc::now(),
                    exact: false,
                }),
                Err(_) => Err(error),
            },
        };

        self.session_count_cache
            .store(filter.clone(), result.as_ref().ok().copied())
            .await;
        result
    }

    /// Planner row estimate for a session filter; milliseconds, no table scan.
    async fn estimate_session_filter(&self, filter: &SessionFilterQuery) -> Result<u64> {
        let mut tx = tokio::time::timeout(std::time::Duration::from_secs(2), self.pool.begin())
            .await
            .map_err(|_| anyhow::anyhow!("Session count estimate connection timeout"))??;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '1s'")
            .execute(&mut *tx)
            .await?;
        let sql = format!(
            "EXPLAIN (FORMAT JSON) SELECT 1 FROM sessions s{}",
            filter.where_clause
        );
        let mut query =
            sqlx::query_scalar::<_, serde_json::Value>(sqlx::AssertSqlSafe(sql.as_str()));
        for value in &filter.params {
            query = query.bind(value);
        }
        let plan = query.fetch_one(&mut *tx).await?;
        let mut estimate = plan_row_estimate(&plan)
            .ok_or_else(|| anyhow::anyhow!("Session count estimate unavailable"))?;
        // The planner has no statistics for the JSON content predicate and
        // assumes roughly half the table (43.7M estimated vs 0.35M actual on
        // 2026-11-13). The partial index over exactly that predicate bounds it.
        if filter
            .where_clause
            .contains(&session_with_content_predicate("s."))
        {
            let indexed: Option<f32> = sqlx::query_scalar(
                "SELECT reltuples FROM pg_class WHERE relname = 'idx_sessions_with_any_content'",
            )
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(indexed) = indexed.filter(|rows| rows.is_finite() && *rows >= 0.0) {
                estimate = estimate.min(indexed.round() as u64);
            }
        }
        tx.commit().await?;
        Ok(estimate)
    }

    /// Query Security Session(Used for)
    /// session_id, According to, limit items
    pub async fn query_unanalyzed_sessions(
        &self,
        since: &str,
        limit: u32,
    ) -> Result<Vec<uuid::Uuid>> {
        let until = chrono::Utc::now().to_rfc3339();
        let rows = self
            .query_unanalyzed_session_candidates(since, None, None, &until, limit)
            .await?;

        Ok(rows.into_iter().map(|(id, _)| id).collect())
    }

    /// Query completed sessions that still have no verdict using a stable
    /// `(started_at, id)` cursor. This is used by the Engine catch-up scanner
    /// so a small batch of repeatedly missed sessions cannot starve older
    /// unanalyzed mail.
    pub async fn query_unanalyzed_session_candidates(
        &self,
        since: &str,
        cursor_started_at: Option<&str>,
        cursor_id: Option<&str>,
        until: &str,
        limit: u32,
    ) -> Result<Vec<(uuid::Uuid, String)>> {
        let content_predicate = session_with_content_predicate("s.");
        let query = format!(
            "SELECT s.id, s.started_at FROM sessions s \
             WHERE s.status = 'Completed' \
               AND s.started_at >= $1 \
               AND s.started_at <= $2 \
               AND ($3::TEXT IS NULL OR s.started_at > $3 \
                    OR (s.started_at = $3 AND s.id > COALESCE($4::TEXT, ''))) \
               AND NOT EXISTS (SELECT 1 FROM security_verdicts v WHERE v.session_id = s.id) \
               AND {content_predicate} \
             ORDER BY s.started_at ASC, s.id ASC \
             LIMIT $5"
        );
        let rows: Vec<(String, String)> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(since)
            .bind(until)
            .bind(cursor_started_at)
            .bind(cursor_id)
            .bind(limit as i32)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(id, started_at)| uuid::Uuid::parse_str(&id).ok().map(|u| (u, started_at)))
            .collect())
    }

    /// QuerySenderDomain (Used forFirst communication)
    /// sender_domain + EXISTS Road, LIKE '%@domain'
    ///
    /// Trust gate (E2): only sessions that were actually analyzed AND came
    /// back below High count as history. Without this, one clean warm-up
    /// greeting (or even an already-Critical email) disarmed first_contact /
    /// new_sender_on_known_domain for every later attack from the domain.
    pub async fn count_sender_domain_history(
        &self,
        sender_domain: &str,
        exclude_session_id: &str,
    ) -> Result<i64> {
        let query = sender_history_exists_sql("s.sender_domain = $1");
        let exists: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(sender_domain)
            .bind(exclude_session_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(exists.0)
    }

    /// Query whether an exact envelope mailbox has appeared in completed
    /// sessions.  Domain history alone cannot distinguish a trusted sender
    /// from a newly rotated attacker mailbox on a shared domain.
    ///
    /// Same trust gate as [`count_sender_domain_history`](Self::count_sender_domain_history):
    /// sessions without a verdict, or with a high/critical verdict, do not
    /// count as trust-building history.
    pub async fn count_sender_address_history(
        &self,
        sender_address: &str,
        exclude_session_id: &str,
    ) -> Result<i64> {
        let query = sender_history_exists_sql("lower(s.mail_from) = lower($1)");
        let exists: (i64,) = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(sender_address)
            .bind(exclude_session_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(exists.0)
    }

    /// Return prior Safe/Low history for an exact sender mailbox and its
    /// relationship with at least one current envelope recipient.
    pub async fn sender_relationship_history(
        &self,
        sender_address: &str,
        recipient_addresses: &[String],
        exclude_session_id: &str,
        before_started_at: &str,
    ) -> Result<(i64, i64, i64, i64)> {
        if recipient_addresses.is_empty() {
            return Ok((0, 0, 0, 0));
        }

        let recipients = recipient_addresses
            .iter()
            .map(|recipient| recipient.trim().to_ascii_lowercase())
            .filter(|recipient| !recipient.is_empty())
            .collect::<Vec<_>>();
        if recipients.is_empty() {
            return Ok((0, 0, 0, 0));
        }

        let counts = sqlx::query_as::<_, (i64, i64, i64, i64)>(SENDER_RELATIONSHIP_HISTORY_SQL)
            .bind(sender_address)
            .bind(recipients)
            .bind(exclude_session_id)
            .bind(before_started_at)
            .fetch_one(&self.pool)
            .await?;
        Ok(counts)
    }

    /// Count distinct senders (mail_from addresses) for a given domain.
    /// Used for sender diversity heuristic in identity_anomaly module.
    pub async fn count_distinct_senders_for_domain(&self, sender_domain: &str) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(DISTINCT mail_from)::BIGINT \
             FROM sessions \
             WHERE sender_domain = $1 AND status = 'Completed'",
        )
        .bind(sender_domain)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Get Session
    pub async fn get_session(&self, id: Uuid) -> Result<Option<EmailSession>> {
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE id = $1"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(row_to_session(r)?)),
            None => Ok(None),
        }
    }

    /// Get Session without embedding attachment payload bytes.
    pub async fn get_session_without_attachment_content(
        &self,
        id: Uuid,
    ) -> Result<Option<EmailSession>> {
        let content_expr = content_without_attachment_payload_sql("content");
        let query = format!(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, {content_expr} as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE id = $1"
        );
        let row: Option<SessionRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_session(r)?)),
            None => Ok(None),
        }
    }

    /// Batch Session
    pub async fn get_sessions_batch(&self, ids: &[Uuid]) -> Result<Vec<EmailSession>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }

        let id_strs: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
        let placeholders = (1..=id_strs.len())
            .map(|i| format!("${}", i))
            .collect::<Vec<_>>()
            .join(",");
        let query_str = format!(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE id IN ({})",
            placeholders
        );

        let mut q = sqlx::query_as::<_, SessionRow>(sqlx::AssertSqlSafe(query_str.as_str()));
        for id in &id_strs {
            q = q.bind(id);
        }
        let rows: Vec<SessionRow> = q.fetch_all(&self.pool).await?;

        let sessions: Vec<EmailSession> = rows
            .into_iter()
            .filter_map(|row| row_to_session(row).ok())
            .collect();

        Ok(sessions)
    }

    /// According to message_id Session
    pub async fn find_related_sessions(
        &self,
        message_id: &str,
        exclude_id: Uuid,
    ) -> Result<Vec<EmailSession>> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE message_id = $1 AND id != $2 ORDER BY started_at ASC"
        )
        .bind(message_id)
        .bind(exclude_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let sessions: Vec<EmailSession> = rows
            .into_iter()
            .filter_map(|row| row_to_session(row).ok())
            .collect();

        Ok(sessions)
    }

    /// According to message_id Session, without embedding attachment payload bytes.
    pub async fn find_related_sessions_without_attachment_content(
        &self,
        message_id: &str,
        exclude_id: Uuid,
    ) -> Result<Vec<EmailSession>> {
        let content_expr = content_without_attachment_payload_sql("content");
        let query = format!(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, {content_expr} as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions WHERE message_id = $1 AND id != $2 ORDER BY started_at ASC"
        );
        let rows: Vec<SessionRow> = sqlx::query_as(sqlx::AssertSqlSafe(query.as_str()))
            .bind(message_id)
            .bind(exclude_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        let sessions: Vec<EmailSession> = rows
            .into_iter()
            .filter_map(|row| row_to_session(row).ok())
            .collect();

        Ok(sessions)
    }

    /// Find downstream delivery hops for the same mail envelope.
    pub async fn find_downstream_sessions_by_envelope(
        &self,
        session: &EmailSession,
        exclude_id: Uuid,
        lookahead_seconds: i64,
    ) -> Result<Vec<EmailSession>> {
        let rcpt_to = serde_json::to_string(&session.rcpt_to)?;
        let started_at = session.started_at.to_rfc3339();
        let deadline =
            (session.started_at + chrono::Duration::seconds(lookahead_seconds)).to_rfc3339();
        let content_expr = content_without_attachment_payload_sql("content");
        let mail_from_filter = if session.mail_from.is_some() {
            "mail_from = $3"
        } else {
            "mail_from IS NULL AND $3::TEXT IS NULL"
        };
        let query = format!(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, {content_expr} as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info, source \
             FROM sessions \
             WHERE id != $1 \
               AND client_ip = $2 \
               AND {mail_from_filter} \
               AND rcpt_to = $4 \
               AND started_at >= $5 \
               AND started_at <= $6 \
             ORDER BY started_at ASC"
        );
        let mut query = sqlx::query_as::<_, SessionRow>(sqlx::AssertSqlSafe(query.as_str()))
            .bind(exclude_id.to_string())
            .bind(&session.server_ip);
        if let Some(mail_from) = &session.mail_from {
            query = query.bind(mail_from);
        } else {
            query = query.bind(Option::<String>::None);
        }
        let rows: Vec<SessionRow> = query
            .bind(&rcpt_to)
            .bind(&started_at)
            .bind(&deadline)
            .fetch_all(&self.pool)
            .await?;

        let sessions: Vec<EmailSession> = rows
            .into_iter()
            .filter_map(|row| row_to_session(row).ok())
            .collect();

        Ok(sessions)
    }
}

/// EmailSession
fn row_to_session(row: SessionRow) -> Result<EmailSession> {
    let content: EmailContent = match &row.content {
        Some(c) => match serde_json::from_str(c) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(
                    "Session {} 内容反序列化失败: {} (内容长度: {})",
                    row.id,
                    e,
                    c.len()
                );
                EmailContent::default()
            }
        },
        None => EmailContent::default(),
    };

    Ok(EmailSession {
        id: Uuid::parse_str(&row.id)?,
        protocol: match row.protocol.as_str() {
            "SMTP" | "Smtp" => Protocol::Smtp,
            "POP3" | "Pop3" => Protocol::Pop3,
            "IMAP" | "Imap" => Protocol::Imap,
            "HTTP" | "Http" => Protocol::Http,
            _ => Protocol::Unknown,
        },
        client_ip: row.client_ip,
        client_port: row.client_port as u16,
        server_ip: row.server_ip,
        server_port: row.server_port as u16,
        started_at: chrono::DateTime::parse_from_rfc3339(&row.started_at)?
            .with_timezone(&chrono::Utc),
        ended_at: row
            .ended_at
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&chrono::Utc)),
        status: match row.status.as_str() {
            "Active" => SessionStatus::Active,
            "Completed" => SessionStatus::Completed,
            "Timeout" => SessionStatus::Timeout,
            "Error" => SessionStatus::Error,
            _ => SessionStatus::Active,
        },
        packet_count: row.packet_count as u32,
        total_bytes: row.total_bytes as usize,
        mail_from: row.mail_from,
        rcpt_to: serde_json::from_str(&row.rcpt_to).unwrap_or_default(),
        subject: row.subject,
        content,
        email_count: row.email_count.unwrap_or(0) as u32,
        error_reason: row.error_reason,
        message_id: row.message_id,
        auth_info: row.auth_info.and_then(|s| serde_json::from_str(&s).ok()),
        threat_level: None,
        threat_type: None,
        source: parse_session_source(row.source.as_deref()),
        smtp_helo: None,
        release_rescan: None,
    })
}

/// EmailSession (, content Summary)
fn list_row_to_session(row: SessionListRow) -> Result<EmailSession> {
    // content_summary SQL JSON: {"is_encrypted":0,"attachment_count":2,"is_complete":1,"has_body":1}
    let content: EmailContent = match &row.content_summary {
        Some(c) => {
            let summary: serde_json::Value = serde_json::from_str(c).unwrap_or_default();
            let is_encrypted = summary
                .get("is_encrypted")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                != 0;
            let attachment_count = summary
                .get("attachment_count")
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as usize;
            let is_complete = summary
                .get("is_complete")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                != 0;
            let placeholder_attachments: Vec<EmailAttachment> = (0..attachment_count)
                .map(|_| EmailAttachment {
                    filename: String::new(),
                    content_type: String::new(),
                    size: 0,
                    hash: String::new(),
                    content_base64: None,
                })
                .collect();
            EmailContent {
                is_encrypted,
                is_complete,
                attachments: placeholder_attachments,
                ..EmailContent::default()
            }
        }
        None => EmailContent::default(),
    };

    Ok(EmailSession {
        id: Uuid::parse_str(&row.id)?,
        protocol: match row.protocol.as_str() {
            "SMTP" | "Smtp" => Protocol::Smtp,
            "POP3" | "Pop3" => Protocol::Pop3,
            "IMAP" | "Imap" => Protocol::Imap,
            "HTTP" | "Http" => Protocol::Http,
            _ => Protocol::Unknown,
        },
        client_ip: row.client_ip,
        client_port: row.client_port as u16,
        server_ip: row.server_ip,
        server_port: row.server_port as u16,
        started_at: chrono::DateTime::parse_from_rfc3339(&row.started_at)?
            .with_timezone(&chrono::Utc),
        ended_at: row
            .ended_at
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(&t).ok())
            .map(|t| t.with_timezone(&chrono::Utc)),
        status: match row.status.as_str() {
            "Active" => SessionStatus::Active,
            "Completed" => SessionStatus::Completed,
            "Timeout" => SessionStatus::Timeout,
            "Error" => SessionStatus::Error,
            _ => SessionStatus::Active,
        },
        packet_count: row.packet_count as u32,
        total_bytes: row.total_bytes as usize,
        mail_from: row.mail_from,
        rcpt_to: serde_json::from_str(&row.rcpt_to).unwrap_or_default(),
        subject: row.subject,
        content,
        email_count: row.email_count.unwrap_or(0) as u32,
        error_reason: row.error_reason,
        message_id: row.message_id,
        auth_info: row.auth_info.and_then(|s| serde_json::from_str(&s).ok()),
        threat_level: row.threat_level,
        threat_type: row.threat_type,
        source: parse_session_source(row.source.as_deref()),
        smtp_helo: None,
        release_rescan: None,
    })
}

fn parse_session_source(value: Option<&str>) -> SessionSource {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "mta_proxy" | "mta" => SessionSource::MtaProxy,
        "import" => SessionSource::Import,
        _ => SessionSource::Sniffer,
    }
}
#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn session_count_cache_hits_do_not_wait_for_another_filter_refresh() {
        let cache = super::SessionCountCache::default();
        let filter = super::session_filter_query(
            None,
            None,
            None,
            Some("WITH_CONTENT"),
            None,
            None,
            None,
            None,
            &[],
        );
        let snapshot = super::SessionCountSnapshot {
            total: 42,
            counted_at: chrono::Utc::now(),
            exact: true,
        };
        cache.store(filter.clone(), Some(snapshot)).await;
        let _refresh = cache.refresh_lock.lock().await;
        let cached = tokio::time::timeout(std::time::Duration::from_secs(1), cache.get(&filter))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(cached.total, 42);
        assert_eq!(cached.counted_at, snapshot.counted_at);
    }

    #[test]
    fn plan_row_estimate_reads_the_top_level_plan_rows() {
        let plan = serde_json::json!([
            { "Plan": { "Node Type": "Index Scan", "Plan Rows": 43764888.4 } }
        ]);
        assert_eq!(super::plan_row_estimate(&plan), Some(43_764_888));
        for invalid in [
            serde_json::json!([]),
            serde_json::json!([{ "Plan": {} }]),
            serde_json::json!([{ "Plan": { "Plan Rows": -1.0 } }]),
            serde_json::json!({ "Plan": { "Plan Rows": 5 } }),
        ] {
            assert_eq!(super::plan_row_estimate(&invalid), None, "{invalid}");
        }
    }

    use super::{
        SENDER_RELATIONSHIP_HISTORY_SQL, TRUSTED_HISTORY_VERDICT_PREDICATE,
        sender_history_exists_sql,
    };

    #[test]
    fn trusted_history_predicate_requires_analyzed_non_malicious_verdict() {
        // PoC (E2): before the fix the history lookup was a bare
        // `status = 'Completed'` check, so one clean warm-up greeting — or
        // even an email already judged Critical — counted as trust history
        // and disarmed first_contact / new_sender_on_known_domain for every
        // later attack from the same domain. The predicate must require a
        // verdict row AND exclude high/critical verdicts.
        assert!(
            TRUSTED_HISTORY_VERDICT_PREDICATE.contains("EXISTS(SELECT 1 FROM security_verdicts")
        );
        assert!(TRUSTED_HISTORY_VERDICT_PREDICATE.contains("v.session_id = s.id"));
        assert!(
            TRUSTED_HISTORY_VERDICT_PREDICATE
                .contains("lower(v.threat_level) NOT IN ('high', 'critical')")
        );
    }

    #[test]
    fn sender_history_queries_apply_trust_gate_and_completed_filter() {
        // Query-construction verification: both history lookups (domain and
        // exact-address) must carry the Completed filter, the current-session
        // exclusion, and the verdict trust gate.
        for sql in [
            sender_history_exists_sql("s.sender_domain = $1"),
            sender_history_exists_sql("lower(s.mail_from) = lower($1)"),
        ] {
            assert!(
                sql.contains("s.status = 'Completed'"),
                "missing Completed filter: {sql}"
            );
            assert!(sql.contains("s.id != $2"), "missing self-exclusion: {sql}");
            assert!(
                sql.contains(TRUSTED_HISTORY_VERDICT_PREDICATE),
                "missing verdict trust gate: {sql}"
            );
        }

        // The two lookups must keep their distinct match predicates.
        assert!(sender_history_exists_sql("s.sender_domain = $1").contains("s.sender_domain = $1"));
        assert!(
            sender_history_exists_sql("lower(s.mail_from) = lower($1)")
                .contains("lower(s.mail_from) = lower($1)")
        );
    }

    #[test]
    fn shadow_relationship_history_is_temporal_live_and_safe_low_only() {
        let sql = SENDER_RELATIONSHIP_HISTORY_SQL;
        assert!(sql.contains("s.source IN ('sniffer', 'mta_proxy')"));
        assert!(sql.contains("s.started_at < $4"));
        assert!(sql.contains("s.id != $3"));
        assert!(sql.contains("IN ('safe', 'low')"));
        assert!(sql.contains("ORDER BY v.created_at DESC, v.id DESC"));
        assert!(sql.contains("lower(recipient.value) = ANY($2::text[])"));
        assert!(sql.contains("FILTER (WHERE recipient_match)"));
    }
}
