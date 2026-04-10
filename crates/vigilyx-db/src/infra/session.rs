//! Session CRUD operations

use anyhow::Result;
use sqlx::FromRow;
use uuid::Uuid;
use vigilyx_core::{EmailAttachment, EmailContent, EmailSession, Protocol, SessionSource, SessionStatus};

use crate::VigilDb;

const SESSION_WITH_CONTENT_PREDICATE_TEMPLATE: &str =
    "(({prefix}content->>'is_encrypted') IS DISTINCT FROM 'true' \
      AND (({prefix}content->>'body_text') IS NOT NULL \
       OR ({prefix}content->>'body_html') IS NOT NULL \
       OR COALESCE(jsonb_array_length({prefix}content->'attachments'), 0) > 0 \
       OR COALESCE(jsonb_array_length({prefix}content->'headers'), 0) > 0))";

pub(crate) fn session_with_content_predicate(prefix: &str) -> String {
    SESSION_WITH_CONTENT_PREDICATE_TEMPLATE.replace("{prefix}", prefix)
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

        sqlx::query(
            r#"
            INSERT INTO sessions (
                id, protocol, client_ip, client_port, server_ip, server_port,
                started_at, ended_at, status, packet_count, total_bytes,
                mail_from, rcpt_to, subject, content, email_count, error_reason, message_id, auth_info,
                sender_domain
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
            ON CONFLICT(id) DO UPDATE SET
                ended_at = excluded.ended_at,
                status = excluded.status,
                packet_count = excluded.packet_count,
                total_bytes = excluded.total_bytes,
                mail_from = COALESCE(excluded.mail_from, sessions.mail_from),
                sender_domain = COALESCE(excluded.sender_domain, sessions.sender_domain),
                rcpt_to = excluded.rcpt_to,
                subject = COALESCE(excluded.subject, sessions.subject),
                content = CASE
                    WHEN (sessions.content->>'body_text' IS NOT NULL
                       OR sessions.content->>'body_html' IS NOT NULL)
                      AND excluded.content->>'body_text' IS NULL
                      AND excluded.content->>'body_html' IS NULL
                    THEN sessions.content
                    ELSE excluded.content
                END,
                email_count = excluded.email_count,
                error_reason = excluded.error_reason,
                message_id = COALESCE(excluded.message_id, sessions.message_id),
                auth_info = COALESCE(excluded.auth_info, sessions.auth_info)
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
        .execute(&self.pool)
        .await?;

        Ok(is_new)
    }

   /// Update session
    pub async fn update_session(&self, session: &EmailSession) -> Result<()> {
        let rcpt_to = serde_json::to_string(&session.rcpt_to)?;
        let content = serde_json::to_value(&session.content)?;
       // Security: Password, skip_serializing (defense-in-depth)
        let auth_info = session.auth_info.as_ref().and_then(|a| {
            let mut safe = a.clone();
            safe.password = None;
            serde_json::to_value(&safe).ok()
        });

        let message_id = session.message_id.clone().or_else(|| {
            session
                .content
                .get_header("Message-ID")
                .map(|s| s.trim().to_string())
        });

        sqlx::query(
            r#"
            UPDATE sessions SET
                ended_at = $1,
                status = $2,
                packet_count = $3,
                total_bytes = $4,
                mail_from = COALESCE($5, sessions.mail_from),
                rcpt_to = CASE
                    WHEN $6 = '[]' AND sessions.rcpt_to != '[]'
                    THEN sessions.rcpt_to
                    ELSE $7
                END,
                subject = COALESCE($8, sessions.subject),
                content = CASE
                    WHEN (sessions.content->>'body_text' IS NOT NULL
                       OR sessions.content->>'body_html' IS NOT NULL)
                      AND ($9)->>'body_text' IS NULL
                      AND ($10)->>'body_html' IS NULL
                    THEN sessions.content
                    ELSE $11
                END,
                email_count = $12,
                error_reason = $13,
                message_id = COALESCE($14, sessions.message_id),
                auth_info = COALESCE($15, sessions.auth_info)
            WHERE id = $16
            "#,
        )
        .bind(session.ended_at.map(|t| t.to_rfc3339()))
        .bind(format!("{:?}", session.status))
        .bind(session.packet_count as i32)
        .bind(session.total_bytes as i64)
        .bind(&session.mail_from)
        .bind(&rcpt_to)
        .bind(&rcpt_to)
        .bind(&session.subject)
        .bind(&content)
        .bind(&content)
        .bind(&content)
        .bind(session.email_count as i32)
        .bind(&session.error_reason)
        .bind(&message_id)
        .bind(&auth_info)
        .bind(session.id.to_string())
        .execute(&self.pool)
        .await?;

        Ok(())
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
        let mut q = sqlx::query_as::<_, (String,)>(&query_str);
        for id in &ids {
            q = q.bind(id);
        }
        let existing_rows = q.fetch_all(&self.pool).await?;
        let existing_ids: std::collections::HashSet<String> =
            existing_rows.into_iter().map(|(id,)| id).collect();

       // Preprocessing: serialize all params (avoid serde errors in SQL build loop)
        const COLS_PER_ROW: usize = 19;
        const BATCH_CHUNK_SIZE: usize = 500; // 500 x 19 = 9500 params, well under 65535

        struct PreparedSession {
            id_str: String,
            protocol: &'static str,
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
            content: serde_json::Value,
            email_count: i32,
            error_reason: Option<String>,
            message_id: Option<String>,
            auth_info: Option<serde_json::Value>,
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
                    started_at, ended_at, status, packet_count, total_bytes, \
                    mail_from, rcpt_to, subject, content, email_count, error_reason, message_id, auth_info\
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
                }
                sql.push(')');
                param_idx += COLS_PER_ROW as u32;
            }

            sql.push_str(
                " ON CONFLICT(id) DO UPDATE SET \
                    ended_at = excluded.ended_at, \
                    status = excluded.status, \
                    packet_count = excluded.packet_count, \
                    total_bytes = excluded.total_bytes, \
                    mail_from = COALESCE(excluded.mail_from, sessions.mail_from), \
                    rcpt_to = excluded.rcpt_to, \
                    subject = COALESCE(excluded.subject, sessions.subject), \
                    content = CASE \
                        WHEN (sessions.content->>'body_text' IS NOT NULL \
                           OR sessions.content->>'body_html' IS NOT NULL) \
                          AND excluded.content->>'body_text' IS NULL \
                          AND excluded.content->>'body_html' IS NULL \
                        THEN sessions.content \
                        ELSE excluded.content \
                    END, \
                    email_count = excluded.email_count, \
                    error_reason = excluded.error_reason, \
                    message_id = COALESCE(excluded.message_id, sessions.message_id), \
                    auth_info = COALESCE(excluded.auth_info, sessions.auth_info)",
            );

            let mut query = sqlx::query(&sql);
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
                    .bind(&row.auth_info);
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
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info \
             FROM sessions WHERE id IN ({})",
            merged_placeholders
        );
        let mut mq = sqlx::query_as::<_, SessionRow>(&merged_query_str);
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
                    "(s.auth_info IS NOT NULL AND (s.auth_info->>'auth_success') = 'true')"
                        .to_string(),
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

       // 1. Count query (can skip: dashboard etc. dont need total count, save ~4.5s)
        let total = if skip_count {
            0
        } else {
            let count_query = format!("SELECT COUNT(*) FROM sessions s{}", where_clause);
            let mut cq = sqlx::query_scalar::<_, i64>(&count_query);
            for p in &params {
                cq = cq.bind(p);
            }
            cq.fetch_one(&self.pool).await.unwrap_or(0) as u64
        };

       // 2. PaginationDataQuery (: Load content, JSONB Extract metadata)
       // LEFT JOIN security_verdicts (threat_level)
        let limit_ph = format!("${}", param_idx);
        param_idx += 1;
        let offset_ph = format!("${}", param_idx);
       // not needed after last use

        let data_query = format!(
            "SELECT s.id, s.protocol, s.client_ip, s.client_port, s.server_ip, s.server_port, \
             s.started_at, s.ended_at, s.status, s.packet_count, s.total_bytes, \
             s.mail_from, s.rcpt_to, s.subject, \
             CASE WHEN s.content IS NOT NULL THEN \
               jsonb_build_object(\
                 'is_encrypted', CASE WHEN (s.content->>'is_encrypted') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'attachment_count', COALESCE(jsonb_array_length(s.content->'attachments'), 0), \
                 'is_complete', CASE WHEN (s.content->>'is_complete') = 'true' THEN 1::BIGINT ELSE 0::BIGINT END, \
                 'has_body', CASE WHEN s.content->>'body_text' IS NOT NULL \
                   OR s.content->>'body_html' IS NOT NULL THEN 1::BIGINT ELSE 0::BIGINT END \
               )::TEXT \
             ELSE NULL END AS content_summary, \
             s.email_count, s.error_reason, s.message_id, s.auth_info::TEXT as auth_info, \
             v.threat_level \
             FROM sessions s \
             LEFT JOIN security_verdicts v ON v.session_id = s.id{} \
             ORDER BY s.started_at DESC LIMIT {} OFFSET {}",
            where_clause, limit_ph, offset_ph
        );

        let mut q = sqlx::query_as::<_, SessionListRow>(&data_query);
        for p in &params {
            q = q.bind(p);
        }
        q = q.bind(limit as i32).bind(offset as i32);

        let rows: Vec<SessionListRow> = q.fetch_all(&self.pool).await?;

        let sessions: Vec<EmailSession> = rows
            .into_iter()
            .filter_map(|row| list_row_to_session(row).ok())
            .collect();

        Ok((sessions, total))
    }

   /// Query Security Session(Used for)
   /// session_id, According to, limit items
    pub async fn query_unanalyzed_sessions(
        &self,
        since: &str,
        limit: u32,
    ) -> Result<Vec<uuid::Uuid>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT s.id FROM sessions s \
             WHERE s.status = 'Completed' \
               AND s.started_at >= $1 \
               AND NOT EXISTS (SELECT 1 FROM security_verdicts v WHERE v.session_id = s.id) \
               AND (s.mail_from IS NOT NULL OR s.content->>'body_text' IS NOT NULL \
                    OR s.content->>'body_html' IS NOT NULL \
                    OR COALESCE(jsonb_array_length(s.content->'attachments'), 0) > 0 \
                    OR COALESCE(jsonb_array_length(s.content->'headers'), 0) > 0) \
             ORDER BY s.started_at DESC \
             LIMIT $2",
        )
        .bind(since)
        .bind(limit as i32)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(id,)| uuid::Uuid::parse_str(&id).ok())
            .collect())
    }

   /// QuerySenderDomain (Used forFirst communication)
   /// sender_domain + EXISTS Road, LIKE '%@domain'
    pub async fn count_sender_domain_history(
        &self,
        sender_domain: &str,
        exclude_session_id: &str,
    ) -> Result<i64> {
        let exists: (i64,) = sqlx::query_as(
            "SELECT CASE WHEN EXISTS( \
                SELECT 1 FROM sessions \
                WHERE sender_domain = $1 AND status = 'Completed' AND id != $2 \
                LIMIT 1 \
             ) THEN 1::BIGINT ELSE 0::BIGINT END",
        )
        .bind(sender_domain)
        .bind(exclude_session_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists.0)
    }

   /// Get Session
    pub async fn get_session(&self, id: Uuid) -> Result<Option<EmailSession>> {
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info \
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
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info \
             FROM sessions WHERE id IN ({})",
            placeholders
        );

        let mut q = sqlx::query_as::<_, SessionRow>(&query_str);
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
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info \
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
        let rows: Vec<SessionRow> = sqlx::query_as(
            "SELECT id, protocol, client_ip, client_port, server_ip, server_port, \
             started_at, ended_at, status, packet_count, total_bytes, \
             mail_from, rcpt_to, subject, content::TEXT as content, email_count, error_reason, message_id, auth_info::TEXT as auth_info \
             FROM sessions \
             WHERE id != $1 \
               AND client_ip = $2 \
               AND mail_from IS NOT DISTINCT FROM $3 \
               AND rcpt_to = $4 \
               AND started_at::timestamptz >= $5::timestamptz \
               AND started_at::timestamptz <= $6::timestamptz \
             ORDER BY started_at::timestamptz ASC"
        )
        .bind(exclude_id.to_string())
        .bind(&session.server_ip)
        .bind(&session.mail_from)
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
        source: SessionSource::default(),
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
           // attachment,.length
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
        source: SessionSource::default(),
    })
}
