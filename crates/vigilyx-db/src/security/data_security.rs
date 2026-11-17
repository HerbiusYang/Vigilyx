//! Data securityModuleData

//! For HTTP Session Data security Query.

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use vigilyx_core::{
    DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity, DataSecurityStats,
    EmailAuditClass, EmailDataSecurityReview, EmailDataSecurityStats, EmailDlpResult,
    EmailInspectionStatus, EmailReviewAction, EmailReviewDirection, HourlyBucket, HttpMethod,
    HttpSession, SessionSource, magic_bytes::DetectedFileType,
};

use crate::VigilDb;

/// HTTP Session items
#[derive(Debug, Default)]
pub struct HttpSessionFilters {
    /// IP
    pub client_ip: Option<String>,

    pub user: Option<String>,
    /// HTTP
    pub method: Option<String>,
    /// URL/URI
    pub keyword: Option<String>,
}

/// Filters for the unified outbound email review workbench.
#[derive(Debug, Default)]
pub struct EmailReviewFilters {
    pub source: Option<String>,
    pub direction: Option<String>,
    pub audit_class: Option<String>,
    pub inspection_status: Option<String>,
    pub dlp_result: Option<String>,
    pub action: Option<String>,
    pub max_jrt_level: Option<u8>,
    pub sender_or_domain: Option<String>,
    pub keyword: Option<String>,
    pub since: Option<String>,
}

impl VigilDb {
    /// Return the durable, all-time data-security engine counters.
    ///
    /// A successfully stored HTTP session is the durable completion record for
    /// the data-security pipeline; incidents are counted only after they have
    /// been persisted. Keeping these counts derived from their source tables
    /// avoids a second mutable counter that can drift after retries or restarts.
    pub async fn get_data_security_engine_totals(&self) -> Result<(u64, u64)> {
        let db = self.clone();
        self.data_security_totals_cache
            .get(move || async move { db.query_data_security_engine_totals().await })
            .await
    }

    async fn query_data_security_engine_totals(&self) -> Result<(u64, u64)> {
        let (sessions, incidents): (i64, i64) = sqlx::query_as(
            r#"
            SELECT
                (SELECT COUNT(*) FROM data_security_http_sessions),
                (SELECT COUNT(*) FROM data_security_incidents)
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok((sessions as u64, incidents as u64))
    }

    /// Data security
    pub async fn init_data_security_tables(&self) -> Result<()> {
        // HTTP Session
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS data_security_http_sessions (
                id TEXT PRIMARY KEY,
                client_ip TEXT NOT NULL,
                client_port BIGINT NOT NULL,
                server_ip TEXT NOT NULL,
                server_port BIGINT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                host TEXT,
                content_type TEXT,
                request_body_size BIGINT NOT NULL DEFAULT 0,
                request_body TEXT,
                response_status BIGINT,
                uploaded_filename TEXT,
                uploaded_file_size BIGINT,
                detected_user TEXT,
                detected_recipients TEXT NOT NULL DEFAULT '[]',
                detected_sender TEXT,
                timestamp TEXT NOT NULL,
                network_session_id TEXT,
                detected_file_type TEXT,
                body_is_binary BOOLEAN NOT NULL DEFAULT FALSE,
                file_type_mismatch TEXT,
                has_gaps BOOLEAN NOT NULL DEFAULT FALSE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // has_gaps ()
        sqlx::query(
            "ALTER TABLE data_security_http_sessions ADD COLUMN IF NOT EXISTS has_gaps BOOLEAN NOT NULL DEFAULT FALSE",
        )
        .execute(&self.pool)
        .await
        .ok();

        // Data security
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS data_security_incidents (
                id TEXT PRIMARY KEY,
                http_session_id TEXT NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence DOUBLE PRECISION NOT NULL,
                summary TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '[]',
                details TEXT,
                dlp_matches TEXT NOT NULL DEFAULT '[]',
                client_ip TEXT NOT NULL,
                detected_user TEXT,
                request_url TEXT NOT NULL DEFAULT '',
                host TEXT,
                method TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Unified SMTP outbound review records. This is deliberately separate
        // from data_security_incidents, whose contract is HTTP-specific.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS data_security_email_reviews (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT 'sniffer',
                mail_direction TEXT NOT NULL DEFAULT 'unknown',
                audit_class TEXT NOT NULL DEFAULT 'legacy',
                direction_reason TEXT,
                inspection_reason TEXT,
                inspection_status TEXT NOT NULL DEFAULT 'failed',
                dlp_result TEXT NOT NULL DEFAULT 'unknown',
                max_jrt_level INTEGER,
                dlp_matches TEXT NOT NULL DEFAULT '[]',
                dlp_details TEXT,
                action TEXT NOT NULL DEFAULT 'audit',
                delivery_status TEXT,
                quarantine_id TEXT,
                verdict_id TEXT,
                client_ip TEXT NOT NULL DEFAULT '',
                mail_from TEXT,
                external_recipient_domains TEXT NOT NULL DEFAULT '[]',
                recipient_count INTEGER NOT NULL DEFAULT 0,
                subject TEXT,
                content_hash TEXT,
                attachment_count INTEGER NOT NULL DEFAULT 0,
                attachments_scanned INTEGER NOT NULL DEFAULT 0,
                attachment_inspection_complete BOOLEAN NOT NULL DEFAULT FALSE,
                encrypted BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // The audit class is a separate coverage/classification axis.  A
        // source may be untrusted while its envelope still proves
        // internal-to-external delivery, so never derive audit coverage from
        // source trust.
        sqlx::query(
            "ALTER TABLE data_security_email_reviews \
             ADD COLUMN IF NOT EXISTS audit_class TEXT NOT NULL DEFAULT 'legacy'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE data_security_email_reviews \
             SET audit_class = CASE \
                 WHEN mail_direction = 'outbound' THEN 'confirmed_outbound' \
                 WHEN mail_direction = 'unknown' \
                      AND COALESCE(external_recipient_domains, '[]') NOT IN ('[]', '') \
                     THEN 'outbound_candidate' \
                 WHEN mail_direction = 'unknown' THEN 'attribution_pending' \
                 ELSE 'legacy' \
             END \
             WHERE audit_class IS NULL OR audit_class = 'legacy'",
        )
        .execute(&self.pool)
        .await?;

        // Older mirror rows used `failed` as a placeholder while the full
        // content scan had not run yet. Keep those records visible, but label
        // them as incomplete coverage instead of a scanner failure.
        sqlx::query(
            "ALTER TABLE data_security_email_reviews \
             ADD COLUMN IF NOT EXISTS inspection_reason TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE data_security_email_reviews \
             SET inspection_status = 'incomplete', inspection_reason = COALESCE(inspection_reason, 'content_scan_not_run') \
             WHERE source = 'sniffer' AND delivery_status = 'mirror_audit' \
               AND inspection_status = 'failed' AND dlp_result = 'unknown'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE data_security_email_reviews \
             SET inspection_reason = COALESCE(inspection_reason, 'capture_incomplete') \
             WHERE source = 'sniffer' AND delivery_status = 'mirror_audit' \
               AND inspection_status = 'incomplete'",
        )
        .execute(&self.pool)
        .await?;
        // Historical rows could contain an explicit capture/parser coverage
        // reason while still carrying the old `inspected` label.  Preserve
        // their DLP evidence, but repair the contradictory coverage axis.
        sqlx::query(
            "UPDATE data_security_email_reviews \
             SET inspection_status = 'incomplete' \
             WHERE inspection_status = 'inspected' \
               AND inspection_reason IS NOT NULL \
               AND TRIM(inspection_reason) <> ''",
        )
        .execute(&self.pool)
        .await?;

        // Index
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_type ON data_security_incidents(incident_type)",
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_severity ON data_security_incidents(severity)",
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_created ON data_security_incidents(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_user ON data_security_incidents(detected_user)",
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_http_session ON data_security_incidents(http_session_id)",
            // Index: type+severity + Query
            "CREATE INDEX IF NOT EXISTS idx_ds_incidents_type_sev_created ON data_security_incidents(incident_type, severity, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_http_sessions_ts ON data_security_http_sessions(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_http_sessions_user ON data_security_http_sessions(detected_user)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_created ON data_security_email_reviews(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_direction_created ON data_security_email_reviews(mail_direction, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_audit_class_created ON data_security_email_reviews(audit_class, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_source_created ON data_security_email_reviews(source, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_status ON data_security_email_reviews(inspection_status)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_action ON data_security_email_reviews(action)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_session ON data_security_email_reviews(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_ds_email_reviews_jrt ON data_security_email_reviews(max_jrt_level)",
        ];

        for idx_sql in indexes {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }

        Ok(())
    }

    // HTTP Session CRUD

    /// HTTP Session
    pub async fn insert_http_session(&self, session: &HttpSession) -> Result<()> {
        let recipients = serde_json::to_string(&session.detected_recipients)?;
        let file_type_str = session
            .detected_file_type
            .map(|ft| ft.display_name().to_string());
        // PostgreSQL TEXT columns cannot contain NULL bytes (0x00); strip them from request_body
        let sanitized_body = session.request_body.as_deref().map(|s| s.replace('\0', ""));
        sqlx::query(
            r#"
            INSERT INTO data_security_http_sessions
                (id, client_ip, client_port, server_ip, server_port,
                 method, uri, host, content_type, request_body_size,
                 request_body, response_status, uploaded_filename,
                 uploaded_file_size, detected_user, detected_recipients,
                 detected_sender, detected_file_type, body_is_binary,
                 file_type_mismatch, has_gaps, timestamp, network_session_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17, $18, $19,
                    $20, $21, $22, $23)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(session.id.to_string())
        .bind(&session.client_ip)
        .bind(session.client_port as i64)
        .bind(&session.server_ip)
        .bind(session.server_port as i64)
        .bind(session.method.to_string())
        // Defense in depth: imports and rolling-upgrade producers may not have
        // applied the capture-boundary sanitizer yet.
        .bind(vigilyx_core::redact_http_uri(&session.uri))
        .bind(&session.host)
        .bind(&session.content_type)
        .bind(session.request_body_size as i64)
        .bind(&sanitized_body)
        .bind(session.response_status.map(|s| s as i64))
        .bind(&session.uploaded_filename)
        .bind(session.uploaded_file_size.map(|s| s as i64))
        .bind(&session.detected_user)
        .bind(&recipients)
        .bind(&session.detected_sender)
        .bind(&file_type_str)
        .bind(session.body_is_binary)
        .bind(&session.file_type_mismatch)
        .bind(session.has_gaps)
        .bind(session.timestamp.to_rfc3339())
        .bind(session.network_session_id.map(|id| id.to_string()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query HTTP Session
    pub async fn get_http_session(&self, id: Uuid) -> Result<Option<HttpSession>> {
        let row: Option<HttpSessionRow> =
            sqlx::query_as("SELECT * FROM data_security_http_sessions WHERE id = $1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.into()))
    }

    /// PaginationQuery HTTP Session
    ///
    /// QueryExclude request_body Transmission,body get_http_session() items.
    pub async fn list_http_sessions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<HttpSession>, u64)> {
        let count_row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM data_security_http_sessions")
            .fetch_one(&self.pool)
            .await?;

        let rows: Vec<HttpSessionListRow> = sqlx::query_as(
            r#"SELECT id, client_ip, client_port, server_ip, server_port,
                      method, uri, host, content_type, request_body_size,
                      response_status, uploaded_filename, uploaded_file_size,
                      detected_user, detected_recipients, detected_sender,
                      detected_file_type, body_is_binary, file_type_mismatch,
                      timestamp, network_session_id
               FROM data_security_http_sessions
               ORDER BY timestamp DESC LIMIT $1 OFFSET $2"#,
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        let sessions: Vec<HttpSession> = rows.into_iter().map(|r| r.into()).collect();
        Ok((sessions, count_row.0 as u64))
    }

    /// PaginationQuery HTTP Session
    ///
    /// According to IP,, HTTP URL.
    /// QueryExclude request_body Transmission.
    pub async fn list_http_sessions_filtered(
        &self,
        filters: &HttpSessionFilters,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<HttpSession>, u64)> {
        // Build WHERE, param_idx $N
        let mut conditions: Vec<String> = Vec::new();
        let mut bind_values: Vec<String> = Vec::new();
        let mut param_idx: usize = 0;

        if let Some(ref ip) = filters.client_ip {
            param_idx += 1;
            conditions.push(format!("client_ip LIKE ${}", param_idx));
            bind_values.push(format!("%{}%", ip));
        }
        if let Some(ref user) = filters.user {
            param_idx += 1;
            conditions.push(format!("detected_user LIKE ${}", param_idx));
            bind_values.push(format!("%{}%", user));
        }
        if let Some(ref method) = filters.method {
            param_idx += 1;
            conditions.push(format!("method = ${}", param_idx));
            bind_values.push(method.to_uppercase());
        }
        if let Some(ref kw) = filters.keyword {
            param_idx += 1;
            let p1 = param_idx;
            param_idx += 1;
            let p2 = param_idx;
            conditions.push(format!("(uri LIKE ${} OR host LIKE ${})", p1, p2));
            let pattern = format!("%{}%", kw);
            bind_values.push(pattern.clone());
            bind_values.push(pattern);
        }

        let where_sql = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        // COUNT Query
        let count_sql = format!(
            "SELECT COUNT(*) FROM data_security_http_sessions {}",
            where_sql
        );
        let mut count_query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(count_sql.as_str()));
        for v in &bind_values {
            count_query = count_query.bind(v);
        }
        let count_row = count_query.fetch_one(&self.pool).await?;

        // DataQuery (bind Index WHERE)
        param_idx += 1;
        let limit_idx = param_idx;
        param_idx += 1;
        let offset_idx = param_idx;
        let list_sql = format!(
            r#"SELECT id, client_ip, client_port, server_ip, server_port,
                      method, uri, host, content_type, request_body_size,
                      response_status, uploaded_filename, uploaded_file_size,
                      detected_user, detected_recipients, detected_sender,
                      detected_file_type, body_is_binary, file_type_mismatch,
                      has_gaps, timestamp, network_session_id
               FROM data_security_http_sessions {}
               ORDER BY timestamp DESC LIMIT ${} OFFSET ${}"#,
            where_sql, limit_idx, offset_idx
        );
        let mut list_query =
            sqlx::query_as::<_, HttpSessionListRow>(sqlx::AssertSqlSafe(list_sql.as_str()));
        for v in &bind_values {
            list_query = list_query.bind(v);
        }
        list_query = list_query.bind(limit as i64).bind(offset as i64);
        let rows = list_query.fetch_all(&self.pool).await?;

        let sessions: Vec<HttpSession> = rows.into_iter().map(|r| r.into()).collect();
        Ok((sessions, count_row.0 as u64))
    }

    /// client_ip 2
    ///
    /// :When file upload From Cookie/body Extract,
    /// 1 IP HTTP Session(Such as compose.jsp).
    pub async fn lookup_user_by_client_ip(&self, client_ip: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"SELECT detected_user FROM data_security_http_sessions
               WHERE client_ip = $1
                 AND detected_user IS NOT NULL
                 AND detected_user != ''
                 AND timestamp > NOW() - INTERVAL '2 hours'
               ORDER BY timestamp DESC
               LIMIT 1"#,
        )
        .bind(client_ip)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.0))
    }

    // Data security CRUD

    /// Data security
    pub async fn insert_data_security_incident(
        &self,
        incident: &DataSecurityIncident,
    ) -> Result<bool> {
        let evidence = serde_json::to_string(&incident.evidence)?;
        let details = incident
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "null".to_string());
        let dlp_matches = serde_json::to_string(&incident.dlp_matches)?;

        let result = sqlx::query(
            r#"
            INSERT INTO data_security_incidents
                (id, http_session_id, incident_type, severity, confidence,
                 summary, evidence, details, dlp_matches, client_ip,
                 detected_user, request_url, host, method, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .bind(incident.id.to_string())
        .bind(incident.http_session_id.to_string())
        .bind(incident.incident_type.to_string())
        .bind(incident.severity.to_string())
        .bind(incident.confidence)
        .bind(&incident.summary)
        .bind(&evidence)
        .bind(&details)
        .bind(&dlp_matches)
        .bind(&incident.client_ip)
        .bind(&incident.detected_user)
        .bind(vigilyx_core::redact_http_uri(&incident.request_url))
        .bind(&incident.host)
        .bind(&incident.method)
        .bind(incident.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// QueryData security
    #[allow(clippy::too_many_arguments)]
    pub async fn list_data_security_incidents(
        &self,
        incident_type: Option<&str>,
        severity: Option<&str>,
        client_ip: Option<&str>,
        user: Option<&str>,
        keyword: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<DataSecurityIncident>, u64)> {
        // Build WHERE, param_idx $N
        let mut where_clauses = Vec::new();
        let mut param_idx: usize = 0;

        if incident_type.is_some() {
            param_idx += 1;
            where_clauses.push(format!("incident_type = ${}", param_idx));
        }
        if severity.is_some() {
            param_idx += 1;
            where_clauses.push(format!("severity = ${}", param_idx));
        }
        if client_ip.is_some() {
            param_idx += 1;
            where_clauses.push(format!("client_ip LIKE ${}", param_idx));
        }
        if user.is_some() {
            param_idx += 1;
            where_clauses.push(format!("detected_user LIKE ${}", param_idx));
        }
        if keyword.is_some() {
            param_idx += 1;
            where_clauses.push(format!("summary LIKE ${}", param_idx));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        param_idx += 1;
        let limit_idx = param_idx;
        param_idx += 1;
        let offset_idx = param_idx;

        let count_sql = format!(
            "SELECT COUNT(*) as count FROM data_security_incidents {}",
            where_sql
        );
        let list_sql = format!(
            "SELECT * FROM data_security_incidents {} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            where_sql, limit_idx, offset_idx
        );

        // :Build LIKE Mode
        let client_ip_pattern = client_ip.map(|v| format!("%{}%", v));
        let user_pattern = user.map(|v| format!("%{}%", v));
        let keyword_pattern = keyword.map(|v| format!("%{}%", v));

        let mut count_query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(count_sql.as_str()));
        if let Some(it) = incident_type {
            count_query = count_query.bind(it);
        }
        if let Some(sv) = severity {
            count_query = count_query.bind(sv);
        }
        if let Some(ref p) = client_ip_pattern {
            count_query = count_query.bind(p.as_str());
        }
        if let Some(ref p) = user_pattern {
            count_query = count_query.bind(p.as_str());
        }
        if let Some(ref p) = keyword_pattern {
            count_query = count_query.bind(p.as_str());
        }
        let count_row = count_query.fetch_one(&self.pool).await?;

        let mut list_query =
            sqlx::query_as::<_, IncidentRow>(sqlx::AssertSqlSafe(list_sql.as_str()));
        if let Some(it) = incident_type {
            list_query = list_query.bind(it);
        }
        if let Some(sv) = severity {
            list_query = list_query.bind(sv);
        }
        if let Some(ref p) = client_ip_pattern {
            list_query = list_query.bind(p.as_str());
        }
        if let Some(ref p) = user_pattern {
            list_query = list_query.bind(p.as_str());
        }
        if let Some(ref p) = keyword_pattern {
            list_query = list_query.bind(p.as_str());
        }
        list_query = list_query.bind(limit as i64).bind(offset as i64);
        let rows = list_query.fetch_all(&self.pool).await?;

        let incidents: Vec<DataSecurityIncident> = rows.into_iter().map(|r| r.into()).collect();

        Ok((incidents, count_row.0 as u64))
    }

    /// Query Data security
    pub async fn get_data_security_incident(
        &self,
        id: Uuid,
    ) -> Result<Option<DataSecurityIncident>> {
        let row: Option<IncidentRow> =
            sqlx::query_as("SELECT * FROM data_security_incidents WHERE id = $1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.into()))
    }

    /// Data securityStatistics
    ///
    /// items SQL Query COUNT Query, Data.
    pub async fn get_data_security_stats(&self) -> Result<DataSecurityStats> {
        let db = self.clone();
        self.data_security_stats_cache
            .get(move || async move { db.query_data_security_stats().await })
            .await
    }

    async fn query_data_security_stats(&self) -> Result<DataSecurityStats> {
        let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

        // items Query:According toType + 24h
        let row: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN incident_type = 'draft_box_abuse' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'file_transit_abuse' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'self_sending' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'volume_anomaly' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') AND created_at >= $1 THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'jrt_compliance_violation' THEN 1 ELSE 0 END), 0)::BIGINT,
                COUNT(*) FILTER (WHERE incident_type = 'sensitive_data_transfer'),
                COUNT(*) FILTER (WHERE incident_type = 'bulk_sensitive_transfer')
            FROM data_security_incidents
            "#,
        )
        .bind(&cutoff)
        .fetch_one(&self.pool)
        .await?;

        // According to (2itemsQuery, Merge SUM key)
        let severity_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT severity, COUNT(*) FROM data_security_incidents GROUP BY severity",
        )
        .fetch_all(&self.pool)
        .await?;

        let incidents_by_severity = severity_rows
            .into_iter()
            .map(|(k, v)| (k, v as u64))
            .collect();

        // 24h HTTP Session (According toSunday +, Asia/Shanghai District)
        // hour: "MM-DD HH:00" Used for, According to
        let hourly_rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT TO_CHAR((timestamp::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00') as hour, COUNT(*) as cnt
            FROM data_security_http_sessions
            WHERE timestamp >= $1
            GROUP BY TO_CHAR((timestamp::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00')
            ORDER BY hour ASC
            "#,
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        let hourly_sessions: Vec<HourlyBucket> = hourly_rows
            .into_iter()
            .map(|(hour, count)| HourlyBucket {
                hour,
                count: count as u64,
            })
            .collect();

        // 24h Security (According toSunday +, Asia/Shanghai District)
        let hourly_incident_rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT TO_CHAR((created_at::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00') as hour, COUNT(*) as cnt
            FROM data_security_incidents
            WHERE created_at >= $1
            GROUP BY TO_CHAR((created_at::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00')
            ORDER BY hour ASC
            "#,
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        let hourly_incidents: Vec<HourlyBucket> = hourly_incident_rows
            .into_iter()
            .map(|(hour, count)| HourlyBucket {
                hour,
                count: count as u64,
            })
            .collect();

        // 24h email reviews (same window and Asia/Shanghai labels as the
        // existing HTTP and incident series). Keep this independent from
        // HTTP session and incident totals so each line retains its meaning.
        let hourly_email_review_rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT TO_CHAR((created_at::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00') as hour, COUNT(*) as cnt
            FROM data_security_email_reviews
            WHERE created_at >= $1
              AND mail_direction IN ('outbound', 'unknown')
            GROUP BY TO_CHAR((created_at::timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Shanghai', 'MM-DD HH24:00')
            ORDER BY hour ASC
            "#,
        )
        .bind(&cutoff)
        .fetch_all(&self.pool)
        .await?;

        let hourly_email_reviews: Vec<HourlyBucket> = hourly_email_review_rows
            .into_iter()
            .map(|(hour, count)| HourlyBucket {
                hour,
                count: count as u64,
            })
            .collect();

        Ok(DataSecurityStats {
            total_incidents: row.0 as u64,
            draft_abuse_count: row.1 as u64,
            file_transit_count: row.2 as u64,
            self_send_count: row.3 as u64,
            volume_anomaly_count: row.4 as u64,
            jrt_compliance_count: row.6 as u64,
            sensitive_transfer_count: row.7 as u64,
            bulk_transfer_count: row.8 as u64,
            high_severity_24h: row.5 as u64,
            incidents_by_severity,
            hourly_sessions,
            hourly_email_reviews,
            hourly_incidents,
        })
    }

    /// Insert or update one email data-security review.
    ///
    /// The database boundary applies a second redaction pass so callers cannot
    /// accidentally persist full mailbox addresses, subjects, or raw DLP
    /// evidence in the review table.
    pub async fn upsert_email_data_security_review(
        &self,
        review: &EmailDataSecurityReview,
    ) -> Result<()> {
        if review.dedupe_key.trim().is_empty() {
            anyhow::bail!("email review dedupe_key must not be empty");
        }

        let dlp_matches = serde_json::to_string(&review.dlp_matches)?;
        let dlp_details = review.dlp_details.as_ref().map(redact_dlp_details);
        let dlp_details = dlp_details.map(|value| value.to_string());
        let recipient_domains = serde_json::to_string(
            &review
                .external_recipient_domains
                .iter()
                .map(|domain| domain.trim().to_ascii_lowercase())
                .filter(|domain| !domain.is_empty())
                .take(100)
                .collect::<Vec<_>>(),
        )?;
        let mail_from = review.mail_from.as_deref().map(mask_email_address);
        let subject = review.subject.as_deref().map(|_| "[REDACTED]".to_string());

        sqlx::query(
            r#"
            INSERT INTO data_security_email_reviews (
                id, session_id, dedupe_key, source, mail_direction, audit_class,
                direction_reason, inspection_reason, inspection_status, dlp_result, max_jrt_level,
                dlp_matches, dlp_details, action, delivery_status, quarantine_id,
                verdict_id, client_ip, mail_from, external_recipient_domains,
                recipient_count, subject, content_hash, attachment_count,
                attachments_scanned, attachment_inspection_complete, encrypted,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27,
                $28, $29
            )
            ON CONFLICT (dedupe_key) DO UPDATE SET
                source = EXCLUDED.source,
                mail_direction = EXCLUDED.mail_direction,
                audit_class = EXCLUDED.audit_class,
                direction_reason = EXCLUDED.direction_reason,
                inspection_reason = EXCLUDED.inspection_reason,
                inspection_status = EXCLUDED.inspection_status,
                dlp_result = EXCLUDED.dlp_result,
                max_jrt_level = EXCLUDED.max_jrt_level,
                dlp_matches = EXCLUDED.dlp_matches,
                dlp_details = EXCLUDED.dlp_details,
                action = EXCLUDED.action,
                delivery_status = EXCLUDED.delivery_status,
                quarantine_id = EXCLUDED.quarantine_id,
                verdict_id = EXCLUDED.verdict_id,
                client_ip = EXCLUDED.client_ip,
                mail_from = EXCLUDED.mail_from,
                external_recipient_domains = EXCLUDED.external_recipient_domains,
                recipient_count = EXCLUDED.recipient_count,
                subject = EXCLUDED.subject,
                content_hash = EXCLUDED.content_hash,
                attachment_count = EXCLUDED.attachment_count,
                attachments_scanned = EXCLUDED.attachments_scanned,
                attachment_inspection_complete = EXCLUDED.attachment_inspection_complete,
                encrypted = EXCLUDED.encrypted,
                updated_at = EXCLUDED.updated_at
            WHERE NOT (
                COALESCE(EXCLUDED.inspection_reason, '') LIKE '%content_scan_not_run%'
                AND COALESCE(data_security_email_reviews.inspection_reason, '') NOT LIKE '%content_scan_not_run%'
                AND data_security_email_reviews.inspection_status <> 'failed'
            )
            "#,
        )
        .bind(review.id.to_string())
        .bind(review.session_id.to_string())
        .bind(&review.dedupe_key)
        .bind(review.source.to_string())
        .bind(review.direction.to_string())
        .bind(review.audit_class.to_string())
        .bind(&review.direction_reason)
        .bind(&review.inspection_reason)
        .bind(review.inspection_status.to_string())
        .bind(review.dlp_result.to_string())
        .bind(review.max_jrt_level.map(i32::from))
        .bind(&dlp_matches)
        .bind(&dlp_details)
        .bind(review.action.to_string())
        .bind(&review.delivery_status)
        .bind(&review.quarantine_id)
        .bind(review.verdict_id.map(|id| id.to_string()))
        .bind(&review.client_ip)
        .bind(&mail_from)
        .bind(&recipient_domains)
        .bind(review.recipient_count as i32)
        .bind(&subject)
        .bind(&review.content_hash)
        .bind(review.attachment_count as i32)
        .bind(review.attachments_scanned as i32)
        .bind(review.attachment_inspection_complete)
        .bind(review.encrypted)
        .bind(review.created_at.to_rfc3339())
        .bind(review.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get one email review by its public identifier.
    pub async fn get_email_data_security_review(
        &self,
        id: Uuid,
    ) -> Result<Option<EmailDataSecurityReview>> {
        let row: Option<EmailReviewRow> =
            sqlx::query_as("SELECT * FROM data_security_email_reviews WHERE id = $1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(EmailReviewRow::into_review))
    }

    /// List outbound email reviews with bounded, parameterized filters.
    pub async fn list_email_data_security_reviews(
        &self,
        filters: &EmailReviewFilters,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<EmailDataSecurityReview>, u64)> {
        let mut where_clauses = Vec::<String>::new();
        let mut bind_values = Vec::<String>::new();

        if let Some(value) = filters.source.as_deref().filter(|v| !v.trim().is_empty()) {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("source = ${}", bind_values.len()));
        }
        if let Some(value) = filters
            .direction
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("mail_direction = ${}", bind_values.len()));
        }
        if let Some(value) = filters
            .audit_class
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("audit_class = ${}", bind_values.len()));
        }
        if let Some(value) = filters
            .inspection_status
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("inspection_status = ${}", bind_values.len()));
        }
        if let Some(value) = filters
            .dlp_result
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("dlp_result = ${}", bind_values.len()));
        }
        if let Some(value) = filters.action.as_deref().filter(|v| !v.trim().is_empty()) {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("action = ${}", bind_values.len()));
        }
        if let Some(level) = filters.max_jrt_level {
            bind_values.push(level.to_string());
            where_clauses.push(format!("max_jrt_level >= ${}::INTEGER", bind_values.len()));
        }
        if let Some(value) = filters
            .sender_or_domain
            .as_deref()
            .filter(|v| !v.trim().is_empty())
        {
            bind_values.push(format!("%{}%", value.trim()));
            where_clauses.push(format!(
                "(mail_from LIKE ${0} OR external_recipient_domains LIKE ${0})",
                bind_values.len()
            ));
        }
        if let Some(value) = filters.keyword.as_deref().filter(|v| !v.trim().is_empty()) {
            bind_values.push(format!("%{}%", value.trim()));
            where_clauses.push(format!(
                "(client_ip LIKE ${0} OR mail_from LIKE ${0} OR subject LIKE ${0} OR dlp_matches LIKE ${0})",
                bind_values.len()
            ));
        }
        if let Some(value) = filters.since.as_deref().filter(|v| !v.trim().is_empty()) {
            bind_values.push(value.trim().to_string());
            where_clauses.push(format!("created_at >= ${}", bind_values.len()));
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        let count_sql = format!(
            "SELECT COUNT(*) FROM data_security_email_reviews {}",
            where_sql
        );
        let list_param_start = bind_values.len();
        let list_sql = format!(
            "SELECT * FROM data_security_email_reviews {} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            where_sql,
            list_param_start + 1,
            list_param_start + 2
        );

        let mut count_query = sqlx::query_as::<_, (i64,)>(sqlx::AssertSqlSafe(count_sql.as_str()));
        for value in &bind_values {
            count_query = count_query.bind(value);
        }
        let count = count_query.fetch_one(&self.pool).await?.0 as u64;

        let mut list_query =
            sqlx::query_as::<_, EmailReviewRow>(sqlx::AssertSqlSafe(list_sql.as_str()));
        for value in &bind_values {
            list_query = list_query.bind(value);
        }
        let rows = list_query
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?;

        Ok((
            rows.into_iter().map(EmailReviewRow::into_review).collect(),
            count,
        ))
    }

    /// Aggregate outbound email inspection coverage and enforcement outcomes.
    pub async fn get_email_data_security_stats(&self) -> Result<EmailDataSecurityStats> {
        let db = self.clone();
        self.email_review_stats_cache
            .get(move || async move { db.query_email_data_security_stats().await })
            .await
    }

    async fn query_email_data_security_stats(&self) -> Result<EmailDataSecurityStats> {
        let row: EmailReviewStatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE inspection_status = 'inspected') AS inspected,
                COUNT(*) FILTER (WHERE inspection_status = 'encrypted') AS encrypted,
                COUNT(*) FILTER (WHERE inspection_status = 'incomplete') AS incomplete,
                COUNT(*) FILTER (WHERE inspection_status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE dlp_result = 'hit') AS dlp_hits,
                COUNT(*) FILTER (WHERE action = 'quarantine') AS quarantined,
                COUNT(*) FILTER (WHERE action = 'block') AS blocked,
                COUNT(*) FILTER (WHERE action = 'reject') AS rejected,
                COUNT(*) FILTER (WHERE mail_direction = 'unknown') AS unknown_direction,
                COUNT(*) FILTER (WHERE audit_class = 'confirmed_outbound') AS confirmed_outbound,
                COUNT(*) FILTER (WHERE audit_class = 'outbound_candidate') AS outbound_candidates,
                COUNT(*) FILTER (WHERE audit_class = 'attribution_pending') AS attribution_pending,
                COUNT(*) FILTER (WHERE inspection_status IN ('encrypted', 'incomplete', 'failed')) AS incomplete_sessions
            FROM data_security_email_reviews
            WHERE mail_direction IN ('outbound', 'unknown')
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(EmailDataSecurityStats {
            total: row.total as u64,
            inspected: row.inspected as u64,
            encrypted: row.encrypted as u64,
            incomplete: row.incomplete as u64,
            failed: row.failed as u64,
            dlp_hits: row.dlp_hits as u64,
            quarantined: row.quarantined as u64,
            blocked: row.blocked as u64,
            rejected: row.rejected as u64,
            unknown_direction: row.unknown_direction as u64,
            confirmed_outbound: row.confirmed_outbound as u64,
            outbound_candidates: row.outbound_candidates as u64,
            attribution_pending: row.attribution_pending as u64,
            incomplete_sessions: row.incomplete_sessions as u64,
        })
    }
}

#[derive(sqlx::FromRow)]
struct EmailReviewStatsRow {
    total: i64,
    inspected: i64,
    encrypted: i64,
    incomplete: i64,
    failed: i64,
    dlp_hits: i64,
    quarantined: i64,
    blocked: i64,
    rejected: i64,
    unknown_direction: i64,
    confirmed_outbound: i64,
    outbound_candidates: i64,
    attribution_pending: i64,
    incomplete_sessions: i64,
}

#[derive(sqlx::FromRow)]
struct EmailReviewRow {
    id: String,
    session_id: String,
    dedupe_key: String,
    source: String,
    mail_direction: String,
    audit_class: String,
    direction_reason: Option<String>,
    inspection_reason: Option<String>,
    inspection_status: String,
    dlp_result: String,
    max_jrt_level: Option<i32>,
    dlp_matches: String,
    dlp_details: Option<String>,
    action: String,
    delivery_status: Option<String>,
    quarantine_id: Option<String>,
    verdict_id: Option<String>,
    client_ip: String,
    mail_from: Option<String>,
    external_recipient_domains: String,
    recipient_count: i32,
    subject: Option<String>,
    content_hash: Option<String>,
    attachment_count: i32,
    attachments_scanned: i32,
    attachment_inspection_complete: bool,
    encrypted: bool,
    created_at: String,
    updated_at: String,
}

impl EmailReviewRow {
    fn into_review(self) -> EmailDataSecurityReview {
        EmailDataSecurityReview {
            id: parse_uuid_or_default(&self.id),
            session_id: parse_uuid_or_default(&self.session_id),
            dedupe_key: self.dedupe_key,
            source: parse_review_source(&self.source),
            direction: parse_email_review_direction(&self.mail_direction),
            audit_class: parse_email_audit_class(&self.audit_class),
            direction_reason: self.direction_reason,
            inspection_reason: self.inspection_reason,
            inspection_status: parse_email_inspection_status(&self.inspection_status),
            dlp_result: parse_email_dlp_result(&self.dlp_result),
            max_jrt_level: self
                .max_jrt_level
                .and_then(|value| u8::try_from(value).ok()),
            dlp_matches: serde_json::from_str(&self.dlp_matches).unwrap_or_default(),
            dlp_details: self
                .dlp_details
                .and_then(|value| serde_json::from_str(&value).ok()),
            action: parse_email_review_action(&self.action),
            delivery_status: self.delivery_status,
            quarantine_id: self.quarantine_id,
            verdict_id: self
                .verdict_id
                .and_then(|value| Uuid::parse_str(&value).ok()),
            client_ip: self.client_ip,
            mail_from: self.mail_from,
            external_recipient_domains: serde_json::from_str(&self.external_recipient_domains)
                .unwrap_or_default(),
            recipient_count: self.recipient_count.max(0) as u32,
            subject: self.subject,
            content_hash: self.content_hash,
            attachment_count: self.attachment_count.max(0) as u32,
            attachments_scanned: self.attachments_scanned.max(0) as u32,
            attachment_inspection_complete: self.attachment_inspection_complete,
            encrypted: self.encrypted,
            created_at: parse_timestamp_or_now(&self.created_at),
            updated_at: parse_timestamp_or_now(&self.updated_at),
        }
    }
}

fn parse_uuid_or_default(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap_or_else(|error| {
        tracing::warn!(value, %error, "email review UUID parse failed");
        Uuid::default()
    })
}

fn parse_timestamp_or_now(value: &str) -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .unwrap_or_else(|error| {
            tracing::warn!(value, %error, "email review timestamp parse failed");
            Utc::now()
        })
}

fn parse_email_review_direction(value: &str) -> EmailReviewDirection {
    match value {
        "inbound" => EmailReviewDirection::Inbound,
        "outbound" => EmailReviewDirection::Outbound,
        "internal" => EmailReviewDirection::Internal,
        _ => EmailReviewDirection::Unknown,
    }
}

fn parse_email_audit_class(value: &str) -> EmailAuditClass {
    match value {
        "confirmed_outbound" => EmailAuditClass::ConfirmedOutbound,
        "outbound_candidate" => EmailAuditClass::OutboundCandidate,
        "attribution_pending" => EmailAuditClass::AttributionPending,
        _ => EmailAuditClass::Legacy,
    }
}

fn parse_review_source(value: &str) -> SessionSource {
    match value {
        "mta_proxy" | "mta" => SessionSource::MtaProxy,
        "import" => SessionSource::Import,
        _ => SessionSource::Sniffer,
    }
}

fn parse_email_inspection_status(value: &str) -> EmailInspectionStatus {
    match value {
        "inspected" => EmailInspectionStatus::Inspected,
        "encrypted" => EmailInspectionStatus::Encrypted,
        "incomplete" => EmailInspectionStatus::Incomplete,
        _ => EmailInspectionStatus::Failed,
    }
}

fn parse_email_dlp_result(value: &str) -> EmailDlpResult {
    match value {
        "clean" => EmailDlpResult::Clean,
        "hit" => EmailDlpResult::Hit,
        _ => EmailDlpResult::Unknown,
    }
}

fn parse_email_review_action(value: &str) -> EmailReviewAction {
    match value {
        "allow" => EmailReviewAction::Allow,
        "alert" => EmailReviewAction::Alert,
        "quarantine" => EmailReviewAction::Quarantine,
        "block" => EmailReviewAction::Block,
        "reject" => EmailReviewAction::Reject,
        "tempfail" => EmailReviewAction::Tempfail,
        _ => EmailReviewAction::Audit,
    }
}

fn mask_email_address(value: &str) -> String {
    let value = value.trim();
    let Some((local, domain)) = value.rsplit_once('@') else {
        return "[REDACTED]".to_string();
    };
    let Some(first) = local.chars().next() else {
        return "[REDACTED]".to_string();
    };
    if domain.trim().is_empty() || first.is_control() {
        return "[REDACTED]".to_string();
    }
    format!("{}****@{}", first, domain.trim().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::mask_email_address;

    #[test]
    fn persisted_mailbox_mask_keeps_only_first_character_and_domain() {
        assert_eq!(
            mask_email_address("analyst@CORP.EXAMPLE"),
            "a****@corp.example"
        );
        assert_eq!(mask_email_address("a@example.com"), "a****@example.com");
    }

    #[test]
    fn persisted_mailbox_mask_does_not_expose_malformed_value() {
        assert_eq!(mask_email_address("synthetic-id"), "[REDACTED]");
        assert_eq!(mask_email_address(""), "[REDACTED]");
        assert_eq!(mask_email_address("@example.com"), "[REDACTED]");
    }
}

/// Persist only category counts from DLP details; individual matched values
/// can themselves be personal or regulated data.
fn redact_dlp_details(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, item) in map {
                let count = item
                    .as_array()
                    .map(|items| items.len())
                    .or_else(|| item.as_object().map(|object| object.len()))
                    .unwrap_or(1);
                redacted.insert(key.clone(), serde_json::json!({ "count": count }));
            }
            serde_json::Value::Object(redacted)
        }
        serde_json::Value::Array(items) => serde_json::json!({ "count": items.len() }),
        _ => serde_json::json!({ "present": true }),
    }
}

// Type

/// (request_body,Used for itemsQuery)
#[derive(sqlx::FromRow)]
struct HttpSessionRow {
    id: String,
    client_ip: String,
    client_port: i64,
    server_ip: String,
    server_port: i64,
    method: String,
    uri: String,
    host: Option<String>,
    content_type: Option<String>,
    request_body_size: i64,
    request_body: Option<String>,
    response_status: Option<i64>,
    uploaded_filename: Option<String>,
    uploaded_file_size: Option<i64>,
    detected_user: Option<String>,
    detected_recipients: String,
    detected_sender: Option<String>,
    detected_file_type: Option<String>,
    body_is_binary: bool,
    file_type_mismatch: Option<String>,
    has_gaps: bool,
    timestamp: String,
    network_session_id: Option<String>,
}

/// (request_body, Transmission)
#[derive(sqlx::FromRow)]
struct HttpSessionListRow {
    id: String,
    client_ip: String,
    client_port: i64,
    server_ip: String,
    server_port: i64,
    method: String,
    uri: String,
    host: Option<String>,
    content_type: Option<String>,
    request_body_size: i64,
    response_status: Option<i64>,
    uploaded_filename: Option<String>,
    uploaded_file_size: Option<i64>,
    detected_user: Option<String>,
    detected_recipients: String,
    detected_sender: Option<String>,
    detected_file_type: Option<String>,
    body_is_binary: bool,
    file_type_mismatch: Option<String>,
    has_gaps: bool,
    timestamp: String,
    network_session_id: Option<String>,
}

impl From<HttpSessionRow> for HttpSession {
    fn from(r: HttpSessionRow) -> Self {
        HttpSession {
            id: Uuid::parse_str(&r.id).unwrap_or_else(|e| {
                tracing::warn!(id = %r.id, error = %e, "HTTP Session ID Parse失败");
                Uuid::default()
            }),
            client_ip: r.client_ip,
            client_port: r.client_port as u16,
            server_ip: r.server_ip,
            server_port: r.server_port as u16,
            method: parse_http_method(&r.method),
            // Redact historical rows on read so old plaintext query values can
            // never cross the API boundary while the background cleanup runs.
            uri: vigilyx_core::redact_http_uri(&r.uri),
            host: r.host,
            content_type: r.content_type,
            request_body_size: r.request_body_size as usize,
            request_body: r.request_body,
            response_status: r.response_status.map(|s| s as u16),
            uploaded_filename: r.uploaded_filename,
            uploaded_file_size: r.uploaded_file_size.map(|s| s as usize),
            detected_user: r.detected_user,
            detected_recipients: serde_json::from_str(&r.detected_recipients).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "HTTP Session recipients JSON 反序列化失败");
                Vec::new()
            }),
            detected_sender: r.detected_sender,
            detected_file_type: r
                .detected_file_type
                .and_then(|s| parse_detected_file_type(&s)),
            body_is_binary: r.body_is_binary,
            file_type_mismatch: r.file_type_mismatch,
            body_temp_file: None, // FileRoad Data
            has_gaps: r.has_gaps,
            timestamp: chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "HTTP Session时间戳Parse失败");
                    Utc::now()
                }),
            network_session_id: r.network_session_id.and_then(|s| Uuid::parse_str(&s).ok()),
        }
    }
}

impl From<HttpSessionListRow> for HttpSession {
    fn from(r: HttpSessionListRow) -> Self {
        HttpSession {
            id: Uuid::parse_str(&r.id).unwrap_or_else(|e| {
                tracing::warn!(id = %r.id, error = %e, "HTTP Session ID Parse失败");
                Uuid::default()
            }),
            client_ip: r.client_ip,
            client_port: r.client_port as u16,
            server_ip: r.server_ip,
            server_port: r.server_port as u16,
            method: parse_http_method(&r.method),
            uri: vigilyx_core::redact_http_uri(&r.uri),
            host: r.host,
            content_type: r.content_type,
            request_body_size: r.request_body_size as usize,
            request_body: None,
            response_status: r.response_status.map(|s| s as u16),
            uploaded_filename: r.uploaded_filename,
            uploaded_file_size: r.uploaded_file_size.map(|s| s as usize),
            detected_user: r.detected_user,
            detected_recipients: serde_json::from_str(&r.detected_recipients).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "HTTP Session recipients JSON 反序列化失败");
                Vec::new()
            }),
            detected_sender: r.detected_sender,
            detected_file_type: r
                .detected_file_type
                .and_then(|s| parse_detected_file_type(&s)),
            body_is_binary: r.body_is_binary,
            file_type_mismatch: r.file_type_mismatch,
            body_temp_file: None,
            has_gaps: r.has_gaps,
            timestamp: chrono::DateTime::parse_from_rfc3339(&r.timestamp)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "HTTP Session时间戳Parse失败");
                    Utc::now()
                }),
            network_session_id: r.network_session_id.and_then(|s| Uuid::parse_str(&s).ok()),
        }
    }
}

#[derive(sqlx::FromRow)]
struct IncidentRow {
    id: String,
    http_session_id: String,
    incident_type: String,
    severity: String,
    confidence: f64,
    summary: String,
    evidence: String,
    details: Option<String>,
    dlp_matches: String,
    client_ip: String,
    detected_user: Option<String>,
    request_url: String,
    host: Option<String>,
    method: String,
    created_at: String,
}

impl From<IncidentRow> for DataSecurityIncident {
    fn from(r: IncidentRow) -> Self {
        DataSecurityIncident {
            id: Uuid::parse_str(&r.id).unwrap_or_else(|e| {
                tracing::warn!(id = %r.id, error = %e, "事件 ID Parse失败");
                Uuid::default()
            }),
            http_session_id: Uuid::parse_str(&r.http_session_id).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "事件 http_session_id Parse失败");
                Uuid::default()
            }),
            incident_type: parse_incident_type(&r.incident_type),
            severity: parse_severity(&r.severity),
            confidence: r.confidence,
            summary: r.summary,
            evidence: serde_json::from_str(&r.evidence).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "事件 evidence JSON 反序列化失败");
                Vec::new()
            }),
            details: r.details.and_then(|s| serde_json::from_str(&s).ok()),
            dlp_matches: serde_json::from_str(&r.dlp_matches).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "事件 dlp_matches JSON 反序列化失败");
                Vec::new()
            }),
            client_ip: r.client_ip,
            detected_user: r.detected_user,
            request_url: vigilyx_core::redact_http_uri(&r.request_url),
            host: r.host,
            method: r.method,
            created_at: chrono::DateTime::parse_from_rfc3339(&r.created_at)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "事件时间戳Parse失败");
                    Utc::now()
                }),
        }
    }
}

fn parse_http_method(s: &str) -> HttpMethod {
    match s {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "OPTIONS" => HttpMethod::Options,
        "HEAD" => HttpMethod::Head,
        _ => HttpMethod::Other,
    }
}

fn parse_incident_type(s: &str) -> DataSecurityIncidentType {
    match s {
        "draft_box_abuse" => DataSecurityIncidentType::DraftBoxAbuse,
        "file_transit_abuse" => DataSecurityIncidentType::FileTransitAbuse,
        "self_sending" => DataSecurityIncidentType::SelfSending,
        "volume_anomaly" => DataSecurityIncidentType::VolumeAnomaly,
        "jrt_compliance_violation" => DataSecurityIncidentType::JrtComplianceViolation,
        "sensitive_data_transfer" => DataSecurityIncidentType::SensitiveDataTransfer,
        "bulk_sensitive_transfer" => DataSecurityIncidentType::BulkSensitiveTransfer,
        _ => DataSecurityIncidentType::DraftBoxAbuse,
    }
}

fn parse_severity(s: &str) -> DataSecuritySeverity {
    match s {
        "info" => DataSecuritySeverity::Info,
        "low" => DataSecuritySeverity::Low,
        "medium" => DataSecuritySeverity::Medium,
        "high" => DataSecuritySeverity::High,
        "critical" => DataSecuritySeverity::Critical,
        _ => DataSecuritySeverity::Info,
    }
}

fn parse_detected_file_type(s: &str) -> Option<DetectedFileType> {
    match s {
        "PE Executable" => Some(DetectedFileType::PeExecutable),
        "ELF Binary" => Some(DetectedFileType::ElfBinary),
        "Mach-O Binary" => Some(DetectedFileType::MachOBinary),
        "ZIP Archive" => Some(DetectedFileType::ZipArchive),
        "PDF" => Some(DetectedFileType::Pdf),
        "RAR Archive" => Some(DetectedFileType::RarArchive),
        "7-Zip Archive" => Some(DetectedFileType::SevenZipArchive),
        "Gzip" => Some(DetectedFileType::Gzip),
        "OLE Compound" => Some(DetectedFileType::OleCompound),
        "JPEG" => Some(DetectedFileType::Jpeg),
        "PNG" => Some(DetectedFileType::Png),
        "GIF" => Some(DetectedFileType::Gif),
        "BMP" => Some(DetectedFileType::Bmp),
        "TIFF" => Some(DetectedFileType::Tiff),
        "SQLite" => Some(DetectedFileType::Sqlite),
        "Windows Shortcut" => Some(DetectedFileType::WindowsShortcut),
        "Java Class" => Some(DetectedFileType::JavaClass),
        "Plain Text" => Some(DetectedFileType::PlainText),
        "Unknown Binary" => Some(DetectedFileType::UnknownBinary),
        _ => None,
    }
}
