//! Data securityModuleData

//! For HTTP Session Data security Query.

use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;
use vigilyx_core::{
    DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity, DataSecurityStats,
    HourlyBucket, HttpMethod, HttpSession, magic_bytes::DetectedFileType,
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

impl VigilDb {
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
        .bind(&session.uri)
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
        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
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
        let mut list_query = sqlx::query_as::<_, HttpSessionListRow>(&list_sql);
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
    ) -> Result<()> {
        let evidence = serde_json::to_string(&incident.evidence)?;
        let details = incident
            .details
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "null".to_string());
        let dlp_matches = serde_json::to_string(&incident.dlp_matches)?;

        sqlx::query(
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
        .bind(&incident.request_url)
        .bind(&incident.host)
        .bind(&incident.method)
        .bind(incident.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

   /// Type (DB Level)
    pub async fn has_recent_incident(
        &self,
        user: &str,
        incident_type: &str,
        dlp_matches_json: &str,
        since: &str,
    ) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1::BIGINT FROM data_security_incidents \
             WHERE detected_user = $1 AND incident_type = $2 AND dlp_matches = $3 \
             AND created_at > $4 LIMIT 1",
        )
        .bind(user)
        .bind(incident_type)
        .bind(dlp_matches_json)
        .bind(since)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
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

        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
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

        let mut list_query = sqlx::query_as::<_, IncidentRow>(&list_sql);
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
        let cutoff = (Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

       // items Query:According toType + 24h
        let row: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(CASE WHEN incident_type = 'draft_box_abuse' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'file_transit_abuse' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'self_sending' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'volume_anomaly' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN severity IN ('high', 'critical') AND created_at >= $1 THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN incident_type = 'jrt_compliance_violation' THEN 1 ELSE 0 END), 0)::BIGINT
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

        Ok(DataSecurityStats {
            total_incidents: row.0 as u64,
            draft_abuse_count: row.1 as u64,
            file_transit_count: row.2 as u64,
            self_send_count: row.3 as u64,
            volume_anomaly_count: row.4 as u64,
            jrt_compliance_count: row.6 as u64,
            high_severity_24h: row.5 as u64,
            incidents_by_severity,
            hourly_sessions,
            hourly_incidents,
        })
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
            uri: r.uri,
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
            uri: r.uri,
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
            request_url: r.request_url,
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
