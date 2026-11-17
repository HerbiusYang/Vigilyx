//! Database Table Creation and Migration (PostgreSQL)

use anyhow::Result;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use crate::VigilDb;

// The PostgreSQL advisory lock serializes migrations across processes. This
// in-process mutex is also required: otherwise many concurrent callers can
// each hold a pooled connection while waiting for the advisory lock, leaving
// the lock holder unable to acquire a second connection for DDL.
static MIGRATION_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) fn migration_mutex() -> &'static Mutex<()> {
    MIGRATION_MUTEX.get_or_init(|| Mutex::new(()))
}

/// A single recorded schema migration entry.
#[derive(Debug, Clone)]
pub struct SchemaMigration {
    pub version: String,
    pub description: String,
    /// ISO 8601 timestamp string of when the migration was first applied.
    pub executed_at: String,
}

impl VigilDb {
    /// Initialize database tables
    pub async fn init(&self) -> Result<()> {
        let _migration_guard = migration_mutex().lock().await;

        // API and standalone engine can start at the same time and both run
        // the idempotent migration sequence. Keep a dedicated connection for
        // the full init so every concurrent-index migration in this method is
        // serialized across services. Dropping the connection releases the
        // session-level advisory lock even if a later migration returns an
        // error.
        let mut schema_migration_connection = self.pool.acquire().await?;
        // A pooled PostgreSQL connection keeps session-level advisory locks
        // when it is returned to the pool.  Force this dedicated migration
        // connection to close on every exit path so the lock cannot leak into
        // a later security migration or another service startup.
        schema_migration_connection.close_on_drop();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended('vigilyx.schema_migrations', 0))")
            .execute(&mut *schema_migration_connection)
            .await?;

        // schema_migrations tracking table (must be created first)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id SERIAL PRIMARY KEY,
                version TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create sessions table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                protocol TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                client_port INTEGER NOT NULL,
                server_ip TEXT NOT NULL,
                server_port INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                started_at_ts TIMESTAMPTZ,
                ended_at_ts TIMESTAMPTZ,
                status TEXT NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                total_bytes BIGINT NOT NULL DEFAULT 0,
                mail_from TEXT,
                rcpt_to TEXT,
                subject TEXT,
                content JSONB,
                email_count INTEGER NOT NULL DEFAULT 0,
                error_reason TEXT,
                message_id TEXT,
                auth_info JSONB,
                sender_domain TEXT,
                source TEXT NOT NULL DEFAULT 'sniffer',
                bounce_metadata_ready BOOLEAN NOT NULL DEFAULT FALSE,
                bounce_candidate BOOLEAN NOT NULL DEFAULT FALSE,
                bounce_reported_alert BOOLEAN NOT NULL DEFAULT FALSE,
                bounce_target_addresses TEXT,
                content_is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
                content_is_complete BOOLEAN NOT NULL DEFAULT FALSE,
                content_attachment_count INTEGER NOT NULL DEFAULT 0,
                content_has_body BOOLEAN NOT NULL DEFAULT FALSE,
                list_has_content BOOLEAN NOT NULL DEFAULT FALSE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Additive NDR metadata columns for existing installations. The
        // FALSE marker keeps legacy rows eligible for bounded compatibility
        // backfill instead of silently treating them as non-bounces.
        for statement in [
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS started_at_ts TIMESTAMPTZ",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ended_at_ts TIMESTAMPTZ",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_metadata_ready BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_candidate BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_reported_alert BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_target_addresses TEXT",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS content_is_encrypted BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS content_is_complete BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS content_attachment_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS content_has_body BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS list_has_content BOOLEAN NOT NULL DEFAULT FALSE",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        // Keep list metadata compatible with rolling upgrades and rollback:
        // every writer, including an older binary that only writes `content`,
        // passes through this persistence-boundary projection. List reads can
        // then avoid detoasting multi-megabyte MIME JSONB values.
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION trg_session_list_metadata_fn()
            RETURNS TRIGGER AS $$
            DECLARE
                attachments_count INTEGER;
                has_headers BOOLEAN;
                has_links BOOLEAN;
            BEGIN
                attachments_count := CASE
                    WHEN jsonb_typeof(NEW.content->'attachments') = 'array'
                    THEN jsonb_array_length(NEW.content->'attachments')
                    ELSE 0
                END;
                has_headers := CASE
                    WHEN jsonb_typeof(NEW.content->'headers') = 'array'
                    THEN jsonb_array_length(NEW.content->'headers') > 0
                    ELSE FALSE
                END;
                has_links := CASE
                    WHEN jsonb_typeof(NEW.content->'links') = 'array'
                    THEN jsonb_array_length(NEW.content->'links') > 0
                    ELSE FALSE
                END;
                NEW.content_is_encrypted := COALESCE(NEW.content->>'is_encrypted' = 'true', FALSE);
                NEW.content_is_complete := COALESCE(NEW.content->>'is_complete' = 'true', FALSE);
                NEW.content_attachment_count := attachments_count;
                NEW.content_has_body := NEW.content->>'body_text' IS NOT NULL
                    OR NEW.content->>'body_html' IS NOT NULL;
                NEW.list_has_content := NOT NEW.content_is_encrypted
                    AND (NEW.content_has_body OR attachments_count > 0 OR has_headers OR has_links);
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_trigger
                    WHERE tgname = 'trg_session_list_metadata' AND NOT tgisinternal
                ) THEN
                    CREATE TRIGGER trg_session_list_metadata
                        BEFORE INSERT OR UPDATE OF content ON sessions
                        FOR EACH ROW EXECUTE FUNCTION trg_session_list_metadata_fn();
                END IF;
            END $$
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Legacy TEXT timestamps remain available to compatibility queries.
        // Their backfill must run as a separately throttled maintenance job;
        // even a bounded batch can scan millions of rows on a large install
        // and must not delay the API/engine listener during startup.

        record_migration(
            &self.pool,
            "001_sessions",
            "sessions table with protocol/email fields",
        )
        .await?;

        // Create config table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(&self.pool, "002_config", "key-value config table").await?;

        // Statistics cache table (eliminate COUNT(*) full table scan)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS stats_cache (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_sessions BIGINT NOT NULL DEFAULT 0,
                active_sessions BIGINT NOT NULL DEFAULT 0,
                total_bytes BIGINT NOT NULL DEFAULT 0,
                total_packets BIGINT NOT NULL DEFAULT 0,
                smtp_sessions BIGINT NOT NULL DEFAULT 0,
                pop3_sessions BIGINT NOT NULL DEFAULT 0,
                imap_sessions BIGINT NOT NULL DEFAULT 0,
                http_sessions BIGINT NOT NULL DEFAULT 0
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE stats_cache ADD COLUMN IF NOT EXISTS http_sessions BIGINT NOT NULL DEFAULT 0",
        )
        .execute(&self.pool)
        .await?;

        // Initialize cache rows (if not exists)
        sqlx::query(
            r#"
            INSERT INTO stats_cache (id, total_sessions, active_sessions, total_bytes, total_packets,
                smtp_sessions, pop3_sessions, imap_sessions, http_sessions)
            SELECT 1,
                (SELECT COUNT(*) FROM sessions),
                (SELECT COUNT(*) FROM sessions WHERE status = 'Active'),
                (SELECT COALESCE(SUM(total_bytes), 0) FROM sessions),
                (SELECT COALESCE(SUM(packet_count), 0) FROM sessions),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('SMTP', 'Smtp')),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('POP3', 'Pop3')),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('IMAP', 'Imap')),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('HTTP', 'Http'))
            WHERE NOT EXISTS (SELECT 1 FROM stats_cache WHERE id = 1)
            "#,
        )
        .execute(&self.pool)
        .await?;

        // L3 query model for the external-login dashboard.  Counts for
        // completed hours are maintained incrementally; the current and
        // boundary hours remain a bounded live tail in get_external_login_stats.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS external_login_hourly (
                hour_start TIMESTAMPTZ NOT NULL,
                protocol TEXT NOT NULL,
                login_count BIGINT NOT NULL DEFAULT 0,
                success_count BIGINT NOT NULL DEFAULT 0,
                failed_count BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (hour_start, protocol)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS external_login_hourly_sources (
                hour_start TIMESTAMPTZ NOT NULL,
                client_ip TEXT NOT NULL,
                PRIMARY KEY (hour_start, client_ip)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        let login_hourly_backfill_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = '015_external_login_hourly') \
             OR (NOT EXISTS (SELECT 1 FROM external_login_hourly) AND EXISTS (\
                 SELECT 1 FROM sessions WHERE started_at_ts IS NOT NULL\
             ))",
        )
        .fetch_one(&self.pool)
        .await?;
        if login_hourly_backfill_needed {
            sqlx::query(
                r#"
                INSERT INTO external_login_hourly
                    (hour_start, protocol, login_count, success_count, failed_count)
                SELECT
                    date_trunc('hour', s.started_at_ts),
                    CASE
                        WHEN s.protocol IN ('SMTP', 'Smtp') THEN 'SMTP'
                        WHEN s.protocol IN ('POP3', 'Pop3') THEN 'POP3'
                        WHEN s.protocol IN ('IMAP', 'Imap') THEN 'IMAP'
                        ELSE 'HTTP'
                    END,
                    COUNT(*)::BIGINT,
                    COUNT(*) FILTER (WHERE s.auth_info->>'auth_success' = 'true')::BIGINT,
                    COUNT(*) FILTER (WHERE s.auth_info->>'auth_success' = 'false')::BIGINT
                FROM sessions s
                WHERE s.started_at_ts IS NOT NULL
                  AND (
                      (s.protocol IN ('SMTP', 'Smtp') AND s.auth_info IS NOT NULL)
                      OR s.protocol IN ('POP3', 'Pop3')
                      OR s.protocol IN ('IMAP', 'Imap')
                      OR (s.protocol IN ('HTTP', 'Http') AND s.auth_info IS NOT NULL)
                  )
                GROUP BY 1, 2
                ON CONFLICT (hour_start, protocol) DO UPDATE SET
                    login_count = EXCLUDED.login_count,
                    success_count = EXCLUDED.success_count,
                    failed_count = EXCLUDED.failed_count
                "#,
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                r#"
                INSERT INTO external_login_hourly_sources (hour_start, client_ip)
                SELECT DISTINCT date_trunc('hour', s.started_at_ts), s.client_ip
                FROM sessions s
                WHERE s.started_at_ts IS NOT NULL
                  AND (
                      (s.protocol IN ('SMTP', 'Smtp') AND s.auth_info IS NOT NULL)
                      OR s.protocol IN ('POP3', 'Pop3')
                      OR s.protocol IN ('IMAP', 'Imap')
                      OR (s.protocol IN ('HTTP', 'Http') AND s.auth_info IS NOT NULL)
                  )
                ON CONFLICT DO NOTHING
                "#,
            )
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "015_external_login_hourly",
                "incremental hourly query model for external login statistics",
            )
            .await?;
        }

        // PL/pgSQL trigger functions
        self.create_triggers().await?;

        record_migration(
            &self.pool,
            "003_stats_cache_triggers",
            "stats_cache table with PL/pgSQL insert/update/delete triggers",
        )
        .await?;

        // Audit log table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                operator TEXT NOT NULL,
                operation TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                detail TEXT,
                ip_address TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "004_audit_logs",
            "audit trail for operator actions",
        )
        .await?;

        // Login history table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS login_history (
                id SERIAL PRIMARY KEY,
                timestamp TEXT NOT NULL DEFAULT TO_CHAR(NOW() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                username TEXT NOT NULL,
                success BOOLEAN NOT NULL,
                ip_address TEXT,
                reason TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "005_login_history",
            "login attempt history table",
        )
        .await?;

        // Older installations may not have this column yet.  Add and backfill it
        // before creating indexes that reference it.
        self.migrate_add_sender_domain().await?;

        // CreatePerformance notesIndex
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_started_at ON sessions(started_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_mail_from ON sessions(mail_from)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_protocol_status ON sessions(protocol, status)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_has_content ON sessions(started_at DESC) \
             WHERE content->>'body_text' IS NOT NULL \
                OR content->>'body_html' IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_sessions_message_id ON sessions(message_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_status_started ON sessions(status, started_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_started_protocol ON sessions(started_at DESC, protocol)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_protocol_started_at ON sessions(protocol, started_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_completed_content ON sessions(started_at DESC) \
             WHERE status = 'Completed' \
               AND (content->>'body_text' IS NOT NULL \
                    OR content->>'body_html' IS NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_sender_domain_status ON sessions(sender_domain, status)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_bounce_metadata_candidate ON sessions(started_at DESC) WHERE bounce_metadata_ready AND bounce_candidate",
            "CREATE INDEX IF NOT EXISTS idx_sessions_bounce_metadata_alert ON sessions(started_at DESC) WHERE bounce_metadata_ready AND bounce_reported_alert",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_operator ON audit_logs(operator, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_login_history_timestamp ON login_history(timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_login_history_username ON login_history(username, timestamp DESC)",
        ];

        for idx_sql in indexes {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }

        record_migration(
            &self.pool,
            "006_infra_indexes",
            "performance indexes on sessions, audit_logs, login_history",
        )
        .await?;

        // pg_trgm extension + 3-gram index (accelerate LIKE '%keyword%' search)
        // NOTE: pg_trgm requires PostgreSQL contrib package (Rocky Linux: postgresql17-contrib)
        // If extension unavailable, index creation will fail but functionality not affected (just full table scan for search)
        let trgm_ok = sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_trgm")
            .execute(&self.pool)
            .await;

        if trgm_ok.is_ok() {
            let trgm_indexes = [
                "CREATE INDEX IF NOT EXISTS idx_sessions_mail_from_trgm \
                 ON sessions USING gin(mail_from gin_trgm_ops)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_subject_trgm \
                 ON sessions USING gin(subject gin_trgm_ops)",
            ];

            for idx_sql in trgm_indexes {
                if let Err(e) = sqlx::query(idx_sql).execute(&self.pool).await {
                    tracing::warn!("Create 3-gram index failed (non-fatal): {}", e);
                }
            }
        } else {
            tracing::warn!(
                "pg_trgm extension unavailable, skip 3-gram index creation (LIKE search will use full table scan)"
            );
        }

        record_migration(
            &self.pool,
            "007_trgm_indexes",
            "pg_trgm trigram indexes on mail_from and subject for LIKE search",
        )
        .await?;

        // Phase 0 observability baseline. Compose loads the module through
        // shared_preload_libraries; this idempotent statement creates the
        // extension in databases upgraded from older deployments.
        if let Err(error) = sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
            .execute(&self.pool)
            .await
        {
            tracing::warn!(
                %error,
                "pg_stat_statements extension unavailable; query history metrics remain disabled"
            );
        }

        // Large-table performance indexes (best-effort, non-blocking for writes).
        // PostgreSQL still takes catalog/DDL locks for an IF NOT EXISTS
        // statement. Check validity first so every API/engine restart does not
        // re-run a long DDL sequence that is already complete.
        let large_table_indexes_missing: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM unnest(ARRAY[
                    'idx_sessions_with_any_content',
                    'idx_sessions_external_login_cover',
                    'idx_sessions_started_at_ts',
                    'idx_sessions_server_content_started'
                ]::text[]) AS required(name)
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM pg_class c
                    INNER JOIN pg_namespace n ON n.oid = c.relnamespace
                    INNER JOIN pg_index i ON i.indexrelid = c.oid
                    WHERE n.nspname = 'public'
                      AND c.relname = required.name
                      AND i.indisvalid
                )
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        if large_table_indexes_missing {
            // CREATE INDEX IF NOT EXISTS treats an interrupted concurrent
            // index as present even when `indisvalid = false`. Remove only
            // those unusable remnants so the idempotent DDL below can repair
            // an interrupted deployment on the next startup.
            for index_name in [
                "idx_sessions_with_any_content",
                "idx_sessions_external_login_cover",
                "idx_sessions_started_at_ts",
                "idx_sessions_server_content_started",
            ] {
                let invalid_index: bool = sqlx::query_scalar(
                    "SELECT EXISTS (\
                        SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
                        WHERE c.relname = $1 AND NOT i.indisvalid\
                     )",
                )
                .bind(index_name)
                .fetch_one(&self.pool)
                .await?;
                if invalid_index {
                    let drop_sql = format!("DROP INDEX IF EXISTS {index_name}");
                    sqlx::query(sqlx::AssertSqlSafe(drop_sql.as_str()))
                        .execute(&self.pool)
                        .await?;
                }
            }

            let concurrent_indexes = [
                format!(
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_with_any_content \
                 ON sessions(started_at DESC) WHERE {}",
                    crate::infra::session::session_with_content_predicate("")
                ),
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_external_login_cover \
             ON sessions(started_at DESC) INCLUDE (protocol, client_ip, auth_info) \
             WHERE ((protocol IN ('SMTP', 'Smtp') AND auth_info IS NOT NULL) \
                OR protocol IN ('POP3', 'Pop3') \
                OR protocol IN ('IMAP', 'Imap') \
                OR (protocol IN ('HTTP', 'Http') AND auth_info IS NOT NULL))"
                    .to_string(),
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_started_at_ts \
             ON sessions(started_at_ts DESC) WHERE started_at_ts IS NOT NULL"
                    .to_string(),
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_server_content_started \
             ON sessions(server_ip, started_at DESC) \
             WHERE ((content->>'is_encrypted') IS DISTINCT FROM 'true' \
                AND ((content->>'body_text') IS NOT NULL \
                  OR (content->>'body_html') IS NOT NULL \
                  OR COALESCE(jsonb_array_length(content->'attachments'), 0) > 0 \
                  OR COALESCE(jsonb_array_length(content->'headers'), 0) > 0 \
                  OR COALESCE(jsonb_array_length(content->'links'), 0) > 0))"
                    .to_string(),
            ];

            for idx_sql in concurrent_indexes {
                // Index DDL assembled in this function from static fragments only.
                if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(idx_sql.as_str()))
                    .execute(&self.pool)
                    .await
                {
                    tracing::warn!(
                        "Create concurrent performance index failed (non-fatal): {}",
                        e
                    );
                }
            }
        }

        record_migration(
            &self.pool,
            "008_large_table_perf_indexes",
            "concurrent partial indexes for content-filtered sessions and external login stats",
        )
        .await?;

        // ── Migration 009: Typed config tables (P1-1) ──
        // Replace the loose TEXT KV `config` table with typed JSONB tables per domain.
        // Each table has: id=1 singleton, version counter (monotonic), JSONB config, updated_at.
        // The old `config` table is NOT dropped — kept for rollback safety and dual-write.

        let typed_config_tables = [
            ("config_security_pipeline", "'{}'"),
            (
                "config_sniffer",
                r#"'{"webmail_servers":[],"http_ports":[80,443,8080]}'"#,
            ),
            ("config_ai_service", "'{}'"),
            ("config_email_alert", "'{}'"),
            ("config_syslog", "'{}'"),
            (
                "config_time_policy",
                r#"'{"enabled":true,"work_hour_start":8,"work_hour_end":18,"utc_offset_hours":8,"weekend_is_off_hours":true}'"#,
            ),
            ("config_deployment", r#"'{"mode":"mirror"}'"#),
            ("config_internal_domains", "'[]'"),
        ];

        for (table, default_json) in typed_config_tables {
            let sql = format!(
                r#"
                CREATE TABLE IF NOT EXISTS {table} (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    version BIGINT NOT NULL DEFAULT 1,
                    config JSONB NOT NULL DEFAULT {default_json}::jsonb,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            );
            sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .execute(&self.pool)
                .await?;
        }

        // Auth credentials — separated from operational config
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS auth_credentials (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash TEXT NOT NULL DEFAULT '',
                token_version BIGINT NOT NULL DEFAULT 1,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Seed typed tables from existing `config` KV table (idempotent)
        let seed_mappings = [
            ("security_pipeline", "config_security_pipeline"),
            ("ai_service_config", "config_ai_service"),
            ("email_alert_config", "config_email_alert"),
            ("sniffer_config", "config_sniffer"),
            ("syslog_config", "config_syslog"),
            ("ds_time_policy", "config_time_policy"),
            ("deployment_mode", "config_deployment"),
            ("auto_internal_domains", "config_internal_domains"),
        ];

        for (config_key, target_table) in seed_mappings {
            let sql = format!(
                r#"
                INSERT INTO {target_table} (id, version, config, updated_at)
                SELECT 1, 1, value::jsonb, NOW()
                FROM config
                WHERE key = $1
                ON CONFLICT (id) DO NOTHING
                "#,
            );
            if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(config_key)
                .execute(&self.pool)
                .await
            {
                tracing::warn!(
                    config_key,
                    target_table,
                    "Seed typed config from KV table failed (non-fatal): {}",
                    e
                );
            }
        }

        // Seed auth_credentials from config KV
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO auth_credentials (id, password_hash, token_version, updated_at)
            SELECT 1,
                   COALESCE((SELECT value FROM config WHERE key = 'auth_password_hash'), ''),
                   COALESCE((SELECT value FROM config WHERE key = 'auth_token_version')::BIGINT, 1),
                   NOW()
            ON CONFLICT (id) DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await
        {
            tracing::warn!(
                "Seed auth_credentials from KV table failed (non-fatal): {}",
                e
            );
        }

        record_migration(
            &self.pool,
            "009_typed_config_tables",
            "typed JSONB config tables per domain + auth_credentials, seeded from KV config",
        )
        .await?;

        let completed_analyzable_index = format!(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_completed_analyzable_started \
             ON sessions(started_at DESC) INCLUDE (id) WHERE status = 'Completed' AND {}",
            crate::infra::session::session_with_content_predicate("")
        );
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(completed_analyzable_index.as_str()))
            .execute(&self.pool)
            .await
        {
            tracing::warn!(
                "Create completed analyzable sessions index failed (non-fatal): {}",
                e
            );
        }

        record_migration(
            &self.pool,
            "010_completed_analyzable_sessions_index",
            "concurrent partial index for completed sessions with analyzable content",
        )
        .await?;

        let downstream_envelope_index =
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_client_started \
             ON sessions(client_ip, started_at)"
                .to_string();
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(downstream_envelope_index.as_str()))
            .execute(&self.pool)
            .await
        {
            tracing::warn!(
                "Create downstream related-session index failed (non-fatal): {}",
                e
            );
        }

        record_migration(
            &self.pool,
            "011_downstream_related_session_index",
            "concurrent index for downstream related-session lookup by client_ip and started_at",
        )
        .await?;

        let completed_analyzable_v2_index = format!(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_completed_analyzable_started_v2 \
             ON sessions(started_at ASC, id ASC) WHERE status = 'Completed' AND {}",
            crate::infra::session::session_with_content_predicate("")
        );
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(completed_analyzable_v2_index.as_str()))
            .execute(&self.pool)
            .await
        {
            tracing::warn!(
                "Create completed analyzable sessions v2 index failed (non-fatal): {}",
                e
            );
        }

        record_migration(
            &self.pool,
            "012_completed_analyzable_sessions_index_v2",
            "concurrent partial index for completed analyzable sessions including links and cursor id",
        )
        .await?;

        // Preserve the transport provenance required by the unified email
        // data-security review. Existing sessions are legacy sniffer records;
        // MTA sessions are stamped explicitly by insert_session().
        for alter_sql in [
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'sniffer'",
            "CREATE INDEX IF NOT EXISTS idx_sessions_source_started ON sessions(source, started_at DESC)",
        ] {
            sqlx::query(alter_sql).execute(&self.pool).await?;
        }
        record_migration(
            &self.pool,
            "013_email_session_provenance",
            "persist session source for mirror and MTA email review",
        )
        .await?;

        // Identity-anomaly history lookups normalize mail_from with lower().
        // The plain mail_from index cannot serve that predicate, so the
        // relationship query can fall back to scanning a large fraction of
        // completed sessions. Build this expression index concurrently: the
        // table is production-sized and session writes must remain available.
        // Both the API and standalone engine initialize the same database at
        // startup. Serialize this DDL on one connection so two concurrent
        // CREATE INDEX CONCURRENTLY attempts cannot deadlock and leave an
        // invalid index behind. If a previous attempt did leave one behind,
        // remove only that invalid index before rebuilding it.
        let identity_history_migration = async {
            let mut connection = self.pool.acquire().await?;
            let advisory_lock =
                "SELECT pg_advisory_lock(hashtextextended('vigilyx.identity_history_sender_index', 0))";
            sqlx::query(advisory_lock)
                .execute(&mut *connection)
                .await?;

            let migration_result: std::result::Result<(), sqlx::Error> = async {
                let invalid_index: bool = sqlx::query_scalar(
                    "SELECT EXISTS (\
                         SELECT 1 FROM pg_index i \
                         JOIN pg_class c ON c.oid = i.indexrelid \
                         WHERE c.relname = 'idx_sessions_lower_mail_from_completed' \
                           AND NOT i.indisvalid\
                     )",
                )
                .fetch_one(&mut *connection)
                .await?;

                if invalid_index {
                    sqlx::query(
                        "DROP INDEX IF EXISTS idx_sessions_lower_mail_from_completed",
                    )
                    .execute(&mut *connection)
                    .await?;
                }

                sqlx::query(
                    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_lower_mail_from_completed \
                     ON sessions (lower(mail_from), started_at DESC) \
                     WHERE status = 'Completed'",
                )
                .execute(&mut *connection)
                .await?;

                let valid_index: bool = sqlx::query_scalar(
                    "SELECT EXISTS (\
                         SELECT 1 FROM pg_index i \
                         JOIN pg_class c ON c.oid = i.indexrelid \
                         WHERE c.relname = 'idx_sessions_lower_mail_from_completed' \
                           AND i.indisvalid\
                     )",
                )
                .fetch_one(&mut *connection)
                .await?;
                if !valid_index {
                    tracing::warn!(
                        "Identity history expression index is present but not valid after migration"
                    );
                }
                Ok(())
            }
            .await;

            let unlock_result = sqlx::query(
                "SELECT pg_advisory_unlock(hashtextextended('vigilyx.identity_history_sender_index', 0))",
            )
            .execute(&mut *connection)
            .await;

            match (migration_result, unlock_result) {
                (Err(error), _) => Err(error),
                (Ok(()), Err(error)) => Err(error),
                (Ok(()), Ok(_)) => Ok(()),
            }
        }
        .await;
        if let Err(error) = identity_history_migration {
            tracing::warn!(
                "Create identity history expression index failed (non-fatal): {}",
                error
            );
        }
        record_migration(
            &self.pool,
            "014_identity_history_sender_index",
            "concurrent partial expression index for completed sender history lookups",
        )
        .await?;

        // Migration 016: project the small set of list-facing content fields
        // out of the potentially multi-megabyte JSONB/TOAST payload. Do not
        // backfill the full sessions table on the API startup path: an old
        // installation may contain millions of JSONB rows and that statement
        // would keep the HTTP listener unavailable for minutes. Legacy rows
        // use the exact content predicate fallback in the list query; new and
        // updated rows are maintained by the trigger above.
        let list_metadata_migration_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '016_session_list_metadata')",
        )
        .fetch_one(&self.pool)
        .await?;
        if list_metadata_migration_needed {
            tracing::info!(
                "Session list metadata enabled; legacy rows remain on the compatibility predicate"
            );
        }

        record_migration(
            &self.pool,
            "016_session_list_metadata",
            "TOAST-free session list metadata and direction-aware partial indexes",
        )
        .await?;

        // Platform identity/RBAC is part of the core schema and is recreated
        // after operational clears without touching the identity rows.
        self.init_platform_auth().await?;

        Ok(())
    }

    /// Create PL/pgSQL trigger functions and triggers
    async fn create_triggers(&self) -> Result<()> {
        // Trigger function: session INSERT
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION trg_session_insert_fn()
            RETURNS TRIGGER AS $$
            BEGIN
                UPDATE stats_cache SET
                    total_sessions = total_sessions + 1,
                    active_sessions = CASE WHEN NEW.status = 'Active' THEN active_sessions + 1 ELSE active_sessions END,
                    total_bytes = total_bytes + NEW.total_bytes,
                    total_packets = total_packets + NEW.packet_count,
                    smtp_sessions = CASE WHEN NEW.protocol IN ('SMTP','Smtp') THEN smtp_sessions + 1 ELSE smtp_sessions END,
                    pop3_sessions = CASE WHEN NEW.protocol IN ('POP3','Pop3') THEN pop3_sessions + 1 ELSE pop3_sessions END,
                    imap_sessions = CASE WHEN NEW.protocol IN ('IMAP','Imap') THEN imap_sessions + 1 ELSE imap_sessions END,
                    http_sessions = CASE WHEN NEW.protocol IN ('HTTP','Http') THEN http_sessions + 1 ELSE http_sessions END
                WHERE id = 1;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_session_insert') THEN
                    CREATE TRIGGER trg_session_insert
                        AFTER INSERT ON sessions
                        FOR EACH ROW EXECUTE FUNCTION trg_session_insert_fn();
                END IF;
            END $$
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Trigger function: session DELETE
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION trg_session_delete_fn()
            RETURNS TRIGGER AS $$
            BEGIN
                UPDATE stats_cache SET
                    total_sessions = GREATEST(0, total_sessions - 1),
                    active_sessions = CASE WHEN OLD.status = 'Active' THEN GREATEST(0, active_sessions - 1) ELSE active_sessions END,
                    total_bytes = GREATEST(0, total_bytes - OLD.total_bytes),
                    total_packets = GREATEST(0, total_packets - OLD.packet_count),
                    smtp_sessions = CASE WHEN OLD.protocol IN ('SMTP','Smtp') THEN GREATEST(0, smtp_sessions - 1) ELSE smtp_sessions END,
                    pop3_sessions = CASE WHEN OLD.protocol IN ('POP3','Pop3') THEN GREATEST(0, pop3_sessions - 1) ELSE pop3_sessions END,
                    imap_sessions = CASE WHEN OLD.protocol IN ('IMAP','Imap') THEN GREATEST(0, imap_sessions - 1) ELSE imap_sessions END,
                    http_sessions = CASE WHEN OLD.protocol IN ('HTTP','Http') THEN GREATEST(0, http_sessions - 1) ELSE http_sessions END
                WHERE id = 1;
                RETURN OLD;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_session_delete') THEN
                    CREATE TRIGGER trg_session_delete
                        AFTER DELETE ON sessions
                        FOR EACH ROW EXECUTE FUNCTION trg_session_delete_fn();
                END IF;
            END $$
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Trigger function: session UPDATE
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION trg_session_update_fn()
            RETURNS TRIGGER AS $$
            BEGIN
                UPDATE stats_cache SET
                    active_sessions = active_sessions
                        + CASE WHEN NEW.status = 'Active' AND OLD.status != 'Active' THEN 1 ELSE 0 END
                        - CASE WHEN OLD.status = 'Active' AND NEW.status != 'Active' THEN 1 ELSE 0 END,
                    total_bytes = total_bytes + (NEW.total_bytes - OLD.total_bytes),
                    total_packets = total_packets + (NEW.packet_count - OLD.packet_count),
                    smtp_sessions = smtp_sessions
                        + CASE WHEN NEW.protocol IN ('SMTP','Smtp') THEN 1 ELSE 0 END
                        - CASE WHEN OLD.protocol IN ('SMTP','Smtp') THEN 1 ELSE 0 END,
                    pop3_sessions = pop3_sessions
                        + CASE WHEN NEW.protocol IN ('POP3','Pop3') THEN 1 ELSE 0 END
                        - CASE WHEN OLD.protocol IN ('POP3','Pop3') THEN 1 ELSE 0 END,
                    imap_sessions = imap_sessions
                        + CASE WHEN NEW.protocol IN ('IMAP','Imap') THEN 1 ELSE 0 END
                        - CASE WHEN OLD.protocol IN ('IMAP','Imap') THEN 1 ELSE 0 END,
                    http_sessions = http_sessions
                        + CASE WHEN NEW.protocol IN ('HTTP','Http') THEN 1 ELSE 0 END
                        - CASE WHEN OLD.protocol IN ('HTTP','Http') THEN 1 ELSE 0 END
                WHERE id = 1;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Recreate this trigger so rolling upgrades also add packet_count and
        // protocol changes to the event list. Updating only the function is
        // not sufficient: PostgreSQL stores UPDATE OF columns on the trigger.
        sqlx::query("DROP TRIGGER IF EXISTS trg_session_update ON sessions")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            r#"
            CREATE TRIGGER trg_session_update
                AFTER UPDATE OF status, packet_count, total_bytes, protocol ON sessions
                FOR EACH ROW EXECUTE FUNCTION trg_session_update_fn()
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Incremental L3 query model for external-login statistics. The
        // session table remains authoritative; this trigger only maintains a
        // compact hourly counter and a distinct-IP side table.
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION vigilyx_login_hourly_delta(
                p_hour TIMESTAMPTZ,
                p_protocol TEXT,
                p_login_delta BIGINT,
                p_success_delta BIGINT,
                p_failed_delta BIGINT
            ) RETURNS VOID AS $$
            BEGIN
                IF p_hour IS NULL OR p_protocol IS NULL THEN
                    RETURN;
                END IF;

                IF p_login_delta > 0 THEN
                    INSERT INTO external_login_hourly
                        (hour_start, protocol, login_count, success_count, failed_count)
                    VALUES (p_hour, p_protocol, p_login_delta, p_success_delta, p_failed_delta)
                    ON CONFLICT (hour_start, protocol) DO UPDATE SET
                        login_count = external_login_hourly.login_count + EXCLUDED.login_count,
                        success_count = external_login_hourly.success_count + EXCLUDED.success_count,
                        failed_count = external_login_hourly.failed_count + EXCLUDED.failed_count;
                ELSE
                    UPDATE external_login_hourly
                    SET login_count = GREATEST(0, login_count + p_login_delta),
                        success_count = GREATEST(0, success_count + p_success_delta),
                        failed_count = GREATEST(0, failed_count + p_failed_delta)
                    WHERE hour_start = p_hour AND protocol = p_protocol;
                    DELETE FROM external_login_hourly
                    WHERE hour_start = p_hour AND protocol = p_protocol
                      AND login_count = 0 AND success_count = 0 AND failed_count = 0;
                END IF;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION trg_external_login_hourly_fn()
            RETURNS TRIGGER AS $$
            DECLARE
                old_protocol TEXT;
                new_protocol TEXT;
                old_hour TIMESTAMPTZ;
                new_hour TIMESTAMPTZ;
                old_eligible BOOLEAN;
                new_eligible BOOLEAN;
                old_success BIGINT;
                old_failed BIGINT;
                new_success BIGINT;
                new_failed BIGINT;
            BEGIN
                old_eligible := FALSE;
                new_eligible := FALSE;

                -- Stream replay UPSERTs name these columns even when their
                -- values are unchanged. Avoid decrement/reincrement and the
                -- historical source lookup for those idempotent updates.
                IF TG_OP = 'UPDATE' THEN
                    IF OLD.started_at_ts IS NOT DISTINCT FROM NEW.started_at_ts
                       AND OLD.protocol IS NOT DISTINCT FROM NEW.protocol
                       AND OLD.auth_info IS NOT DISTINCT FROM NEW.auth_info
                       AND OLD.client_ip IS NOT DISTINCT FROM NEW.client_ip THEN
                        RETURN NEW;
                    END IF;
                END IF;

                IF TG_OP IN ('DELETE', 'UPDATE') THEN
                    old_eligible := OLD.started_at_ts IS NOT NULL AND (
                        (OLD.protocol IN ('SMTP', 'Smtp') AND OLD.auth_info IS NOT NULL)
                        OR OLD.protocol IN ('POP3', 'Pop3')
                        OR OLD.protocol IN ('IMAP', 'Imap')
                        OR (OLD.protocol IN ('HTTP', 'Http') AND OLD.auth_info IS NOT NULL)
                    );
                    IF old_eligible THEN
                        old_hour := date_trunc('hour', OLD.started_at_ts);
                        old_protocol := CASE
                            WHEN OLD.protocol IN ('SMTP', 'Smtp') THEN 'SMTP'
                            WHEN OLD.protocol IN ('POP3', 'Pop3') THEN 'POP3'
                            WHEN OLD.protocol IN ('IMAP', 'Imap') THEN 'IMAP'
                            ELSE 'HTTP'
                        END;
                        old_success := CASE WHEN OLD.auth_info->>'auth_success' = 'true' THEN 1 ELSE 0 END;
                        old_failed := CASE WHEN OLD.auth_info->>'auth_success' = 'false' THEN 1 ELSE 0 END;
                        PERFORM vigilyx_login_hourly_delta(old_hour, old_protocol, -1, -old_success, -old_failed);
                        DELETE FROM external_login_hourly_sources source_row
                        WHERE source_row.hour_start = old_hour
                          AND source_row.client_ip = OLD.client_ip
                          AND NOT EXISTS (
                              SELECT 1 FROM sessions s
                              WHERE s.id <> OLD.id
                                AND s.started_at_ts IS NOT NULL
                                AND s.started_at_ts >= old_hour
                                AND s.started_at_ts < old_hour + INTERVAL '1 hour'
                                AND s.client_ip = OLD.client_ip
                                AND (
                                    (s.protocol IN ('SMTP', 'Smtp') AND s.auth_info IS NOT NULL)
                                    OR s.protocol IN ('POP3', 'Pop3')
                                    OR s.protocol IN ('IMAP', 'Imap')
                                    OR (s.protocol IN ('HTTP', 'Http') AND s.auth_info IS NOT NULL)
                                )
                          );
                    END IF;
                END IF;

                IF TG_OP IN ('INSERT', 'UPDATE') THEN
                    new_eligible := NEW.started_at_ts IS NOT NULL AND (
                        (NEW.protocol IN ('SMTP', 'Smtp') AND NEW.auth_info IS NOT NULL)
                        OR NEW.protocol IN ('POP3', 'Pop3')
                        OR NEW.protocol IN ('IMAP', 'Imap')
                        OR (NEW.protocol IN ('HTTP', 'Http') AND NEW.auth_info IS NOT NULL)
                    );
                    IF new_eligible THEN
                        new_hour := date_trunc('hour', NEW.started_at_ts);
                        new_protocol := CASE
                            WHEN NEW.protocol IN ('SMTP', 'Smtp') THEN 'SMTP'
                            WHEN NEW.protocol IN ('POP3', 'Pop3') THEN 'POP3'
                            WHEN NEW.protocol IN ('IMAP', 'Imap') THEN 'IMAP'
                            ELSE 'HTTP'
                        END;
                        new_success := CASE WHEN NEW.auth_info->>'auth_success' = 'true' THEN 1 ELSE 0 END;
                        new_failed := CASE WHEN NEW.auth_info->>'auth_success' = 'false' THEN 1 ELSE 0 END;
                        PERFORM vigilyx_login_hourly_delta(new_hour, new_protocol, 1, new_success, new_failed);
                        INSERT INTO external_login_hourly_sources (hour_start, client_ip)
                        VALUES (new_hour, NEW.client_ip)
                        ON CONFLICT DO NOTHING;
                    END IF;
                END IF;

                IF TG_OP = 'DELETE' THEN
                    RETURN OLD;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_external_login_hourly') THEN
                    CREATE TRIGGER trg_external_login_hourly
                        AFTER INSERT OR DELETE OR UPDATE OF started_at_ts, protocol, auth_info, client_ip ON sessions
                        FOR EACH ROW EXECUTE FUNCTION trg_external_login_hourly_fn();
                END IF;
            END $$
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Clean up legacy packets table and related trigger functions
        sqlx::query("DROP TABLE IF EXISTS packets CASCADE")
            .execute(&self.pool)
            .await?;
        sqlx::query("DROP FUNCTION IF EXISTS trg_packet_insert_fn() CASCADE")
            .execute(&self.pool)
            .await?;
        sqlx::query("DROP FUNCTION IF EXISTS trg_packet_delete_fn() CASCADE")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Database Migration: add sender_domain column and backfill
    async fn migrate_add_sender_domain(&self) -> Result<()> {
        // PostgreSQL: check if column exists
        let columns: Vec<(String,)> = sqlx::query_as(
            "SELECT column_name::TEXT FROM information_schema.columns \
             WHERE table_name = 'sessions' AND column_name = 'sender_domain'",
        )
        .fetch_all(&self.pool)
        .await?;

        if columns.is_empty() {
            tracing::info!("Migrating database: adding sender_domain column...");
            sqlx::query("ALTER TABLE sessions ADD COLUMN sender_domain TEXT")
                .execute(&self.pool)
                .await?;

            // Backfill existing data: extract domain after @ from mail_from
            let affected = sqlx::query(
                "UPDATE sessions SET sender_domain = LOWER(SUBSTRING(mail_from FROM POSITION('@' IN mail_from) + 1)) \
                 WHERE mail_from IS NOT NULL AND POSITION('@' IN mail_from) > 0",
            )
            .execute(&self.pool)
            .await?;
            tracing::info!(
                "Database migration complete: sender_domain column added, backfilled {} rows",
                affected.rows_affected()
            );
        }

        Ok(())
    }

    /// List all applied schema migrations, ordered by version.
    ///
    /// Returns an empty Vec if the `schema_migrations` table does not yet exist
    /// (e.g. first run before `init()` is called).
    pub async fn list_migrations(&self) -> Result<Vec<SchemaMigration>> {
        // Guard: table may not exist yet on a brand-new database.
        let table_exists: Option<(String,)> = sqlx::query_as(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'schema_migrations'",
        )
        .fetch_optional(&self.pool)
        .await?;

        if table_exists.is_none() {
            return Ok(Vec::new());
        }

        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT version, description, TO_CHAR(executed_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
             FROM schema_migrations ORDER BY version",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(version, description, executed_at)| SchemaMigration {
                version,
                description,
                executed_at,
            })
            .collect())
    }
}

/// Record a migration version. Idempotent: `ON CONFLICT DO NOTHING` ensures
/// re-running `init()` / `init_security_tables()` never fails or duplicates rows.
pub(crate) async fn record_migration(
    pool: &sqlx::Pool<sqlx::Postgres>,
    version: &str,
    description: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO schema_migrations (version, description) \
         VALUES ($1, $2) ON CONFLICT (version) DO NOTHING",
    )
    .bind(version)
    .bind(description)
    .execute(pool)
    .await?;
    Ok(())
}
