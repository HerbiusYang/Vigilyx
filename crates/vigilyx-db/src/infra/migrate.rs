//! Database Table Creation and Migration (PostgreSQL)

use anyhow::Result;

use crate::VigilDb;

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
                sender_domain TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

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

        // Initialize cache rows (if not exists)
        sqlx::query(
            r#"
            INSERT INTO stats_cache (id, total_sessions, active_sessions, total_bytes, total_packets,
                smtp_sessions, pop3_sessions, imap_sessions)
            SELECT 1,
                (SELECT COUNT(*) FROM sessions),
                (SELECT COUNT(*) FROM sessions WHERE status = 'Active'),
                (SELECT COALESCE(SUM(total_bytes), 0) FROM sessions),
                (SELECT COALESCE(SUM(packet_count), 0) FROM sessions),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('SMTP', 'Smtp')),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('POP3', 'Pop3')),
                (SELECT COUNT(*) FROM sessions WHERE protocol IN ('IMAP', 'Imap'))
            WHERE NOT EXISTS (SELECT 1 FROM stats_cache WHERE id = 1)
            "#,
        )
        .execute(&self.pool)
        .await?;

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

        // Large-table performance indexes (best-effort, non-blocking for writes)
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
        ];

        for idx_sql in concurrent_indexes {
            if let Err(e) = sqlx::query(&idx_sql).execute(&self.pool).await {
                tracing::warn!(
                    "Create concurrent performance index failed (non-fatal): {}",
                    e
                );
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
            sqlx::query(&sql).execute(&self.pool).await?;
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
            if let Err(e) = sqlx::query(&sql).bind(config_key).execute(&self.pool).await {
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
        if let Err(e) = sqlx::query(&completed_analyzable_index)
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
                    imap_sessions = CASE WHEN NEW.protocol IN ('IMAP','Imap') THEN imap_sessions + 1 ELSE imap_sessions END
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
                    imap_sessions = CASE WHEN OLD.protocol IN ('IMAP','Imap') THEN GREATEST(0, imap_sessions - 1) ELSE imap_sessions END
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
                    total_packets = total_packets + (NEW.packet_count - OLD.packet_count)
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
                IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_session_update') THEN
                    CREATE TRIGGER trg_session_update
                        AFTER UPDATE OF status, total_bytes ON sessions
                        FOR EACH ROW EXECUTE FUNCTION trg_session_update_fn();
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

    /// Database Migration: add content and email_count columns (if not exists)
    /// PostgreSQL uses ADD COLUMN IF NOT EXISTS (9.6+)
    /// Note: When creating new database, CREATE TABLE already includes all columns, this method only used for incremental migration from old schema
    #[allow(dead_code)]
    async fn migrate_add_content_column(&self) -> Result<()> {
        let columns_to_add = [
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS content JSONB",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS email_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS error_reason TEXT",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS message_id TEXT",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_info JSONB",
        ];

        for alter_sql in columns_to_add {
            sqlx::query(alter_sql).execute(&self.pool).await?;
        }

        Ok(())
    }

    /// Database Migration: add sender_domain column and backfill
    #[allow(dead_code)]
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
