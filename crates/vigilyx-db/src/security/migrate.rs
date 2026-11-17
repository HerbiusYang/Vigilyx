//! SecurityEngineData Create Migration (PostgreSQL)

use anyhow::Result;
use vigilyx_core::security::classify_threat_type;

use super::module_data_seed::embedded_module_data_seed;
use crate::VigilDb;
use crate::infra::migrate::record_migration;

const KEYWORD_SYSTEM_SEED_JSON: &str =
    include_str!("../../../../shared/schemas/keyword_overrides_seed.json");

impl VigilDb {
    /// SecurityEngine
    pub async fn init_security_tables(&self) -> Result<()> {
        let _migration_guard = crate::infra::migrate::migration_mutex().lock().await;

        // The API and standalone engine start together in mirror mode and
        // both initialize the security schema.  PostgreSQL's
        // `CREATE INDEX IF NOT EXISTS` is not race-free when two sessions
        // create the same previously-missing index concurrently, so keep one
        // dedicated connection and serialize the complete security migration
        // sequence across processes.  `close_on_drop` guarantees that the
        // session-level lock is released on every return path.
        let mut security_migration_connection = self.pool.acquire().await?;
        security_migration_connection.close_on_drop();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended('vigilyx.security_migrations', 0))")
            .execute(&mut *security_migration_connection)
            .await?;

        // `sessions` is created by the base migration, but older deployments
        // may reach security initialization without the additive NDR fields.
        for statement in [
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_metadata_ready BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_candidate BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_reported_alert BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS bounce_target_addresses TEXT",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        // Security
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_verdicts (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                threat_type TEXT,
                confidence DOUBLE PRECISION NOT NULL,
                categories TEXT NOT NULL,
                summary TEXT NOT NULL,
                pillar_scores TEXT NOT NULL,
                modules_run BIGINT NOT NULL,
                modules_flagged BIGINT NOT NULL,
                total_duration_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                fusion_details TEXT,
                verdict_origin TEXT NOT NULL DEFAULT 'native',
                source_session_id TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Existing installations need the provenance columns before reused
        // first-hop verdicts can be written. Native verdicts keep the default.
        sqlx::query(
            "ALTER TABLE security_verdicts \
             ADD COLUMN IF NOT EXISTS verdict_origin TEXT NOT NULL DEFAULT 'native'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE security_verdicts ADD COLUMN IF NOT EXISTS source_session_id TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE security_verdicts ADD COLUMN IF NOT EXISTS threat_type TEXT")
            .execute(&self.pool)
            .await?;

        // Old verdicts remain unknown: absence of prior coverage metadata
        // cannot establish a complete inspection retrospectively.
        sqlx::query("ALTER TABLE security_verdicts ADD COLUMN IF NOT EXISTS inspection_coverage TEXT NOT NULL DEFAULT 'unknown'")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE security_verdicts ADD COLUMN IF NOT EXISTS coverage_reasons TEXT NOT NULL DEFAULT '[]'")
            .execute(&self.pool)
            .await?;

        record_migration(
            &self.pool,
            "131_verdict_inspection_coverage",
            "persist inspection coverage separately from threat and delivery policy",
        )
        .await?;

        let security_reconciliation_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '100_security_verdicts')",
        )
        .fetch_one(&self.pool)
        .await?;

        if security_reconciliation_needed {
            // Repair legacy illegal combinations before backfilling. A public
            // malicious family is established only for Medium-or-higher verdicts;
            // Safe/Low rows retain their detailed observations in categories.
            let cleared = sqlx::query(
                "UPDATE security_verdicts SET threat_type = NULL \
                 WHERE threat_type = 'data_exfiltration' \
                    OR (threat_type IS NOT NULL AND threat_level IN ('safe', 'low'))",
            )
            .execute(&self.pool)
            .await?
            .rows_affected();
            if cleared > 0 {
                tracing::info!(cleared, "Cleared non-actionable legacy threat types");
            }

            // Backfill the new primary label from existing actionable rows. This
            // is deterministic and uses the same category-family map as live
            // verdicts; anomaly/coverage/spam-like rows remain NULL.
            let legacy_rows = sqlx::query_as::<_, (String, String)>(
                "SELECT id, categories FROM security_verdicts \
                 WHERE threat_type IS NULL \
                   AND threat_level IN ('medium', 'high', 'critical')",
            )
            .fetch_all(&self.pool)
            .await?;
            let mut backfilled = 0_u64;
            for (id, categories_json) in legacy_rows {
                let categories =
                    serde_json::from_str::<Vec<String>>(&categories_json).unwrap_or_default();
                let Some(threat_type) = classify_threat_type(&categories) else {
                    continue;
                };
                let result = sqlx::query(
                    "UPDATE security_verdicts SET threat_type = $2 \
                     WHERE id = $1 AND threat_type IS NULL",
                )
                .bind(id)
                .bind(threat_type.to_string())
                .execute(&self.pool)
                .await?;
                backfilled += result.rows_affected();
            }
            if backfilled > 0 {
                tracing::info!(backfilled, "Backfilled primary email threat types");
            }
        }

        // Module
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_module_results (
                id SERIAL PRIMARY KEY,
                verdict_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                module_id TEXT NOT NULL,
                module_name TEXT NOT NULL,
                pillar TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                confidence DOUBLE PRECISION NOT NULL,
                categories TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence TEXT NOT NULL,
                details TEXT,
                duration_ms BIGINT NOT NULL,
                analyzed_at TEXT NOT NULL,
                bpa_b DOUBLE PRECISION,
                bpa_d DOUBLE PRECISION,
                bpa_u DOUBLE PRECISION,
                engine_id TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Concurrent analyses of one session (live stream, catch-up rescan,
        // release rescan) used to stack two rows per module. Keep the newest
        // row (highest SERIAL id) per (session_id, module_id) before enforcing
        // uniqueness; the unique index then makes the UPSERT in
        // `insert_module_results` race-safe.
        if security_reconciliation_needed {
            sqlx::query(
                r#"
                DELETE FROM security_module_results older
                USING security_module_results newer
                WHERE older.session_id = newer.session_id
                  AND older.module_id = newer.module_id
                  AND older.id < newer.id
                "#,
            )
            .execute(&self.pool)
            .await?;
        }
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_module_results_session_module \
             ON security_module_results(session_id, module_id)",
        )
        .execute(&self.pool)
        .await?;

        // At-least-once Stream replay may analyze one session concurrently.
        // Keep the newest historical row before enforcing one current verdict
        // per session; the unique index makes subsequent writes race-safe.
        if security_reconciliation_needed {
            sqlx::query(
                r#"
                DELETE FROM security_verdicts older
                USING security_verdicts newer
                WHERE older.session_id = newer.session_id
                  AND (
                        older.created_at < newer.created_at
                     OR (older.created_at = newer.created_at AND older.id < newer.id)
                  )
                "#,
            )
            .execute(&self.pool)
            .await?;
        }
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_security_verdicts_session ON security_verdicts(session_id)",
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "100_security_verdicts",
            "security_verdicts and security_module_results tables",
        )
        .await?;

        // IOC
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc (
                id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'manual',
                verdict TEXT NOT NULL DEFAULT 'suspicious',
                confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
                attack_type TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                hit_count BIGINT NOT NULL DEFAULT 0,
                context TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "101_security_ioc",
            "IOC (Indicators of Compromise) table",
        )
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_whitelist (
                id TEXT PRIMARY KEY,
                entry_type TEXT NOT NULL,
                value TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT DEFAULT 'system'
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "102_security_whitelist",
            "security whitelist table",
        )
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_feedback (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                verdict_id TEXT,
                submitted_by TEXT NOT NULL DEFAULT '',
                feedback_type TEXT NOT NULL,
                module_id TEXT,
                original_threat_level TEXT NOT NULL,
                user_comment TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                processed_at TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "103_security_feedback",
            "false-positive feedback table",
        )
        .await?;

        // Sender (Used for anomaly_detect)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_sender_baselines (
                sender TEXT PRIMARY KEY,
                avg_daily_count DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                avg_recipients DOUBLE PRECISION NOT NULL DEFAULT 1.0,
                typical_hours TEXT NOT NULL DEFAULT '[]',
                has_attachments_ratio DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                total_emails BIGINT NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "104_sender_baselines",
            "sender behavior baseline table for anomaly detection",
        )
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_disposition_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                priority BIGINT NOT NULL DEFAULT 100,
                conditions TEXT NOT NULL,
                actions TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "105_disposition_rules",
            "automated disposition rules table",
        )
        .await?;

        // CUSUM
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_temporal_cusum (
                entity_key TEXT PRIMARY KEY,
                s_pos DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                s_neg DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                mu_0 DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                sample_count BIGINT NOT NULL DEFAULT 0,
                alarm_active BOOLEAN NOT NULL DEFAULT FALSE,
                running_sum DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                running_sq_sum DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // EWMA
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_temporal_ewma (
                entity_key TEXT PRIMARY KEY,
                fast_value DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                slow_value DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                initialized BOOLEAN NOT NULL DEFAULT FALSE,
                observation_count BIGINT NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_entity_risk (
                entity_key TEXT PRIMARY KEY,
                risk_value DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                alpha DOUBLE PRECISION NOT NULL DEFAULT 0.92,
                email_count BIGINT NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "106_temporal_analysis",
            "CUSUM, dual-speed EWMA, and entity risk accumulation tables",
        )
        .await?;

        // (NLP fine-tuning)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS training_samples (
                id              TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL,
                label           INTEGER NOT NULL,
                label_name      TEXT NOT NULL,
                subject         TEXT,
                body_text       TEXT,
                body_html       TEXT,
                mail_from       TEXT,
                rcpt_to         TEXT,
                analyst_comment TEXT,
                original_threat_level TEXT,
                verdict_id      TEXT,
                created_at      TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "107_training_samples",
            "NLP fine-tuning training samples table",
        )
        .await?;

        // Alert (Phase 4)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_alerts (
                id TEXT PRIMARY KEY,
                verdict_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                alert_level TEXT NOT NULL,
                expected_loss DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                return_period DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                cvar DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                risk_final DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                k_conflict DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                cusum_alarm BOOLEAN NOT NULL DEFAULT FALSE,
                rationale TEXT NOT NULL DEFAULT '',
                acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
                acknowledged_by TEXT,
                acknowledged_at TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "108_security_alerts",
            "risk-scored security alerts table",
        )
        .await?;

        // Index
        let indexes = [
            "CREATE INDEX IF NOT EXISTS idx_verdicts_session ON security_verdicts(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_verdicts_threat ON security_verdicts(threat_level)",
            "CREATE INDEX IF NOT EXISTS idx_verdicts_created ON security_verdicts(created_at DESC)",
            // Index: SecurityStatistics JOIN + GROUP BY (session_id, threat_level, created_at)
            "CREATE INDEX IF NOT EXISTS idx_verdicts_session_threat_created ON security_verdicts(session_id, threat_level, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_results_verdict ON security_module_results(verdict_id)",
            "CREATE INDEX IF NOT EXISTS idx_results_session ON security_module_results(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_results_module ON security_module_results(module_id)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_indicator ON security_ioc(indicator)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_type ON security_ioc(ioc_type)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_type_indicator ON security_ioc(ioc_type, indicator)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_source ON security_ioc(source)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_attack_type ON security_ioc(attack_type)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_expires ON security_ioc(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_whitelist_type_value ON security_whitelist(entry_type, value)",
            "CREATE INDEX IF NOT EXISTS idx_feedback_session ON security_feedback(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_feedback_status ON security_feedback(status)",
            "CREATE INDEX IF NOT EXISTS idx_disposition_priority ON security_disposition_rules(priority, enabled)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_level ON security_alerts(alert_level)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_session ON security_alerts(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_training_samples_label ON training_samples(label)",
            "CREATE INDEX IF NOT EXISTS idx_training_samples_session ON training_samples(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_training_samples_created ON training_samples(created_at DESC)",
        ];

        for idx_sql in indexes {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }

        record_migration(
            &self.pool,
            "109_security_indexes",
            "performance indexes on security verdicts, IOC, whitelist, feedback, alerts, training_samples",
        )
        .await?;

        // YARA
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_yara_rules (
                id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'custom',
                severity TEXT NOT NULL DEFAULT 'high',
                source TEXT NOT NULL DEFAULT 'custom',
                rule_source TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                hit_count BIGINT NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // YARA Index
        let yara_indexes = [
            "CREATE INDEX IF NOT EXISTS idx_yara_rules_enabled ON security_yara_rules(enabled)",
            "CREATE INDEX IF NOT EXISTS idx_yara_rules_category ON security_yara_rules(category)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_yara_rules_name ON security_yara_rules(rule_name)",
        ];
        for idx_sql in yara_indexes {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }

        record_migration(
            &self.pool,
            "110_yara_rules",
            "YARA rule storage and indexes",
        )
        .await?;

        // Data securityModule
        self.init_data_security_tables().await?;

        record_migration(
            &self.pool,
            "111_data_security",
            "HTTP data-security tables and unified email review table",
        )
        .await?;

        let seed_value = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind("keyword_system_seed")
        .bind(seed_value)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "112_keyword_system_seed",
            "seed canonical system keyword set into config",
        )
        .await?;

        // MTA
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS quarantine (
                id              TEXT PRIMARY KEY,
                session_id      TEXT NOT NULL,
                verdict_id      TEXT,
                mail_from       TEXT,
                rcpt_to         TEXT NOT NULL DEFAULT '[]',
                subject         TEXT,
                raw_eml         BYTEA NOT NULL,
                threat_level    TEXT NOT NULL,
                reason          TEXT,
                status          TEXT NOT NULL DEFAULT 'quarantined',
                created_at      TEXT NOT NULL,
                released_at     TEXT,
                released_by     TEXT,
                ttl_days        INTEGER NOT NULL DEFAULT 30,
                client_ip       TEXT,
                direction       TEXT NOT NULL DEFAULT 'unknown',
                release_rescan_request_id TEXT,
                release_rescan_verdict_id TEXT,
                release_rescan_threat_level TEXT,
                release_rescan_content_sha256 TEXT,
                release_rescan_completed_at TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Incremental upgrade for existing deployments (CREATE TABLE IF NOT
        // EXISTS does not add columns to pre-existing tables).
        sqlx::query("ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS client_ip TEXT")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'unknown'",
        )
        .execute(&self.pool)
        .await?;
        for statement in [
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS release_rescan_request_id TEXT",
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS release_rescan_verdict_id TEXT",
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS release_rescan_threat_level TEXT",
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS release_rescan_content_sha256 TEXT",
            "ALTER TABLE quarantine ADD COLUMN IF NOT EXISTS release_rescan_completed_at TEXT",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_status_created
             ON quarantine(status, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_session_id
             ON quarantine(session_id)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_quarantine_direction_status
             ON quarantine(direction, status, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "110_quarantine",
            "MTA proxy quarantine storage table",
        )
        .await?;

        // ── 113: threat scene tables ──────────────────────────────────
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_threat_scenes (
                id                  TEXT PRIMARY KEY,
                scene_type          TEXT NOT NULL,
                actor               TEXT NOT NULL,
                actor_type          TEXT NOT NULL,
                target_domain       TEXT,
                time_window_start   TEXT NOT NULL,
                time_window_end     TEXT NOT NULL,
                email_count         INTEGER NOT NULL DEFAULT 0,
                unique_recipients   INTEGER NOT NULL DEFAULT 0,
                bounce_count        INTEGER NOT NULL DEFAULT 0,
                sample_subjects     JSONB NOT NULL DEFAULT '[]',
                sample_recipients   JSONB NOT NULL DEFAULT '[]',
                threat_level        TEXT NOT NULL,
                status              TEXT NOT NULL DEFAULT 'active',
                auto_blocked        BOOLEAN NOT NULL DEFAULT FALSE,
                ioc_id              TEXT,
                details             JSONB NOT NULL DEFAULT '{}',
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_scenes_type_status
             ON security_threat_scenes(scene_type, status)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_scenes_created
             ON security_threat_scenes(created_at DESC)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_scenes_actor
             ON security_threat_scenes(actor)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_scenes_threat_level
             ON security_threat_scenes(threat_level)",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_scene_rules (
                scene_type  TEXT PRIMARY KEY,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                config      JSONB NOT NULL DEFAULT '{}',
                updated_at  TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO security_scene_rules (scene_type, enabled, config, updated_at)
            VALUES ('bulk_mailing', TRUE, '{}', NOW()::TEXT)
            ON CONFLICT DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO security_scene_rules (scene_type, enabled, config, updated_at)
            VALUES ('bounce_harvest', TRUE, '{}', NOW()::TEXT)
            ON CONFLICT DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO security_scene_rules (scene_type, enabled, config, updated_at)
            VALUES ('internal_domain_impersonation', TRUE, '{}', NOW()::TEXT)
            ON CONFLICT DO NOTHING
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_sessions_bounce_candidates
             ON sessions(started_at DESC)
             WHERE mail_from IS NULL OR mail_from = '' OR mail_from = '<>'",
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "113_threat_scenes",
            "Threat scene detection tables and bounce candidate index",
        )
        .await?;

        // ── 114: refresh keyword seed (force-overwrite with latest multilingual set) ──
        let seed_v2 = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("keyword_system_seed")
        .bind(seed_v2)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "114_keyword_system_seed_v2",
            "refresh keyword seed with multilingual phishing/BEC/authority phrases (1000+ each)",
        )
        .await?;

        let seed_v3 = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("keyword_system_seed")
        .bind(seed_v3)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "115_keyword_system_seed_v3",
            "extend keyword seed with runtime scenario banner, DSN, and auto-reply phrase sets",
        )
        .await?;

        let seed_v4 = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("keyword_system_seed")
        .bind(seed_v4)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "116_keyword_system_seed_v4",
            "refresh keyword seed with production gateway warning phrases used by content prefilter",
        )
        .await?;

        // Migration #117: Seed engine module data (all hardcoded static lists from detection modules)
        let module_data_seed = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            embedded_module_data_seed(),
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("engine_module_data_seed")
        .bind(module_data_seed)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "117_engine_module_data_seed_v1",
            "seed all engine detection module data lists (58 lists) from JSON into config table",
        )
        .await?;

        // Migration #118: Refresh every keyword category with the canonical
        // multilingual seed (at least 2,000 entries per category).  The
        // separate keyword_overrides config is deliberately left untouched so
        // administrator additions/removals survive the refresh.
        let seed_v5 = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("keyword_system_seed")
        .bind(seed_v5)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "118_keyword_system_seed_v5",
            "refresh all keyword categories to 2000+ deterministic multilingual entries",
        )
        .await?;

        // Migration #119: Re-apply the canonical seed after normalizing
        // full-width/confusable characters with the same rules as the engine.
        // This keeps persisted counts and runtime effective counts identical
        // on databases that already applied migration 118.
        let seed_v6 = serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
            KEYWORD_SYSTEM_SEED_JSON,
        )?)?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("keyword_system_seed")
        .bind(seed_v6)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "119_keyword_system_seed_v6",
            "re-apply Unicode-normalized keyword seed without duplicate effective entries",
        )
        .await?;

        // Migration #120: Older versions persisted a minimal built-in YARA
        // snapshot with `condition: true`. These rows are metadata only; the
        // runtime now loads executable extras exclusively from source=custom.
        // Neutralize existing snapshots as a defense in depth and preserve
        // the rows for audit/UI visibility.
        sqlx::query(
            r#"
            UPDATE security_yara_rules
            SET rule_source = regexp_replace(
                    rule_source,
                    'condition:[[:space:]]*true',
                    'condition: false',
                    'g'
                ),
                updated_at = NOW()::TEXT
            WHERE source = 'builtin'
              AND rule_source ~ 'condition:[[:space:]]*true'
            "#,
        )
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "120_yara_builtin_rule_source_safe",
            "neutralize persisted built-in YARA universal-match snapshots",
        )
        .await?;

        // Migration #121: retain the submitting platform identity so feedback
        // throttling and same-user idempotency remain effective across API
        // restarts and multiple API replicas. Existing feedback is preserved.
        sqlx::query(
            "ALTER TABLE security_feedback ADD COLUMN IF NOT EXISTS submitted_by TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_feedback_actor_created ON security_feedback(submitted_by, created_at)",
        )
        .execute(&self.pool)
        .await?;
        record_migration(
            &self.pool,
            "121_feedback_integrity",
            "persist feedback actor for authorization, throttling, and idempotency",
        )
        .await?;

        // Migration #122: preserve the first observed inbound SMTP hop and
        // the downstream hops that reuse its verdict in passive mirror mode.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS email_delivery_chains (
                chain_id                    TEXT PRIMARY KEY,
                fingerprint                 TEXT NOT NULL,
                first_session_id            TEXT NOT NULL,
                first_seen_at               TEXT NOT NULL,
                first_server_ip             TEXT NOT NULL,
                first_verdict_id            TEXT,
                first_threat_level          TEXT,
                last_seen_at                TEXT NOT NULL,
                hop_count                   INTEGER NOT NULL DEFAULT 1,
                dangerous_forwarded_count   INTEGER NOT NULL DEFAULT 0,
                created_at                  TEXT NOT NULL,
                updated_at                  TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS email_delivery_hops (
                session_id              TEXT PRIMARY KEY,
                chain_id                TEXT NOT NULL,
                fingerprint             TEXT NOT NULL,
                first_session_id        TEXT NOT NULL,
                hop_index               INTEGER NOT NULL,
                client_ip               TEXT NOT NULL DEFAULT '',
                server_ip               TEXT NOT NULL,
                observed_at             TEXT NOT NULL,
                first_hop_threat_level  TEXT,
                verdict_origin          TEXT NOT NULL DEFAULT 'pending',
                reused_from_session_id TEXT,
                dangerous_forwarded     BOOLEAN NOT NULL DEFAULT FALSE,
                smtp_security_rejected  BOOLEAN NOT NULL DEFAULT FALSE,
                smtp_security_rejection_metadata_ready BOOLEAN NOT NULL DEFAULT FALSE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE email_delivery_hops \
             ADD COLUMN IF NOT EXISTS client_ip TEXT NOT NULL DEFAULT ''",
        )
        .execute(&self.pool)
        .await?;
        for statement in [
            "ALTER TABLE email_delivery_hops ADD COLUMN IF NOT EXISTS smtp_security_rejected BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE email_delivery_hops ADD COLUMN IF NOT EXISTS smtp_security_rejection_metadata_ready BOOLEAN NOT NULL DEFAULT FALSE",
        ] {
            sqlx::query(statement).execute(&self.pool).await?;
        }

        // Expand each legacy SMTP transcript only once during migration and
        // persist the result on the hop. Runtime delivery statistics then use
        // a typed predicate instead of repeatedly walking session JSONB.
        let smtp_security_rejection_backfill = sqlx::query(
            r#"
            UPDATE email_delivery_hops h
            SET smtp_security_rejected = COALESCE((
                    SELECT EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements(
                            COALESCE(s.content->'smtp_dialog', '[]'::jsonb)
                        ) AS dialog
                        WHERE dialog->>'direction' = 'inbound'
                          AND dialog->>'command'
                              ~ '^55[0-4] 5\.7\.[0-9]+ SECURITY_POLICY_REJECTED$'
                    )
                    FROM sessions s
                    WHERE s.id = h.session_id
                ), FALSE),
                smtp_security_rejection_metadata_ready = TRUE
            WHERE NOT smtp_security_rejection_metadata_ready
            "#,
        )
        .execute(&self.pool)
        .await?;
        if smtp_security_rejection_backfill.rows_affected() > 0 {
            tracing::info!(
                rows = smtp_security_rejection_backfill.rows_affected(),
                "Backfilled structured SMTP message-security rejection metadata"
            );
        }

        // A passive capture can emit the completed message before the server's
        // final DATA response arrives. Registration handles the opposite
        // ordering; this trigger closes the late-response race by refreshing
        // the typed action whenever the persisted SMTP transcript changes.
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION vigilyx_refresh_hop_smtp_security_rejection()
            RETURNS TRIGGER
            LANGUAGE plpgsql
            AS $function$
            BEGIN
                UPDATE email_delivery_hops h
                SET smtp_security_rejected = EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements(
                            COALESCE(NEW.content->'smtp_dialog', '[]'::jsonb)
                        ) AS dialog
                        WHERE dialog->>'direction' = 'inbound'
                          AND dialog->>'command'
                              ~ '^55[0-4] 5\.7\.[0-9]+ SECURITY_POLICY_REJECTED$'
                    ),
                    smtp_security_rejection_metadata_ready = TRUE
                WHERE h.session_id = NEW.id;
                RETURN NEW;
            END;
            $function$
            "#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"
            DO $block$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_trigger
                    WHERE tgname = 'trg_sessions_refresh_hop_smtp_security_rejection'
                      AND tgrelid = 'sessions'::regclass
                      AND NOT tgisinternal
                ) THEN
                    CREATE TRIGGER trg_sessions_refresh_hop_smtp_security_rejection
                    AFTER INSERT OR UPDATE OF content ON sessions
                    FOR EACH ROW
                    EXECUTE FUNCTION vigilyx_refresh_hop_smtp_security_rejection();
                END IF;
            END;
            $block$
            "#,
        )
        .execute(&self.pool)
        .await?;
        // PostgreSQL's built-in TEXT -> timestamptz cast is STABLE rather
        // than IMMUTABLE, so it cannot appear directly in an expression
        // index. Delivery timestamps are emitted as RFC3339 values by
        // Vigilyx; this immutable, UTC-pinned parser also makes malformed
        // legacy rows harmless to the index and rolling-window queries.
        sqlx::query(
            r#"
            CREATE OR REPLACE FUNCTION vigilyx_text_timestamptz(value TEXT)
            RETURNS TIMESTAMPTZ
            LANGUAGE plpgsql
            IMMUTABLE
            STRICT
            PARALLEL SAFE
            SET timezone = 'UTC'
            AS $$
            BEGIN
                IF NOT pg_input_is_valid(value, 'timestamptz') THEN
                    RETURN NULL;
                END IF;
                RETURN value::timestamptz;
            END;
            $$
            "#,
        )
        .execute(&self.pool)
        .await?;

        // A large legacy installation can retain millions of rows where the
        // typed session timestamp is NULL.  The external-login dashboard only
        // needs the first and current hour, but a plain TEXT timestamp index
        // still makes PostgreSQL walk the entire 24-hour lexical range before
        // parsing every row.  Keep this expression index partial so the hot
        // path stays small and new typed rows use idx_sessions_started_at_ts.
        if let Err(error) = sqlx::query(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_sessions_started_legacy_ts \
             ON sessions((vigilyx_text_timestamptz(started_at)) DESC) \
             WHERE started_at_ts IS NULL",
        )
        .execute(&self.pool)
        .await
        {
            tracing::warn!(
                %error,
                "Create legacy session timestamp expression index failed (non-fatal)"
            );
        }

        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_delivery_chains_fingerprint_seen ON email_delivery_chains(fingerprint, last_seen_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_chains_fingerprint_updated ON email_delivery_chains(fingerprint, updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_chains_first_seen ON email_delivery_chains(first_seen_at DESC)",
            // Runtime rolling-window queries compare these legacy TEXT
            // timestamps as timestamptz. The plain TEXT indexes above cannot
            // support that cast, so keep expression indexes for the hot path.
            "CREATE INDEX IF NOT EXISTS idx_delivery_chains_first_seen_ts ON email_delivery_chains((vigilyx_text_timestamptz(first_seen_at)) DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_hops_chain_observed ON email_delivery_hops(chain_id, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_hops_chain_observed_ts ON email_delivery_hops(chain_id, (vigilyx_text_timestamptz(observed_at)) DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_hops_observed_ts ON email_delivery_hops((vigilyx_text_timestamptz(observed_at)) DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_hops_forwarded ON email_delivery_hops(dangerous_forwarded, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_delivery_hops_security_rejected ON email_delivery_hops(chain_id, server_ip, hop_index) WHERE smtp_security_rejection_metadata_ready AND smtp_security_rejected",
        ] {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_verdicts_origin \
             ON security_verdicts(verdict_origin, created_at DESC)",
        )
        .execute(&self.pool)
        .await?;
        record_migration(
            &self.pool,
            "122_email_delivery_lineage",
            "first-hop verdict reuse and downstream forwarding coverage",
        )
        .await?;

        // Migration #124: remove gateway-mutated subject/recipient metadata
        // from the delivery identity and order hops by SMTP relay topology.
        // Raw sessions and verdicts are intentionally kept.
        self.reconcile_email_delivery_lineage_v3().await?;

        // Migration #125: collect the local denominator and per-session IOC
        // observations needed by the likelihood-ratio shadow model. These
        // tables are telemetry-only in stage 1 and do not alter verdicts.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_message_population (
                session_id TEXT PRIMARY KEY,
                verdict_id TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'unknown',
                threat_level TEXT NOT NULL DEFAULT 'safe',
                engine_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                observed_at TEXT NOT NULL,
                capture_coverage TEXT NOT NULL DEFAULT 'unknown'
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_observations (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                verdict_id TEXT NOT NULL,
                indicator TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source_detector TEXT NOT NULL DEFAULT 'traffic_observation',
                activity_key TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'unknown',
                threat_level TEXT NOT NULL DEFAULT 'safe',
                engine_confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
                observed_at TEXT NOT NULL,
                capture_coverage TEXT NOT NULL DEFAULT 'unknown',
                UNIQUE (session_id, ioc_type, indicator)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Stage-2 correlation metadata is additive so databases that already
        // ran migration 125 keep their observations and can be upgraded in
        // place.
        for alter_sql in [
            "ALTER TABLE security_ioc_observations ADD COLUMN IF NOT EXISTS detector_family TEXT NOT NULL DEFAULT 'traffic_observation'",
            "ALTER TABLE security_ioc_observations ADD COLUMN IF NOT EXISTS external_provider TEXT NOT NULL DEFAULT 'local'",
            "ALTER TABLE security_ioc_observations ADD COLUMN IF NOT EXISTS evidence_cluster TEXT NOT NULL DEFAULT 'traffic_observation'",
        ] {
            sqlx::query(alter_sql).execute(&self.pool).await?;
        }

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_traffic_stats (
                ioc_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                observed_count BIGINT NOT NULL DEFAULT 0 CHECK (observed_count >= 0),
                outbound_count BIGINT NOT NULL DEFAULT 0 CHECK (outbound_count >= 0),
                inbound_count BIGINT NOT NULL DEFAULT 0 CHECK (inbound_count >= 0),
                unknown_direction_count BIGINT NOT NULL DEFAULT 0 CHECK (unknown_direction_count >= 0),
                provisional_threat_count BIGINT NOT NULL DEFAULT 0 CHECK (provisional_threat_count >= 0),
                distinct_session_count BIGINT NOT NULL DEFAULT 0 CHECK (distinct_session_count >= 0),
                distinct_activity_count BIGINT NOT NULL DEFAULT 0 CHECK (distinct_activity_count >= 0),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (ioc_type, indicator)
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_outcomes (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL,
                verdict_id TEXT,
                ioc_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                outcome TEXT NOT NULL,
                source TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                reason TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_message_outcomes (
                id BIGSERIAL PRIMARY KEY,
                session_id TEXT NOT NULL,
                verdict_id TEXT,
                outcome TEXT NOT NULL,
                source TEXT NOT NULL,
                actor TEXT NOT NULL DEFAULT '',
                reason TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_ioc_shadow_type_config (
                ioc_type TEXT PRIMARY KEY,
                half_life_hours DOUBLE PRECISION NOT NULL CHECK (half_life_hours > 0),
                min_labeled_evidence BIGINT NOT NULL DEFAULT 20 CHECK (min_labeled_evidence >= 0),
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        for (ioc_type, half_life_hours) in [
            ("hash", 24.0 * 365.0),
            ("ip", 24.0 * 7.0),
            ("url", 24.0 * 30.0),
            ("domain", 24.0 * 90.0),
            ("email", 24.0 * 30.0),
            ("helo", 24.0 * 14.0),
            ("x_mailer", 24.0 * 14.0),
        ] {
            sqlx::query(
                "INSERT INTO security_ioc_shadow_type_config \
                 (ioc_type, half_life_hours, min_labeled_evidence, updated_at) \
                 VALUES ($1, $2, 20, NOW()::TEXT) ON CONFLICT (ioc_type) DO NOTHING",
            )
            .bind(ioc_type)
            .bind(half_life_hours)
            .execute(&self.pool)
            .await?;
        }

        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_ioc_population_observed ON security_ioc_message_population(observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_population_direction ON security_ioc_message_population(direction, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_observations_indicator ON security_ioc_observations(ioc_type, indicator, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_observations_activity ON security_ioc_observations(activity_key, observed_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_observations_session ON security_ioc_observations(session_id)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_observations_cluster ON security_ioc_observations(ioc_type, indicator, evidence_cluster)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_outcomes_indicator ON security_ioc_outcomes(ioc_type, indicator, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_outcomes_session ON security_ioc_outcomes(session_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_message_outcomes_session ON security_ioc_message_outcomes(session_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_message_outcomes_label ON security_ioc_message_outcomes(outcome, created_at DESC)",
        ] {
            sqlx::query(idx_sql).execute(&self.pool).await?;
        }

        record_migration(
            &self.pool,
            "125_ioc_denominator_telemetry",
            "IOC local denominator, deduplicated observations, traffic stats, and outcomes",
        )
        .await?;
        record_migration(
            &self.pool,
            "126_ioc_shadow_read_model",
            "IOC evidence clusters, message outcomes, type decay configuration, and Shadow read model",
        )
        .await?;

        // Migration #127: Refresh the runtime detector vocabulary after adding
        // the narrow routine-release and long-form bulletin calibrations.
        let module_data_seed_v2 = serde_json::to_string(
            &serde_json::from_str::<serde_json::Value>(embedded_module_data_seed())?,
        )?;
        sqlx::query(
            "INSERT INTO config (key, value) VALUES ($1, $2) \
             ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind("engine_module_data_seed")
        .bind(module_data_seed_v2)
        .execute(&self.pool)
        .await?;

        record_migration(
            &self.pool,
            "127_engine_module_data_seed_v2",
            "refresh engine detector data with routine release and bulletin calibration lists",
        )
        .await?;

        // Migration #128: older HTTP rows may contain session identifiers,
        // CSRF tokens, or bearer material in query values. New writes use the
        // shared redactor; historical rows are irreversibly reduced to their
        // path before any runtime role or API can read them again.
        let http_uri_redaction_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '128_http_uri_secret_redaction')",
        )
        .fetch_one(&self.pool)
        .await?;
        if http_uri_redaction_needed {
            sqlx::query(
                "UPDATE data_security_http_sessions
                 SET uri = split_part(split_part(uri, '?', 1), '#', 1)
                 WHERE uri LIKE '%?%' OR uri LIKE '%#%'",
            )
            .execute(&self.pool)
            .await?;
            sqlx::query(
                "UPDATE data_security_incidents
                 SET request_url = split_part(split_part(request_url, '?', 1), '#', 1)
                 WHERE request_url LIKE '%?%' OR request_url LIKE '%#%'",
            )
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "128_http_uri_secret_redaction",
                "remove query and fragment secrets from historical HTTP security records",
            )
            .await?;
        }

        // Migration #129: privacy projection is now a non-disableable system
        // invariant. Normalize legacy installations whose persisted policy
        // still says `enabled=false` so backups, support tooling, and older
        // readers cannot mistake stale configuration for the live policy.
        let privacy_policy_enforcement_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '129_enforce_privacy_policy')",
        )
        .fetch_one(&self.pool)
        .await?;
        if privacy_policy_enforcement_needed {
            sqlx::query(
                "INSERT INTO config (key, value) VALUES ('privacy_policy', '{\"enabled\":true}') \
                 ON CONFLICT (key) DO UPDATE \
                 SET value = jsonb_set(config.value::jsonb, '{enabled}', 'true'::jsonb, true)::text",
            )
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "129_enforce_privacy_policy",
                "normalize legacy privacy policy to the non-disableable protected state",
            )
            .await?;
        }

        // Migration #130: the original URI cleanup removed historical query
        // values and fragments but could leave absolute-form authority/userinfo
        // behind, while the first live redactor retained redacted query keys.
        // Canonical storage is now path-only for every producer and old row.
        let http_uri_path_only_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '130_http_uri_path_only')",
        )
        .fetch_one(&self.pool)
        .await?;
        if http_uri_path_only_needed {
            for table_and_column in [
                ("data_security_http_sessions", "uri"),
                ("data_security_incidents", "request_url"),
            ] {
                let (table, column) = table_and_column;
                let strip_suffix = format!(
                    "UPDATE {table} SET {column} = split_part(split_part({column}, '?', 1), '#', 1) \
                     WHERE {column} LIKE '%?%' OR {column} LIKE '%#%'"
                );
                sqlx::query(sqlx::AssertSqlSafe(strip_suffix))
                    .execute(&self.pool)
                    .await?;
                let strip_authority = format!(
                    "UPDATE {table} \
                     SET {column} = COALESCE(NULLIF(regexp_replace({column}, \
                         '^([A-Za-z][A-Za-z0-9+.-]*:)?//[^/]*', ''), ''), '/') \
                     WHERE {column} ~ '^([A-Za-z][A-Za-z0-9+.-]*:)?//'"
                );
                sqlx::query(sqlx::AssertSqlSafe(strip_authority))
                    .execute(&self.pool)
                    .await?;
            }
            record_migration(
                &self.pool,
                "130_http_uri_path_only",
                "reduce all historical HTTP request targets to path-only storage",
            )
            .await?;
        }

        // Migration #131: add source-attributed semantic vocabulary and
        // non-scoring cross-part candidates for account-verification and
        // storage-quota reward lures. Runtime promotions remain governed by
        // their separate evidence registry and evaluation gates.
        let semantic_candidate_seed_refresh_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '131_semantic_cross_claim_candidates')",
        )
        .fetch_one(&self.pool)
        .await?;
        if semantic_candidate_seed_refresh_needed {
            let semantic_candidate_seed =
                serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
                    embedded_module_data_seed(),
                )?)?;
            sqlx::query(
                "INSERT INTO config (key, value) VALUES ($1, $2) \
                 ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind("engine_module_data_seed")
            .bind(semantic_candidate_seed)
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "131_semantic_cross_claim_candidates",
                "refresh semantic detector seed with source-attributed linked-CTA candidate policy",
            )
            .await?;
        }

        // Migration #132: refresh semantic candidate policy after tightening
        // block-local CTA binding, ambiguity resolution, and incomplete-scan
        // reporting. This remains observation-only and does not alter fusion.
        let semantic_resolution_seed_refresh_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '132_semantic_resolution_policy')",
        )
        .fetch_one(&self.pool)
        .await?;
        if semantic_resolution_seed_refresh_needed {
            let semantic_resolution_seed =
                serde_json::to_string(&serde_json::from_str::<serde_json::Value>(
                    embedded_module_data_seed(),
                )?)?;
            sqlx::query(
                "INSERT INTO config (key, value) VALUES ($1, $2) \
                 ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind("engine_module_data_seed")
            .bind(semantic_resolution_seed)
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "132_semantic_resolution_policy",
                "refresh semantic candidate policy with bounded relation resolution and coverage states",
            )
            .await?;
        }

        // Retire stored V1 selectors without replacing any other pipeline settings.
        sqlx::query(
            "UPDATE config SET value = jsonb_set(value::jsonb, '{verdict_config,aggregation}', \
             '\"clustered_ds_v2\"'::jsonb)::text \
             WHERE key = 'security_pipeline' AND value::jsonb #>> '{verdict_config,aggregation}' \
             IN ('ds_murphy', 'clustered_ds_v1', 'legacy_ds_murphy')",
        )
        .execute(&self.pool)
        .await?;
        record_migration(
            &self.pool,
            "133_authoritative_ds_v2",
            "retire V1 selectors and enable authoritative D-S V2 with explicit identity-review policy",
        )
        .await?;

        // Feedback is an immutable label/evidence ledger. Legacy rows remain
        // missing snapshots; never reconstruct old evidence from today's verdict.
        sqlx::query(
            "ALTER TABLE security_feedback \
             ADD COLUMN IF NOT EXISTS corrected_threat_level TEXT, \
             ADD COLUMN IF NOT EXISTS evidence_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb, \
             ADD COLUMN IF NOT EXISTS snapshot_sha256 TEXT, \
             ADD COLUMN IF NOT EXISTS learning_status TEXT NOT NULL DEFAULT 'insufficient_evidence', \
             ADD COLUMN IF NOT EXISTS learning_reason TEXT DEFAULT 'legacy_missing_snapshot'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'feedback_corrected_severity_valid') THEN
                    ALTER TABLE security_feedback ADD CONSTRAINT feedback_corrected_severity_valid
                    CHECK (corrected_threat_level IS NULL OR
                        (feedback_type = 'legitimate' AND corrected_threat_level = 'safe') OR
                        (feedback_type IN ('phishing','spoofing','social_engineering','other_threat')
                         AND corrected_threat_level IN ('low','medium','high','critical')));
                END IF;
            END $$"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            r#"CREATE OR REPLACE FUNCTION vigilyx_immutable_feedback_evidence() RETURNS trigger
            LANGUAGE plpgsql AS $$ BEGIN
                IF ROW(NEW.id, NEW.session_id, NEW.submitted_by, NEW.created_at,
                       NEW.feedback_type, NEW.corrected_threat_level, NEW.evidence_snapshot,
                       NEW.snapshot_sha256, NEW.verdict_id, NEW.original_threat_level)
                   IS DISTINCT FROM ROW(OLD.id, OLD.session_id, OLD.submitted_by, OLD.created_at,
                       OLD.feedback_type, OLD.corrected_threat_level, OLD.evidence_snapshot,
                       OLD.snapshot_sha256, OLD.verdict_id, OLD.original_threat_level) THEN
                    RAISE EXCEPTION 'feedback labels and evidence are immutable; append a correction';
                END IF;
                RETURN NEW;
            END $$"#,
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("DROP TRIGGER IF EXISTS feedback_evidence_immutable ON security_feedback")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TRIGGER feedback_evidence_immutable BEFORE UPDATE ON security_feedback \
             FOR EACH ROW EXECUTE FUNCTION vigilyx_immutable_feedback_evidence()",
        )
        .execute(&self.pool)
        .await?;
        record_migration(
            &self.pool,
            "134_ds_learning_feedback",
            "immutable analyst severity and DS evidence snapshots",
        )
        .await?;

        // Refresh only the two requested review policies. Preserve all other
        // seeded lists, pipeline settings and administrator overrides.
        let review_seed_refresh_needed: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM schema_migrations \
             WHERE version = '135_medium_content_review')",
        )
        .fetch_one(&self.pool)
        .await?;
        if review_seed_refresh_needed {
            let seed: serde_json::Value = serde_json::from_str(embedded_module_data_seed())?;
            sqlx::query(
                "UPDATE config SET value = jsonb_set(\
                 jsonb_set(value::jsonb, '{lists,semantic_intent_review_policy_v2}', $1), \
                 '{lists,recipient_targeting_review_policy_v2}', $2)::text \
                 WHERE key = 'engine_module_data_seed'",
            )
            .bind(&seed["lists"]["semantic_intent_review_policy_v2"])
            .bind(&seed["lists"]["recipient_targeting_review_policy_v2"])
            .execute(&self.pool)
            .await?;
            record_migration(
                &self.pool,
                "135_medium_content_review",
                "Medium review for scored semantic intent and admitted recipient-specific URLs",
            )
            .await?;
        }

        self.init_privacy_tables().await?;

        Ok(())
    }
}
