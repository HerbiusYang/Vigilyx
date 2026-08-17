//! SecurityEngineData Create Migration (PostgreSQL)

use anyhow::Result;

use crate::VigilDb;
use crate::infra::migrate::record_migration;

const KEYWORD_SYSTEM_SEED_JSON: &str =
    include_str!("../../../../shared/schemas/keyword_overrides_seed.json");

const ENGINE_MODULE_DATA_SEED_JSON: &str =
    include_str!("../../../../shared/schemas/engine_module_data_seed.json");

impl VigilDb {
    /// SecurityEngine
    pub async fn init_security_tables(&self) -> Result<()> {
        // Security
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS security_verdicts (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                confidence DOUBLE PRECISION NOT NULL,
                categories TEXT NOT NULL,
                summary TEXT NOT NULL,
                pillar_scores TEXT NOT NULL,
                modules_run BIGINT NOT NULL,
                modules_flagged BIGINT NOT NULL,
                total_duration_ms BIGINT NOT NULL,
                created_at TEXT NOT NULL,
                fusion_details TEXT
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

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
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_module_results_session_module \
             ON security_module_results(session_id, module_id)",
        )
        .execute(&self.pool)
        .await?;

        // At-least-once Stream replay may analyze one session concurrently.
        // Keep the newest historical row before enforcing one current verdict
        // per session; the unique index makes subsequent writes race-safe.
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
            "HTTP session and data security incident tables",
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
                client_ip       TEXT
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
            ENGINE_MODULE_DATA_SEED_JSON,
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

        Ok(())
    }
}
