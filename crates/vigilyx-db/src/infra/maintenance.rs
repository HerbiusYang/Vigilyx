//! Database Maintenance Operations: cleanup, optimize, disk rotation

use anyhow::Result;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use vigilyx_core::{ExternalLoginStats, HourlyLoginEntry, TrafficStats};

use crate::VigilDb;

const HTTP_TEMP_DIR: &str = "data/tmp/http";

/// Global disk usage threshold (percentage)
static DISK_THRESHOLD: AtomicU8 = AtomicU8::new(90);

/// Whether to enable auto rotation
static AUTO_ROTATE_ENABLED: AtomicBool = AtomicBool::new(true);

impl VigilDb {
    
    
   /// :sessions, verdicts, IOC, whitelist, feedback, temporal state,
   /// quarantine, training samples, config (/pipeline/ /AI),
   /// audit logs, login history..
    pub async fn factory_reset(&self) -> Result<()> {
       // 1. DROP
        let drop_tables = [
            "DROP TABLE IF EXISTS security_module_results",
            "DROP TABLE IF EXISTS security_verdicts",
            "DROP TABLE IF EXISTS security_ioc",
            "DROP TABLE IF EXISTS security_whitelist",
            "DROP TABLE IF EXISTS security_feedback",
            "DROP TABLE IF EXISTS security_sender_baselines",
            "DROP TABLE IF EXISTS security_disposition_rules",
            "DROP TABLE IF EXISTS security_temporal_cusum",
            "DROP TABLE IF EXISTS security_temporal_ewma",
            "DROP TABLE IF EXISTS security_entity_risk",
            "DROP TABLE IF EXISTS security_alerts",
            "DROP TABLE IF EXISTS security_config",
            "DROP TABLE IF EXISTS security_yara_rules",
            "DROP TABLE IF EXISTS quarantine",
            "DROP TABLE IF EXISTS security_threat_scenes",
            "DROP TABLE IF EXISTS security_scene_rules",
            "DROP TABLE IF EXISTS training_samples",
            "DROP TABLE IF EXISTS sessions",
            "DROP TABLE IF EXISTS data_security_incidents",
            "DROP TABLE IF EXISTS data_security_http_sessions",
            "DROP TABLE IF EXISTS config_security_pipeline",
            "DROP TABLE IF EXISTS config_sniffer",
            "DROP TABLE IF EXISTS config_ai_service",
            "DROP TABLE IF EXISTS config_email_alert",
            "DROP TABLE IF EXISTS config_syslog",
            "DROP TABLE IF EXISTS config_time_policy",
            "DROP TABLE IF EXISTS config_deployment",
            "DROP TABLE IF EXISTS config_internal_domains",
            "DROP TABLE IF EXISTS auth_credentials",
            "DROP TABLE IF EXISTS stats_cache",
            "DROP TABLE IF EXISTS audit_logs",
            "DROP TABLE IF EXISTS login_history",
        ];
        for sql in drop_tables {
            sqlx::query(sql).execute(&self.pool).await?;
        }

       // 2. config (, pipeline,)
        sqlx::query("DELETE FROM config").execute(&self.pool).await?;

        
        self.init().await?;
        self.init_security_tables().await?;

       // 4. VACUUM
        sqlx::query("VACUUM").execute(&self.pool).await?;
        sqlx::query("ANALYZE").execute(&self.pool).await?;
        // SEC-M02: avoid blocking the async runtime with std::fs operations
        let _ = tokio::task::spawn_blocking(cleanup_all_http_temp_files).await;

        Ok(())
    }

   /// Security cleanup: DROP TABLE + recreate + VACUUM + ANALYZE
    pub async fn clear_safe(&self) -> Result<()> {
        let drop_tables = [
            "DROP TABLE IF EXISTS security_module_results",
            "DROP TABLE IF EXISTS security_verdicts",
            "DROP TABLE IF EXISTS security_ioc",
            "DROP TABLE IF EXISTS security_whitelist",
            "DROP TABLE IF EXISTS security_feedback",
            "DROP TABLE IF EXISTS security_sender_baselines",
            "DROP TABLE IF EXISTS security_disposition_rules",
            "DROP TABLE IF EXISTS security_temporal_cusum",
            "DROP TABLE IF EXISTS security_temporal_ewma",
            "DROP TABLE IF EXISTS security_entity_risk",
            "DROP TABLE IF EXISTS security_alerts",
            "DROP TABLE IF EXISTS security_config",
            "DROP TABLE IF EXISTS quarantine",
            "DROP TABLE IF EXISTS security_threat_scenes",
            "DROP TABLE IF EXISTS training_samples",
            "DROP TABLE IF EXISTS sessions",
           // Data security engine tables
            "DROP TABLE IF EXISTS data_security_incidents",
            "DROP TABLE IF EXISTS data_security_http_sessions",
            "DROP TABLE IF EXISTS stats_cache",
        ];
        for sql in drop_tables {
            sqlx::query(sql).execute(&self.pool).await?;
        }

        self.init().await?;
        self.init_security_tables().await?;

        sqlx::query("VACUUM").execute(&self.pool).await?;
        sqlx::query("ANALYZE").execute(&self.pool).await?;
        let _ = tokio::task::spawn_blocking(cleanup_all_http_temp_files).await;

        Ok(())
    }

   /// Fast cleanup: DROP TABLE + recreate
    pub async fn clear_quick(&self) -> Result<()> {
        let drop_tables = [
            "DROP TABLE IF EXISTS security_module_results",
            "DROP TABLE IF EXISTS security_verdicts",
            "DROP TABLE IF EXISTS security_ioc",
            "DROP TABLE IF EXISTS security_whitelist",
            "DROP TABLE IF EXISTS security_feedback",
            "DROP TABLE IF EXISTS security_sender_baselines",
            "DROP TABLE IF EXISTS security_disposition_rules",
            "DROP TABLE IF EXISTS security_temporal_cusum",
            "DROP TABLE IF EXISTS security_temporal_ewma",
            "DROP TABLE IF EXISTS security_entity_risk",
            "DROP TABLE IF EXISTS security_alerts",
            "DROP TABLE IF EXISTS security_config",
            "DROP TABLE IF EXISTS quarantine",
            "DROP TABLE IF EXISTS security_threat_scenes",
            "DROP TABLE IF EXISTS training_samples",
            "DROP TABLE IF EXISTS sessions",
           // Data security engine tables
            "DROP TABLE IF EXISTS data_security_incidents",
            "DROP TABLE IF EXISTS data_security_http_sessions",
            "DROP TABLE IF EXISTS stats_cache",
        ];
        for sql in drop_tables {
            sqlx::query(sql).execute(&self.pool).await?;
        }

        self.init().await?;
        self.init_security_tables().await?;
        let _ = tokio::task::spawn_blocking(cleanup_all_http_temp_files).await;

        Ok(())
    }

   /// High-performance cleanup: DELETE without VACUUM
    pub async fn clear_high_performance(&self) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM security_module_results")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_verdicts")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_ioc")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_whitelist")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_feedback")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_sender_baselines")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_disposition_rules")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_temporal_cusum")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_temporal_ewma")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_entity_risk")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_alerts")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_config")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM quarantine")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM security_threat_scenes")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM training_samples")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM sessions")
            .execute(&mut *tx)
            .await?;
       // Data security engine tables
        sqlx::query("DELETE FROM data_security_incidents")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM data_security_http_sessions")
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM stats_cache")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO stats_cache (
                id, total_sessions, active_sessions, total_bytes, total_packets,
                smtp_sessions, pop3_sessions, imap_sessions, http_sessions
            ) VALUES (1, 0, 0, 0, 0, 0, 0, 0, 0)
            "#,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        let _ = tokio::task::spawn_blocking(cleanup_all_http_temp_files).await;

        Ok(())
    }

   /// ClearData (, clear_safe)
    pub async fn clear_all(&self) -> Result<()> {
        self.clear_safe().await
    }

   /// GetStatistics
    pub async fn get_stats(&self) -> Result<TrafficStats> {
       // From stats_cache (O(1) COUNT(*))
        let stats: Option<(i64, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
            "SELECT total_sessions::BIGINT, active_sessions::BIGINT, total_bytes::BIGINT, total_packets::BIGINT, \
                    smtp_sessions::BIGINT, pop3_sessions::BIGINT, imap_sessions::BIGINT \
             FROM stats_cache WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        match stats {
            Some(s) => Ok(TrafficStats {
                total_sessions: s.0 as u64,
                active_sessions: s.1 as u64,
                total_packets: s.3 as u64,
                total_bytes: s.2 as u64,
                smtp_sessions: s.4 as u64,
                pop3_sessions: s.5 as u64,
                imap_sessions: s.6 as u64,
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
            }),
           // stats_cache (First/)
            None => {
                let s: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
                    r#"SELECT
                        COUNT(*), COALESCE(SUM(CASE WHEN status='Active' THEN 1 ELSE 0 END), 0)::BIGINT,
                        COALESCE(SUM(total_bytes),0)::BIGINT,
                        COALESCE(SUM(packet_count),0)::BIGINT,
                        COALESCE(SUM(CASE WHEN protocol IN ('SMTP','Smtp') THEN 1 ELSE 0 END), 0)::BIGINT,
                        COALESCE(SUM(CASE WHEN protocol IN ('POP3','Pop3') THEN 1 ELSE 0 END), 0)::BIGINT,
                        COALESCE(SUM(CASE WHEN protocol IN ('IMAP','Imap') THEN 1 ELSE 0 END), 0)::BIGINT
                    FROM sessions"#,
                )
                .fetch_one(&self.pool)
                .await?;
                Ok(TrafficStats {
                    total_sessions: s.0 as u64,
                    active_sessions: s.1 as u64,
                    total_packets: s.3 as u64,
                    total_bytes: s.2 as u64,
                    smtp_sessions: s.4 as u64,
                    pop3_sessions: s.5 as u64,
                    imap_sessions: s.6 as u64,
                    packets_per_second: 0.0,
                    bytes_per_second: 0.0,
                })
            }
        }
    }

   /// Get Statistics (24, According to)
   ///
   /// Statistics:
   /// - SMTP: auth_info Session ()
   /// - POP3/IMAP: Session ()
   /// - HTTP:, When Data
    pub async fn get_external_login_stats(&self) -> Result<ExternalLoginStats> {
        let since = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();

       // x
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"
            SELECT
                TO_CHAR(started_at::timestamp, 'YYYY-MM-DD"T"HH24:00:00"Z"') as hour,
                protocol,
                COUNT(*) as cnt
            FROM sessions
            WHERE started_at >= $1
                AND (
                    (protocol IN ('SMTP', 'Smtp') AND auth_info IS NOT NULL)
                    OR protocol IN ('POP3', 'Pop3')
                    OR protocol IN ('IMAP', 'Imap')
                    OR (protocol IN ('HTTP', 'Http') AND auth_info IS NOT NULL)
                )
            GROUP BY hour, protocol
            ORDER BY hour ASC
            "#,
        )
        .bind(&since)
        .fetch_all(&self.pool)
        .await?;

       // Merge: IP + SMTP / (2 -> 1 DB)
        let agg: (i64, i64, i64) = sqlx::query_as(
            r#"
            SELECT
                COUNT(DISTINCT client_ip),
                COALESCE(SUM(CASE WHEN (auth_info->>'auth_success') = 'true' THEN 1 ELSE 0 END), 0)::BIGINT,
                COALESCE(SUM(CASE WHEN (auth_info->>'auth_success') = 'false' THEN 1 ELSE 0 END), 0)::BIGINT
            FROM sessions
            WHERE started_at >= $1
                AND (
                    (protocol IN ('SMTP', 'Smtp') AND auth_info IS NOT NULL)
                    OR protocol IN ('POP3', 'Pop3')
                    OR protocol IN ('IMAP', 'Imap')
                    OR (protocol IN ('HTTP', 'Http') AND auth_info IS NOT NULL)
                )
            "#,
        )
        .bind(&since)
        .fetch_one(&self.pool)
        .await?;
        let unique_ips = agg.0;
        let auth_stats = (agg.1, agg.2);

       // Build items
        let mut hourly_map: std::collections::BTreeMap<String, HourlyLoginEntry> =
            std::collections::BTreeMap::new();

        for (hour, protocol, cnt) in &rows {
            let entry = hourly_map
                .entry(hour.clone())
                .or_insert_with(|| HourlyLoginEntry {
                    hour: hour.clone(),
                    ..HourlyLoginEntry::default()
                });
            let count = *cnt as u64;
            match protocol.as_str() {
                "SMTP" | "Smtp" => entry.smtp = count,
                "POP3" | "Pop3" => entry.pop3 = count,
                "IMAP" | "Imap" => entry.imap = count,
                "HTTP" | "Http" => entry.http = count,
                _ => {}
            }
            entry.total = entry.smtp + entry.pop3 + entry.imap + entry.http;
        }

        let hourly: Vec<HourlyLoginEntry> = hourly_map.into_values().collect();

        let smtp_24h: u64 = hourly.iter().map(|h| h.smtp).sum();
        let pop3_24h: u64 = hourly.iter().map(|h| h.pop3).sum();
        let imap_24h: u64 = hourly.iter().map(|h| h.imap).sum();
        let http_24h: u64 = hourly.iter().map(|h| h.http).sum();
        let total_24h = smtp_24h + pop3_24h + imap_24h + http_24h;

        Ok(ExternalLoginStats {
            hourly,
            total_24h,
            smtp_24h,
            pop3_24h,
            imap_24h,
            http_24h,
            success_24h: auth_stats.0 as u64,
            failed_24h: auth_stats.1 as u64,
            unique_ips_24h: unique_ips as u64,
        })
    }

   /// Delete Data(sessions + verdicts/module_results/data_security)
   ///
   /// (sessions_deleted, security_rows_deleted).
   /// Delete: (FK But) ->.
    pub async fn cleanup_old_data(&self, days: i64) -> Result<(u64, u64)> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days);
        let cutoff_str = cutoff.to_rfc3339();
        let mut security_deleted: u64 = 0;

       // 1. module_results(verdict_id verdicts)
        let mr = sqlx::query(
            "DELETE FROM security_module_results WHERE verdict_id IN \
             (SELECT id FROM security_verdicts WHERE created_at < $1)",
        )
        .bind(&cutoff_str)
        .execute(&self.pool)
        .await?
        .rows_affected();
        security_deleted += mr;

       // 2. verdicts
        let vd = sqlx::query("DELETE FROM security_verdicts WHERE created_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        security_deleted += vd;

       // 3. data_security_incidents
        let dsi = sqlx::query("DELETE FROM data_security_incidents WHERE created_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        security_deleted += dsi;

       // 4. Delete old data_security_http_sessions + associated temp body files (CWE-459)
       // First collect IDs of sessions to be deleted, then clean up their temp files
        let doomed_ids: Vec<String> = sqlx::query_scalar(
            "SELECT id::text FROM data_security_http_sessions WHERE timestamp < $1",
        )
        .bind(&cutoff_str)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        let dsh = sqlx::query("DELETE FROM data_security_http_sessions WHERE timestamp < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        security_deleted += dsh;

       // SEC-M02: Clean up orphaned HTTP body temp files (spawn_blocking to avoid blocking async runtime)
        if !doomed_ids.is_empty() {
            let ids = doomed_ids.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut files_cleaned = 0u64;
                for id in &ids {
                    let path = format!("data/tmp/http/{}.bin", id);
                    if std::path::Path::new(&path).exists() {
                        if let Err(e) = std::fs::remove_file(&path) {
                            tracing::warn!(path, "Failed to remove HTTP temp file: {}", e);
                        } else {
                            files_cleaned += 1;
                        }
                    }
                }
                if files_cleaned > 0 {
                    tracing::info!(files_cleaned, "Cleaned up HTTP body temp files");
                }
            }).await;
        }

       // 5. security_feedback
        let fb = sqlx::query("DELETE FROM security_feedback WHERE created_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        security_deleted += fb;

       // 6. sessions()
        let sessions_deleted = sqlx::query("DELETE FROM sessions WHERE started_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();

        tracing::info!(
            sessions = sessions_deleted,
            verdicts = vd,
            module_results = mr,
            ds_incidents = dsi,
            ds_http_sessions = dsh,
            feedback = fb,
            days = days,
            "Data保留清理完成"
        );

        Ok((sessions_deleted, security_deleted))
    }

   /// (sender_baselines, temporal_cusum/ewma, entity_risk)
   ///
   /// New,.
    pub async fn cleanup_stale_temporal(&self, stale_days: i64) -> Result<u64> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(stale_days);
        let cutoff_str = cutoff.to_rfc3339();
        let mut total: u64 = 0;

        let r1 = sqlx::query("DELETE FROM security_sender_baselines WHERE updated_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        total += r1;

        let r2 = sqlx::query("DELETE FROM security_temporal_cusum WHERE updated_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        total += r2;

        let r3 = sqlx::query("DELETE FROM security_temporal_ewma WHERE updated_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        total += r3;

        let r4 = sqlx::query("DELETE FROM security_entity_risk WHERE updated_at < $1")
            .bind(&cutoff_str)
            .execute(&self.pool)
            .await?
            .rows_affected();
        total += r4;

        if total > 0 {
            tracing::info!(
                sender_baselines = r1,
                cusum = r2,
                ewma = r3,
                entity_risk = r4,
                stale_days = stale_days,
                "时序状态清理完成"
            );
        }

        Ok(total)
    }

   /// Performance notesData
    pub async fn optimize(&self) -> Result<()> {
        tracing::info!("开始OptimizeData库...");
        sqlx::query("ANALYZE").execute(&self.pool).await?;
        sqlx::query("VACUUM").execute(&self.pool).await?;
        tracing::info!("Data库Optimize完成");
        Ok(())
    }

   /// GetData
   ///
   /// (total_size, free_size).PostgreSQL freelist,
   /// free_size 0(VACUUM).
    pub async fn get_db_size(&self) -> Result<(u64, u64)> {
        let (total_size,): (i64,) = sqlx::query_as("SELECT pg_database_size(current_database())")
            .fetch_one(&self.pool)
            .await?;

        Ok((total_size as u64, 0))
    }

   /// Get
   ///
   /// PostgreSQL Mode Data.
   /// Such as PostgreSQL Data, District.
    pub fn get_disk_usage_percent(_db_url: &str) -> u8 {
       // PostgreSQL Mode: Data
       // PGDATA, DefaultRoad
        let pg_data_dir =
            std::env::var("PGDATA").unwrap_or_else(|_| "/var/lib/postgresql/data".to_string());
        let dir = std::path::Path::new(&pg_data_dir);

        #[cfg(unix)]
        {
            use std::ffi::CString;
           // PostgreSQL Data,Such as
            let check_dir = if dir.exists() {
                dir
            } else {
                std::path::Path::new("/")
            };
            if let Ok(c_path) = CString::new(check_dir.to_string_lossy().as_bytes()) {
               // SAFETY: c_path is a valid CString (null-terminated), stat is zero-initialized
               // which is valid for statvfs, and both outlive the libc::statvfs call.
                unsafe {
                    let mut stat: libc::statvfs = std::mem::zeroed();
                    if libc::statvfs(c_path.as_ptr(), &mut stat) == 0 {
                        let block_size = stat.f_frsize;
                        let total = stat.f_blocks * block_size;
                        let free = stat.f_bfree * block_size;
                        let avail = stat.f_bavail * block_size;

                        if total > 0 {
                            let used = total.saturating_sub(free);
                            let denominator = used + avail;
                            if denominator > 0 {
                                return (used as f64 / denominator as f64 * 100.0).round() as u8;
                            }
                        }
                    }
                }
            }
        }

        let disks = sysinfo::Disks::new_with_refreshed_list();
        let mut best_match: Option<(usize, u8)> = None;

        for disk in disks.list() {
            let mount = disk.mount_point();
            if dir.starts_with(mount) {
                let mount_len = mount.as_os_str().len();
                let total = disk.total_space();
                let avail = disk.available_space();
                let usage = if total > 0 {
                    ((total - avail) as f64 / total as f64 * 100.0).round() as u8
                } else {
                    0
                };
                if best_match.is_none_or(|(len, _)| mount_len > len) {
                    best_match = Some((mount_len, usage));
                }
            }
        }

        best_match.map_or(0, |(_, usage)| usage)
    }

   /// Get Threshold
    pub fn get_rotate_threshold() -> u8 {
        DISK_THRESHOLD.load(Ordering::Relaxed)
    }

   /// Threshold
    pub fn set_rotate_threshold(percent: u8) {
        DISK_THRESHOLD.store(percent.clamp(50, 99), Ordering::Relaxed);
    }

   /// Get
    pub fn is_auto_rotate_enabled() -> bool {
        AUTO_ROTATE_ENABLED.load(Ordering::Relaxed)
    }

    
    pub fn set_auto_rotate_enabled(enabled: bool) {
        AUTO_ROTATE_ENABLED.store(enabled, Ordering::Relaxed);
    }

    
    pub async fn check_and_rotate_if_needed(&self, db_url: &str) -> Result<(bool, u64, u64)> {
        if !Self::is_auto_rotate_enabled() {
            return Ok((false, 0, 0));
        }

        let usage = Self::get_disk_usage_percent(db_url);
        let threshold = Self::get_rotate_threshold();

        if usage < threshold {
            return Ok((false, 0, 0));
        }

        tracing::warn!(
            "磁盘使用率 {}% 超过Threshold {}%，开始自动轮转清理最旧Data...",
            usage,
            threshold
        );

        let (total_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await?;

        if total_count == 0 {
            return Ok((false, 0, 0));
        }

        let delete_count = ((total_count as f64 * 0.10).ceil() as i64).max(1);

        let mut tx = self.pool.begin().await?;

        let oldest_ids: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM sessions ORDER BY started_at ASC LIMIT $1")
                .bind(delete_count)
                .fetch_all(&mut *tx)
                .await?;

        if oldest_ids.is_empty() {
            tx.commit().await?;
            return Ok((false, 0, 0));
        }

        let id_list: Vec<&str> = oldest_ids.iter().map(|(id,)| id.as_str()).collect();
        let placeholders: String = id_list
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect::<Vec<_>>()
            .join(",");

        let sess_query = format!("DELETE FROM sessions WHERE id IN ({})", placeholders);
        let mut q2 = sqlx::query(&sess_query);
        for id in &id_list {
            q2 = q2.bind(*id);
        }
        let sessions_deleted = q2.execute(&mut *tx).await?.rows_affected();

        tx.commit().await?;

        tracing::info!(
            "自动轮转完成: 删除 {} Session (磁盘使用率: {}%)",
            sessions_deleted,
            usage
        );

        Ok((true, sessions_deleted, 0))
    }
}

fn cleanup_all_http_temp_files() {
    let dir = std::path::Path::new(HTTP_TEMP_DIR);
    if !dir.exists() {
        return;
    }

    let mut files_cleaned = 0u64;
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(dir = HTTP_TEMP_DIR, "Failed to read HTTP temp directory: {}", e);
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), "Failed to remove HTTP temp file: {}", e);
        } else {
            files_cleaned += 1;
        }
    }

    if files_cleaned > 0 {
        tracing::info!(files_cleaned, "Cleaned all HTTP body temp files");
    }
}
