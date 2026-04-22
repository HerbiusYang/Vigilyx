//! IOC (Indicators of Compromise) Data

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::security::IocEntry;

use crate::VigilDb;

fn is_case_insensitive_ioc_type(ioc_type: &str) -> bool {
    matches!(ioc_type, "domain" | "email" | "hash" | "helo" | "x_mailer")
}

impl VigilDb {
    /// New IOC (UPSERT: New last_seen + hit_count)
    ///
    /// : admin_clean items, Source.
    /// confidence New MAX(),.
    pub async fn upsert_ioc(&self, ioc: &IocEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_ioc
                (id, indicator, ioc_type, source, verdict, confidence, attack_type,
                 first_seen, last_seen, hit_count, context, expires_at,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT(ioc_type, indicator) DO UPDATE SET
                last_seen = EXCLUDED.last_seen,
                hit_count = security_ioc.hit_count + 1,
                confidence = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.confidence
                    ELSE EXCLUDED.confidence
                END,
                verdict = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.verdict
                    ELSE EXCLUDED.verdict
                END,
                source = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.source
                    ELSE EXCLUDED.source
                END,
                attack_type = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.attack_type
                    WHEN EXCLUDED.attack_type != '' THEN EXCLUDED.attack_type
                    ELSE security_ioc.attack_type
                END,
                context = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.context
                    ELSE EXCLUDED.context
                END,
                expires_at = CASE
                    WHEN security_ioc.source IN ('admin_clean', 'system')
                        AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.expires_at
                    ELSE EXCLUDED.expires_at
                END,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(ioc.id.to_string())
        .bind(&ioc.indicator)
        .bind(&ioc.ioc_type)
        .bind(&ioc.source)
        .bind(&ioc.verdict)
        .bind(ioc.confidence)
        .bind(&ioc.attack_type)
        .bind(ioc.first_seen.to_rfc3339())
        .bind(ioc.last_seen.to_rfc3339())
        .bind(ioc.hit_count as i64)
        .bind(&ioc.context)
        .bind(ioc.expires_at.map(|t| t.to_rfc3339()))
        .bind(ioc.created_at.to_rfc3339())
        .bind(ioc.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// upsert IOC (, VALUES)
    ///
    /// upsert_ioc 1: admin_clean,confidence MAX.
    /// VALUES INSERT, N DB ceil(N/CHUNK).
    /// 14 x 500 = 7000,Security.
    pub async fn batch_upsert_iocs(&self, iocs: &[IocEntry]) -> Result<()> {
        if iocs.is_empty() {
            return Ok(());
        }

        const COLS_PER_ROW: usize = 14;
        const BATCH_CHUNK_SIZE: usize = 500;

        // Process:
        struct PreparedIoc {
            id: String,
            indicator: String,
            ioc_type: String,
            source: String,
            verdict: String,
            confidence: f64,
            attack_type: String,
            first_seen: String,
            last_seen: String,
            hit_count: i64,
            context: Option<String>,
            expires_at: Option<String>,
            created_at: String,
            updated_at: String,
        }

        let prepared: Vec<PreparedIoc> = iocs
            .iter()
            .map(|ioc| PreparedIoc {
                id: ioc.id.to_string(),
                indicator: ioc.indicator.clone(),
                ioc_type: ioc.ioc_type.clone(),
                source: ioc.source.clone(),
                verdict: ioc.verdict.clone(),
                confidence: ioc.confidence,
                attack_type: ioc.attack_type.clone(),
                first_seen: ioc.first_seen.to_rfc3339(),
                last_seen: ioc.last_seen.to_rfc3339(),
                hit_count: ioc.hit_count as i64,
                context: ioc.context.clone(),
                expires_at: ioc.expires_at.map(|t| t.to_rfc3339()),
                created_at: ioc.created_at.to_rfc3339(),
                updated_at: ioc.updated_at.to_rfc3339(),
            })
            .collect();

        let mut tx = self.pool.begin().await?;

        for chunk in prepared.chunks(BATCH_CHUNK_SIZE) {
            let mut sql = String::from(
                "INSERT INTO security_ioc \
                    (id, indicator, ioc_type, source, verdict, confidence, attack_type, \
                     first_seen, last_seen, hit_count, context, expires_at, \
                     created_at, updated_at) \
                VALUES ",
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
                    sql.push_str(&(param_idx + col as u32).to_string());
                }
                sql.push(')');
                param_idx += COLS_PER_ROW as u32;
            }

            sql.push_str(
                " ON CONFLICT(ioc_type, indicator) DO UPDATE SET \
                    last_seen = EXCLUDED.last_seen, \
                    hit_count = security_ioc.hit_count + 1, \
                    confidence = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.confidence \
                        ELSE EXCLUDED.confidence \
                    END, \
                    verdict = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.verdict \
                        ELSE EXCLUDED.verdict \
                    END, \
                    source = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.source \
                        ELSE EXCLUDED.source \
                    END, \
                    attack_type = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.attack_type \
                        WHEN EXCLUDED.attack_type != '' THEN EXCLUDED.attack_type \
                        ELSE security_ioc.attack_type \
                    END, \
                    context = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.context \
                        ELSE EXCLUDED.context \
                    END, \
                    expires_at = CASE \
                        WHEN security_ioc.source IN ('admin_clean', 'system') \
                            AND EXCLUDED.source NOT IN ('admin_clean', 'system') THEN security_ioc.expires_at \
                        ELSE EXCLUDED.expires_at \
                    END, \
                    updated_at = EXCLUDED.updated_at",
            );

            let mut query = sqlx::query(&sql);
            for row in chunk {
                query = query
                    .bind(&row.id)
                    .bind(&row.indicator)
                    .bind(&row.ioc_type)
                    .bind(&row.source)
                    .bind(&row.verdict)
                    .bind(row.confidence)
                    .bind(&row.attack_type)
                    .bind(&row.first_seen)
                    .bind(&row.last_seen)
                    .bind(row.hit_count)
                    .bind(&row.context)
                    .bind(&row.expires_at)
                    .bind(&row.created_at)
                    .bind(&row.updated_at);
            }
            query.execute(&mut *tx).await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// According toType+ IOC
    pub async fn find_ioc(&self, ioc_type: &str, indicator: &str) -> Result<Option<IocEntry>> {
        let row = if is_case_insensitive_ioc_type(ioc_type) {
            sqlx::query_as::<_, IocRow>(
                r#"
                SELECT id, indicator, ioc_type, source, verdict, confidence, attack_type,
                       first_seen, last_seen, hit_count, context, expires_at,
                       created_at, updated_at
                FROM security_ioc
                WHERE ioc_type = $1 AND LOWER(indicator) = LOWER($2)
                AND (expires_at IS NULL OR expires_at::timestamptz > NOW())
                LIMIT 1
                "#,
            )
            .bind(ioc_type)
            .bind(indicator)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, IocRow>(
                r#"
                SELECT id, indicator, ioc_type, source, verdict, confidence, attack_type,
                       first_seen, last_seen, hit_count, context, expires_at,
                       created_at, updated_at
                FROM security_ioc
                WHERE ioc_type = $1 AND indicator = $2
                AND (expires_at IS NULL OR expires_at::timestamptz > NOW())
                LIMIT 1
                "#,
            )
            .bind(ioc_type)
            .bind(indicator)
            .fetch_optional(&self.pool)
            .await?
        };

        match row {
            Some(r) => Ok(Some(r.into_ioc()?)),
            None => Ok(None),
        }
    }

    /// IOC (Pagination)
    pub async fn list_ioc(
        &self,
        ioc_type: Option<&str>,
        source: Option<&str>,
        search: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<IocEntry>, u64)> {
        self.list_ioc_filtered(ioc_type, source, search, None, limit, offset)
            .await
    }

    /// IOC with verdict filter (Pagination)
    pub async fn list_ioc_filtered(
        &self,
        ioc_type: Option<&str>,
        source: Option<&str>,
        search: Option<&str>,
        verdicts: Option<&[String]>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<IocEntry>, u64)> {
        let mut sql = String::from(
            r#"SELECT id, indicator, ioc_type, source, verdict, confidence, attack_type,
                      first_seen, last_seen, hit_count, context, expires_at,
                      created_at, updated_at,
                      COUNT(*) OVER() as total_count
               FROM security_ioc WHERE 1=1"#,
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(t) = ioc_type {
            binds.push(t.to_string());
            sql.push_str(&format!(" AND ioc_type = ${}", binds.len()));
        }
        if let Some(s) = source {
            binds.push(s.to_string());
            sql.push_str(&format!(" AND source = ${}", binds.len()));
        }
        if let Some(q) = search {
            binds.push(format!("%{q}%"));
            sql.push_str(&format!(" AND indicator LIKE ${}", binds.len()));
        }
        if let Some(v) = verdicts
            && !v.is_empty()
        {
            let placeholders: Vec<String> = v
                .iter()
                .map(|val| {
                    binds.push(val.clone());
                    format!("${}", binds.len())
                })
                .collect();
            sql.push_str(&format!(" AND verdict IN ({})", placeholders.join(",")));
        }

        sql.push_str(" ORDER BY last_seen DESC");
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

        let mut query = sqlx::query_as::<_, IocRowWithCount>(&sql);
        for b in &binds {
            query = query.bind(b);
        }

        let rows = query.fetch_all(&self.pool).await?;
        let total = rows
            .first()
            .map(|r| r.total_count.unwrap_or(0) as u64)
            .unwrap_or(0);
        let items: Result<Vec<IocEntry>> = rows.into_iter().map(|r| r.into_ioc()).collect();

        Ok((items?, total))
    }

    /// IOC (source='system' items, New)
    pub async fn delete_ioc(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM security_ioc WHERE id = $1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// IOC
    pub async fn cleanup_expired_ioc(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM security_ioc WHERE expires_at IS NOT NULL AND expires_at::timestamptz < NOW()",
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// (source='admin_clean'/'system' clean IOC)
    pub async fn list_intel_whitelist(
        &self,
        ioc_type: Option<&str>,
        search: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<IocEntry>, u64)> {
        let mut sql = String::from(
            r#"SELECT id, indicator, ioc_type, source, verdict, confidence, attack_type,
                      first_seen, last_seen, hit_count, context, expires_at,
                      created_at, updated_at,
                      COUNT(*) OVER() as total_count
               FROM security_ioc
               WHERE verdict = 'clean'
               AND source IN ('admin_clean', 'system')
               AND (expires_at IS NULL OR expires_at::timestamptz > NOW())"#,
        );
        let mut binds: Vec<String> = Vec::new();

        if let Some(t) = ioc_type {
            binds.push(t.to_string());
            sql.push_str(&format!(" AND ioc_type = ${}", binds.len()));
        }
        if let Some(q) = search {
            binds.push(format!("%{q}%"));
            sql.push_str(&format!(" AND indicator LIKE ${}", binds.len()));
        }

        sql.push_str(" ORDER BY last_seen DESC");
        sql.push_str(&format!(" LIMIT {} OFFSET {}", limit, offset));

        let mut query = sqlx::query_as::<_, IocRowWithCount>(&sql);
        for b in &binds {
            query = query.bind(b);
        }

        let rows = query.fetch_all(&self.pool).await?;
        let total = rows
            .first()
            .map(|r| r.total_count.unwrap_or(0) as u64)
            .unwrap_or(0);
        let items: Result<Vec<IocEntry>> = rows.into_iter().map(|r| r.into_ioc()).collect();

        Ok((items?, total))
    }

    /// (Security)
    pub async fn add_intel_clean(
        &self,
        indicator: &str,
        ioc_type: &str,
        description: Option<&str>,
    ) -> Result<IocEntry> {
        let now = Utc::now();
        let ioc = IocEntry {
            id: Uuid::new_v4(),
            indicator: indicator.to_string(),
            ioc_type: ioc_type.to_string(),
            source: "admin_clean".to_string(),
            verdict: "clean".to_string(),
            confidence: 1.0,
            attack_type: String::new(),
            first_seen: now,
            last_seen: now,
            hit_count: 0,
            context: description.map(|s| s.to_string()),
            expires_at: None,
            created_at: now,
            updated_at: now,
        };
        self.upsert_ioc(&ioc).await?;
        Ok(ioc)
    }

    /// IOC
    pub async fn extend_ioc_expiry(&self, id: Uuid, days: i64) -> Result<bool> {
        let now = Utc::now();
        let extension = chrono::Duration::days(days);
        // FromWhen expires_at now, Rust RFC3339
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT expires_at FROM security_ioc WHERE id = $1")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;

        let Some((expires_opt,)) = row else {
            return Ok(false);
        };

        let base = match expires_opt.as_deref() {
            Some(ts) => chrono::DateTime::parse_from_rfc3339(ts)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now),
            None => return Ok(false), // items
        };
        // Such as,From now; From expires_at
        let new_expires = if base < now {
            now + extension
        } else {
            base + extension
        };

        let result =
            sqlx::query("UPDATE security_ioc SET expires_at = $2, updated_at = $3 WHERE id = $1")
                .bind(id.to_string())
                .bind(new_expires.to_rfc3339())
                .bind(now.to_rfc3339())
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Load clean (source='system' 'admin_clean')
    pub async fn load_clean_domains(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT indicator FROM security_ioc
               WHERE ioc_type = 'domain' AND verdict = 'clean'
               AND source IN ('admin_clean', 'system')
               AND (expires_at IS NULL OR expires_at::timestamptz > NOW())"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(ind,)| ind).collect())
    }

    /// Load clean domains used by well-known sender heuristics.
    ///
    /// Includes both built-in system seeds and admin-curated whitelist entries.
    /// Admin-added clean domains should be treated as safe everywhere — not
    /// just by the intel module.
    pub async fn load_system_clean_domains(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT indicator FROM security_ioc
               WHERE ioc_type = 'domain' AND verdict = 'clean'
               AND source IN ('system', 'admin_clean')
               AND (expires_at IS NULL OR expires_at::timestamptz > NOW())"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(ind,)| ind).collect())
    }

    /// Load URL-structure trusted domains (used by link structural checks).
    ///
    /// Includes system seeds with `context='url_trusted'` AND all admin-curated
    /// clean domains (if an admin explicitly marks a domain clean, it should
    /// be trusted for URL structural checks as well).
    pub async fn load_url_trusted_domains(&self) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"SELECT indicator FROM security_ioc
               WHERE ioc_type = 'domain' AND verdict = 'clean'
               AND (
                   (source = 'system' AND context = 'url_trusted')
                   OR source = 'admin_clean'
               )
               AND (expires_at IS NULL OR expires_at::timestamptz > NOW())"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(ind,)| ind).collect())
    }

    /// Seed or refresh the built-in system whitelist at startup.
    ///
    /// Domain:
    /// - `intel_safe`: Query (OTX/VT) SecurityDomain
    /// - `url_trusted`: URL ServiceDomain
    pub async fn seed_system_whitelist(&self) -> Result<u64> {
        // Load from compiled-in JSON seed file (shared/schemas/system_whitelist_seed.json)
        let seed_json: &str = include_str!("../../../../shared/schemas/system_whitelist_seed.json");
        let seed: serde_json::Value = serde_json::from_str(seed_json)
            .map_err(|e| anyhow::anyhow!("system_whitelist_seed.json parse error: {}", e))?;

        let intel_safe: Vec<&str> = seed
            .get("intel_safe")
            .and_then(|v| v.get("items"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let url_trusted: Vec<&str> = seed
            .get("url_trusted")
            .and_then(|v| v.get("items"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let now = Utc::now().to_rfc3339();
        let mut inserted: u64 = 0;
        let mut tx = self.pool.begin().await?;

        for &domain in &intel_safe {
            let id = Uuid::new_v4().to_string();
            let result = sqlx::query(
                r#"INSERT INTO security_ioc
                    (id, indicator, ioc_type, source, verdict, confidence, attack_type,
                     first_seen, last_seen, hit_count, context, expires_at, created_at, updated_at)
                   VALUES ($1, $2, 'domain', 'system', 'clean', 1.0, '',
                           $3, $3, 0, 'intel_safe', NULL, $3, $3)
                   ON CONFLICT(ioc_type, indicator) DO UPDATE
                   SET source = 'system',
                       verdict = 'clean',
                       confidence = 1.0,
                       attack_type = '',
                       context = 'intel_safe',
                       expires_at = NULL,
                       updated_at = EXCLUDED.updated_at
                   WHERE security_ioc.source NOT IN ('manual', 'admin_clean')
                     AND COALESCE(security_ioc.context, '') <> 'system_malicious'"#,
            )
            .bind(&id)
            .bind(domain)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            inserted += result.rows_affected();
        }

        for &domain in &url_trusted {
            let id = Uuid::new_v4().to_string();
            let result = sqlx::query(
                r#"INSERT INTO security_ioc
                    (id, indicator, ioc_type, source, verdict, confidence, attack_type,
                     first_seen, last_seen, hit_count, context, expires_at, created_at, updated_at)
                   VALUES ($1, $2, 'domain', 'system', 'clean', 1.0, '',
                           $3, $3, 0, 'url_trusted', NULL, $3, $3)
                   ON CONFLICT(ioc_type, indicator) DO UPDATE
                   SET source = 'system',
                       verdict = 'clean',
                       confidence = 1.0,
                       attack_type = '',
                       context = 'url_trusted',
                       expires_at = NULL,
                       updated_at = EXCLUDED.updated_at
                   WHERE security_ioc.source NOT IN ('manual', 'admin_clean')
                     AND COALESCE(security_ioc.context, '') <> 'system_malicious'"#,
            )
            .bind(&id)
            .bind(domain)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
            inserted += result.rows_affected();
        }

        // --- Seed malicious domains ---
        let malicious_domains: Vec<&serde_json::Value> = seed
            .get("malicious_domains")
            .and_then(|v| v.get("items"))
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().collect())
            .unwrap_or_default();

        for item in &malicious_domains {
            let indicator = item.get("indicator").and_then(|v| v.as_str()).unwrap_or("");
            let confidence = item
                .get("confidence")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.9);
            let attack_type = item
                .get("attack_type")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let description = item
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let context = if description.is_empty() {
                "system_malicious".to_string()
            } else {
                format!("system_malicious: {}", description)
            };
            if indicator.is_empty() {
                continue;
            }
            let id = Uuid::new_v4().to_string();
            let result = sqlx::query(
                r#"INSERT INTO security_ioc
                    (id, indicator, ioc_type, source, verdict, confidence, attack_type,
                     first_seen, last_seen, hit_count, context, expires_at, created_at, updated_at)
                   VALUES ($1, $2, 'domain', 'system', 'malicious', $3, $4,
                           $5, $5, 0, $6, NULL, $5, $5)
                   ON CONFLICT(ioc_type, indicator) DO UPDATE
                   SET verdict = 'malicious',
                       confidence = EXCLUDED.confidence,
                       attack_type = EXCLUDED.attack_type,
                       source = 'system',
                       context = EXCLUDED.context,
                       updated_at = EXCLUDED.updated_at"#,
            )
            .bind(&id)
            .bind(indicator)
            .bind(confidence)
            .bind(attack_type)
            .bind(&now)
            .bind(&context)
            .execute(&mut *tx)
            .await?;
            inserted += result.rows_affected();
        }

        tx.commit().await?;
        Ok(inserted)
    }

    /// IOC ()
    pub async fn reduce_ioc_confidence(
        &self,
        ioc_type: &str,
        indicator: &str,
        reduction: f64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE security_ioc
            SET confidence = GREATEST(0.0, confidence - $3),
                updated_at = $4
            WHERE ioc_type = $1 AND indicator = $2
            "#,
        )
        .bind(ioc_type)
        .bind(indicator)
        .bind(reduction)
        .bind(Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// Database row type

#[derive(Debug, sqlx::FromRow)]
struct IocRow {
    id: String,
    indicator: String,
    ioc_type: String,
    source: String,
    verdict: String,
    confidence: f64,
    #[sqlx(default)]
    attack_type: String,
    first_seen: String,
    last_seen: String,
    hit_count: i64,
    context: Option<String>,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
}

impl IocRow {
    fn into_ioc(self) -> Result<IocEntry> {
        Ok(IocEntry {
            id: Uuid::parse_str(&self.id)?,
            indicator: self.indicator,
            ioc_type: self.ioc_type,
            source: self.source,
            verdict: self.verdict,
            confidence: self.confidence,
            attack_type: self.attack_type,
            first_seen: DateTime::parse_from_rfc3339(&self.first_seen)?.with_timezone(&Utc),
            last_seen: DateTime::parse_from_rfc3339(&self.last_seen)?.with_timezone(&Utc),
            hit_count: self.hit_count as u64,
            context: self.context,
            expires_at: self
                .expires_at
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()?
                .map(|t| t.with_timezone(&Utc)),
            created_at: DateTime::parse_from_rfc3339(&self.created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)?.with_timezone(&Utc),
        })
    }
}

#[derive(Debug, sqlx::FromRow)]
struct IocRowWithCount {
    id: String,
    indicator: String,
    ioc_type: String,
    source: String,
    verdict: String,
    confidence: f64,
    #[sqlx(default)]
    attack_type: String,
    first_seen: String,
    last_seen: String,
    hit_count: i64,
    context: Option<String>,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    #[sqlx(default)]
    total_count: Option<i64>,
}

impl IocRowWithCount {
    fn into_ioc(self) -> Result<IocEntry> {
        Ok(IocEntry {
            id: Uuid::parse_str(&self.id)?,
            indicator: self.indicator,
            ioc_type: self.ioc_type,
            source: self.source,
            verdict: self.verdict,
            confidence: self.confidence,
            attack_type: self.attack_type,
            first_seen: DateTime::parse_from_rfc3339(&self.first_seen)?.with_timezone(&Utc),
            last_seen: DateTime::parse_from_rfc3339(&self.last_seen)?.with_timezone(&Utc),
            hit_count: self.hit_count as u64,
            context: self.context,
            expires_at: self
                .expires_at
                .as_deref()
                .map(DateTime::parse_from_rfc3339)
                .transpose()?
                .map(|t| t.with_timezone(&Utc)),
            created_at: DateTime::parse_from_rfc3339(&self.created_at)?.with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)?.with_timezone(&Utc),
        })
    }
}
