//! Data

use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use vigilyx_core::security::WhitelistEntry;

use crate::VigilDb;

impl VigilDb {
    pub async fn get_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let rows = sqlx::query_as::<_, WhitelistRow>(
            r#"
            SELECT id, entry_type, value, description, created_at, created_by
            FROM security_whitelist
            ORDER BY entry_type, value
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    pub async fn is_whitelisted(&self, entry_type: &str, value: &str) -> Result<bool> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM security_whitelist WHERE entry_type = $1 AND value = $2",
        )
        .bind(entry_type)
        .bind(value)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.0 > 0)
    }

    /// items
    pub async fn add_whitelist_entry(&self, entry: &WhitelistEntry) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_whitelist
                (id, entry_type, value, description, created_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(entry.id.to_string())
        .bind(&entry.entry_type)
        .bind(&entry.value)
        .bind(&entry.description)
        .bind(entry.created_at.to_rfc3339())
        .bind(&entry.created_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// items
    pub async fn delete_whitelist_entry(&self, id: Uuid) -> Result<bool> {
        let result = sqlx::query("DELETE FROM security_whitelist WHERE id = $1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn batch_set_whitelist(&self, entries: &[WhitelistEntry]) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM security_whitelist")
            .execute(&mut *tx)
            .await?;
        for entry in entries {
            sqlx::query(
                r#"
                INSERT INTO security_whitelist
                    (id, entry_type, value, description, created_at, created_by)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(entry.id.to_string())
            .bind(&entry.entry_type)
            .bind(&entry.value)
            .bind(&entry.description)
            .bind(entry.created_at.to_rfc3339())
            .bind(&entry.created_by)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

// Database row type

#[derive(Debug, sqlx::FromRow)]
struct WhitelistRow {
    id: String,
    entry_type: String,
    value: String,
    description: Option<String>,
    created_at: String,
    created_by: Option<String>,
}

impl WhitelistRow {
    fn into_entry(self) -> Result<WhitelistEntry> {
        Ok(WhitelistEntry {
            id: Uuid::parse_str(&self.id)?,
            entry_type: self.entry_type,
            value: self.value,
            description: self.description,
            created_at: DateTime::parse_from_rfc3339(&self.created_at)?.with_timezone(&Utc),
            created_by: self.created_by.unwrap_or_else(|| "system".to_string()),
        })
    }
}
