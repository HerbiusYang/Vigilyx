//! YARA Data

use anyhow::Result;

use crate::VigilDb;

/// YARA
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct YaraRuleRow {
    pub id: String,
    pub rule_name: String,
    pub category: String,
    pub severity: String,
    pub source: String, // "builtin" | "custom"
    pub rule_source: String,
    pub description: String,
    pub enabled: bool,
    pub hit_count: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl VigilDb {
    /// YARA ()
    pub async fn list_yara_rules(&self, enabled_only: Option<bool>) -> Result<Vec<YaraRuleRow>> {
        let rows = if let Some(true) = enabled_only {
            sqlx::query_as::<_, YaraRuleRow>(
                r#"
                SELECT id, rule_name, category, severity, source, rule_source,
                       description, enabled, hit_count, created_at, updated_at
                FROM security_yara_rules
                WHERE enabled IS TRUE
                ORDER BY category, rule_name
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, YaraRuleRow>(
                r#"
                SELECT id, rule_name, category, severity, source, rule_source,
                       description, enabled, hit_count, created_at, updated_at
                FROM security_yara_rules
                ORDER BY category, rule_name
                "#,
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows)
    }

    /// According to YARA
    pub async fn list_yara_rules_by_category(&self, category: &str) -> Result<Vec<YaraRuleRow>> {
        let rows = sqlx::query_as::<_, YaraRuleRow>(
            r#"
            SELECT id, rule_name, category, severity, source, rule_source,
                   description, enabled, hit_count, created_at, updated_at
            FROM security_yara_rules
            WHERE category = $1
            ORDER BY rule_name
            "#,
        )
        .bind(category)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// items YARA
    pub async fn get_yara_rule(&self, id: &str) -> Result<Option<YaraRuleRow>> {
        let row = sqlx::query_as::<_, YaraRuleRow>(
            r#"
            SELECT id, rule_name, category, severity, source, rule_source,
                   description, enabled, hit_count, created_at, updated_at
            FROM security_yara_rules
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// YARA
    pub async fn insert_yara_rule(&self, rule: &YaraRuleRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_yara_rules
                (id, rule_name, category, severity, source, rule_source,
                 description, enabled, hit_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.rule_name)
        .bind(&rule.category)
        .bind(&rule.severity)
        .bind(&rule.source)
        .bind(&rule.rule_source)
        .bind(&rule.description)
        .bind(rule.enabled)
        .bind(rule.hit_count)
        .bind(&rule.created_at)
        .bind(&rule.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// New YARA
    pub async fn update_yara_rule(&self, rule: &YaraRuleRow) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE security_yara_rules
            SET rule_name = $2, category = $3, severity = $4,
                rule_source = $5, description = $6, enabled = $7, updated_at = $8
            WHERE id = $1
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.rule_name)
        .bind(&rule.category)
        .bind(&rule.severity)
        .bind(&rule.rule_source)
        .bind(&rule.description)
        .bind(rule.enabled)
        .bind(&rule.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// YARA
    pub async fn delete_yara_rule(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM security_yara_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// / YARA
    pub async fn toggle_yara_rule(&self, id: &str, enabled: bool) -> Result<bool> {
        let now = chrono::Utc::now().to_rfc3339();
        let result = sqlx::query(
            "UPDATE security_yara_rules SET enabled = $2, updated_at = $3 WHERE id = $1",
        )
        .bind(id)
        .bind(enabled)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// According to ()
    pub async fn count_builtin_yara_rules(&self) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::BIGINT FROM security_yara_rules WHERE source = 'builtin'",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// UPSERT (According to rule_name, New rule_source)
    pub async fn upsert_builtin_yara_rule(&self, rule: &YaraRuleRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_yara_rules
                (id, rule_name, category, severity, source, rule_source,
                 description, enabled, hit_count, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'builtin', $5, $6, TRUE, 0, $7, $7)
            ON CONFLICT (rule_name) DO UPDATE SET
                rule_source = EXCLUDED.rule_source,
                category = EXCLUDED.category,
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.rule_name)
        .bind(&rule.category)
        .bind(&rule.severity)
        .bind(&rule.rule_source)
        .bind(&rule.description)
        .bind(&rule.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
