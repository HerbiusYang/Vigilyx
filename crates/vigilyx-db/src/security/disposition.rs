//! Disposition Rule Database Operations

use anyhow::Result;

use crate::VigilDb;

/// Disposition rule row
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct DispositionRuleRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i64,
    pub conditions: String,
    pub actions: String,
    pub created_at: String,
    pub updated_at: String,
}

impl VigilDb {
   /// Get all enabled disposition rules (sorted by priority level)
    pub async fn get_active_disposition_rules(&self) -> Result<Vec<DispositionRuleRow>> {
        let rows = sqlx::query_as::<_, DispositionRuleRow>(
            r#"
            SELECT id, name, description, (enabled::int = 1) as enabled, priority, conditions, actions,
                   created_at, updated_at
            FROM security_disposition_rules
            WHERE enabled::int = 1
            ORDER BY priority ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

   /// Get one disposition rule by id
    pub async fn get_disposition_rule(&self, id: &str) -> Result<Option<DispositionRuleRow>> {
        let row = sqlx::query_as::<_, DispositionRuleRow>(
            r#"
            SELECT id, name, description, (enabled::int = 1) as enabled, priority, conditions, actions,
                   created_at, updated_at
            FROM security_disposition_rules
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

   /// Get all disposition rules
    pub async fn list_disposition_rules(&self) -> Result<Vec<DispositionRuleRow>> {
        let rows = sqlx::query_as::<_, DispositionRuleRow>(
            r#"
            SELECT id, name, description, (enabled::int = 1) as enabled, priority, conditions, actions,
                   created_at, updated_at
            FROM security_disposition_rules
            ORDER BY priority ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

   /// Insert disposition rule
    pub async fn insert_disposition_rule(&self, rule: &DispositionRuleRow) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO security_disposition_rules
                (id, name, description, enabled, priority, conditions, actions,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.enabled)
        .bind(rule.priority)
        .bind(&rule.conditions)
        .bind(&rule.actions)
        .bind(&rule.created_at)
        .bind(&rule.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

   /// Update disposition rule
    pub async fn update_disposition_rule(&self, rule: &DispositionRuleRow) -> Result<bool> {
        let result = sqlx::query(
            r#"
            UPDATE security_disposition_rules
            SET name = $2, description = $3, enabled = $4, priority = $5,
                conditions = $6, actions = $7, updated_at = $8
            WHERE id = $1
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(&rule.description)
        .bind(rule.enabled)
        .bind(rule.priority)
        .bind(&rule.conditions)
        .bind(&rule.actions)
        .bind(&rule.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

   /// Delete disposition rule
    pub async fn delete_disposition_rule(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM security_disposition_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}
