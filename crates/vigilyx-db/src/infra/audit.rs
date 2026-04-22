//! Audit log and login history persistence

use anyhow::Result;
use serde::Serialize;

use crate::VigilDb;

/// Audit log item
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub operator: String,
    pub operation: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub detail: Option<String>,
    pub ip_address: Option<String>,
}

/// Login history item
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct LoginHistoryEntry {
    pub id: i64,
    pub timestamp: String,
    pub username: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub reason: Option<String>,
}

impl VigilDb {
    /// Write audit log
    pub async fn write_audit_log(
        &self,
        operator: &str,
        operation: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        detail: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_logs (operator, operation, resource_type, resource_id, detail, ip_address) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(operator)
        .bind(operation)
        .bind(resource_type)
        .bind(resource_id)
        .bind(detail)
        .bind(ip_address)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query audit log (pagination, by time descending)
    pub async fn list_audit_logs(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<AuditLogEntry>, i64)> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&self.pool)
            .await?;

        let entries: Vec<AuditLogEntry> = sqlx::query_as(
            "SELECT id, timestamp, operator, operation, resource_type, resource_id, detail, ip_address \
             FROM audit_logs ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok((entries, total.0))
    }

    /// Record login attempt
    pub async fn record_login(
        &self,
        username: &str,
        success: bool,
        ip_address: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO login_history (username, success, ip_address, reason) VALUES ($1, $2, $3, $4)",
        )
        .bind(username)
        .bind(success)
        .bind(ip_address)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Query login history (pagination, by time descending)
    pub async fn list_login_history(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<LoginHistoryEntry>, i64)> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM login_history")
            .fetch_one(&self.pool)
            .await?;

        let entries: Vec<LoginHistoryEntry> = sqlx::query_as(
            "SELECT id, timestamp, username, success, ip_address, reason \
             FROM login_history ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok((entries, total.0))
    }
}
