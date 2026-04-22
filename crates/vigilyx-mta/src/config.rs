//! MTA

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vigilyx_core::security::ThreatLevel;
use vigilyx_core::validate_mta_hostname;

/// MTA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaConfig {
    /// SMTP (25)
    pub listen_smtp: SocketAddr,
    /// Submission (587, STARTTLS)
    pub listen_submission: Option<SocketAddr>,
    /// SMTPS (465, TLS)
    pub listen_smtps: Option<SocketAddr>,

    pub max_connections: usize,

    /// TLS
    pub tls: Option<TlsConfig>,

    /// MTA (->,)
    pub downstream: DownstreamConfig,
    /// (->,DLP)
    /// None = (,)
    pub outbound: Option<DownstreamConfig>,
    /// (SMTP)
    pub local_domains: Vec<String>,

    /// Inline verdict ()
    pub inline_timeout_secs: u32,

    pub fail_open: bool,

    pub quarantine_threshold: ThreatLevel,

    pub reject_threshold: ThreatLevel,

    pub max_message_size: usize,

    pub max_recipients: usize,

    /// URL
    pub database_url: String,
    /// Redis URL
    pub redis_url: Option<String>,

    /// (SMTP banner)
    pub hostname: String,

    /// DLP ()
    pub dlp: crate::dlp::DlpConfig,
}

/// TLS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// PEM
    pub cert_path: PathBuf,
    /// PEM
    pub key_path: PathBuf,
}

/// MTA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownstreamConfig {
    /// MTA
    pub host: String,
    /// MTA
    pub port: u16,
    /// STARTTLS
    pub starttls: bool,

    pub timeout_secs: u32,
}

impl MtaConfig {
    /// Fields whose UI settings can override DB values (env vars remain the defaults).
    pub async fn override_from_db(&mut self, db_url: &str) -> anyhow::Result<()> {
        let pool = sqlx::PgPool::connect(db_url).await?;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM config WHERE key = 'deployment_mode'")
                .fetch_optional(&pool)
                .await?;
        pool.close().await;

        if let Some((raw,)) = row
            && let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw)
        {
            if let Some(h) = val
                .get("mta_downstream_host")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                tracing::info!(old = %self.downstream.host, new = %h, "DB override: downstream host");
                self.downstream.host = h.to_string();
            }
            if let Some(p) = val.get("mta_downstream_port").and_then(|v| v.as_u64()) {
                self.downstream.port = p as u16;
            }
            if let Some(t) = val.get("mta_inline_timeout_secs").and_then(|v| v.as_u64()) {
                self.inline_timeout_secs = t as u32;
            }
            if let Some(h) = val
                .get("mta_hostname")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                match validate_mta_hostname(h) {
                    Ok(validated) => self.hostname = validated,
                    Err(reason) => tracing::warn!(
                        hostname = %h,
                        reason = %reason,
                        "Ignoring invalid MTA hostname from DB override"
                    ),
                }
            }
            if let Some(m) = val.get("mta_max_connections").and_then(|v| v.as_u64()) {
                self.max_connections = m as usize;
            }
            if let Some(s) = val.get("mta_starttls").and_then(|v| v.as_bool()) {
                self.downstream.starttls = s;
            }
            if let Some(f) = val.get("mta_fail_open").and_then(|v| v.as_bool()) {
                self.fail_open = f;
            }
            if let Some(d) = val
                .get("mta_local_domains")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                let mut domains: Vec<String> = d
                    .split(',')
                    .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                domains.sort();
                domains.dedup();
                if !domains.is_empty() {
                    self.local_domains = domains;
                }
            }
            // DLP configuration (saved from the frontend via deployment_mode)
            if let Some(e) = val.get("mta_dlp_enabled").and_then(|v| v.as_bool()) {
                self.dlp.enabled = e;
            }
            if let Some(a) = val.get("mta_dlp_action").and_then(|v| v.as_str()) {
                match a.to_lowercase().as_str() {
                    "block" => self.dlp.action = crate::dlp::DlpAction::Block,
                    "allow" | "allow_and_alert" => {
                        self.dlp.action = crate::dlp::DlpAction::AllowAndAlert
                    }
                    "quarantine" => self.dlp.action = crate::dlp::DlpAction::Quarantine,
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let listen_port: u16 = std::env::var("MTA_SMTP_PORT")
            .unwrap_or_else(|_| "25".into())
            .parse()?;

        let listen_addr = format!(
            "{}:{}",
            std::env::var("MTA_LISTEN_HOST").unwrap_or_else(|_| "0.0.0.0".into()),
            listen_port
        );

        let submission_port: Option<u16> = std::env::var("MTA_SUBMISSION_PORT")
            .ok()
            .and_then(|p| p.parse().ok());

        let smtps_port: Option<u16> = std::env::var("MTA_SMTPS_PORT")
            .ok()
            .and_then(|p| p.parse().ok());

        let listen_host = std::env::var("MTA_LISTEN_HOST").unwrap_or_else(|_| "0.0.0.0".into());

        let tls = match (
            std::env::var("MTA_TLS_CERT").ok().filter(|s| !s.is_empty()),
            std::env::var("MTA_TLS_KEY").ok().filter(|s| !s.is_empty()),
        ) {
            (Some(cert), Some(key)) => Some(TlsConfig {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }),
            _ => None,
        };

        let downstream_host =
            std::env::var("MTA_DOWNSTREAM_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let downstream_port: u16 = std::env::var("MTA_DOWNSTREAM_PORT")
            .unwrap_or_else(|_| "25".into())
            .parse()?;
        let mut local_domains = std::env::var("MTA_LOCAL_DOMAINS")
            .unwrap_or_default()
            .split(',')
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect::<Vec<_>>();
        local_domains.sort();
        local_domains.dedup();

        Ok(Self {
            listen_smtp: listen_addr.parse()?,
            listen_submission: submission_port
                .map(|p| format!("{listen_host}:{p}").parse())
                .transpose()?,
            listen_smtps: smtps_port
                .map(|p| format!("{listen_host}:{p}").parse())
                .transpose()?,
            max_connections: std::env::var("MTA_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "100".into())
                .parse()?,
            tls,
            downstream: DownstreamConfig {
                host: downstream_host,
                port: downstream_port,
                starttls: std::env::var("MTA_DOWNSTREAM_STARTTLS")
                    .unwrap_or_else(|_| "true".into())
                    .parse()?,
                timeout_secs: 30,
            },
            outbound: std::env::var("MTA_OUTBOUND_HOST").ok().map(|host| {
                let port = std::env::var("MTA_OUTBOUND_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(25);
                let starttls = std::env::var("MTA_OUTBOUND_STARTTLS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(true);
                DownstreamConfig {
                    host,
                    port,
                    starttls,
                    timeout_secs: 30,
                }
            }),
            local_domains,
            inline_timeout_secs: std::env::var("MTA_INLINE_TIMEOUT_SECS")
                .unwrap_or_else(|_| "8".into())
                .parse()?,
            // SEC: fail closed by default. When the engine times out or is overloaded, return 451 and do not pass through unscanned mail.
            // If the business truly requires delivery over scanning completeness, explicitly set MTA_FAIL_OPEN=true.
            fail_open: std::env::var("MTA_FAIL_OPEN")
                .unwrap_or_else(|_| "false".into())
                .parse()?,
            quarantine_threshold: ThreatLevel::Medium,
            reject_threshold: ThreatLevel::Critical,
            max_message_size: 25 * 1024 * 1024, // 25MB (OOM)
            max_recipients: 100,
            database_url: std::env::var("DATABASE_URL")?,
            redis_url: std::env::var("REDIS_URL").ok(),
            hostname: validate_mta_hostname(
                &std::env::var("MTA_HOSTNAME").unwrap_or_else(|_| "vigilyx-mta".into()),
            )
            .map_err(|reason| anyhow::anyhow!("invalid MTA_HOSTNAME: {reason}"))?,
            dlp: crate::dlp::DlpConfig::from_env(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_values() {
        // Verify ThreatLevel comparison works for disposition mapping
        assert!(ThreatLevel::Medium >= ThreatLevel::Medium);
        assert!(ThreatLevel::High >= ThreatLevel::Medium);
        assert!(ThreatLevel::Critical >= ThreatLevel::Critical);
        assert!(ThreatLevel::Low < ThreatLevel::Medium);
    }
}
