//! MTA

use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vigilyx_core::security::ThreatLevel;
use vigilyx_core::validate_mta_hostname;

pub const MTA_INLINE_TIMEOUT_MIN_SECS: u32 = 1;
pub const MTA_INLINE_TIMEOUT_MAX_SECS: u32 = 60;
pub const MTA_MAX_CONNECTIONS_MIN: usize = 1;
pub const MTA_MAX_CONNECTIONS_MAX: usize = 1000;

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
    /// Trusted upstream IPs/CIDRs that are allowed to originate local-domain
    /// mail without being forced into inbound classification.
    pub trusted_upstream_cidrs: Vec<String>,

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
                match valid_mta_port(p) {
                    Some(port) => self.downstream.port = port,
                    None => tracing::warn!(
                        port = p,
                        "Ignoring invalid MTA downstream port from DB override"
                    ),
                }
            }
            if let Some(t) = val.get("mta_inline_timeout_secs").and_then(|v| v.as_u64()) {
                let timeout = u32::try_from(t).unwrap_or(MTA_INLINE_TIMEOUT_MAX_SECS);
                self.inline_timeout_secs = clamp_inline_timeout_secs(timeout);
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
                let max_connections = usize::try_from(m).unwrap_or(MTA_MAX_CONNECTIONS_MAX);
                self.max_connections = clamp_max_connections(max_connections);
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
            if let Some(raw) = val
                .get("mta_trusted_upstream_cidrs")
                .and_then(|v| v.as_str())
            {
                self.trusted_upstream_cidrs = normalize_trusted_upstream_cidrs(raw);
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
        let trusted_upstream_cidrs = normalize_trusted_upstream_cidrs(
            &std::env::var("MTA_TRUSTED_UPSTREAM_CIDRS")
                .or_else(|_| std::env::var("MTA_TRUSTED_SUBMITTER_CIDRS"))
                .unwrap_or_default(),
        );

        Ok(Self {
            listen_smtp: listen_addr.parse()?,
            listen_submission: submission_port
                .map(|p| format!("{listen_host}:{p}").parse())
                .transpose()?,
            listen_smtps: smtps_port
                .map(|p| format!("{listen_host}:{p}").parse())
                .transpose()?,
            max_connections: clamp_max_connections(
                std::env::var("MTA_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "100".into())
                    .parse()?,
            ),
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
            trusted_upstream_cidrs,
            inline_timeout_secs: clamp_inline_timeout_secs(
                std::env::var("MTA_INLINE_TIMEOUT_SECS")
                    .unwrap_or_else(|_| "8".into())
                    .parse()?,
            ),
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

pub fn clamp_inline_timeout_secs(value: u32) -> u32 {
    value.clamp(MTA_INLINE_TIMEOUT_MIN_SECS, MTA_INLINE_TIMEOUT_MAX_SECS)
}

pub fn clamp_max_connections(value: usize) -> usize {
    value.clamp(MTA_MAX_CONNECTIONS_MIN, MTA_MAX_CONNECTIONS_MAX)
}

fn valid_mta_port(value: u64) -> Option<u16> {
    u16::try_from(value).ok().filter(|port| *port > 0)
}

fn parse_ip_or_cidr(entry: &str) -> Option<(IpAddr, Option<u8>)> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((ip_raw, prefix_raw)) = trimmed.split_once('/') {
        let ip = ip_raw.trim().parse::<IpAddr>().ok()?;
        let prefix = prefix_raw.trim().parse::<u8>().ok()?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix > 0 && prefix <= max_prefix).then_some((ip, Some(prefix)))
    } else {
        trimmed.parse::<IpAddr>().ok().map(|ip| (ip, None))
    }
}

pub fn normalize_trusted_upstream_cidrs(raw: &str) -> Vec<String> {
    let mut entries = raw
        .split(',')
        .filter_map(parse_ip_or_cidr)
        .map(|(ip, prefix)| match prefix {
            Some(prefix) => format!("{ip}/{prefix}"),
            None => ip.to_string(),
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries.dedup();
    entries
}

fn ip_matches_entry(ip: IpAddr, entry: &str) -> bool {
    let Some((base_ip, prefix)) = parse_ip_or_cidr(entry) else {
        return false;
    };

    match (ip, base_ip, prefix) {
        (IpAddr::V4(ip), IpAddr::V4(base), Some(prefix)) => {
            if prefix == 0 {
                true
            } else {
                let mask = u32::MAX << (32 - prefix);
                (u32::from(ip) & mask) == (u32::from(base) & mask)
            }
        }
        (IpAddr::V6(ip), IpAddr::V6(base), Some(prefix)) => {
            if prefix == 0 {
                true
            } else {
                let mask = u128::MAX << (128 - prefix);
                (u128::from_be_bytes(ip.octets()) & mask)
                    == (u128::from_be_bytes(base.octets()) & mask)
            }
        }
        (ip, base, None) => ip == base,
        _ => false,
    }
}

pub fn is_trusted_upstream_ip(client_ip: &str, trusted_upstream_cidrs: &[String]) -> bool {
    let Ok(client_ip) = client_ip.parse::<IpAddr>() else {
        return false;
    };
    trusted_upstream_cidrs
        .iter()
        .any(|entry| ip_matches_entry(client_ip, entry))
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

    #[test]
    fn test_normalize_trusted_upstream_cidrs_filters_invalid_and_dedups() {
        let entries = normalize_trusted_upstream_cidrs(
            "10.0.0.1, 10.0.0.0/24, garbage, 10.0.0.1, 2001:db8::/32, 10.0.0.0/33",
        );
        assert_eq!(
            entries,
            vec![
                "10.0.0.0/24".to_string(),
                "10.0.0.1".to_string(),
                "2001:db8::/32".to_string()
            ]
        );
    }

    #[test]
    fn test_normalize_trusted_upstream_cidrs_rejects_wildcard_trust() {
        let entries = normalize_trusted_upstream_cidrs("0.0.0.0/0, ::/0, 10.0.0.0/24");

        assert_eq!(entries, vec!["10.0.0.0/24".to_string()]);
        assert!(
            !is_trusted_upstream_ip("203.0.113.10", &entries),
            "Wildcard CIDR must not make every remote MTA a trusted submitter"
        );
    }

    #[test]
    fn test_normalize_trusted_upstream_cidrs_handles_ipv6_exact_and_bad_prefixes() {
        let entries = normalize_trusted_upstream_cidrs(
            " 2001:db8::1 , 2001:db8::/129, 10.0.0.0/-1, 10.0.0.0/24 ",
        );

        assert_eq!(
            entries,
            vec!["10.0.0.0/24".to_string(), "2001:db8::1".to_string()]
        );
    }

    #[test]
    fn test_is_trusted_upstream_ip_matches_exact_ip_and_cidr() {
        let entries = vec!["10.0.0.1".to_string(), "192.168.0.0/24".to_string()];
        assert!(is_trusted_upstream_ip("10.0.0.1", &entries));
        assert!(is_trusted_upstream_ip("192.168.0.42", &entries));
        assert!(!is_trusted_upstream_ip("192.168.1.42", &entries));
    }

    #[test]
    fn test_is_trusted_upstream_ip_supports_ipv6_cidr() {
        let entries = vec!["2001:db8::/32".to_string()];
        assert!(is_trusted_upstream_ip("2001:db8::1", &entries));
        assert!(!is_trusted_upstream_ip("2001:db9::1", &entries));
    }

    #[test]
    fn test_is_trusted_upstream_ip_rejects_invalid_client_ip() {
        let entries = vec!["10.0.0.0/24".to_string()];
        assert!(!is_trusted_upstream_ip("not-an-ip", &entries));
    }

    #[test]
    fn test_is_trusted_upstream_ip_respects_prefix_boundaries_and_family() {
        let entries = vec![
            "10.0.0.128/25".to_string(),
            "2001:db8:abcd::/48".to_string(),
        ];

        assert!(!is_trusted_upstream_ip("10.0.0.127", &entries));
        assert!(is_trusted_upstream_ip("10.0.0.128", &entries));
        assert!(is_trusted_upstream_ip("10.0.0.255", &entries));
        assert!(!is_trusted_upstream_ip("10.0.1.1", &entries));
        assert!(is_trusted_upstream_ip("2001:db8:abcd::42", &entries));
        assert!(!is_trusted_upstream_ip("2001:db8:abce::1", &entries));
        assert!(!is_trusted_upstream_ip(
            "2001:db8:abcd::42",
            &["10.0.0.0/8".to_string()]
        ));
    }

    #[test]
    fn test_mta_numeric_config_clamps_to_safe_bounds() {
        assert_eq!(clamp_inline_timeout_secs(0), MTA_INLINE_TIMEOUT_MIN_SECS);
        assert_eq!(clamp_inline_timeout_secs(8), 8);
        assert_eq!(clamp_inline_timeout_secs(600), MTA_INLINE_TIMEOUT_MAX_SECS);

        assert_eq!(clamp_max_connections(0), MTA_MAX_CONNECTIONS_MIN);
        assert_eq!(clamp_max_connections(100), 100);
        assert_eq!(clamp_max_connections(10_000), MTA_MAX_CONNECTIONS_MAX);
    }

    #[test]
    fn test_valid_mta_port_rejects_zero_and_overflow() {
        assert_eq!(valid_mta_port(25), Some(25));
        assert_eq!(valid_mta_port(u16::MAX as u64), Some(u16::MAX));
        assert_eq!(valid_mta_port(0), None);
        assert_eq!(valid_mta_port(u16::MAX as u64 + 1), None);
    }
}
