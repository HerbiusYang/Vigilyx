//! Syslog forwarder - sends data security incidents to a remote syslog server via TCP/UDP.
//!
//! Features:
//! - Asynchronous dispatch via tokio bounded mpsc channel (non-blocking to detection engine)
//! - TCP mode with persistent connection, auto-reconnect on failure (max 30s backoff)
//! - Supports both RFC 5424 and RFC 3164 message formats

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use vigilyx_core::{
    DEFAULT_BLOCKED_HOSTNAMES, DataSecurityIncident, DataSecuritySeverity,
    extract_host_from_network_target, resolve_network_host,
};

/// Syslog Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogForwardConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_address: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_protocol")]
    pub protocol: String,
    #[serde(default = "default_facility")]
    pub facility: u8,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
}

fn default_port() -> u16 {
    514
}
fn default_protocol() -> String {
    "udp".into()
}
fn default_facility() -> u8 {
    4
}
fn default_format() -> String {
    "rfc5424".into()
}
fn default_min_severity() -> String {
    "medium".into()
}

impl Default for SyslogForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_address: String::new(),
            port: 514,
            protocol: "udp".into(),
            facility: 4,
            format: "rfc5424".into(),
            min_severity: "medium".into(),
        }
    }
}

/// DataSecuritySeverity -> syslog Critical (RFC 5424 Table 2)
fn severity_to_syslog(sev: &DataSecuritySeverity) -> u8 {
    match sev {
        DataSecuritySeverity::Critical => 2, // critical
        DataSecuritySeverity::High => 3,     // error
        DataSecuritySeverity::Medium => 4,   // warning
        DataSecuritySeverity::Low => 5,      // notice
        DataSecuritySeverity::Info => 6,     // informational
    }
}

/// Parse LowCritical String
fn parse_min_severity(s: &str) -> DataSecuritySeverity {
    match s.to_lowercase().as_str() {
        "info" => DataSecuritySeverity::Info,
        "low" => DataSecuritySeverity::Low,
        "medium" => DataSecuritySeverity::Medium,
        "high" => DataSecuritySeverity::High,
        "critical" => DataSecuritySeverity::Critical,
        _ => DataSecuritySeverity::Medium,
    }
}

/// PRI value: facility * 8 + severity
fn calc_pri(facility: u8, severity: u8) -> u16 {
    (facility as u16) * 8 + (severity as u16)
}

/// SEC: Sanitize CRLF and control chars in syslog fields to prevent log injection (CWE-117)
fn sanitize_syslog_field(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .map(|c| match c {
            '"' => '\'', // RFC 5424 SD-PARAM value
            ']' => ')',  // RFC 5424 SD
            '\\' => '/',
            _ => c,
        })
        .take(256)
        .collect()
}

/// Format RFC 5424 Message
fn format_rfc5424(incident: &DataSecurityIncident, facility: u8) -> String {
    let syslog_severity = severity_to_syslog(&incident.severity);
    let pri = calc_pri(facility, syslog_severity);
    let ts = incident.created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let user = sanitize_syslog_field(incident.detected_user.as_deref().unwrap_or("-"));
    let host = sanitize_syslog_field(incident.host.as_deref().unwrap_or("-"));
    let summary = sanitize_syslog_field(&incident.summary);

    format!(
        "<{pri}>1 {ts} {host} vigilyx ds-engine - - [vigilyx@0 incident_type=\"{itype}\" severity=\"{sev}\" client_ip=\"{ip}\" user=\"{user}\" confidence=\"{conf:.2}\"] {summary}\n",
        pri = pri,
        ts = ts,
        host = host,
        itype = incident.incident_type,
        sev = incident.severity,
        ip = incident.client_ip,
        user = user,
        conf = incident.confidence,
        summary = summary,
    )
}

/// Format RFC 3164 Message
fn format_rfc3164(incident: &DataSecurityIncident, facility: u8) -> String {
    let syslog_severity = severity_to_syslog(&incident.severity);
    let pri = calc_pri(facility, syslog_severity);
    let ts = incident.created_at.format("%b %d %H:%M:%S");
    let host = sanitize_syslog_field(incident.host.as_deref().unwrap_or("vigilyx"));
    let user = sanitize_syslog_field(incident.detected_user.as_deref().unwrap_or("-"));
    let summary = sanitize_syslog_field(&incident.summary);

    format!(
        "<{pri}>{ts} {host} vigilyx: [{sev}] {itype} - {summary} (ip={ip} user={user})\n",
        pri = pri,
        ts = ts,
        host = host,
        sev = incident.severity,
        itype = incident.incident_type,
        summary = summary,
        ip = incident.client_ip,
        user = user,
    )
}

/// Syslog handlerhandle
pub struct SyslogForwarder {
    tx: mpsc::Sender<DataSecurityIncident>,
    dropped: std::sync::Arc<AtomicU64>,
}

impl SyslogForwarder {
   /// Start Syslog handler
    pub fn start(config: SyslogForwardConfig) -> Result<Self, String> {
        resolve_syslog_target(&config)?;

        let (tx, rx) = mpsc::channel::<DataSecurityIncident>(1_000);
        let dropped = std::sync::Arc::new(AtomicU64::new(0));
        let dropped_clone = std::sync::Arc::clone(&dropped);

        info!(
            "Syslog forwarder starting: {}:{} ({}) format={} min_severity={}",
            config.server_address, config.port, config.protocol, config.format, config.min_severity,
        );

        tokio::spawn(async move {
            sender_loop(rx, config, dropped_clone).await;
        });

        Ok(Self { tx, dropped })
    }

   /// (non-blocking,channelfull drop)
    pub fn try_forward(&self, incident: &DataSecurityIncident) {
        match self.tx.try_send(incident.clone()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let count = self.dropped.fetch_add(1, Ordering::Relaxed);
                if count.is_multiple_of(100) {
                    warn!(
                        "Syslog forwarder channel full, dropped {} events total",
                        count + 1
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                debug!("Syslog forwarder channel closed");
            }
        }
    }
}

/// SendLoop
async fn sender_loop(
    mut rx: mpsc::Receiver<DataSecurityIncident>,
    config: SyslogForwardConfig,
    dropped: std::sync::Arc<AtomicU64>,
) {
    let min_sev = parse_min_severity(&config.min_severity);
    let is_rfc5424 = config.format == "rfc5424";
    let is_tcp = config.protocol == "tcp";

    let mut tcp_conn: Option<TcpStream> = None;
    let mut udp_sock: Option<UdpSocket> = None;
    let mut reconnect_delay = std::time::Duration::from_secs(1);

   // initialize UDP socket (0.0.0.0:0)
    if !is_tcp {
        match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => {
                udp_sock = Some(s);
                info!("Syslog UDP socket bound");
            }
            Err(e) => {
                error!("Failed to bind syslog UDP socket: {}", e);
                return;
            }
        }
    }

    let mut sent_count: u64 = 0;

    while let Some(incident) = rx.recv().await {
       // Critical
        if incident.severity < min_sev {
            continue;
        }

        let msg = if is_rfc5424 {
            format_rfc5424(&incident, config.facility)
        } else {
            format_rfc3164(&incident, config.facility)
        };
        let msg_bytes = msg.as_bytes();

        if is_tcp {
           // TCP: Send,Failed
            let mut sent = false;
            for _ in 0..3 {
               // EnsureConnectionstored
                if tcp_conn.is_none() {
                    let addr = match resolve_syslog_target(&config) {
                        Ok(addr) => addr,
                        Err(reason) => {
                            warn!(
                                target = %config.server_address,
                                "Syslog TCP target blocked at runtime: {}, retry in {:?}",
                                reason,
                                reconnect_delay
                            );
                            tokio::time::sleep(reconnect_delay).await;
                            reconnect_delay =
                                (reconnect_delay * 2).min(std::time::Duration::from_secs(30));
                            continue;
                        }
                    };
                    match TcpStream::connect(addr).await {
                        Ok(s) => {
                            info!("Syslog TCP connected to {}", addr);
                            tcp_conn = Some(s);
                            reconnect_delay = std::time::Duration::from_secs(1);
                        }
                        Err(e) => {
                            warn!(
                                "Syslog TCP connect to {} failed: {}, retry in {:?}",
                                addr, e, reconnect_delay
                            );
                            tokio::time::sleep(reconnect_delay).await;
                            reconnect_delay =
                                (reconnect_delay * 2).min(std::time::Duration::from_secs(30));
                            continue;
                        }
                    };
                }
                if let Some(ref mut stream) = tcp_conn {
                    match stream.write_all(msg_bytes).await {
                        Ok(()) => {
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            warn!("Syslog TCP write failed: {}, reconnecting", e);
                            tcp_conn = None;
                        }
                    }
                }
            }
            if !sent {
                error!(
                    "Syslog TCP: failed to send after 3 attempts to {}:{}",
                    config.server_address,
                    config.port
                );
            }
        } else {
           // UDP: StatusSend
            if let Some(ref sock) = udp_sock {
                let addr = match resolve_syslog_target(&config) {
                    Ok(addr) => addr,
                    Err(reason) => {
                        warn!(
                            target = %config.server_address,
                            "Syslog UDP target blocked at runtime: {}",
                            reason
                        );
                        continue;
                    }
                };
                match sock.send_to(msg_bytes, addr).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Syslog UDP send to {} failed: {}", addr, e);
                    }
                }
            }
        }

        sent_count += 1;
        if sent_count.is_multiple_of(1000) {
            let d = dropped.load(Ordering::Relaxed);
            info!("Syslog forwarder stats: sent={}, dropped={}", sent_count, d);
        }
    }

    info!("Syslog forwarder loop ended (channel closed)");
}

/// SendTestMessage(Used for API Test)
pub async fn send_test_message(config: &SyslogForwardConfig) -> Result<String, String> {
    let addr = resolve_syslog_target(config)?;

    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let pri = calc_pri(config.facility, 6); // informational
    let test_msg = if config.format == "rfc5424" {
        format!(
            "<{pri}>1 {ts} vigilyx vigilyx ds-engine - - [vigilyx@0 test=\"true\"] Vigilyx syslog connectivity test\n"
        )
    } else {
        let ts3164 = Utc::now().format("%b %d %H:%M:%S");
        format!("<{pri}>{ts3164} vigilyx vigilyx: [info] Vigilyx syslog connectivity test\n")
    };

    if config.protocol == "tcp" {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("TCP connection to {} failed: {}", addr, e))?;
        let mut stream = stream;
        stream
            .write_all(test_msg.as_bytes())
            .await
            .map_err(|e| format!("TCP send failed: {}", e))?;
        Ok(format!("TCP test message sent to {}", addr))
    } else {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("UDP bind failed: {}", e))?;
        sock.send_to(test_msg.as_bytes(), addr)
            .await
            .map_err(|e| format!("UDP send to {} failed: {}", addr, e))?;
        Ok(format!("UDP test message sent to {}", addr))
    }
}

fn resolve_syslog_target(config: &SyslogForwardConfig) -> Result<SocketAddr, String> {
    let host = extract_host_from_network_target(&config.server_address)
        .ok_or_else(|| "Syslog target has no host".to_string())?;

    resolve_network_host(&host, config.port, DEFAULT_BLOCKED_HOSTNAMES)
        .map_err(|reason| format!("Syslog target blocked (SSRF prevention): {reason}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "Syslog target resolved to no addresses".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;
    use vigilyx_core::{DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity};

    fn make_test_incident(severity: DataSecuritySeverity) -> DataSecurityIncident {
        DataSecurityIncident {
            id: Uuid::new_v4(),
            http_session_id: Uuid::new_v4(),
            incident_type: DataSecurityIncidentType::DraftBoxAbuse,
            severity,
            confidence: 0.85,
            summary: "Test event: draft box abuse detection".into(),
            evidence: vec![],
            details: None,
            dlp_matches: vec![],
            client_ip: "192.168.1.100".into(),
            detected_user: Some("testuser@example.com".into()),
            request_url: "/coremail/XT5/proxy/mail/draft".into(),
            host: Some("mail.example.com".into()),
            method: "POST".into(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_pri_calculation() {
       // facility=4 (auth), severity=2 (critical) -> 4*8+2 = 34
        assert_eq!(calc_pri(4, 2), 34);
       // facility=1 (user), severity=6 (info) -> 1*8+6 = 14
        assert_eq!(calc_pri(1, 6), 14);
       // facility=0, severity=0 -> 0
        assert_eq!(calc_pri(0, 0), 0);
    }

    #[test]
    fn test_severity_to_syslog() {
        assert_eq!(severity_to_syslog(&DataSecuritySeverity::Critical), 2);
        assert_eq!(severity_to_syslog(&DataSecuritySeverity::High), 3);
        assert_eq!(severity_to_syslog(&DataSecuritySeverity::Medium), 4);
        assert_eq!(severity_to_syslog(&DataSecuritySeverity::Low), 5);
        assert_eq!(severity_to_syslog(&DataSecuritySeverity::Info), 6);
    }

    #[test]
    fn test_parse_min_severity() {
        assert_eq!(parse_min_severity("info"), DataSecuritySeverity::Info);
        assert_eq!(parse_min_severity("low"), DataSecuritySeverity::Low);
        assert_eq!(parse_min_severity("medium"), DataSecuritySeverity::Medium);
        assert_eq!(parse_min_severity("HIGH"), DataSecuritySeverity::High);
        assert_eq!(
            parse_min_severity("Critical"),
            DataSecuritySeverity::Critical
        );
        assert_eq!(parse_min_severity("unknown"), DataSecuritySeverity::Medium);
    }

    #[test]
    fn test_format_rfc5424_contains_required_fields() {
        let incident = make_test_incident(DataSecuritySeverity::High);
        let msg = format_rfc5424(&incident, 4);

        assert!(msg.starts_with("<35>")); 
        assert!(msg.contains("vigilyx"));
        assert!(msg.contains("ds-engine"));
        assert!(msg.contains("draft_box_abuse"));
        assert!(msg.contains("high"));
        assert!(msg.contains("192.168.1.100"));
        assert!(msg.contains("testuser@example.com"));
        assert!(msg.contains("0.85"));
        assert!(msg.ends_with('\n'));
    }

    #[test]
    fn test_format_rfc3164_contains_required_fields() {
        let incident = make_test_incident(DataSecuritySeverity::Medium);
        let msg = format_rfc3164(&incident, 4);

        assert!(msg.starts_with("<36>")); 
        assert!(msg.contains("vigilyx:"));
        assert!(msg.contains("[medium]"));
        assert!(msg.contains("draft_box_abuse"));
        assert!(msg.contains("ip=192.168.1.100"));
        assert!(msg.ends_with('\n'));
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = SyslogForwardConfig {
            enabled: true,
            server_address: "10.0.0.50".into(),
            port: 1514,
            protocol: "tcp".into(),
            facility: 13,
            format: "rfc3164".into(),
            min_severity: "high".into(),
        };
        let json = serde_json::to_string(&config).expect("serialize");
        let parsed: SyslogForwardConfig = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.enabled);
        assert_eq!(parsed.server_address, "10.0.0.50");
        assert_eq!(parsed.port, 1514);
        assert_eq!(parsed.protocol, "tcp");
        assert_eq!(parsed.facility, 13);
    }

    #[test]
    fn test_config_partial_json_uses_defaults() {
        let json = r#"{"enabled": true, "server_address": "10.0.0.50"}"#;
        let config: SyslogForwardConfig = serde_json::from_str(json).expect("parse");
        assert_eq!(config.port, 514);
        assert_eq!(config.protocol, "udp");
        assert_eq!(config.facility, 4);
        assert_eq!(config.format, "rfc5424");
        assert_eq!(config.min_severity, "medium");
    }

    #[test]
    fn test_summary_truncated_at_256_chars() {
        let mut incident = make_test_incident(DataSecuritySeverity::High);
        incident.summary = "A".repeat(500);
        let msg = format_rfc5424(&incident, 4);
       // summary MessageMedium Break/Judge 256 characters
        assert!(!msg.contains(&"A".repeat(300)));
    }

    #[test]
    fn test_resolve_syslog_target_uses_configured_port() {
        let config = SyslogForwardConfig {
            enabled: true,
            server_address: "8.8.8.8".into(),
            port: 1514,
            ..Default::default()
        };

        let addr = resolve_syslog_target(&config).expect("public IP target should resolve");
        assert_eq!(addr, "8.8.8.8:1514".parse().expect("valid socket addr"));
    }

    #[test]
    fn test_resolve_syslog_target_rejects_localhost_with_trailing_dot() {
        let config = SyslogForwardConfig {
            enabled: true,
            server_address: "localhost.".into(),
            port: 514,
            ..Default::default()
        };

        let err = resolve_syslog_target(&config).expect_err("localhost must be rejected");
        assert!(err.contains("Syslog target blocked"));
    }
}
