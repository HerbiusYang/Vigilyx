//! MTA

//! lettre SmtpTransport MTA.
//! EML (,).

use std::net::IpAddr;
use std::time::Duration;

use lettre::transport::smtp::client::Tls;
use lettre::address::Envelope;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use tracing::{error, info, warn};

use crate::config::DownstreamConfig;
use crate::envelope::is_valid_envelope_address;

/// SEC: Check whether an IP address is private, reserved, or otherwise forbidden
/// for use as a downstream relay target (CWE-918).
///
/// Covers: loopback, private (RFC 1918), link-local, broadcast, unspecified,
/// IPv6 ULA (fc00::/7), and IPv4-mapped IPv6 addresses that map to private ranges.
fn is_forbidden_ip(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
            {
                return Some(format!("私有/保留 IPv4 地址: {v4}"));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return Some(format!("回环/未指定 IPv6 地址: {v6}"));
            }
            let segments = v6.segments();
            // fe80::/10 link-local
            if segments[0] & 0xffc0 == 0xfe80 {
                return Some(format!("link-local IPv6 地址: {v6}"));
            }
            // fc00::/7 ULA (Unique Local Address)
            if segments[0] & 0xfe00 == 0xfc00 {
                return Some(format!("ULA 私有 IPv6 地址: {v6}"));
            }
            // ::ffff:a.b.c.d  IPv4-mapped IPv6 — check the embedded v4 address
            if let Some(v4) = v6.to_ipv4_mapped()
                && (v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 0)
            {
                return Some(format!("IPv4-mapped 私有地址: {v6} -> {v4}"));
            }
        }
    }
    None
}

/// SEC: validate the downstream host string and reject private/reserved/loopback addresses (CWE-918).
///
/// This is the synchronous string-level check. For hostnames, it only blocks
/// obviously internal names; DNS-based validation is done by [`validate_downstream_host_resolved`].
pub fn validate_downstream_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("下游主机地址不能为空".into());
    }
    if host.len() > 255 {
        return Err("下游主机地址过长".into());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if let Some(reason) = is_forbidden_ip(ip) {
            return Err(format!("下游主机不能使用{reason}"));
        }
    } else {
        // Hostname: reject obviously internal service names
        let lower = host.to_lowercase();
        const BLOCKED_HOSTS: &[&str] = &[
            "localhost", "redis", "postgres", "vigilyx-postgres",
            "metadata.google.internal", "instance-data",
        ];
        if BLOCKED_HOSTS.iter().any(|&b| lower == b || lower.ends_with(&format!(".{b}"))) {
            return Err(format!("下游主机不能指向内部服务: {host}"));
        }
    }
    Ok(())
}

/// SEC: Async validation that resolves DNS and checks all resulting addresses (CWE-918).
///
/// After passing the string-level [`validate_downstream_host`] check, this function
/// performs DNS resolution and verifies that none of the A/AAAA records point to
/// private, reserved, or otherwise forbidden IP addresses.
///
/// This prevents attacks where `mta_downstream_host` is set to a hostname that
/// resolves to an internal/loopback address.
pub async fn validate_downstream_host_resolved(host: &str, port: u16) -> Result<(), String> {
    // First, run the sync string-level validation
    validate_downstream_host(host)?;

    // If the host is already a literal IP, we already validated it above
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // Resolve DNS and check all resulting addresses
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS 解析失败 ({host}): {e}"))?;

    let mut found_any = false;
    for addr in addrs {
        found_any = true;
        if let Some(reason) = is_forbidden_ip(addr.ip()) {
            return Err(format!("下游主机 {host} 解析到禁止的地址: {reason}"));
        }
    }

    if !found_any {
        return Err(format!("下游主机 {host} DNS 解析无结果"));
    }

    Ok(())
}

/// MTA
pub struct DownstreamRelay {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    config: DownstreamConfig,
}


pub enum RelayResult {
    
    Accepted,
   /// (4xx)
    TempFail(String),
   /// (5xx)
    PermFail(String),
    
    ConnError(String),
}

impl DownstreamRelay {
    pub async fn new(config: &DownstreamConfig) -> anyhow::Result<Self> {
        // SEC: reject private/reserved downstream addresses with DNS resolution (CWE-918)
        validate_downstream_host_resolved(&config.host, config.port)
            .await
            .map_err(|e| anyhow::anyhow!("SEC: 下游地址校验失败: {e}"))?;

        // SEC: plaintext SMTP requires explicit opt-in via env var (defense-in-depth)
        if !config.starttls {
            let allow_plain = std::env::var("VIGILYX_ALLOW_PLAINTEXT_SMTP")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            if !allow_plain {
                anyhow::bail!(
                    "SEC: 明文 SMTP 下游转发已禁用。如确需明文传输，请设置 VIGILYX_ALLOW_PLAINTEXT_SMTP=true"
                );
            }
            warn!("Plaintext downstream SMTP enabled via VIGILYX_ALLOW_PLAINTEXT_SMTP — all relayed mail is unencrypted!");
        }

        let addr = format!("{}:{}", config.host, config.port);

        let builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| anyhow::anyhow!("STARTTLS relay error: {e}"))?
                .port(config.port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .tls(Tls::None)
        };

        let transport = builder
            .timeout(Some(Duration::from_secs(config.timeout_secs as u64)))
            .build();

        info!(downstream = %addr, starttls = config.starttls, "Downstream relay initialized");

        Ok(Self {
            transport,
            config: config.clone(),
        })
    }

   /// MTA
    
   /// `mail_from`: SMTP MAIL FROM (None = bounce "<>")
   /// `rcpt_to`: SMTP RCPT TO
   /// `raw_eml`: (,)
    pub async fn relay(
        &self,
        mail_from: Option<&str>,
        rcpt_to: &[String],
        raw_eml: &[u8],
    ) -> RelayResult {
        let envelope = match build_envelope(mail_from, rcpt_to) {
            Ok(envelope) => envelope,
            Err(err) => {
                return RelayResult::PermFail(err);
            }
        };

        
        match self.transport.send_raw(&envelope, raw_eml).await {
            Ok(response) => {
                if response.is_positive() {
                    info!(
                        downstream = format!("{}:{}", self.config.host, self.config.port),
                        code = %response.code(),
                        "Downstream accepted"
                    );
                    RelayResult::Accepted
                } else {
                    let code = response.code();
                    let msg = response
                        .message()
                        .collect::<Vec<_>>()
                        .join(" ");
                    if code.severity == lettre::transport::smtp::response::Severity::TransientNegativeCompletion {
                        warn!(code = %code, msg = %msg, "Downstream temp failure");
                        RelayResult::TempFail(format!("{code} {msg}"))
                    } else {
                        warn!(code = %code, msg = %msg, "Downstream perm failure");
                        RelayResult::PermFail(format!("{code} {msg}"))
                    }
                }
            }
            Err(e) => {
                error!(
                    downstream = format!("{}:{}", self.config.host, self.config.port),
                    error = %e,
                    "Downstream connection error"
                );
                RelayResult::ConnError(format!("Relay error: {e}"))
            }
        }
    }
}

fn build_envelope(mail_from: Option<&str>, rcpt_to: &[String]) -> Result<Envelope, String> {
    let from = match mail_from {
        Some(raw) => {
            if !is_valid_envelope_address(raw) {
                return Err("Invalid MAIL FROM: invalid address syntax".into());
            }
            match raw.parse::<Address>() {
                Ok(addr) => Some(addr),
                Err(e) => return Err(format!("Invalid MAIL FROM: {e}")),
            }
        }
        None => None,
    };

    let mut to = Vec::with_capacity(rcpt_to.len());
    for raw in rcpt_to {
        if !is_valid_envelope_address(raw) {
            return Err(format!("Invalid RCPT TO '{raw}': invalid address syntax"));
        }
        match raw.parse::<Address>() {
            Ok(addr) => to.push(addr),
            Err(e) => return Err(format!("Invalid RCPT TO '{raw}': {e}")),
        }
    }

    if to.is_empty() {
        return Err("No valid recipients".into());
    }

    Envelope::new(from, to).map_err(|e| format!("Invalid envelope: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_result_variants() {
        let r = RelayResult::Accepted;
        assert!(matches!(r, RelayResult::Accepted));
        let r = RelayResult::TempFail("busy".into());
        assert!(matches!(r, RelayResult::TempFail(_)));
        let r = RelayResult::PermFail("rejected".into());
        assert!(matches!(r, RelayResult::PermFail(_)));
        let r = RelayResult::ConnError("timeout".into());
        assert!(matches!(r, RelayResult::ConnError(_)));
    }

    #[test]
    fn test_build_envelope_rejects_invalid_mail_from() {
        let err = build_envelope(Some("user@bad_domain"), &["rcpt@test.com".into()])
            .expect_err("invalid MAIL FROM should fail");
        assert!(err.contains("Invalid MAIL FROM"));
    }

    #[test]
    fn test_build_envelope_rejects_invalid_rcpt() {
        let err = build_envelope(Some("sender@test.com"), &["bad rcpt".into()])
            .expect_err("invalid RCPT TO should fail");
        assert!(err.contains("Invalid RCPT TO"));
    }

    // --- is_forbidden_ip tests ---

    #[test]
    fn test_forbidden_ip_rejects_ipv4_loopback() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv4_private_10() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv4_private_172() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv4_private_192() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv4_link_local() {
        let ip: IpAddr = "169.254.169.254".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "Cloud metadata address should be blocked");
    }

    #[test]
    fn test_forbidden_ip_allows_public_ipv4() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_none());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv6_loopback() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv6_link_local() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some());
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv6_ula() {
        let ip: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "ULA (fc00::/7) should be blocked");
    }

    #[test]
    fn test_forbidden_ip_rejects_ipv6_ula_fc() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "ULA fc00:: should be blocked");
    }

    #[test]
    fn test_forbidden_ip_rejects_v4_mapped_loopback() {
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "IPv4-mapped loopback should be blocked");
    }

    #[test]
    fn test_forbidden_ip_rejects_v4_mapped_private() {
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "IPv4-mapped private should be blocked");
    }

    #[test]
    fn test_forbidden_ip_rejects_v4_mapped_link_local() {
        let ip: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_some(), "IPv4-mapped metadata should be blocked");
    }

    #[test]
    fn test_forbidden_ip_allows_public_ipv6() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_none(), "Public IPv6 should be allowed");
    }

    #[test]
    fn test_forbidden_ip_allows_v4_mapped_public() {
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(is_forbidden_ip(ip).is_none(), "IPv4-mapped public should be allowed");
    }

    // --- validate_downstream_host tests ---

    #[test]
    fn test_validate_rejects_empty_host() {
        assert!(validate_downstream_host("").is_err());
    }

    #[test]
    fn test_validate_rejects_localhost() {
        assert!(validate_downstream_host("localhost").is_err());
    }

    #[test]
    fn test_validate_rejects_redis() {
        assert!(validate_downstream_host("redis").is_err());
    }

    #[test]
    fn test_validate_rejects_metadata_service() {
        assert!(validate_downstream_host("metadata.google.internal").is_err());
    }

    #[test]
    fn test_validate_allows_public_hostname() {
        assert!(validate_downstream_host("mail.example.com").is_ok());
    }

    #[test]
    fn test_validate_rejects_ipv6_ula_string() {
        assert!(validate_downstream_host("fd00::1").is_err());
    }

    #[test]
    fn test_validate_rejects_v4_mapped_private_string() {
        assert!(validate_downstream_host("::ffff:192.168.1.1").is_err());
    }
}
