//! MTA
//!
//! lettre SmtpTransport MTA.
//! EML (,).

use std::time::Duration;

use lettre::address::Envelope;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use tracing::{error, info, warn};
#[allow(unused_imports)]
use vigilyx_core::{
    DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES, extract_host_from_network_target,
    resolve_mail_relay_host, validate_mail_relay_host,
};

use crate::config::DownstreamConfig;
use crate::envelope::is_valid_envelope_address;

/// MTA
pub struct DownstreamRelay {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    config: DownstreamConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedRelayTarget {
    connect_addr: std::net::SocketAddr,
    tls_host: String,
}

fn resolve_relay_tls_host(host: &str) -> anyhow::Result<String> {
    let tls_host = extract_host_from_network_target(host)
        .unwrap_or_else(|| host.trim().to_string())
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if tls_host.is_empty() {
        anyhow::bail!("SEC: 下游地址校验失败: relay host is empty");
    }

    Ok(tls_host)
}

fn resolve_relay_target(config: &DownstreamConfig) -> anyhow::Result<PinnedRelayTarget> {
    let connect_addr = resolve_mail_relay_host(
        &config.host,
        config.port,
        DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES,
    )
    .map_err(|e| anyhow::anyhow!("SEC: 下游地址校验失败: {e}"))?
    .into_iter()
    .next()
    .ok_or_else(|| anyhow::anyhow!("SEC: 下游地址校验失败: relay resolved to no addresses"))?;

    Ok(PinnedRelayTarget {
        connect_addr,
        tls_host: resolve_relay_tls_host(&config.host)?,
    })
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
        // Allow RFC1918 relay targets used by real deployments, but still reject
        // loopback/link-local/internal service endpoints and fail closed on DNS errors.
        let target = resolve_relay_target(config)?;

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
            warn!(
                "Plaintext downstream SMTP enabled via VIGILYX_ALLOW_PLAINTEXT_SMTP — all relayed mail is unencrypted!"
            );
        }

        let addr = target.connect_addr.to_string();
        let connect_host = target.connect_addr.ip().to_string();

        let builder = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(connect_host)
                .port(config.port)
                .tls(Tls::Required(
                    TlsParameters::new(target.tls_host)
                        .map_err(|e| anyhow::anyhow!("STARTTLS relay error: {e}"))?,
                ))
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(connect_host)
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
                    let msg = response.message().collect::<Vec<_>>().join(" ");
                    if code.severity
                        == lettre::transport::smtp::response::Severity::TransientNegativeCompletion
                    {
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

    #[test]
    fn test_validate_rejects_empty_host() {
        assert!(validate_mail_relay_host("", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES).is_err());
    }

    #[test]
    fn test_validate_rejects_localhost() {
        assert!(
            validate_mail_relay_host("localhost", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES).is_err()
        );
    }

    #[test]
    fn test_validate_rejects_redis() {
        assert!(validate_mail_relay_host("redis", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES).is_err());
    }

    #[test]
    fn test_validate_rejects_metadata_service() {
        assert!(
            validate_mail_relay_host(
                "metadata.google.internal",
                DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES
            )
            .is_err()
        );
    }

    #[test]
    fn test_validate_allows_public_hostname() {
        assert!(
            validate_mail_relay_host("mail.example.com", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_allows_private_ipv4_relay() {
        assert!(
            validate_mail_relay_host("10.1.246.33", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES).is_ok()
        );
    }

    #[test]
    fn test_validate_rejects_link_local_ipv4() {
        assert!(
            validate_mail_relay_host("169.254.169.254", DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES)
                .is_err()
        );
    }

    #[test]
    fn test_validate_rejects_urls() {
        assert!(
            validate_mail_relay_host(
                "http://mail.example.com",
                DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES
            )
            .is_err()
        );
    }

    #[test]
    fn test_resolve_relay_target_uses_private_ipv4_socket_addr() {
        let config = DownstreamConfig {
            host: "10.1.246.33".into(),
            port: 2525,
            starttls: true,
            timeout_secs: 30,
        };

        let target = resolve_relay_target(&config).expect("private relay IP should be allowed");
        assert_eq!(
            target.connect_addr,
            "10.1.246.33:2525".parse().expect("valid socket addr")
        );
        assert_eq!(target.tls_host, "10.1.246.33");
    }

    #[test]
    fn test_resolve_relay_target_rejects_localhost_with_trailing_dot() {
        let config = DownstreamConfig {
            host: "localhost.".into(),
            port: 25,
            starttls: true,
            timeout_secs: 30,
        };

        let err = resolve_relay_target(&config).expect_err("localhost must be rejected");
        assert!(err.to_string().contains("SEC: 下游地址校验失败"));
    }
}
