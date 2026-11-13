//! MTA-owned SPF, DKIM, and DMARC authentication boundary.
//!
//! Authentication claims supplied in SMTP DATA are attacker-controlled. This
//! module removes them, performs fresh standards-complete verification, and
//! prepends one result owned by this MTA. Temporary failures and coverage
//! errors remain `temperror`/`permerror`; they are never rewritten as an
//! authentication `fail`.

use std::net::IpAddr;
use std::time::Duration;

use mail_auth::dmarc::verify::DmarcParameters;
use mail_auth::hickory_resolver::TokioResolver;
use mail_auth::hickory_resolver::config::{ResolverConfig, ResolverOpts};
use mail_auth::hickory_resolver::net::runtime::TokioRuntimeProvider;
use mail_auth::spf::verify::SpfParameters;
use mail_auth::{AuthenticatedMessage, AuthenticationResults, MessageAuthenticator};
use tokio::time::timeout;

use vigilyx_core::models::EmailSession;

const DNS_TIMEOUT: Duration = Duration::from_secs(2);
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(6);
const AUTH_RESULT_HEADERS: &[&str] = &[
    "authentication-results",
    "arc-authentication-results",
    "received-spf",
    "x-ms-exchange-authentication-results",
];

#[derive(Clone)]
pub struct AuthenticationVerifier {
    authenticator: MessageAuthenticator,
}

impl AuthenticationVerifier {
    pub fn new() -> Self {
        let (config, opts) = mail_auth::hickory_resolver::system_conf::read_system_conf()
            .expect("MTA requires a readable system DNS configuration");
        Self {
            authenticator: MessageAuthenticator(build_dns_resolver(config, opts)),
        }
    }

    /// Remove inbound identity claims and prepend one MTA-owned result.
    pub async fn stamp(
        &self,
        session: &mut EmailSession,
        raw_eml: Vec<u8>,
        authserv_id: &str,
    ) -> Vec<u8> {
        let authserv_id = sanitize_authserv_id(authserv_id);
        let header_value = self
            .verify(session, &raw_eml, &authserv_id)
            .await
            .unwrap_or_else(|| {
                format!("{authserv_id}; spf=temperror; dkim=temperror; dmarc=temperror")
            });

        session.content.headers.retain(|(name, _)| {
            !AUTH_RESULT_HEADERS
                .iter()
                .any(|candidate| name.eq_ignore_ascii_case(candidate))
        });
        // The in-memory parsed model stores an unfolded value. Keeping CRLF
        // folding here would look like header injection to downstream checks;
        // the raw RFC 5322 message below retains the standards-compliant fold.
        let unfolded_header_value = header_value.replace("\r\n\t", " ");
        session.content.headers.insert(
            0,
            ("Authentication-Results".to_string(), unfolded_header_value),
        );

        let sanitized = strip_inbound_auth_headers(&raw_eml);
        let mut stamped = Vec::with_capacity(
            sanitized
                .len()
                .saturating_add(header_value.len())
                .saturating_add(26),
        );
        stamped.extend_from_slice(b"Authentication-Results: ");
        stamped.extend_from_slice(header_value.as_bytes());
        stamped.extend_from_slice(b"\r\n");
        stamped.extend_from_slice(&sanitized);
        stamped
    }

    /// Returns `None` only when the bounded authentication operation times
    /// out or the message cannot be parsed. The caller stamps explicit error
    /// states for both cases, preserving coverage separately from auth result.
    async fn verify(
        &self,
        session: &EmailSession,
        raw_eml: &[u8],
        authserv_id: &str,
    ) -> Option<String> {
        let message = AuthenticatedMessage::parse(raw_eml)?;
        let ip = session.client_ip.parse::<IpAddr>().ok()?;
        let helo = session
            .smtp_helo
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(authserv_id);
        let mail_from = session.mail_from.as_deref().unwrap_or("");
        let header_from = message.from.first().map(String::as_str).unwrap_or("");

        timeout(AUTHENTICATION_TIMEOUT, async {
            let (spf, dkim) = tokio::join!(
                self.authenticator
                    .verify_spf(SpfParameters::verify_mail_from(
                        ip,
                        helo,
                        authserv_id,
                        mail_from,
                    )),
                self.authenticator.verify_dkim(&message),
            );
            let dmarc = self
                .authenticator
                .verify_dmarc(DmarcParameters::new(&message, &dkim, spf.domain(), &spf))
                .await;

            let mut result = AuthenticationResults::new(authserv_id)
                .with_spf_mailfrom_result(&spf, ip, mail_from, helo);
            if !dkim.is_empty() {
                result = result.with_dkim_results(&dkim, header_from);
            }
            result = result.with_dmarc_result(&dmarc);

            let mut rendered = result.to_string();
            if dkim.is_empty() {
                rendered.push_str(";\r\n\tdkim=none");
            }
            rendered
        })
        .await
        .ok()
    }
}

impl Default for AuthenticationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

fn build_dns_resolver(config: ResolverConfig, mut opts: ResolverOpts) -> TokioResolver {
    assert!(
        !config.name_servers().is_empty(),
        "MTA DNS configuration must contain an upstream nameserver"
    );
    opts.timeout = DNS_TIMEOUT;
    opts.attempts = 1;
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    *builder.options_mut() = opts;
    builder
        .build()
        .expect("MTA DNS configuration must be valid")
}

fn sanitize_authserv_id(value: &str) -> String {
    let sanitized: String = value
        .trim()
        .chars()
        .take(253)
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
        .collect();
    if sanitized.is_empty() {
        "vigilyx-mta".to_string()
    } else {
        sanitized
    }
}

fn is_authentication_header(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return false;
    };
    let name = String::from_utf8_lossy(&line[..colon]);
    AUTH_RESULT_HEADERS
        .iter()
        .any(|candidate| name.trim().eq_ignore_ascii_case(candidate))
}

fn strip_inbound_auth_headers(raw: &[u8]) -> Vec<u8> {
    let body_start = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        });
    let (header_bytes, body_bytes): (&[u8], &[u8]) = match body_start {
        Some(position) => (&raw[..position], &raw[position..]),
        None => (raw, &[]),
    };

    let mut output = Vec::with_capacity(raw.len());
    let mut dropping = false;
    for line in header_bytes.split_inclusive(|byte| *byte == b'\n') {
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if continuation {
            if !dropping {
                output.extend_from_slice(line);
            }
            continue;
        }
        dropping = is_authentication_header(line);
        if !dropping {
            output.extend_from_slice(line);
        }
    }
    output.extend_from_slice(body_bytes);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "upstream nameserver")]
    fn dns_configuration_rejects_empty_upstreams() {
        build_dns_resolver(ResolverConfig::default(), ResolverOpts::default());
    }

    #[tokio::test]
    async fn configured_dns_verifies_spf_and_dmarc_without_trusting_inbound_claims() {
        use mail_auth::hickory_resolver::config::{ConnectionConfig, NameServerConfig};
        use vigilyx_core::models::Protocol;

        // A bounded, loopback-only DNS fixture; no public DNS dependency.
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let query = &buffer[..len];
                let mut end = 12;
                let mut labels = Vec::new();
                while query[end] != 0 {
                    let count = query[end] as usize;
                    end += 1;
                    labels.push(std::str::from_utf8(&query[end..end + count]).unwrap());
                    end += count;
                }
                end += 1;
                let name = labels.join(".");
                let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
                let value = if name == "_dmarc.fixture.example" {
                    "v=DMARC1; p=reject"
                } else {
                    "v=spf1 ip4:192.0.2.10 -all"
                };
                let mut response = query[..end + 4].to_vec();
                response[2..12].copy_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
                assert_eq!(qtype, 16, "authentication fixture only serves TXT");
                response.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
                response.extend_from_slice(&((value.len() + 1) as u16).to_be_bytes());
                response.push(value.len() as u8);
                response.extend_from_slice(value.as_bytes());
                socket.send_to(&response, peer).await.unwrap();
            }
        });
        let mut connection = ConnectionConfig::udp();
        connection.port = addr.port();
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(addr.ip(), true, vec![connection])],
        );
        let verifier = AuthenticationVerifier {
            authenticator: MessageAuthenticator(build_dns_resolver(
                config,
                ResolverOpts::default(),
            )),
        };
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".into(),
            12345,
            "192.0.2.20".into(),
            25,
        );
        session.mail_from = Some("sender@fixture.example".into());
        session.smtp_helo = Some("mx.fixture.example".into());
        let raw = b"From: sender@fixture.example\r\nTo: recipient@example.test\r\nSubject: fixture\r\nAuthentication-Results: untrusted; dkim=pass\r\n\r\nhello";
        let stamped = tokio::time::timeout(
            Duration::from_secs(3),
            verifier.stamp(&mut session, raw.to_vec(), "mx.fixture.example"),
        )
        .await
        .unwrap();
        let stamped = String::from_utf8(stamped).unwrap();
        assert!(stamped.contains("spf=pass"), "{stamped}");
        assert!(stamped.contains("dmarc=pass"), "{stamped}");
        assert!(stamped.contains("dkim=none"));
        assert!(!stamped.contains("untrusted"));
        assert!(!stamped.contains("dkim=pass"));
        server.abort();
    }

    #[tokio::test]
    async fn unavailable_dns_remains_temperror() {
        use mail_auth::hickory_resolver::config::{ConnectionConfig, NameServerConfig};
        use vigilyx_core::models::Protocol;
        // A closed local UDP port returns promptly and never contacts public DNS.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let mut connection = ConnectionConfig::udp();
        connection.port = addr.port();
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig::new(addr.ip(), true, vec![connection])],
        );
        let verifier = AuthenticationVerifier {
            authenticator: MessageAuthenticator(build_dns_resolver(
                config,
                ResolverOpts::default(),
            )),
        };
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".into(),
            12345,
            "192.0.2.20".into(),
            25,
        );
        session.mail_from = Some("sender@fixture.example".into());
        let raw = b"From: sender@fixture.example\r\nSubject: fixture\r\n\r\nhello";
        let stamped = String::from_utf8(
            verifier
                .stamp(&mut session, raw.to_vec(), "mx.fixture.example")
                .await,
        )
        .unwrap();
        assert!(stamped.contains("spf=temperror"), "{stamped}");
        assert!(!stamped.contains("spf=fail"));
        assert!(!stamped.contains("spf=pass"));
    }

    #[test]
    fn inbound_auth_headers_and_folded_lines_are_removed() {
        let raw = b"Subject: hello\r\nAuthentication-Results: attacker; spf=pass\r\n\tdkim=pass\r\nReceived-SPF: pass\r\nFrom: user@example.com\r\n\r\nbody";
        let sanitized = strip_inbound_auth_headers(raw);
        let text = String::from_utf8(sanitized).unwrap();
        assert!(!text.contains("Authentication-Results"));
        assert!(!text.contains("Received-SPF"));
        assert!(!text.contains("dkim=pass"));
        assert!(text.contains("Subject: hello"));
        assert!(text.ends_with("body"));
    }

    #[test]
    fn malformed_header_block_still_removes_inbound_auth_headers() {
        let raw =
            b"Authentication-Results: attacker; spf=pass\r\n\tdkim=pass\r\nSubject: hello\r\n";
        let sanitized = strip_inbound_auth_headers(raw);
        let text = String::from_utf8(sanitized).unwrap();
        assert!(!text.contains("Authentication-Results"));
        assert!(!text.contains("dkim=pass"));
        assert!(text.contains("Subject: hello"));
    }

    #[test]
    fn authserv_id_cannot_inject_header_content() {
        assert_eq!(
            sanitize_authserv_id(" mx.example\r\nX-Evil: yes "),
            "mx.exampleX-Evilyes"
        );
        assert_eq!(sanitize_authserv_id("***"), "vigilyx-mta");
    }
}
