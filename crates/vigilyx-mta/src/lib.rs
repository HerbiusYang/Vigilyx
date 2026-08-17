//! Vigilyx MTA

//! SMTP, -> TLS -> -> / /.
//! SecurityEngine <8s inline.

pub mod config;
pub mod dlp;
pub(crate) mod envelope;
pub mod metrics;
pub mod relay;
pub mod server;

/// MTA-owned authentication boundary.
///
/// Inbound authentication headers are attacker-controlled at the SMTP DATA
/// boundary. This module strips them, performs a bounded SPF/DMARC evaluation,
/// and emits one result that the engine may trust only for an MTA session.
pub mod authentication {
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::time::Duration;

    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::proto::rr::RData;
    use tokio::time::timeout;

    use vigilyx_core::models::EmailSession;

    const DNS_TIMEOUT: Duration = Duration::from_secs(2);
    const MAX_SPF_LOOKUPS: usize = 10;
    const MAX_SPF_DEPTH: u8 = 5;
    const AUTH_RESULT_HEADERS: &[&str] = &[
        "authentication-results",
        "arc-authentication-results",
        "x-ms-exchange-authentication-results",
    ];

    #[derive(Clone)]
    pub struct AuthenticationVerifier {
        resolver: TokioResolver,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SpfResult {
        Pass,
        Fail,
        SoftFail,
        Neutral,
        None,
        TempError,
        PermError,
    }

    impl SpfResult {
        fn as_str(self) -> &'static str {
            match self {
                Self::Pass => "pass",
                Self::Fail => "fail",
                Self::SoftFail => "softfail",
                Self::Neutral => "neutral",
                Self::None => "none",
                Self::TempError => "temperror",
                Self::PermError => "permerror",
            }
        }
    }

    impl AuthenticationVerifier {
        pub fn new() -> Self {
            let mut opts = ResolverOpts::default();
            opts.timeout = DNS_TIMEOUT;
            opts.attempts = 1;
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            );
            *builder.options_mut() = opts;
            let resolver = builder
                .build()
                .expect("default DNS resolver configuration must be valid");
            Self { resolver }
        }

        /// Remove inbound identity claims and prepend one MTA-owned result.
        /// DNS failures are represented as `temperror`; they never cause the
        /// message to be treated as authenticated and never fail open here.
        pub async fn stamp(
            &self,
            session: &mut EmailSession,
            raw_eml: Vec<u8>,
            authserv_id: &str,
        ) -> Vec<u8> {
            let envelope_domain = session.mail_from.as_deref().and_then(address_domain);
            let spf = match (session.client_ip.parse::<IpAddr>(), envelope_domain.as_deref()) {
                (Ok(ip), Some(domain)) => {
                    let mut budget = MAX_SPF_LOOKUPS;
                    self.evaluate_spf_domain(ip, domain.to_string(), 0, &mut budget)
                        .await
                }
                _ => SpfResult::None,
            };
            let from_domain = header_domain(session);
            let dmarc = self
                .evaluate_dmarc(from_domain.as_deref(), envelope_domain.as_deref(), spf)
                .await;

            let authserv_id = sanitize_authserv_id(authserv_id);
            let header_value = format!(
                "{authserv_id}; spf={}; dkim=none; dmarc={}",
                spf.as_str(),
                dmarc.as_str()
            );

            session.content.headers.retain(|(name, _)| {
                !AUTH_RESULT_HEADERS
                    .iter()
                    .any(|candidate| name.eq_ignore_ascii_case(candidate))
            });
            session
                .content
                .headers
                .insert(0, ("Authentication-Results".to_string(), header_value.clone()));

            let sanitized = strip_inbound_auth_headers(&raw_eml);
            let mut stamped = Vec::with_capacity(
                sanitized
                    .len()
                    .saturating_add(header_value.len())
                    .saturating_add(2),
            );
            stamped.extend_from_slice(b"Authentication-Results: ");
            stamped.extend_from_slice(header_value.as_bytes());
            stamped.extend_from_slice(b"\r\n");
            stamped.extend_from_slice(&sanitized);
            stamped
        }

        async fn evaluate_dmarc(
            &self,
            from_domain: Option<&str>,
            envelope_domain: Option<&str>,
            spf: SpfResult,
        ) -> SpfResult {
            let Some(from_domain) = from_domain else {
                return SpfResult::None;
            };
            let name = format!("_dmarc.{from_domain}");
            let records = match self.lookup_txt(&name).await {
                Ok(records) => records,
                Err(_) => return SpfResult::TempError,
            };
            let has_policy = records.iter().any(|record| {
                record.split(';').any(|term| {
                    term.trim().eq_ignore_ascii_case("v=dmarc1")
                        || term.trim().to_ascii_lowercase().starts_with("v=dmarc1")
                })
            });
            if !has_policy {
                return SpfResult::None;
            }

            // Exact alignment is deliberately conservative. A PSL-aware
            // organizational-domain implementation can be added later, but
            // it must not turn an unverified From into a pass.
            if spf == SpfResult::Pass
                && envelope_domain.is_some_and(|domain| domain == from_domain)
            {
                SpfResult::Pass
            } else {
                SpfResult::Fail
            }
        }

        fn evaluate_spf_domain<'a>(
            &'a self,
            ip: IpAddr,
            domain: String,
            depth: u8,
            budget: &'a mut usize,
        ) -> Pin<Box<dyn Future<Output = SpfResult> + Send + 'a>> {
            Box::pin(async move {
                if depth > MAX_SPF_DEPTH || *budget == 0 {
                    return SpfResult::PermError;
                }
                *budget -= 1;
                let records = match self.lookup_txt(&domain).await {
                    Ok(records) => records,
                    Err(_) => return SpfResult::TempError,
                };
                let spf_records: Vec<&str> = records
                    .iter()
                    .map(String::as_str)
                    .filter(|record| {
                        record
                            .split_whitespace()
                            .next()
                            .is_some_and(|version| version.eq_ignore_ascii_case("v=spf1"))
                    })
                    .collect();
                if spf_records.is_empty() {
                    return SpfResult::None;
                }
                if spf_records.len() > 1 {
                    return SpfResult::PermError;
                }

                let mut redirect: Option<&str> = None;
                for raw_term in spf_records[0].split_whitespace().skip(1) {
                    if raw_term.starts_with("v=") {
                        continue;
                    }
                    let (qualifier, term) = split_qualifier(raw_term);
                    if let Some(target) = term.strip_prefix("redirect=") {
                        redirect = Some(target);
                        continue;
                    }
                    if term == "all" {
                        return qualifier_result(qualifier);
                    }
                    if let Some(cidr) = term.strip_prefix("ip4:")
                        && ip_matches_cidr(ip, cidr, false)
                    {
                        return qualifier_result(qualifier);
                    }
                    if let Some(cidr) = term.strip_prefix("ip6:")
                        && ip_matches_cidr(ip, cidr, true)
                    {
                        return qualifier_result(qualifier);
                    }
                    if let Some(include_domain) = term.strip_prefix("include:") {
                        let included = self
                            .evaluate_spf_domain(ip, include_domain.to_string(), depth + 1, budget)
                            .await;
                        match included {
                            SpfResult::Pass => return qualifier_result(qualifier),
                            SpfResult::TempError | SpfResult::PermError => return included,
                            _ => {}
                        }
                    }
                    // `a`, `mx`, and `exists` mechanisms are intentionally not
                    // treated as a pass without their own bounded resolver
                    // implementations. The record's later `all` term still
                    // determines the conservative result.
                }

                if let Some(redirect_domain) = redirect {
                    return self
                        .evaluate_spf_domain(ip, redirect_domain.to_string(), depth + 1, budget)
                        .await;
                }
                SpfResult::Neutral
            })
        }

        async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, ()> {
            let lookup = timeout(DNS_TIMEOUT, self.resolver.txt_lookup(name))
                .await
                .map_err(|_| ())
                .and_then(|result| result.map_err(|_| ()))?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect())
        }
    }

    impl Default for AuthenticationVerifier {
        fn default() -> Self {
            Self::new()
        }
    }

    fn split_qualifier(term: &str) -> (char, &str) {
        match term.as_bytes().first().copied() {
            Some(b'+') | Some(b'-') | Some(b'~') | Some(b'?') => {
                (term.as_bytes()[0] as char, &term[1..])
            }
            _ => ('+', term),
        }
    }

    fn qualifier_result(qualifier: char) -> SpfResult {
        match qualifier {
            '-' => SpfResult::Fail,
            '~' => SpfResult::SoftFail,
            '?' => SpfResult::Neutral,
            _ => SpfResult::Pass,
        }
    }

    fn ip_matches_cidr(ip: IpAddr, spec: &str, ipv6: bool) -> bool {
        let (address, prefix) = spec.split_once('/').unwrap_or((spec, if ipv6 { "128" } else { "32" }));
        let Ok(prefix) = prefix.parse::<u32>() else {
            return false;
        };
        match (ip, address.parse::<IpAddr>().ok(), ipv6) {
            (IpAddr::V4(ip), Some(IpAddr::V4(network)), false) if prefix <= 32 => {
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                (u32::from(ip) & mask) == (u32::from(network) & mask)
            }
            (IpAddr::V6(ip), Some(IpAddr::V6(network)), true) if prefix <= 128 => {
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                (u128::from(ip) & mask) == (u128::from(network) & mask)
            }
            _ => false,
        }
    }

    fn address_domain(address: &str) -> Option<String> {
        let address = address
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        let (_, domain) = address.rsplit_once('@')?;
        let domain = domain
            .trim()
            .trim_end_matches('>')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        (!domain.is_empty()
            && domain.len() <= 253
            && !domain.chars().any(char::is_whitespace))
            .then_some(domain)
    }

    fn header_domain(session: &EmailSession) -> Option<String> {
        session
            .content
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("from"))
            .and_then(|(_, value)| {
                let mailbox = value
                    .split_once('<')
                    .and_then(|(_, rest)| rest.split_once('>').map(|(mailbox, _)| mailbox))
                    .unwrap_or(value.as_str());
                address_domain(mailbox)
            })
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
            // Malformed DATA without a header/body separator is still treated
            // as an all-header block for this sanitization boundary. Never
            // forward an inbound Authentication-Results claim just because
            // the message is malformed.
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
        fn cidr_matching_is_family_and_prefix_bounded() {
            assert!(ip_matches_cidr(
                "203.0.113.10".parse().unwrap(),
                "203.0.113.0/24",
                false
            ));
            assert!(!ip_matches_cidr(
                "203.0.114.10".parse().unwrap(),
                "203.0.113.0/24",
                false
            ));
            assert!(ip_matches_cidr(
                "2001:db8::10".parse().unwrap(),
                "2001:db8::/32",
                true
            ));
        }

        #[test]
        fn inbound_auth_headers_and_folded_lines_are_removed() {
            let raw = b"Subject: hello\r\nAuthentication-Results: attacker; spf=pass\r\n\tdkim=pass\r\nFrom: user@example.com\r\n\r\nbody";
            let sanitized = strip_inbound_auth_headers(raw);
            let text = String::from_utf8(sanitized).unwrap();
            assert!(!text.contains("Authentication-Results"));
            assert!(!text.contains("dkim=pass"));
        assert!(text.contains("Subject: hello"));
        assert!(text.ends_with("body"));
    }

    #[test]
    fn malformed_header_block_still_removes_inbound_auth_headers() {
        let raw = b"Authentication-Results: attacker; spf=pass\r\n\tdkim=pass\r\nSubject: hello\r\n";
        let sanitized = strip_inbound_auth_headers(raw);
        let text = String::from_utf8(sanitized).unwrap();
        assert!(!text.contains("Authentication-Results"));
        assert!(!text.contains("dkim=pass"));
        assert!(text.contains("Subject: hello"));
    }
}
}
