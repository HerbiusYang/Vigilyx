use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

pub const DEFAULT_BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "kubernetes.default",
    "metadata.google.internal",
    "metadata.aliyun.com",
    "redis",
    "vigilyx-redis",
    "postgres",
    "vigilyx-postgres",
    "ai",
    "vigilyx-ai",
];

pub const DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES: &[&str] = &[
    "localhost",
    "host.docker.internal",
    "gateway.docker.internal",
    "metadata.google.internal",
    "metadata.aliyun.com",
    "instance-data",
    "redis",
    "vigilyx-redis",
    "postgres",
    "vigilyx-postgres",
];

pub const DEFAULT_INTERNAL_SERVICE_HOSTS: &[&str] =
    &["ai", "vigilyx-ai", "localhost", "127.0.0.1", "::1"];

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn extract_host_from_network_target(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim();

    if authority.is_empty() {
        return None;
    }

    if authority.starts_with('[') {
        return authority
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('[').to_string());
    }

    if authority.parse::<IpAddr>().is_ok() {
        return Some(authority.to_string());
    }

    Some(
        authority
            .rsplit_once(':')
            .and_then(|(host, port)| port.parse::<u16>().ok().map(|_| host))
            .unwrap_or(authority)
            .to_string(),
    )
}

pub fn is_sensitive_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_private()
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_sensitive_ip(IpAddr::V4(v4)))
        }
    }
}

pub fn resolve_network_host(
    host: &str,
    port: u16,
    blocked_hostnames: &[&str],
) -> Result<Vec<SocketAddr>, String> {
    let host = normalize_host(host);
    if host.is_empty() {
        return Err("Host is empty".to_string());
    }
    if host.contains('@') {
        return Err("Host must not contain userinfo".to_string());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_sensitive_ip(ip) {
            return Err(format!("Disallowed IP address: {ip}"));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    if blocked_hostnames.contains(&host.as_str()) {
        return Err(format!("Disallowed host: {host}"));
    }
    if host.ends_with(".internal") || host.ends_with(".local") {
        return Err(format!("Disallowed host suffix: {host}"));
    }

    let addrs = (host.as_str(), 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("Hostname resolution failed for {host}: {e}"))?;
    let mut resolved = Vec::new();
    let mut found_any = false;
    for addr in addrs {
        found_any = true;
        if is_sensitive_ip(addr.ip()) {
            return Err(format!("Hostname resolves to disallowed IP: {}", addr.ip()));
        }
        resolved.push(SocketAddr::new(addr.ip(), port));
    }
    if !found_any {
        return Err(format!("Hostname resolution returned no addresses for {host}"));
    }

    Ok(resolved)
}

pub fn validate_network_host(host: &str, blocked_hostnames: &[&str]) -> Result<(), String> {
    resolve_network_host(host, 0, blocked_hostnames).map(|_| ())
}

fn validate_mail_relay_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return Err(format!("Mail relay IP must not be loopback: {v4}"));
            }
            if v4.is_link_local() {
                return Err(format!("Mail relay IP must not be link-local: {v4}"));
            }
            if v4.is_broadcast() {
                return Err(format!("Mail relay IP must not be broadcast: {v4}"));
            }
            if v4.is_unspecified() || v4.octets()[0] == 0 {
                return Err(format!("Mail relay IP must not be unspecified: {v4}"));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return Err(format!("Mail relay IP must not be loopback: {v6}"));
            }
            if v6.is_unspecified() {
                return Err(format!("Mail relay IP must not be unspecified: {v6}"));
            }
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Err(format!("Mail relay IP must not be link-local: {v6}"));
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                validate_mail_relay_ip(IpAddr::V4(v4))?;
            }
        }
    }

    Ok(())
}

pub fn validate_mail_relay_host(host: &str, blocked_hostnames: &[&str]) -> Result<(), String> {
    let raw = host.trim();
    if raw.is_empty() {
        return Err("Mail relay host is empty".to_string());
    }
    if raw.len() > 255 {
        return Err("Mail relay host is too long".to_string());
    }
    if raw.contains("://")
        || raw.contains('/')
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains('@')
    {
        return Err("Mail relay host must be a hostname or IP address".to_string());
    }

    let host = normalize_host(raw);
    if host.is_empty() {
        return Err("Mail relay host is empty".to_string());
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return validate_mail_relay_ip(ip);
    }

    if host.contains(':') {
        return Err("Mail relay host must not include a port".to_string());
    }

    if blocked_hostnames
        .iter()
        .any(|blocked| host == *blocked || host.ends_with(&format!(".{blocked}")))
    {
        return Err(format!("Disallowed mail relay host: {host}"));
    }

    Ok(())
}

pub fn resolve_mail_relay_host(
    host: &str,
    port: u16,
    blocked_hostnames: &[&str],
) -> Result<Vec<SocketAddr>, String> {
    validate_mail_relay_host(host, blocked_hostnames)?;

    let normalized = normalize_host(host);
    if let Ok(ip) = normalized.parse::<IpAddr>() {
        validate_mail_relay_ip(ip)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let addrs = (normalized.as_str(), 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("Mail relay hostname resolution failed for {normalized}: {e}"))?;
    let mut resolved = Vec::new();
    let mut found_any = false;
    for addr in addrs {
        found_any = true;
        validate_mail_relay_ip(addr.ip())?;
        resolved.push(SocketAddr::new(addr.ip(), port));
    }
    if !found_any {
        return Err(format!(
            "Mail relay hostname resolution returned no addresses for {normalized}"
        ));
    }

    Ok(resolved)
}

pub fn validate_mail_relay_host_resolved(
    host: &str,
    port: u16,
    blocked_hostnames: &[&str],
) -> Result<(), String> {
    resolve_mail_relay_host(host, port, blocked_hostnames).map(|_| ())
}

pub fn validate_internal_service_url(target: &str, allowed_hosts: &[&str]) -> Result<(), String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("Target is empty".to_string());
    }

    let parsed =
        url::Url::parse(trimmed).map_err(|e| format!("Invalid target URL: {e}"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("Disallowed scheme: {scheme}"));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Target must not contain userinfo".to_string());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("Target must not contain query or fragment".to_string());
    }
    if parsed.path() != "/" {
        return Err("Target path must be empty or /".to_string());
    }

    let host = parsed
        .host_str()
        .map(normalize_host)
        .ok_or_else(|| "Target has no host".to_string())?;
    if host.is_empty() {
        return Err("Host is empty".to_string());
    }

    if !allowed_hosts.iter().any(|allowed| host == *allowed) {
        return Err(format!("Host not in allowlist: {host}"));
    }

    Ok(())
}

pub fn validate_network_target(target: &str, blocked_hostnames: &[&str]) -> Result<(), String> {
    let host = extract_host_from_network_target(target)
        .ok_or_else(|| "Target has no host".to_string())?;
    validate_network_host(&host, blocked_hostnames)
}

pub fn validate_mta_hostname(hostname: &str) -> Result<String, String> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("MTA hostname is empty".to_string());
    }
    if normalized.len() > 253 {
        return Err("MTA hostname is too long".to_string());
    }
    if normalized
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || ch.is_ascii_control())
    {
        return Err("MTA hostname must not contain whitespace or control characters".to_string());
    }

    for label in normalized.split('.') {
        if label.is_empty() {
            return Err("MTA hostname must not contain empty labels".to_string());
        }
        if label.len() > 63 {
            return Err("MTA hostname label is too long".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("MTA hostname labels must not start or end with '-'".to_string());
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err(
                "MTA hostname labels may only contain ASCII letters, digits, and '-'"
                    .to_string(),
            );
        }
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_ipv6_unique_local_addresses() {
        assert!(is_sensitive_ip("fd00:ec2::254".parse().expect("valid ipv6")));
        assert!(is_sensitive_ip("fc00::1".parse().expect("valid ipv6")));
    }

    #[test]
    fn extracts_host_from_bracketed_ipv6() {
        assert_eq!(
            extract_host_from_network_target("[fd00:ec2::254]:514").as_deref(),
            Some("fd00:ec2::254")
        );
    }

    #[test]
    fn validates_public_target() {
        assert!(validate_network_target("8.8.8.8:25", DEFAULT_BLOCKED_HOSTNAMES).is_ok());
    }

    #[test]
    fn rejects_unresolvable_hostnames() {
        let result = validate_network_target("definitely-does-not-exist.invalid:25", DEFAULT_BLOCKED_HOSTNAMES);
        assert!(result.is_err(), "unresolvable hostnames must fail closed");
    }

    #[test]
    fn blocks_localhost_with_trailing_dot() {
        let result = validate_network_target("localhost.:25", DEFAULT_BLOCKED_HOSTNAMES);
        assert!(result.is_err(), "trailing dots must not bypass host blocking");
    }

    #[test]
    fn allows_internal_service_url() {
        assert!(
            validate_internal_service_url(
                "http://vigilyx-ai:8900",
                DEFAULT_INTERNAL_SERVICE_HOSTS
            )
            .is_ok()
        );
        assert!(
            validate_internal_service_url("http://[::1]:8900", DEFAULT_INTERNAL_SERVICE_HOSTS)
                .is_ok()
        );
    }

    #[test]
    fn blocks_external_internal_service_url() {
        assert!(
            validate_internal_service_url("https://evil.example", DEFAULT_INTERNAL_SERVICE_HOSTS)
                .is_err()
        );
        assert!(
            validate_internal_service_url("ftp://ai:21", DEFAULT_INTERNAL_SERVICE_HOSTS).is_err()
        );
        assert!(
            validate_internal_service_url("ai:8900", DEFAULT_INTERNAL_SERVICE_HOSTS).is_err()
        );
    }

    #[test]
    fn mail_relay_validation_allows_private_ipv4_targets() {
        assert!(
            validate_mail_relay_host_resolved(
                "10.1.246.33",
                25,
                DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES
            )
            .is_ok()
        );
    }

    #[test]
    fn mail_relay_validation_rejects_localhost() {
        assert!(
            validate_mail_relay_host_resolved(
                "localhost",
                25,
                DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES
            )
            .is_err()
        );
    }

    #[test]
    fn mail_relay_resolution_returns_private_ipv4_socket_addr() {
        let addrs = resolve_mail_relay_host(
            "10.1.246.33",
            2525,
            DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES,
        )
        .expect("private relay IP should be allowed");

        assert_eq!(addrs, vec!["10.1.246.33:2525".parse().expect("valid socket")]);
    }

    #[test]
    fn mail_relay_validation_rejects_urls() {
        assert!(
            validate_mail_relay_host(
                "http://mail.example.com",
                DEFAULT_BLOCKED_MAIL_RELAY_HOSTNAMES
            )
            .is_err()
        );
    }

    #[test]
    fn blocks_internal_service_url_with_non_root_path() {
        assert!(
            validate_internal_service_url(
                "http://vigilyx-ai:8900/training/status",
                DEFAULT_INTERNAL_SERVICE_HOSTS
            )
            .is_err()
        );
    }

    #[test]
    fn blocks_internal_service_url_with_query_or_fragment() {
        assert!(
            validate_internal_service_url(
                "http://127.0.0.1:8900/?x=1",
                DEFAULT_INTERNAL_SERVICE_HOSTS
            )
            .is_err()
        );
        assert!(
            validate_internal_service_url(
                "http://127.0.0.1:8900/#frag",
                DEFAULT_INTERNAL_SERVICE_HOSTS
            )
            .is_err()
        );
    }

    #[test]
    fn blocks_internal_service_url_with_userinfo() {
        assert!(
            validate_internal_service_url(
                "http://user:pass@vigilyx-ai:8900",
                DEFAULT_INTERNAL_SERVICE_HOSTS
            )
            .is_err()
        );
    }

    #[test]
    fn mta_hostname_validation_accepts_valid_names() {
        assert_eq!(
            validate_mta_hostname("Mail-Gateway.Example.COM.").as_deref(),
            Ok("mail-gateway.example.com")
        );
        assert_eq!(validate_mta_hostname("vigilyx-mta").as_deref(), Ok("vigilyx-mta"));
    }

    #[test]
    fn mta_hostname_validation_rejects_control_chars_and_invalid_labels() {
        assert!(validate_mta_hostname("mail\r\n250-XBAD").is_err());
        assert!(validate_mta_hostname("bad host").is_err());
        assert!(validate_mta_hostname("-bad.example").is_err());
        assert!(validate_mta_hostname("bad_.example").is_err());
    }
}
