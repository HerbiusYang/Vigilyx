use std::net::{IpAddr, ToSocketAddrs};

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

pub const DEFAULT_INTERNAL_SERVICE_HOSTS: &[&str] =
    &["ai", "vigilyx-ai", "localhost", "127.0.0.1", "::1"];

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_matches('[')
        .trim_matches(']')
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

pub fn validate_network_host(host: &str, blocked_hostnames: &[&str]) -> Result<(), String> {
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
        return Ok(());
    }

    if blocked_hostnames.contains(&host.as_str()) {
        return Err(format!("Disallowed host: {host}"));
    }
    if host.ends_with(".internal") || host.ends_with(".local") {
        return Err(format!("Disallowed host suffix: {host}"));
    }

    if let Ok(addrs) = (host.as_str(), 0u16).to_socket_addrs() {
        for addr in addrs {
            if is_sensitive_ip(addr.ip()) {
                return Err(format!("Hostname resolves to disallowed IP: {}", addr.ip()));
            }
        }
    }

    Ok(())
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
        assert!(validate_network_target("smtp.example.com:25", DEFAULT_BLOCKED_HOSTNAMES).is_ok());
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
}
