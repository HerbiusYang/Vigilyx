//! Shared utility functions for security analysis modules.

//! Domain extraction helpers used across header_scan, domain_verify,
//! link_scan, and link_reputation modules.

use std::collections::HashSet;

/// Extract domain from an email address string.

/// Handles both plain addresses (`user@example.com`) and display-name
/// format (`"Display Name <user@example.com>"`).

/// # Examples

/// # use vigilyx_engine::modules::common::extract_domain_from_email;
/// assert_eq!(
/// extract_domain_from_email("user@example.com"),
/// Some("example.com".to_string()),

/// assert_eq!(
/// extract_domain_from_email("Alice <alice@CORP.com>"),
/// Some("corp.com".to_string()),


pub fn extract_domain_from_email(addr: &str) -> Option<String> {
   // Try to find <...> first (display-name format)
    let email = if let Some(start) = addr.find('<') {
        if let Some(end) = addr[start..].find('>') {
            &addr[start + 1..start + end]
        } else {
            addr
        }
    } else {
        addr.trim()
    };

    email
        .rsplit('@')
        .next()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
}

/// Extract the hostname from a URL, stripping scheme, port, path, and query.

/// Only recognises `http://` and `https://` schemes. Returns `None` for
/// other schemes (e.g. `ftp://`) or when the host portion is empty.

/// # Examples

/// # use vigilyx_engine::modules::common::extract_domain_from_url;
/// assert_eq!(
/// extract_domain_from_url("https://www.google.com/search?q=rust"),
/// Some("www.google.com".to_string()),

/// assert_eq!(
/// extract_domain_from_url("http://evil.tk:8080/payload"),
/// Some("evil.tk".to_string()),

/// assert_eq!(extract_domain_from_url("ftp://invalid"), None);

pub fn extract_domain_from_url(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = after_scheme.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or(host); // strip port
    let host = host.split('?').next().unwrap_or(host); // strip query (for bare host?key=val)
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Percent-decode a URL component without allocating intermediate parsers.
pub fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&input[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract embedded redirect target URLs from tracking/security-gateway links.
pub fn extract_redirect_target_urls(url: &str) -> Vec<String> {
    const REDIRECT_PARAMS: &[&str] = &[
        "clickenc=",
        "redirect=",
        "url=",
        "goto=",
        "target=",
        "dest=",
        "destination=",
        "redir=",
        "link=",
        "to=",
        "bounce=",
        "forward=",
        "next=",
        "return_url=",
    ];

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    let Some((_, query)) = url.split_once('?') else {
        return targets;
    };

    for pair in query.split('&') {
        let Some((name, raw_value)) = pair.split_once('=') else {
            continue;
        };
        let name_lower = name.to_lowercase();
        if !REDIRECT_PARAMS
            .iter()
            .filter_map(|param| param.strip_suffix('='))
            .any(|param| param == name_lower.as_str())
        {
            continue;
        }

        let decoded = percent_decode(raw_value);
        if (decoded.starts_with("http://") || decoded.starts_with("https://"))
            && seen.insert(decoded.clone())
        {
            targets.push(decoded);
        }
    }

    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    
   // extract_domain_from_email
    

    #[test]
    fn test_extract_domain_from_email_plain_address() {
        assert_eq!(
            extract_domain_from_email("user@example.com"),
            Some("example.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_email_display_name_format() {
        assert_eq!(
            extract_domain_from_email("Alice <alice@corp.com>"),
            Some("corp.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_email_uppercase_normalised() {
        assert_eq!(
            extract_domain_from_email("Bob <bob@UPPER.COM>"),
            Some("upper.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_email_no_at_returns_input_as_domain() {
       // rsplit('@').next() returns the whole string when no '@' is present
        assert_eq!(
            extract_domain_from_email("nodomain"),
            Some("nodomain".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_email_empty_returns_none() {
        assert_eq!(extract_domain_from_email(""), None);
    }

    #[test]
    fn test_extract_domain_from_email_only_at_returns_none() {
        assert_eq!(extract_domain_from_email("user@"), None);
    }

    #[test]
    fn test_extract_domain_from_email_whitespace_trimmed() {
        assert_eq!(
            extract_domain_from_email("  user@padded.com  "),
            Some("padded.com".to_string()),
        );
    }

    
   // extract_domain_from_url
    

    #[test]
    fn test_extract_domain_from_url_https() {
        assert_eq!(
            extract_domain_from_url("https://www.google.com/search"),
            Some("www.google.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_url_http_with_port() {
        assert_eq!(
            extract_domain_from_url("http://evil.tk:8080/payload"),
            Some("evil.tk".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_url_unknown_scheme_returns_none() {
        assert_eq!(extract_domain_from_url("ftp://invalid"), None);
    }

    #[test]
    fn test_extract_domain_from_url_with_query_string() {
        assert_eq!(
            extract_domain_from_url("https://example.com?key=val"),
            Some("example.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_url_empty_host_returns_none() {
        assert_eq!(extract_domain_from_url("https:///path"), None);
    }

    #[test]
    fn test_extract_domain_from_url_uppercase_normalised() {
        assert_eq!(
            extract_domain_from_url("https://EXAMPLE.COM/path"),
            Some("example.com".to_string()),
        );
    }

    #[test]
    fn test_extract_redirect_target_urls_decodes_embedded_target() {
        let targets = extract_redirect_target_urls(
            "https://gateway.example/track?url=https%3A%2F%2Fevil.example%2Flogin%3Fnext%3D1",
        );
        assert_eq!(targets, vec!["https://evil.example/login?next=1".to_string()]);
    }
}
