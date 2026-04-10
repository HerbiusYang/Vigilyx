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

/// Extract the URL path component (`/path/to/file`) from an HTTP(S) URL.
pub fn extract_path_from_url(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let (_, rest) = after_scheme.split_once('/')?;
    let path = format!("/{}", rest);
    Some(
        path
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(path.as_str())
        .split_once('#')
        .map(|(p, _)| p)
        .unwrap_or(path.as_str())
        .to_string(),
    )
}

const STATIC_ASSET_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "avif", "css", "js", "mjs",
    "map", "woff", "woff2", "ttf", "eot",
];

/// Detect a static asset path on a CDN/object-storage host.
pub fn is_probable_static_asset_path(path: &str) -> bool {
    let last_segment = path
        .split('?')
        .next()
        .unwrap_or(path)
        .split('#')
        .next()
        .unwrap_or(path)
        .rsplit('/')
        .next()
        .unwrap_or("");
    let Some((_, ext)) = last_segment.rsplit_once('.') else {
        return false;
    };
    STATIC_ASSET_EXTENSIONS
        .iter()
        .any(|known| ext.eq_ignore_ascii_case(known))
}

/// Detect common object-storage / CDN bucket hosts.
pub fn is_probable_cloud_asset_host(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    (lower.ends_with(".aliyuncs.com") && lower.contains(".oss-"))
        || lower.ends_with(".blob.core.windows.net")
        || lower == "storage.googleapis.com"
        || lower.ends_with(".storage.googleapis.com")
        || lower.ends_with(".digitaloceanspaces.com")
        || lower.ends_with(".r2.cloudflarestorage.com")
        || (lower.ends_with(".myqcloud.com") && lower.contains(".cos."))
        || (lower.ends_with(".amazonaws.com")
            && (lower == "s3.amazonaws.com"
                || lower.starts_with("s3.")
                || lower.contains(".s3.")
                || lower.contains(".s3-")))
}

/// Detect a URL that points to a static asset hosted on common object-storage infrastructure.
pub fn is_probable_cloud_asset_url(url: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url) else {
        return false;
    };
    let Some(path) = extract_path_from_url(url) else {
        return false;
    };
    is_probable_cloud_asset_host(&domain) && is_probable_static_asset_path(&path)
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

/// Detect raw MIME container text that should not be treated as human-readable body content.
///
/// This is a structural detector, not a keyword list:
/// - boundary line at the top
/// - MIME part headers (`Content-Type`, `Content-Transfer-Encoding`, ...)
/// - one or more long base64-looking payload lines
pub fn looks_like_raw_mime_container_text(text: &str) -> bool {
    let preview: Vec<&str> = text.lines().take(40).collect();
    if preview.is_empty() {
        return false;
    }

    let boundary_like = preview
        .iter()
        .take(3)
        .map(|line| line.trim())
        .any(|line| line.len() > 8 && line.starts_with("--") && !line[2..].contains(' '));

    let marker_count = preview
        .iter()
        .map(|line| line.trim_start().to_ascii_lowercase())
        .filter(|line| {
            line.starts_with("content-type:")
                || line.starts_with("content-transfer-encoding:")
                || line.starts_with("content-disposition:")
                || line.starts_with("mime-version:")
        })
        .count();

    let base64_lines = preview
        .iter()
        .filter(|line| is_base64_payload_line(line.trim()))
        .count();

    (boundary_like && marker_count >= 2 && base64_lines >= 1) || (marker_count >= 3 && base64_lines >= 2)
}

fn is_base64_payload_line(line: &str) -> bool {
    if line.len() < 24 {
        return false;
    }

    let non_ws_len = line.chars().filter(|c| !c.is_whitespace()).count();
    if non_ws_len < 24 {
        return false;
    }

    let valid = line
        .chars()
        .filter(|c| !c.is_whitespace())
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));

    valid && non_ws_len % 4 == 0
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

    #[test]
    fn test_detects_raw_mime_container_text() {
        let raw = "--=_NextPart_123\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
U29tZSBuZXN0ZWQgcGF5bG9hZA==\r\n";

        assert!(looks_like_raw_mime_container_text(raw));
    }

    #[test]
    fn test_plain_business_text_is_not_raw_mime_container() {
        let plain = "Please review invoice INV-12345 and reply today.";
        assert!(!looks_like_raw_mime_container_text(plain));
    }

    #[test]
    fn test_detects_cloud_static_asset_url() {
        assert!(is_probable_cloud_asset_url(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login-banner.png?x-oss-process=image/resize,w_600"
        ));
    }

    #[test]
    fn test_login_page_on_object_storage_is_not_treated_as_static_asset() {
        assert!(!is_probable_cloud_asset_url(
            "https://bucket.s3.amazonaws.com/login/index.html?token=abc"
        ));
    }
}
