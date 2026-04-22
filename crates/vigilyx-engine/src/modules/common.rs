//! Shared utility functions for security analysis modules.

//! Domain extraction helpers used across header_scan, domain_verify,
//! link_scan, and link_reputation modules.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use url::Url;
use vigilyx_parser::mime::decode_rfc2047;

use crate::module_data::module_data;

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


static RE_EMAIL_ADDR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
    )
    .unwrap()
});

fn normalize_address_header(input: &str) -> String {
    let unfolded = input.replace(['\r', '\n'], " ");
    let collapsed = unfolded.split_whitespace().collect::<Vec<_>>().join(" ");
    decode_rfc2047(collapsed.trim())
}

fn extract_email_address(addr: &str) -> Option<String> {
    let normalized = normalize_address_header(addr);
    if normalized.is_empty() {
        return None;
    }

   // Prefer the address inside angle brackets, but fall back to scanning the whole header.
    if let Some(start) = normalized.rfind('<')
        && let Some(end_rel) = normalized[start..].find('>')
    {
        let candidate = &normalized[start + 1..start + end_rel];
        if let Some(m) = RE_EMAIL_ADDR.find(candidate) {
            return Some(m.as_str().to_ascii_lowercase());
        }
    }

    RE_EMAIL_ADDR
        .find(&normalized)
        .map(|m| m.as_str().to_ascii_lowercase())
}

pub fn extract_domain_from_email(addr: &str) -> Option<String> {
    let email = extract_email_address(addr)?;
    email
        .rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

fn sanitized_http_url_candidate(url: &str) -> Option<&str> {
    let trimmed = url.trim();
    if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
        return None;
    }
    let end = trimmed
        .char_indices()
        .find(|(_, c)| {
            matches!(
                c,
                '"'
                    | '\''
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '，'
                    | '。'
                    | '；'
                    | '：'
                    | '“'
                    | '”'
                    | '‘'
                    | '’'
                    | '、'
                    | ' '
                    | '\r'
                    | '\n'
                    | '\t'
            )
        })
        .map(|(idx, _)| idx)
        .unwrap_or(trimmed.len());
    Some(&trimmed[..end])
}

fn parse_http_url(url: &str) -> Option<Url> {
    let candidate = sanitized_http_url_candidate(url)?;
    let after_scheme = candidate
        .strip_prefix("https://")
        .or_else(|| candidate.strip_prefix("http://"))?;
    if after_scheme.is_empty() || after_scheme.starts_with(['/', '?', '#']) {
        return None;
    }
    let parsed = Url::parse(candidate).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some(parsed)
}

pub fn host_matches_domain_or_subdomain(host: &str, candidate: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let candidate = candidate
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    !candidate.is_empty() && (host == candidate || host.ends_with(&format!(".{}", candidate)))
}

/// Match a host against an explicit trust rule.
///
/// Policy:
/// - plain `example.com` matches only the exact host
/// - wildcard `*.example.com` matches `a.example.com`, `b.c.example.com`, etc.
///   but does not match the bare apex `example.com`
pub fn host_matches_domain_policy_rule(host: &str, rule: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let rule = rule.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || rule.is_empty() {
        return false;
    }

    if let Some(suffix) = rule.strip_prefix("*.") {
        !suffix.is_empty()
            && host.len() > suffix.len()
            && host.ends_with(&format!(".{}", suffix))
    } else {
        host == rule
    }
}

/// Match a host against a set of exact/wildcard trust rules.
pub fn domain_matches_policy_set(domain: &str, set: &HashSet<String>) -> bool {
    let lower = domain.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if set.contains(&lower) {
        return true;
    }

    let mut parts = lower.as_str();
    while let Some(pos) = parts.find('.') {
        parts = &parts[pos + 1..];
        if set.contains(&format!("*.{}", parts)) {
            return true;
        }
    }

    false
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
    let parsed = parse_http_url(url)?;
    parsed
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
}

/// Extract the URL path component (`/path/to/file`) from an HTTP(S) URL.
pub fn extract_path_from_url(url: &str) -> Option<String> {
    let parsed = parse_http_url(url)?;
    Some(parsed.path().to_string())
}

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
    module_data().contains("static_asset_extensions", ext)
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

fn is_probable_provider_asset_host(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    lower == "qlogo.cn"
        || lower.ends_with(".qlogo.cn")
        || lower == "qpic.cn"
        || lower.ends_with(".qpic.cn")
        || lower == "gtimg.com"
        || lower.ends_with(".gtimg.com")
        || lower == "127.net"
        || lower.ends_with(".127.net")
}

pub fn is_probable_safe_static_asset_url(url: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url) else {
        return false;
    };
    let path = extract_path_from_url(url)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_probable_cloud_asset_host(&domain) && is_probable_static_asset_path(&path) {
        return true;
    }

    let lower_domain = domain.to_ascii_lowercase();
    if (lower_domain == "qlogo.cn" || lower_domain.ends_with(".qlogo.cn"))
        && (path.contains("/qq_product/") || path.contains("/ek_qqapp/") || path.ends_with("/0"))
    {
        return true;
    }

    if is_probable_provider_asset_host(&lower_domain)
        && (is_probable_static_asset_path(&path)
            || path.contains("/gchatpic_new/")
            || path.contains("/storepics/"))
    {
        return true;
    }

    false
}

/// Detect non-clickable image/render endpoints that are commonly embedded as
/// `<img src>` resources in marketing mail rather than user-facing landing pages.
pub fn is_probable_non_clickable_render_asset_url(url: &str) -> bool {
    if is_probable_safe_static_asset_url(url) {
        return true;
    }

    let Some(parsed) = parse_http_url(url) else {
        return false;
    };
    let path = parsed.path().to_ascii_lowercase();
    let looks_like_render_endpoint = path.ends_with("/showimg")
        || path.contains("/showimg/")
        || path.ends_with("/showimage")
        || path.contains("/showimage/")
        || path.ends_with("/viewimage")
        || path.contains("/viewimage/")
        || path.contains("/portal/sendcloud/showimg");
    if !looks_like_render_endpoint {
        return false;
    }

    let query = parsed.query().unwrap_or("");
    if query.is_empty() {
        return true;
    }

    let allowed_params = [
        "id", "img", "image", "cid", "mid", "rid", "name", "w", "h", "width", "height", "v",
        "t", "fmt", "format",
    ];
    query.split('&').all(|pair| {
        let name = pair
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        !name.is_empty() && allowed_params.contains(&name.as_str())
    })
}

/// Detect opaque click/open/unsubscribe callback URLs used by known mail-delivery
/// platforms. These URLs intentionally carry long encrypted tokens and should
/// not be treated like user-facing landing pages.
pub fn is_probable_opaque_mail_callback_url(url: &str) -> bool {
    let Some(parsed) = parse_http_url(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    if path != "/api/webhook" {
        return false;
    }

    let md = module_data();
    let host_allowed = md
        .get_list("opaque_mail_callback_domains")
        .iter()
        .any(|candidate| host == *candidate || host.ends_with(&format!(".{}", candidate)));
    if !host_allowed {
        return false;
    }

    let query = parsed.query().unwrap_or("");
    if query.is_empty() {
        return false;
    }

    let allowed_params = ["upn"];
    let mut saw_opaque_token = false;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        if !allowed_params.contains(&name.as_str()) {
            return false;
        }
        if value.len() >= 64 {
            saw_opaque_token = true;
        }
    }

    saw_opaque_token
}

/// Detect non-clickable XML/HTML namespace references that frequently appear in
/// raw MIME / Word-generated HTML but are not user-facing links.
pub fn is_probable_schema_reference_url(url: &str) -> bool {
    let Some(domain) = extract_domain_from_url(url) else {
        return false;
    };
    let path = extract_path_from_url(url)
        .unwrap_or_default()
        .to_ascii_lowercase();

    match domain.as_str() {
        "schemas.microsoft.com" => {
            path.starts_with("/office/") || path.starts_with("/office/2004/")
        }
        "schemas.openxmlformats.org" => true,
        "www.w3.org" | "w3.org" => {
            path.starts_with("/tr/")
                || path.starts_with("/2000/")
                || path.starts_with("/1999/")
                || path.contains("/xhtml")
                || path.contains("/xml")
                || path.contains("/svg")
        }
        _ => false,
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
    let redirect_params = module_data().get_list("redirect_params").to_vec();

    let mut targets = Vec::new();
    let mut seen = HashSet::new();

    let Some(parsed) = parse_http_url(url) else {
        return targets;
    };

    for (name, raw_value) in parsed.query_pairs() {
        let name_lower = name.to_ascii_lowercase();
        if !redirect_params
            .iter()
            .filter_map(|param| param.strip_suffix('='))
            .any(|param| param == name_lower.as_str())
        {
            continue;
        }

        let mut decoded = raw_value.into_owned();
        for _ in 0..2 {
            let next = percent_decode(&decoded);
            if next == decoded {
                break;
            }
            decoded = next;
        }

        if let Some(target) = sanitized_http_url_candidate(&decoded)
            && seen.insert(target.to_string())
        {
            targets.push(target.to_string());
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
    fn test_extract_domain_from_email_no_at_returns_none() {
        assert_eq!(extract_domain_from_email("nodomain"), None);
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

    #[test]
    fn test_extract_domain_from_email_decodes_rfc2047_display_name() {
        assert_eq!(
            extract_domain_from_email("=?utf-8?B?5byg5LiJ?= <user@example.com>"),
            Some("example.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_email_ignores_malformed_folded_header_without_address() {
        assert_eq!(extract_domain_from_email("\"=?utf-8?B?OTE5NzA4NzQx"), None);
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
    fn test_extract_domain_from_url_stops_at_cjk_punctuation() {
        assert_eq!(
            extract_domain_from_url("https://portal.unionpay.com，点击右上角“在线客服”提问"),
            Some("portal.unionpay.com".to_string()),
        );
    }

    #[test]
    fn test_extract_domain_from_url_rejects_userinfo() {
        assert_eq!(extract_domain_from_url("https://user:pass@evil.example/login"), None);
    }

    #[test]
    fn test_host_matches_domain_policy_rule_exact_only() {
        assert!(host_matches_domain_policy_rule("12306.com", "12306.com"));
        assert!(!host_matches_domain_policy_rule("login.12306.com", "12306.com"));
    }

    #[test]
    fn test_host_matches_domain_policy_rule_wildcard_subdomain_only() {
        assert!(host_matches_domain_policy_rule(
            "wx.mail.qq.com",
            "*.mail.qq.com"
        ));
        assert!(host_matches_domain_policy_rule(
            "a.b.partner.example.cn",
            "*.partner.example.cn"
        ));
        assert!(!host_matches_domain_policy_rule(
            "mail.qq.com",
            "*.mail.qq.com"
        ));
    }

    #[test]
    fn test_extract_domain_from_url_rejects_port_before_userinfo_bypass() {
        assert_eq!(
            extract_domain_from_url("https://12306.com:443@evil.example/login"),
            None
        );
    }

    #[test]
    fn test_qlogo_asset_url_is_treated_as_safe_static_asset() {
        assert!(is_probable_safe_static_asset_url(
            "http://thirdqq.qlogo.cn/ek_qqapp/AQImdrqed/example/0"
        ));
    }

    #[test]
    fn test_127_net_jpg_is_treated_as_safe_static_asset() {
        assert!(is_probable_safe_static_asset_url(
            "https://mail-online.nosdn.127.net/wzpmmc/b7713ee39fc6d0272a61196c395ab44e.jpg"
        ));
    }

    #[test]
    fn test_extract_redirect_target_urls_decodes_embedded_target() {
        let targets = extract_redirect_target_urls(
            "https://gateway.example/track?url=https%3A%2F%2Fevil.example%2Flogin%3Fnext%3D1",
        );
        assert_eq!(targets, vec!["https://evil.example/login?next=1".to_string()]);
    }

    #[test]
    fn test_extract_redirect_target_urls_double_decodes_embedded_target() {
        let targets = extract_redirect_target_urls(
            "https://gateway.example/track?url=https%253A%252F%252Fevil.example%252Flogin%253Fnext%253D1",
        );
        assert_eq!(targets, vec!["https://evil.example/login?next=1".to_string()]);
    }

    #[test]
    fn test_non_clickable_render_asset_url_recognizes_showimg_endpoint() {
        assert!(is_probable_non_clickable_render_asset_url(
            "http://home.sumscope.com:8050/portal/sendcloud/showImg?id=74916bf1ba5d4f7f9731941883c1ffc0"
        ));
    }

    #[test]
    fn test_opaque_mail_callback_url_recognizes_cloudses_webhook() {
        assert!(is_probable_opaque_mail_callback_url(
            "https://1254335589-hk.callback.cloudses.com/api/webhook?upn=eb4ffc552935405db76234bb95083795f5831773d61927b5570fc6a831840ab1e14a24f90146ee0acaa8686e500ef2d"
        ));
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
