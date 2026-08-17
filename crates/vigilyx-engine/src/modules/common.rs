//! Shared utility functions for security analysis modules.

//! Domain extraction helpers used across header_scan, domain_verify,
//! link_scan, and link_reputation modules.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
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
        // Trim trailing dots: "evil.com." (FQDN form) must normalize to the
        // same domain as "evil.com" or IOC exact-match lookups miss.
        .map(|(_, d)| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
}

/// Return the registrable/organizational domain used for relaxed sender
/// alignment. This intentionally centralizes the existing compound-suffix
/// policy so header, identity, and link modules cannot disagree about the
/// same parent/subdomain relationship.
pub fn organizational_domain(domain: &str) -> Option<String> {
    let normalized = domain
        .trim()
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if normalized.parse::<IpAddr>().is_ok() {
        return Some(normalized);
    }

    let labels: Vec<&str> = normalized
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    if labels.is_empty() {
        return None;
    }

    let public_suffix_labels = module_data()
        .get_list("compound_tlds")
        .iter()
        .filter_map(|suffix| {
            let suffix = suffix.trim_start_matches('.').to_ascii_lowercase();
            (normalized == suffix || normalized.ends_with(&format!(".{suffix}")))
                .then(|| suffix.split('.').count())
        })
        .max()
        .unwrap_or(1);

    if labels.len() <= public_suffix_labels {
        return Some(normalized);
    }

    Some(labels[labels.len() - public_suffix_labels - 1..].join("."))
}

/// RFC 7489-style relaxed organizational-domain comparison.
pub fn domains_share_organizational_domain(left: &str, right: &str) -> bool {
    match (organizational_domain(left), organizational_domain(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
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
                '"' | '\''
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

/// Parse an HTTP(S) URL candidate with the WHATWG parser.
///
/// Userinfo (`http://mail.qq.com:443@evil.tk/login`) is NOT rejected: the
/// parser keeps the real host (the segment after `@`) available via
/// `host_str()`, so callers see the actual destination. Rejecting userinfo
/// here previously blinded every downstream check (href/text mismatch, TLD,
/// redirect) because the URL could not be parsed at all. Callers that grant
/// exemptions must additionally consult [`url_has_userinfo`] — a URL carrying
/// userinfo must never be treated as a trusted/static asset.
fn parse_http_url(url: &str) -> Option<Url> {
    let candidate = sanitized_http_url_candidate(url)?;
    let after_scheme = candidate
        .strip_prefix("https://")
        .or_else(|| candidate.strip_prefix("http://"))?;
    if after_scheme.is_empty() || after_scheme.starts_with(['/', '?', '#']) {
        return None;
    }
    Url::parse(candidate).ok()
}

/// Whether an HTTP(S) URL carries userinfo in its authority component
/// (`http://user:pass@host/` or the deceptive `http://trusted.name@evil.tk/`).
/// The mere presence of userinfo in an email link is a phishing signal: mail
/// clients render the leading "trusted.name@" portion while the browser
/// connects to the host after `@`.
pub fn url_has_userinfo(url: &str) -> bool {
    let Some(parsed) = parse_http_url(url) else {
        return false;
    };
    !parsed.username().is_empty() || parsed.password().is_some()
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
        !suffix.is_empty() && host.len() > suffix.len() && host.ends_with(&format!(".{}", suffix))
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
/// extract_domain_from_url("<https://www.google.com/search?q=rust>"),
/// Some("www.google.com".to_string()),

/// assert_eq!(
/// extract_domain_from_url("<http://evil.tk:8080/payload>"),
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
    // A userinfo URL must never inherit an asset exemption.
    if url_has_userinfo(url) {
        return false;
    }
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
    // A userinfo URL must never inherit an asset exemption.
    if url_has_userinfo(url) {
        return false;
    }
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
        && (path == "/g"
            || path.contains("/qq_product/")
            || path.contains("/ek_qqapp/")
            || path.ends_with("/0"))
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
    // A userinfo URL must never inherit an asset exemption.
    if url_has_userinfo(url) {
        return false;
    }
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
        "id", "img", "image", "cid", "mid", "rid", "name", "w", "h", "width", "height", "v", "t",
        "fmt", "format",
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
    // A userinfo URL must never inherit an asset exemption.
    if url_has_userinfo(url) {
        return false;
    }
    let Some(parsed) = parse_http_url(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();

    // Huawei Developer notification telemetry observed in the production
    // corpus. Keep this exemption provider- and schema-specific: accepting a
    // parent-domain suffix or unknown fields would let attacker-controlled
    // lookalikes and embedded redirect targets bypass normal URL analysis.
    if host == "svc-drcn.developer.huawei.com" {
        return is_huawei_developer_telemetry_callback(&parsed, &path);
    }

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

fn is_huawei_developer_telemetry_callback(parsed: &Url, normalized_path: &str) -> bool {
    if parsed.scheme() != "https" || parsed.port().is_some() || parsed.fragment().is_some() {
        return false;
    }

    let mut params = HashMap::new();
    for (name, value) in parsed.query_pairs() {
        if params
            .insert(name.into_owned(), value.into_owned())
            .is_some()
        {
            return false;
        }
    }

    let has_common_fields = params.get("localMsgID").is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) && params.get("msgType").is_some_and(|value| value == "1")
        && params.get("key").is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        });
    if !has_common_fields {
        return false;
    }

    match normalized_path {
        "/partnermessage/dadian/v2/opennum" => params.len() == 3,
        "/partnermessage/dadian/v2/clicknum" => {
            params.len() == 5
                && params
                    .get("urlPageIndex")
                    .is_some_and(|value| is_canonical_lowercase_uuid(value))
                && params
                    .get("urlIndex")
                    .is_some_and(|value| is_canonical_lowercase_uuid(value))
        }
        _ => false,
    }
}

fn is_canonical_lowercase_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

/// Detect non-clickable XML/HTML namespace references that frequently appear in
/// raw MIME / Word-generated HTML but are not user-facing links.
pub fn is_probable_schema_reference_url(url: &str) -> bool {
    // A userinfo URL must never inherit an asset exemption.
    if url_has_userinfo(url) {
        return false;
    }
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
        "www.wps.cn" | "wps.cn" => path.starts_with("/officedocument/"),
        "purl.org" => path.starts_with("/dc/"),
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

/// Extract one layer of embedded redirect target URLs.
fn extract_redirect_target_urls_once(url: &str) -> Vec<String> {
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

        let target = normalize_embedded_http_target(&decoded);
        if let Some(target) = target
            && seen.insert(target.clone())
        {
            targets.push(target);
        }
    }

    targets
}

/// Normalize redirect parameters that omit a scheme (common in enterprise
/// mail gateways: `url=www.example.com/path`).  Only host-like values are
/// promoted to HTTPS; arbitrary strings and non-HTTP schemes are rejected.
fn normalize_embedded_http_target(value: &str) -> Option<String> {
    if let Some(candidate) = sanitized_http_url_candidate(value) {
        return Some(candidate.to_string());
    }

    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| matches!(c, ' ' | '\r' | '\n' | '\t' | '"' | '\'' | '<' | '>' | ':'))
        || !trimmed.contains('.')
    {
        return None;
    }

    let candidate = format!("https://{trimmed}");
    sanitized_http_url_candidate(&candidate).map(str::to_string)
}

/// Extract embedded redirect target URLs from tracking/security-gateway links.
///
/// Redirect wrappers are frequently nested (for example a mail gateway wraps a
/// tracking URL which itself carries a second `next=` target).  The old helper
/// stopped after the first wrapper, allowing the final phishing host to avoid
/// both reputation and structural analysis.  Walk a bounded chain so malformed
/// or cyclic URLs cannot cause unbounded work.
pub fn extract_redirect_target_urls(url: &str) -> Vec<String> {
    const MAX_REDIRECT_DEPTH: usize = 4;
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut frontier = vec![(url.to_string(), 0usize)];

    while let Some((current, depth)) = frontier.pop() {
        if depth >= MAX_REDIRECT_DEPTH {
            continue;
        }
        for target in extract_redirect_target_urls_once(&current) {
            if seen.insert(target.clone()) {
                frontier.push((target.clone(), depth + 1));
                targets.push(target);
            }
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

    (boundary_like && marker_count >= 2 && base64_lines >= 1)
        || (marker_count >= 3 && base64_lines >= 2)
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
    fn test_extract_domain_from_email_trailing_dot_fqdn_normalised() {
        // Trailing-dot FQDN evasion: "evil.com." must match the "evil.com" IOC.
        assert_eq!(
            extract_domain_from_email("Carol <carol@Evil.COM.>"),
            Some("evil.com".to_string()),
        );
        assert_eq!(
            extract_domain_from_email("dave@example.com.."),
            Some("example.com".to_string()),
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
    fn test_extract_domain_from_url_userinfo_returns_real_host() {
        // PoC (B1-1): before the fix, userinfo URLs were rejected outright and
        // every downstream check (href/text mismatch, TLD, reputation) was
        // blind. The real destination is the host after `@`.
        assert_eq!(
            extract_domain_from_url("https://user:pass@evil.example/login"),
            Some("evil.example".to_string()),
        );
    }

    #[test]
    fn test_url_has_userinfo_detects_authority_obfuscation() {
        assert!(url_has_userinfo("https://user:pass@evil.example/login"));
        assert!(url_has_userinfo("http://mail.qq.com:443@evil.tk/login"));
        assert!(!url_has_userinfo(
            "https://evil.example/login?next=user@example.com"
        ));
        assert!(!url_has_userinfo("https://mail.qq.com/login"));
    }

    #[test]
    fn test_userinfo_url_never_gets_static_asset_exemption() {
        // A deceptive userinfo prefix must not ride the trusted-CDN exemption.
        assert!(!is_probable_safe_static_asset_url(
            "https://attacker@mail-online.nosdn.127.net/wzpmmc/b7713ee39fc6d0272a61196c395ab44e.jpg"
        ));
        assert!(!is_probable_schema_reference_url(
            "http://user@schemas.openxmlformats.org/officeDocument"
        ));
    }

    #[test]
    fn test_host_matches_domain_policy_rule_exact_only() {
        assert!(host_matches_domain_policy_rule("12306.com", "12306.com"));
        assert!(!host_matches_domain_policy_rule(
            "login.12306.com",
            "12306.com"
        ));
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
    fn test_extract_domain_from_url_port_before_userinfo_returns_real_host() {
        // PoC (B1-1): `https://12306.com:443@evil.example/login` displays the
        // trusted name but connects to evil.example — the parser must expose
        // the real host, not reject the URL.
        assert_eq!(
            extract_domain_from_url("https://12306.com:443@evil.example/login"),
            Some("evil.example".to_string()),
        );
    }

    #[test]
    fn test_qlogo_asset_url_is_treated_as_safe_static_asset() {
        assert!(is_probable_safe_static_asset_url(
            "http://thirdqq.qlogo.cn/ek_qqapp/AQImdrqed/example/0"
        ));
        assert!(is_probable_safe_static_asset_url(
            "http://thirdqq.qlogo.cn/g?b=oidb&k=avatar-token&s=100&t=1700000000"
        ));
    }

    #[test]
    fn test_wps_document_namespace_is_not_a_clickable_url() {
        assert!(is_probable_schema_reference_url(
            "http://www.wps.cn/officeDocument/2013/wpsCustomData"
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
        assert_eq!(
            targets,
            vec!["https://evil.example/login?next=1".to_string()]
        );
    }

    #[test]
    fn test_extract_redirect_target_urls_double_decodes_embedded_target() {
        let targets = extract_redirect_target_urls(
            "https://gateway.example/track?url=https%253A%252F%252Fevil.example%252Flogin%253Fnext%253D1",
        );
        assert_eq!(
            targets,
            vec!["https://evil.example/login?next=1".to_string()]
        );
    }

    #[test]
    fn test_extract_redirect_target_urls_walks_nested_wrappers() {
        let targets = extract_redirect_target_urls(
            "https://gateway.example/track?url=https%3A%2F%2Fjump.example%2Fgo%3Fnext%3Dhttps%253A%252F%252Fevil.example%252Flogin",
        );
        assert!(
            targets
                .contains(&"https://jump.example/go?next=https://evil.example/login".to_string())
        );
        assert!(targets.contains(&"https://evil.example/login".to_string()));
    }

    #[test]
    fn test_organizational_domain_relaxed_alignment() {
        assert_eq!(
            organizational_domain("mail.contact.acams.org"),
            Some("acams.org".to_string())
        );
        assert!(domains_share_organizational_domain(
            "acams.org",
            "contact.acams.org"
        ));
        assert!(domains_share_organizational_domain(
            "example.co.uk",
            "mailer.example.co.uk"
        ));
        assert!(!domains_share_organizational_domain(
            "acams.org",
            "acams-login.example"
        ));
        assert!(domains_share_organizational_domain(
            "192.0.2.1",
            "192.0.2.1"
        ));
        assert!(!domains_share_organizational_domain(
            "192.0.2.1",
            "192.0.2.2"
        ));
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
    fn test_opaque_mail_callback_url_recognizes_observed_huawei_telemetry_schema() {
        assert!(is_probable_opaque_mail_callback_url(
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/clicknum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&urlPageIndex=f7cf6546-809b-4359-b402-b04ae180817a&urlIndex=d5431c23-7909-41fa-8c8b-0541cfd1ff17&key=92e3d69690d94e58685eec9ecaf3e3e93d5d63f6716ad3543aa4caa6869b9de6"
        ));
        assert!(is_probable_opaque_mail_callback_url(
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82"
        ));
    }

    #[test]
    fn test_huawei_telemetry_exemption_rejects_lookalikes_and_schema_deviations() {
        let valid = "localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82";
        for url in [
            format!("https://svc-drcn.developer.huawei.com.evil.example/partnermessage/dadian/v2/opennum?{valid}"),
            format!("https://evil.example@svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?{valid}"),
            format!("http://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?{valid}"),
            format!("https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?{valid}&url=https%3A%2F%2Fevil.example%2Flogin"),
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=short&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82".to_string(),
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=2&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82".to_string(),
        ] {
            assert!(
                !is_probable_opaque_mail_callback_url(&url),
                "schema deviation must remain analyzable: {url}"
            );
        }
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
