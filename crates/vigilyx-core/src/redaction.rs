//! Shared privacy-boundary redaction helpers.
//!
//! Network request targets are hostile input and may carry bearer credentials
//! in query parameters.  Keep one fail-closed implementation at the earliest
//! ingestion boundary and reuse it again at persistence/API boundaries so old
//! rows and alternate producers cannot reintroduce plaintext query values.

const MAX_URI_CHARS: usize = 4_096;

/// Return only the bounded path component of an HTTP request target.
///
/// The complete query and fragment are discarded. Retaining query key names
/// is not fail-closed because an opaque bearer token can legally appear as a
/// key-only segment (`?eyJ...`) and would then be copied verbatim. Absolute-
/// form and scheme-relative request targets also lose their authority and
/// userinfo so proxy credentials never cross a persistence/log boundary.
pub fn redact_http_uri(raw: &str) -> String {
    let without_suffix = raw.trim().split(['?', '#']).next().unwrap_or_default();
    let lower = without_suffix.to_ascii_lowercase();
    let authority_start = if lower.starts_with("http://") {
        Some("http://".len())
    } else if lower.starts_with("https://") {
        Some("https://".len())
    } else if without_suffix.starts_with("//") {
        Some(2)
    } else {
        None
    };
    let path = authority_start.map_or(without_suffix, |start| {
        without_suffix[start..]
            .find('/')
            .map_or("/", |slash| &without_suffix[start + slash..])
    });
    truncate_chars(path, MAX_URI_CHARS)
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated: String = value.chars().take(max_chars).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::redact_http_uri;

    #[test]
    fn removes_the_complete_query_and_fragment() {
        let redacted =
            redact_http_uri("/coremail/s/json?sid=secret-session&action=compose#access-token");
        assert_eq!(redacted, "/coremail/s/json");
        assert!(!redacted.contains("secret-session"));
        assert!(!redacted.contains("access-token"));
    }

    #[test]
    fn key_only_query_segments_are_not_retained() {
        let redacted = redact_http_uri("/mail?%73id=top-secret&bare-token");
        assert_eq!(redacted, "/mail");
        assert!(!redacted.contains("top-secret"));
        assert!(!redacted.contains("bare-token"));
    }

    #[test]
    fn path_without_query_is_unchanged() {
        assert_eq!(redact_http_uri("/mail/compose"), "/mail/compose");
    }

    #[test]
    fn malformed_queries_are_removed() {
        let redacted = redact_http_uri("/mail?=secret&&%=also-secret");
        assert_eq!(redacted, "/mail");
        assert!(!redacted.contains("secret"));
    }

    #[test]
    fn absolute_form_drops_authority_userinfo_and_values() {
        let redacted = redact_http_uri("https://user:password@example.test/mail?sid=secret#bearer");
        assert_eq!(redacted, "/mail");
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("password"));
        assert!(!redacted.contains("example.test"));
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("bearer"));
    }

    #[test]
    fn scheme_relative_authority_is_dropped() {
        assert_eq!(
            redact_http_uri("//user:password@example.test/upload?token"),
            "/upload"
        );
    }
}
