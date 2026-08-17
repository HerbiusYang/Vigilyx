//! 落库前请求体凭据脱敏 (F4)
//!
//! 引擎此前把每个 HTTP 会话的 `request_body` (含登录 POST 的
//! `username=x&password=明文`) 无条件明文写入 http_sessions 表, 脱敏只发生在
//! API 读取层 (vigilyx-api handlers/data_security.rs `redact_request_body`)。
//! 本模块在引擎落库前按**同一套规则**脱敏, 使静态数据库快照/备份不再泄露明文口令。
//!
//! ⚠️ 重复实现说明: 共享 crate (vigilyx-core / vigilyx-db) 不在本修复 slice 名下,
//! 无法下沉共用; 本文件与 `crates/vigilyx-api/src/handlers/data_security.rs` 的
//! redact 逻辑必须保持同步 (键表 / 正则 / JSON 递归规则一致)。修改任一侧时
//! 必须同步另一侧。

use regex::{Captures, Regex};

/// 脱敏占位符 (与 API 读取层一致)
const REDACTED_VALUE: &str = "[REDACTED]";
/// 精确匹配的敏感键 (小写归一后)
const SENSITIVE_KEY_EXACT: &[&str] = &["auth", "otp", "pass", "pwd", "secret", "token"];
/// 子串匹配的敏感键片段 (小写归一后)
const SENSITIVE_KEY_FRAGMENTS: &[&str] = &[
    "accesstoken",
    "apikey",
    "authorization",
    "clientsecret",
    "credential",
    "passwd",
    "passcode",
    "passphrase",
    "password",
    "refreshtoken",
    "sessiontoken",
    "verificationcode",
];

/// 键名归一: 仅保留 ASCII 字母数字并小写化 (与 API 读取层一致)
fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>();

    SENSITIVE_KEY_EXACT.iter().any(|item| normalized == *item)
        || SENSITIVE_KEY_FRAGMENTS
            .iter()
            .any(|item| normalized.contains(item))
}

/// 按 Content-Type / 内容形态分派脱敏: JSON 递归脱敏 > 键值对正则 > XML 标签
/// (与 API 读取层 `redact_request_body` 规则等价)。
pub fn redact_request_body(body: &str, content_type: Option<&str>) -> String {
    let ct = content_type.map(|value| value.to_ascii_lowercase());
    let trimmed = body.trim_start();

    if (ct
        .as_deref()
        .is_some_and(|value| value.contains("json") || value.ends_with("+json"))
        || trimmed.starts_with('{')
        || trimmed.starts_with('['))
        && let Some(redacted) = redact_json_credentials(body)
    {
        return redacted;
    }

    let mut redacted = redact_key_value_credentials(body);
    if ct
        .as_deref()
        .is_some_and(|value| value.contains("xml") || value.ends_with("+xml"))
        || trimmed.starts_with('<')
    {
        redacted = redact_xml_tag_credentials(&redacted);
    }
    redacted
}

fn redact_json_credentials(body: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(body).ok()?;
    redact_json_value(&mut value);
    serde_json::to_string(&value).ok()
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if is_sensitive_key(key) {
                    *item = serde_json::Value::String(REDACTED_VALUE.to_string());
                } else {
                    redact_json_value(item);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

fn redact_key_value_credentials(body: &str) -> String {
    key_value_regex()
        .replace_all(body, |caps: &Captures<'_>| {
            let key = caps
                .name("dkey")
                .or_else(|| caps.name("skey"))
                .or_else(|| caps.name("bare"))
                .map(|m| m.as_str())
                .unwrap_or_default();

            if !is_sensitive_key(key) {
                return caps[0].to_string();
            }

            let prefix = caps.name("prefix").map(|m| m.as_str()).unwrap_or_default();
            let value = caps.name("value").map(|m| m.as_str()).unwrap_or_default();
            format!("{prefix}{}", redacted_literal(value, prefix))
        })
        .into_owned()
}

fn redact_xml_tag_credentials(body: &str) -> String {
    xml_tag_regex()
        .replace_all(body, |caps: &Captures<'_>| {
            let tag = caps.name("tag").map(|m| m.as_str()).unwrap_or_default();
            if !is_sensitive_key(tag.rsplit(':').next().unwrap_or(tag)) {
                return caps[0].to_string();
            }

            let open = caps.name("open").map(|m| m.as_str()).unwrap_or_default();
            let close = caps.name("close").map(|m| m.as_str()).unwrap_or_default();
            format!("{open}{REDACTED_VALUE}{close}")
        })
        .into_owned()
}

fn redacted_literal(value: &str, prefix: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0] as char;
        let last = value.as_bytes()[value.len() - 1] as char;
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            return format!("{first}{REDACTED_VALUE}{last}");
        }
    }

    if prefix.contains(':') {
        format!("\"{REDACTED_VALUE}\"")
    } else {
        REDACTED_VALUE.to_string()
    }
}

fn key_value_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?ix)
            (?P<prefix>
                (?:
                    "(?P<dkey>[^"]+)"
                    |
                    '(?P<skey>[^']+)'
                    |
                    (?P<bare>[A-Za-z0-9_.:-]+)
                )
                \s*[:=]\s*
            )
            (?P<value>
                "(?:\\.|[^"])*"
                |
                '(?:\\.|[^'])*'
                |
                [^,&;\s}\]\r\n]+
            )
            "#,
        )
        .expect("valid key/value redaction regex")
    })
}

fn xml_tag_regex() -> &'static Regex {
    static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?isx)
            (?P<open><(?P<tag>[A-Za-z0-9_.:-]+)[^>]*>)
            (?P<value>[^<]*)
            (?P<close></[A-Za-z0-9_.:-]+\s*>)
            "#,
        )
        .expect("valid XML redaction regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_form_login_credentials_before_storage() {
        // F4 PoC (修复前明文落库): 登录 POST 的 form body 必须在写入
        // http_sessions 表之前脱敏
        let redacted = redact_request_body(
            "username=alice&password=Sup3rSecret!&token=abc123",
            Some("application/x-www-form-urlencoded"),
        );
        assert_eq!(
            redacted,
            "username=alice&password=[REDACTED]&token=[REDACTED]"
        );
        assert!(!redacted.contains("Sup3rSecret!"));
    }

    #[test]
    fn redacts_json_login_credentials_before_storage() {
        let redacted = redact_request_body(
            r#"{"username":"alice","password":"Sup3rSecret!","nested":{"access_token":"abc"}}"#,
            Some("application/json"),
        );
        let value: serde_json::Value = serde_json::from_str(&redacted).expect("valid json");
        assert_eq!(value["username"], "alice");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["nested"]["access_token"], "[REDACTED]");
        assert!(!redacted.contains("Sup3rSecret!"));
    }

    #[test]
    fn redacts_xml_credentials_before_storage() {
        let redacted = redact_request_body(
            r#"<login><username>alice</username><password>Sup3rSecret!</password></login>"#,
            Some("application/xml"),
        );
        assert!(redacted.contains("<password>[REDACTED]</password>"));
        assert!(redacted.contains("<username>alice</username>"));
        assert!(!redacted.contains("Sup3rSecret!"));
    }

    #[test]
    fn non_login_body_is_not_touched() {
        // 反误报护栏: 非登录 body (无敏感键) 落库内容不变
        let body = "subject=会议纪要&content=下周例会改到周三下午三点&priority=high";
        let redacted = redact_request_body(body, Some("application/x-www-form-urlencoded"));
        assert_eq!(redacted, body);

        let plain = "这是一封正常业务邮件的正文内容，不含任何凭据字段。";
        assert_eq!(redact_request_body(plain, Some("text/plain")), plain);
    }

    #[test]
    fn redacts_generic_content_type_json_body() {
        // Content-Type 缺失/通用但内容是 JSON 时同样脱敏 (与 API 读取层一致)
        let redacted = redact_request_body(
            r#"{"pwd":"Sup3rSecret!"}"#,
            Some("application/octet-stream"),
        );
        assert!(!redacted.contains("Sup3rSecret!"));
        assert!(redacted.contains("[REDACTED]"));
    }
}
