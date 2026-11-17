//! Deterministic privacy transformation for exported AI training data.
//!
//! The exporter must keep security semantics useful for model training while
//! ensuring that an exported JSONL file does not carry the original mailbox,
//! message content, indicators, credentials, or database identifiers.  This
//! module deliberately has no database access and operates only on the bounded
//! JSON payload assembled by the training handler.

use chrono::{DateTime, Duration, Utc};
use regex::{Captures, Regex};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::net::IpAddr;
use std::sync::OnceLock;
use url::Url;

pub const REDACTION_PROFILE: &str = "vigilyx.redaction.v2";

#[derive(Clone)]
pub(crate) struct RedactionKey {
    bytes: Vec<u8>,
    key_id: String,
}

impl RedactionKey {
    /// Prefer a dedicated key, while keeping existing installations upgrade
    /// compatible by deriving from the already-required JWT secret. The key
    /// itself is never put in a response, log, or dataset field.
    pub(crate) fn from_env() -> Self {
        let raw = env::var("VIGILYX_TRAINING_REDACTION_KEY")
            .or_else(|_| env::var("API_JWT_SECRET"))
            .unwrap_or_else(|_| "vigilyx-training-redaction-development-key".to_string());
        Self::new(raw.as_bytes())
    }

    #[cfg(test)]
    fn new_for_test(raw: &str) -> Self {
        Self::new(raw.as_bytes())
    }

    fn new(raw: &[u8]) -> Self {
        let bytes = if raw.is_empty() {
            b"vigilyx-training-redaction-development-key".to_vec()
        } else {
            raw.to_vec()
        };
        let key_id_digest = hmac_sha256(&bytes, b"vigilyx/redaction/key-id/v1");
        Self {
            bytes,
            key_id: format!("rk_{}", hex_prefix(&key_id_digest, 12)),
        }
    }
}

#[derive(Default)]
pub(crate) struct RedactionCounts {
    values: BTreeMap<String, u64>,
}

impl RedactionCounts {
    fn record(&mut self, category: &str) {
        *self.values.entry(category.to_string()).or_default() += 1;
    }

    fn into_json(self) -> Value {
        serde_json::to_value(self.values).unwrap_or_else(|_| json!({}))
    }
}

pub(crate) struct Redactor {
    key: RedactionKey,
    counts: RedactionCounts,
}

impl Redactor {
    pub(crate) fn new(key: RedactionKey) -> Self {
        Self {
            key,
            counts: RedactionCounts::default(),
        }
    }

    /// Redact all data-bearing fields while preserving the label and feature
    /// metadata used by the training pipeline.
    pub(crate) fn redact_payload(mut self, mut payload: Value) -> Value {
        if let Some(object) = payload.as_object_mut() {
            if is_already_redacted(object) {
                return payload;
            }
            self.redact_identifier(object, "id");
            self.redact_identifier(object, "session_id");
            self.redact_identifier(object, "verdict_id");
            self.redact_text_field(object, "subject");
            self.redact_text_field(object, "body_text");
            self.redact_html_field(object, "body_html");
            self.redact_text_field(object, "text");
            self.redact_address_field(object, "mail_from");
            self.redact_recipient_field(object, "rcpt_to");
            self.redact_text_field(object, "analyst_comment");
            self.redact_timestamp_field(object, "created_at");
            self.redact_unknown_fields(object);

            object.insert(
                "redaction".to_string(),
                json!({
                    "enabled": true,
                    "profile": REDACTION_PROFILE,
                    "key_id": self.key.key_id.clone(),
                    "counts": self.counts.into_json(),
                }),
            );
        }
        payload
    }
}

pub(crate) fn mark_raw_payload(mut payload: Value) -> Value {
    if let Some(object) = payload.as_object_mut() {
        object.insert(
            "redaction".to_string(),
            json!({
                "enabled": false,
                "profile": Value::Null,
            }),
        );
    }
    payload
}

impl Redactor {
    fn redact_identifier(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(raw) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let replacement = if is_redaction_placeholder(&raw) {
            raw
        } else {
            self.token("identifier", &raw, "id")
        };
        if let Some(value) = object.get_mut(field) {
            *value = Value::String(replacement);
        }
    }

    fn redact_text_field(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(raw) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let redacted = self.redact_text(&raw);
        let replacement = limit_field(field, redacted, object);
        if let Some(value) = object.get_mut(field) {
            *value = Value::String(replacement);
        }
    }

    fn redact_html_field(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(raw) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let redacted = self.redact_html(&raw);
        let replacement = limit_field(field, redacted, object);
        if let Some(value) = object.get_mut(field) {
            *value = Value::String(replacement);
        }
    }

    fn redact_address_field(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(raw) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let redacted = self.redact_address(&raw);
        let replacement = limit_field(field, redacted, object);
        if let Some(value) = object.get_mut(field) {
            *value = Value::String(replacement);
        }
    }

    fn redact_recipient_field(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(recipients) = object.get(field).and_then(Value::as_array).cloned() else {
            return;
        };
        let replacements = recipients
            .iter()
            .map(|recipient| match recipient {
                Value::String(raw) => Value::String(self.redact_address(raw)),
                other => other.clone(),
            })
            .collect();
        if let Some(value) = object.get_mut(field) {
            *value = Value::Array(replacements);
        }
    }

    fn redact_timestamp_field(&mut self, object: &mut Map<String, Value>, field: &str) {
        let Some(raw) = object.get(field).and_then(Value::as_str).map(str::to_owned) else {
            return;
        };
        let replacement = if let Ok(timestamp) = DateTime::parse_from_rfc3339(&raw) {
            self.counts.record("timestamp");
            (timestamp.with_timezone(&Utc) + self.timestamp_shift()).to_rfc3339()
        } else {
            self.token("timestamp", &raw, "time")
        };
        if let Some(value) = object.get_mut(field) {
            *value = Value::String(replacement);
        }
    }

    fn redact_unknown_fields(&mut self, object: &mut Map<String, Value>) {
        let fields = object.keys().cloned().collect::<Vec<_>>();
        for field in fields {
            if is_known_training_field(&field) || field == "redaction" {
                continue;
            }
            if let Some(value) = object.get_mut(&field) {
                self.redact_unknown_value(value);
            }
        }
    }

    fn redact_unknown_value(&mut self, value: &mut Value) {
        match value {
            Value::String(raw) => {
                let replacement = self.redact_text(raw);
                let (replacement, _) = truncate_chars(&replacement, MAX_UNKNOWN_FIELD_CHARS);
                *raw = replacement;
            }
            Value::Array(values) => {
                for value in values {
                    self.redact_unknown_value(value);
                }
            }
            Value::Object(fields) => {
                for (field, value) in fields {
                    if !is_safe_metadata_field(field) {
                        self.redact_unknown_value(value);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn timestamp_shift(&self) -> Duration {
        let digest = hmac_sha256(&self.key.bytes, b"vigilyx/redaction/timestamp-shift/v1");
        let days = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 731;
        Duration::days(i64::from(days) - 365)
    }

    fn redact_address(&mut self, raw: &str) -> String {
        let trimmed = raw.trim();
        let Some(email_match) = email_regex().find(trimmed) else {
            return self.token("address", trimmed, "address");
        };
        let pseudo = self.redact_email(email_match.as_str());
        if trimmed.starts_with('<') || trimmed.contains('<') {
            return format!("Recipient <{pseudo}>");
        }
        pseudo
    }

    fn redact_email(&mut self, raw: &str) -> String {
        let Some((local, domain)) = raw.rsplit_once('@') else {
            return self.token("email", raw, "mail");
        };
        if local.starts_with("user_")
            && domain.starts_with("domain_")
            && domain.ends_with(".invalid")
        {
            return raw.to_string();
        }
        let local_token = self.token("email_local", local, "user");
        let domain_token = self.token("email_domain", domain, "domain");
        format!("{local_token}@{domain_token}.invalid")
    }

    fn redact_html(&mut self, raw: &str) -> String {
        self.redact_text(raw)
    }

    fn redact_text(&mut self, raw: &str) -> String {
        let data_uris = replace_captures(data_uri_regex(), raw, |_| {
            self.counts.record("data_uri");
            "[DATA_URI_REDACTED]".to_string()
        });
        let private_keys = replace_captures(private_key_regex(), &data_uris, |caps| {
            self.token(
                "private_key",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "key",
            )
        });
        let jwt_tokens = replace_captures(jwt_regex(), &private_keys, |caps| {
            let raw = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            if is_redaction_placeholder(raw) {
                raw.to_string()
            } else {
                self.token("jwt", raw, "token")
            }
        });
        let compact_secrets = replace_captures(compact_secret_regex(), &jwt_tokens, |caps| {
            let raw = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            if is_redaction_placeholder(raw) {
                raw.to_string()
            } else {
                self.token("secret", raw, "token")
            }
        });
        let urls = replace_captures(url_regex(), &compact_secrets, |caps| {
            self.redact_url_literal(caps.get(0).map(|m| m.as_str()).unwrap_or_default())
        });
        let auth_tokens = replace_captures(auth_token_regex(), &urls, |caps| {
            let raw = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
            if is_redaction_placeholder(raw) {
                caps.get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                let scheme = caps.get(1).map(|m| m.as_str()).unwrap_or("Bearer");
                let whitespace = caps.get(2).map(|m| m.as_str()).unwrap_or(" ");
                format!("{scheme}{whitespace}{}", self.token("secret", raw, "token"))
            }
        });
        let secrets = replace_captures(secret_regex(), &auth_tokens, |caps| {
            let key = caps.get(2).map(|m| m.as_str()).unwrap_or("secret");
            let value = caps.get(6).map(|m| m.as_str()).unwrap_or_default();
            if (key.eq_ignore_ascii_case("authorization")
                && matches!(value.to_ascii_lowercase().as_str(), "bearer" | "basic"))
                || is_redaction_placeholder(value)
            {
                caps.get(0)
                    .map(|m| m.as_str())
                    .unwrap_or_default()
                    .to_string()
            } else {
                let key_prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
                let key_suffix = caps.get(3).map(|m| m.as_str()).unwrap_or_default();
                let separator = caps.get(4).map(|m| m.as_str()).unwrap_or("=");
                let value_prefix = caps.get(5).map(|m| m.as_str()).unwrap_or_default();
                format!(
                    "{key_prefix}{key}{key_suffix}{separator}{value_prefix}{}",
                    self.token("secret", value, "token")
                )
            }
        });
        let header_addresses = replace_captures(header_address_regex(), &secrets, |caps| {
            let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let address = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
            format!("{prefix}<{}>", self.redact_email(address))
        });
        let national_ids = replace_captures(national_id_regex(), &header_addresses, |caps| {
            self.token(
                "national_id",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "id",
            )
        });
        let ibans = replace_captures(iban_regex(), &national_ids, |caps| {
            self.token(
                "iban",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "account",
            )
        });
        let financial_ids = replace_captures(financial_id_regex(), &ibans, |caps| {
            self.token(
                "financial_id",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "account",
            )
        });
        let macs = replace_captures(mac_regex(), &financial_ids, |caps| {
            self.token(
                "mac",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "mac",
            )
        });
        let emails = replace_captures(email_regex(), &macs, |caps| {
            self.redact_email(caps.get(0).map(|m| m.as_str()).unwrap_or_default())
        });
        let uuids = replace_captures(uuid_regex(), &emails, |caps| {
            self.token(
                "identifier",
                caps.get(0).map(|m| m.as_str()).unwrap_or_default(),
                "id",
            )
        });
        let ips = replace_captures(ip_regex(), &uuids, |caps| {
            let raw_ip = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            if raw_ip.starts_with("ip_") {
                raw_ip.to_string()
            } else {
                format!("{}.invalid", self.token("ip", raw_ip, "ip"))
            }
        });
        let phones = replace_captures(phone_regex(), &ips, |caps| {
            let value = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            if value
                .chars()
                .filter(|character| character.is_ascii_digit())
                .count()
                < 7
            {
                value.to_string()
            } else {
                self.token("phone", value, "phone")
            }
        });
        replace_captures(domain_regex(), &phones, |caps| {
            let domain = caps.get(0).map(|m| m.as_str()).unwrap_or_default();
            if is_redaction_placeholder(domain) || domain.to_ascii_lowercase().ends_with(".invalid")
            {
                domain.to_string()
            } else {
                format!("{}.invalid", self.token("domain", domain, "domain"))
            }
        })
    }

    fn redact_url_literal(&mut self, raw: &str) -> String {
        let (url_part, suffix) = trim_url_suffix(raw);
        let Ok(parsed) = Url::parse(url_part) else {
            return format!("{}{}", self.token("url", url_part, "url"), suffix);
        };
        let Some(host) = parsed.host_str() else {
            return format!("{}{}", self.token("url", url_part, "url"), suffix);
        };
        let host_token = if host.parse::<IpAddr>().is_ok() {
            format!("{}.invalid", self.token("ip", host, "ip"))
        } else if is_synthetic_host(host) {
            host.to_string()
        } else {
            format!("{}.invalid", self.token("domain", host, "domain"))
        };
        let mut output = format!("{}://{}", parsed.scheme(), host_token);
        if let Some(port) = parsed.port() {
            output.push(':');
            output.push_str(&port.to_string());
        }
        let path = parsed.path();
        if !path.is_empty() && path != "/" {
            output.push('/');
            let mut first = true;
            for segment in path.trim_start_matches('/').split('/') {
                if !first {
                    output.push('/');
                }
                first = false;
                if is_security_path_keyword(segment) {
                    output.push_str(&segment.to_ascii_lowercase());
                } else if segment.is_empty() {
                    continue;
                } else {
                    output.push_str(&self.token("url_path", segment, "seg"));
                }
            }
        }
        if let Some(query) = parsed.query() {
            output.push('?');
            for (index, pair) in query.split('&').enumerate() {
                if index > 0 {
                    output.push('&');
                }
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let clean_key = if is_safe_query_key(key) {
                    key.to_ascii_lowercase()
                } else {
                    self.token("url_query_key", key, "param")
                };
                output.push_str(&clean_key);
                if pair.contains('=') {
                    output.push('=');
                    let category = if is_secret_key(key) {
                        "secret"
                    } else {
                        "url_query_value"
                    };
                    output.push_str(&self.token(category, value, "token"));
                }
            }
        }
        if parsed.fragment().is_some() {
            output.push('#');
            output.push_str(&self.token(
                "url_fragment",
                parsed.fragment().unwrap_or_default(),
                "frag",
            ));
        }
        output.push_str(suffix);
        output
    }

    fn token(&mut self, category: &str, raw: &str, prefix: &str) -> String {
        self.counts.record(category);
        let mut message = Vec::with_capacity(category.len() + raw.len() + 32);
        message.extend_from_slice(b"vigilyx/redaction/v2/");
        message.extend_from_slice(category.as_bytes());
        message.push(0);
        message.extend_from_slice(raw.as_bytes());
        let digest = hmac_sha256(&self.key.bytes, &message);
        format!("{prefix}_{}", hex_prefix(&digest, 16))
    }
}

const MAX_UNKNOWN_FIELD_CHARS: usize = 20_000;

fn is_already_redacted(object: &Map<String, Value>) -> bool {
    object
        .get("redaction")
        .and_then(Value::as_object)
        .and_then(|redaction| redaction.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true)
        && object
            .get("redaction")
            .and_then(Value::as_object)
            .and_then(|redaction| redaction.get("profile"))
            .and_then(Value::as_str)
            == Some(REDACTION_PROFILE)
}

fn is_redaction_placeholder(value: &str) -> bool {
    let (prefix, digest) = value.split_once('_').unwrap_or(("", ""));
    matches!(
        prefix,
        "account"
            | "address"
            | "domain"
            | "frag"
            | "host"
            | "id"
            | "ip"
            | "key"
            | "mail"
            | "param"
            | "phone"
            | "seg"
            | "time"
            | "token"
            | "url"
            | "user"
    ) && digest.len() == 16
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_synthetic_host(value: &str) -> bool {
    value
        .strip_suffix(".invalid")
        .is_some_and(is_redaction_placeholder)
}

fn is_known_training_field(field: &str) -> bool {
    matches!(
        field,
        "schema_version"
            | "id"
            | "session_id"
            | "label"
            | "label_name"
            | "label_source"
            | "source_threat_type"
            | "text"
            | "text_source"
            | "text_truncated"
            | "subject"
            | "body_text"
            | "body_html"
            | "mail_from"
            | "rcpt_to"
            | "analyst_comment"
            | "original_threat_level"
            | "verdict_id"
            | "created_at"
    )
}

fn is_safe_metadata_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "type"
            | "kind"
            | "format"
            | "mime_type"
            | "content_type"
            | "encoding"
            | "language"
            | "version"
            | "status"
            | "severity"
            | "category"
            | "score"
            | "confidence"
            | "enabled"
            | "count"
            | "size"
            | "index"
            | "offset"
            | "length"
    )
}

fn field_limit(field: &str) -> Option<usize> {
    match field {
        "subject" => Some(500),
        "body_text" | "body_html" => Some(20_000),
        "text" => Some(3_000),
        "mail_from" => Some(320),
        "analyst_comment" => Some(2_000),
        _ => None,
    }
}

fn limit_field(field: &str, value: String, object: &mut Map<String, Value>) -> String {
    let Some(limit) = field_limit(field) else {
        return value;
    };
    let (limited, truncated) = truncate_chars(&value, limit);
    if truncated && field == "text" {
        object.insert("text_truncated".to_string(), Value::Bool(true));
    }
    limited
}

fn truncate_chars(value: &str, limit: usize) -> (String, bool) {
    let mut characters = value.chars();
    let truncated = characters.nth(limit).is_some();
    if !truncated {
        return (value.to_string(), false);
    }
    (value.chars().take(limit).collect(), true)
}

fn replace_captures<F>(regex: &Regex, input: &str, mut replacement: F) -> String
where
    F: FnMut(&Captures<'_>) -> String,
{
    let mut output = String::with_capacity(input.len());
    let mut last = 0;
    for captures in regex.captures_iter(input) {
        let Some(full) = captures.get(0) else {
            continue;
        };
        output.push_str(&input[last..full.start()]);
        output.push_str(&replacement(&captures));
        last = full.end();
    }
    output.push_str(&input[last..]);
    output
}

fn trim_url_suffix(raw: &str) -> (&str, &str) {
    let split_at = raw
        .trim_end_matches(|character: char| ",.;:!?)]}".contains(character))
        .len();
    raw.split_at(split_at)
}

fn is_security_path_keyword(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "account"
            | "auth"
            | "authorize"
            | "login"
            | "oauth"
            | "password"
            | "reset"
            | "secure"
            | "signin"
            | "sso"
            | "verify"
            | "verification"
            | "wallet"
    )
}

fn is_safe_query_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn is_secret_key(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "authorization"
            | "code"
            | "cookie"
            | "key"
            | "otp"
            | "password"
            | "passwd"
            | "secret"
            | "token"
            | "verification_code"
    ) || value.to_ascii_lowercase().contains("token")
        || value.to_ascii_lowercase().contains("secret")
        || value.to_ascii_lowercase().contains("password")
}

fn hex_prefix(bytes: &[u8; 32], characters: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(characters);
    for byte in bytes.iter().copied() {
        if output.len() >= characters {
            break;
        }
        output.push(HEX[(byte >> 4) as usize] as char);
        if output.len() < characters {
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    output
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut normalized_key = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        normalized_key[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; BLOCK_SIZE];
    let mut outer_pad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    result
}

fn data_uri_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?is)\bdata:[^<>"'\s)]+"#).expect("valid data URI regex"))
}

fn url_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"']+"#).expect("valid URL regex"))
}

fn secret_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)(["']?)\b(password|passwd|passcode|token|secret|api[_-]?key|access[_-]?key|access[_-]?token|client[_-]?secret|cookie|authorization|otp|private[_-]?key|refresh[_-]?token|verification[_-]?code)\b(["']?)(\s*[:=]\s*["']?)(["']?)([^\s&<>"',};]+)"#)
            .expect("valid secret regex")
    })
}

fn auth_token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer|basic)(\s+)([A-Za-z0-9._~+/=-]+)")
            .expect("valid authorization token regex")
    })
}

fn private_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?is)-----BEGIN [^-\r\n]+-----.*?-----END [^-\r\n]+-----")
            .expect("valid private key regex")
    })
}

fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
            .expect("valid JWT regex")
    })
}

fn compact_secret_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
            .expect("valid compact secret regex")
    })
}

fn email_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?iu)[\p{L}\p{N}0-9.!#$%&'*+/=?^_`{|}~-]+@[\p{L}\p{N}0-9](?:[\p{L}\p{N}0-9-]{0,61}[\p{L}\p{N}0-9])?(?:\.[\p{L}\p{N}0-9](?:[\p{L}\p{N}0-9-]{0,61}[\p{L}\p{N}0-9])?)+")
            .expect("valid email regex")
    })
}

fn header_address_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?im)^(\s*(?:from|to|cc|bcc|reply-to|sender|return-path)\s*:\s*)[^<\r\n]*<([^>\r\n]+)>")
            .expect("valid mail header address regex")
    })
}

fn national_id_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9x]|[1-9][0-9]{5}[0-9]{6}[0-9]{3})\b")
            .expect("valid national ID regex")
    })
}

fn iban_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{2,4}[ -]?){3,8}[A-Z0-9]{1,4}\b")
            .expect("valid IBAN regex")
    })
}

fn financial_id_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"\b[0-9]{13,19}\b|\b[0-9]{4}(?:[ -]?[0-9]{4}){2,3}\b")
            .expect("valid financial identifier regex")
    })
}

fn mac_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{2}(?:(?::|-)[0-9a-f]{2}){5}\b")
            .expect("valid MAC address regex")
    })
}

fn uuid_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("valid UUID regex")
    })
}

fn ip_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f:]*[0-9a-f]\b)",
        )
        .expect("valid IP address regex")
    })
}

fn phone_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| Regex::new(r"(?x)\+?\d[\d\s().-]{5,}\d").expect("valid phone regex"))
}

fn domain_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?iu)(?:\b[\p{L}\p{N}0-9](?:[\p{L}\p{N}0-9-]{0,61}[\p{L}\p{N}0-9])?\.)+(?:[\p{L}]{2,63}|invalid)\b")
            .expect("valid domain regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn sample_payload() -> Value {
        json!({
            "schema_version": "vigilyx.email_training.v1",
            "id": "11111111-1111-4111-8111-111111111111",
            "session_id": "22222222-2222-4222-8222-222222222222",
            "label": 1,
            "label_name": "phishing",
            "label_source": "analyst_feedback",
            "source_threat_type": "phishing",
            "text": "From: Alice <alice@example.com>\nSubject: Verify account\nVisit https://evil.example/login?token=raw-secret or https://钓鱼.中国/verify. JSON {\"token\":\"raw-json-secret\"}",
            "text_source": "body_text",
            "text_truncated": false,
            "subject": "Verify alice@example.com",
            "body_text": "Call +86 138 0013 8000. Password=super-secret. Authorization: Bearer rawbearertoken. IP 10.2.3.4 and 2001:db8::1. JSON {\"token\":\"raw-json-secret\",\"password\":\"raw-json-password\"}. ID 000000194912310027, card 4111 1111 1111 1111, MAC 00:11:22:33:44:55, IBAN DE36000000000000000000, JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c, key AKIAIOSFODNN7EXAMPLE, -----BEGIN PRIVATE KEY-----RAWPRIVATE-----END PRIVATE KEY-----.",
            "body_html": "<a href=\"https://evil.example/reset?id=11111111-1111-4111-8111-111111111111\">verify</a><img src=\"data:image/png;base64,RAWIMAGE\">",
            "mail_from": "Alice <alice@example.com>",
            "rcpt_to": ["bob@example.com", "bob@example.com", "用户@例子.中国"],
            "analyst_comment": "case for alice@example.com",
            "future_field": {
                "note": "future-secret@example.com",
                "mime_type": "text/plain"
            },
            "original_threat_level": "high",
            "verdict_id": "33333333-3333-4333-8333-333333333333",
            "created_at": "2026-08-25T12:00:00+00:00"
        })
    }

    #[test]
    fn deterministic_mapping_is_stable_and_key_scoped() {
        let key = RedactionKey::new_for_test("same-key");
        let first = Redactor::new(key.clone()).redact_payload(sample_payload());
        let second = Redactor::new(key).redact_payload(sample_payload());
        assert_eq!(first, second);
        assert_ne!(first["mail_from"], "Alice <alice@example.com>");
        assert!(first["mail_from"].as_str().unwrap().contains(".invalid"));

        let other = RedactionKey::new_for_test("other-key");
        let changed = Redactor::new(other).redact_payload(sample_payload());
        assert_ne!(first["mail_from"], changed["mail_from"]);
    }

    #[test]
    fn redaction_removes_sensitive_values_but_preserves_training_semantics() {
        let payload =
            Redactor::new(RedactionKey::new_for_test("test-key")).redact_payload(sample_payload());
        let serialized = serde_json::to_string(&payload).expect("serialize");
        for secret in [
            "Alice",
            "alice@example.com",
            "bob@example.com",
            "raw-secret",
            "super-secret",
            "rawbearertoken",
            "138 0013 8000",
            "10.2.3.4",
            "2001:db8::1",
            "RAWIMAGE",
            "11111111-1111-4111-8111-111111111111",
            "raw-json-secret",
            "raw-json-password",
            "000000194912310027",
            "4111 1111 1111 1111",
            "00:11:22:33:44:55",
            "DE36000000000000000000",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "AKIAIOSFODNN7EXAMPLE",
            "RAWPRIVATE",
            "用户@例子.中国",
            "future-secret@example.com",
        ] {
            assert!(!serialized.contains(secret), "raw value leaked: {secret}");
        }
        assert_eq!(payload["label_name"], "phishing");
        assert_eq!(payload["original_threat_level"], "high");
        assert_eq!(payload["text_source"], "body_text");
        assert_eq!(payload["redaction"]["enabled"], true);
        assert_eq!(payload["redaction"]["profile"], REDACTION_PROFILE);
        assert!(payload["redaction"]["counts"].as_object().is_some());
        assert!(
            payload["body_html"]
                .as_str()
                .unwrap()
                .contains("DATA_URI_REDACTED")
        );
        assert!(
            payload["body_text"]
                .as_str()
                .unwrap()
                .contains("Authorization: Bearer token_")
        );
        assert!(
            payload["body_text"]
                .as_str()
                .unwrap()
                .contains("\"token\":\"token_")
        );
        assert!(payload["future_field"]["mime_type"] == "text/plain");
        assert!(
            payload["future_field"]["note"]
                .as_str()
                .unwrap()
                .contains("user_")
        );
    }

    #[test]
    fn redaction_is_idempotent_for_export_retries() {
        let key = RedactionKey::new_for_test("idempotence-key");
        let first = Redactor::new(key.clone()).redact_payload(sample_payload());
        let second = Redactor::new(key).redact_payload(first.clone());
        assert_eq!(first, second);
    }

    #[test]
    fn redacted_text_respects_training_bounds() {
        let raw = format!("{} alice@example.com", "x".repeat(3_000));
        let payload = json!({
            "text": raw,
            "text_truncated": false,
            "label": 1,
            "future_field": "a very long value with alice@example.com ".repeat(1_000)
        });
        let redacted =
            Redactor::new(RedactionKey::new_for_test("bounds-key")).redact_payload(payload);
        assert_eq!(redacted["text"].as_str().unwrap().chars().count(), 3_000);
        assert_eq!(redacted["text_truncated"], true);
        assert!(
            redacted["future_field"].as_str().unwrap().chars().count() <= MAX_UNKNOWN_FIELD_CHARS
        );
    }

    #[test]
    fn pseudonyms_have_low_collision_rate_at_dataset_scale() {
        let key = RedactionKey::new_for_test("collision-key");
        let mut redactor = Redactor::new(key);
        let mut values = HashSet::new();
        for index in 0..10_000 {
            values.insert(redactor.token("email_local", &format!("user-{index}"), "user"));
        }
        assert_eq!(values.len(), 10_000);
    }

    #[test]
    fn raw_payload_is_marked_without_changing_content() {
        let payload = sample_payload();
        let marked = mark_raw_payload(payload.clone());
        assert_eq!(marked["body_text"], payload["body_text"]);
        assert_eq!(marked["mail_from"], payload["mail_from"]);
        assert_eq!(marked["redaction"]["enabled"], false);
    }

    #[test]
    fn timestamp_shift_is_stable_and_keeps_ordering() {
        let key = RedactionKey::new_for_test("timestamp-key");
        let mut first = json!({ "created_at": "2026-01-01T00:00:00Z" });
        let mut second = json!({ "created_at": "2026-01-02T00:00:00Z" });
        let mut redactor = Redactor::new(key.clone());
        let mut redactor2 = Redactor::new(key);
        redactor.redact_timestamp_field(first.as_object_mut().unwrap(), "created_at");
        redactor2.redact_timestamp_field(second.as_object_mut().unwrap(), "created_at");
        let first_time =
            DateTime::parse_from_rfc3339(first["created_at"].as_str().unwrap()).unwrap();
        let second_time =
            DateTime::parse_from_rfc3339(second["created_at"].as_str().unwrap()).unwrap();
        assert!(second_time > first_time);
    }
}
