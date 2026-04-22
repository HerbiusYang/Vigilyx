//! HTTP Request/ResponseParsehandler

//! From TCP Streamreassemble ofdataMediumExtract HTTP RequestInfo,
//! Used fordataSecuritydetect(Risk, FileMedium, self-send).

//! Use `httparse` line HeaderParse,Avoid Allocate.

use vigilyx_core::HttpMethod;

/// Parse body of large GetLength (64 KB)
const MAX_BODY_CAPTURE: usize = 64 * 1024;

/// Parse of HTTP Request
pub struct ParsedHttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    #[allow(dead_code)] // TestMediumVerify
    pub host: Option<String>,
    #[allow(dead_code)] // TestMediumVerify
    pub content_type: Option<String>,
    #[allow(dead_code)] // Parse,TestMediumVerify, Response Use
    pub content_length: Option<usize>,
    #[allow(dead_code)] // TestMediumVerify,ProtocolParser Command Use Segment
    pub cookie: Option<String>,
    /// Request (Break/Judge MAX_BODY_CAPTURE)
    #[allow(dead_code)]
    // TestMediumVerify,Streamreassemblemode body FromStreamMedium Connect
    pub body: Option<Vec<u8>>,
    #[allow(dead_code)] // Parse,TestMediumVerify, body split Use
    pub header_size: usize,
}

/// Parse of HTTP Response (Used for HTTP SessionResponsematch)
#[allow(dead_code)] // already TestMediumVerify, ResponseStatusCode/Digitdetect Use
pub struct ParsedHttpResponse {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub header_size: usize,
}

/// From ByteParse HTTP Request
pub fn parse_http_request(data: &[u8]) -> Option<ParsedHttpRequest> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let header_size = match req.parse(data) {
        Ok(httparse::Status::Complete(size)) => size,
        _ => return None,
    };

    let method = match req.method? {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "OPTIONS" => HttpMethod::Options,
        "HEAD" => HttpMethod::Head,
        _ => HttpMethod::Other,
    };

    let uri = req.path?.to_string();

    let mut host = None;
    let mut content_type = None;
    let mut content_length = None;
    let mut cookie = None;

    for header in req.headers.iter() {
        if header.name.eq_ignore_ascii_case("host") {
            host = std::str::from_utf8(header.value)
                .ok()
                .map(|s| s.to_string());
        } else if header.name.eq_ignore_ascii_case("content-type") {
            content_type = std::str::from_utf8(header.value)
                .ok()
                .map(|s| s.to_string());
        } else if header.name.eq_ignore_ascii_case("content-length") {
            content_length = std::str::from_utf8(header.value)
                .ok()
                .and_then(|s| s.trim().parse().ok());
        } else if header.name.eq_ignore_ascii_case("cookie") {
            cookie = std::str::from_utf8(header.value)
                .ok()
                .map(|s| s.to_string());
        }
    }

    let body = if header_size < data.len() {
        let body_data = &data[header_size..];
        let cap = body_data.len().min(MAX_BODY_CAPTURE);
        Some(body_data[..cap].to_vec())
    } else {
        None
    };

    Some(ParsedHttpRequest {
        method,
        uri,
        host,
        content_type,
        content_length,
        cookie,
        body,
        header_size,
    })
}

/// From ByteParse HTTP ResponseStatusline (Used for HTTP SessionResponsematch)
#[allow(dead_code)] // already TestMediumVerify, ResponseStatusCode/Digitdetect Use
pub fn parse_http_response(data: &[u8]) -> Option<ParsedHttpResponse> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);

    let header_size = match resp.parse(data) {
        Ok(httparse::Status::Complete(size)) => size,
        _ => return None,
    };

    let status_code = resp.code?;
    let mut content_type = None;

    for header in resp.headers.iter() {
        if header.name.eq_ignore_ascii_case("content-type") {
            content_type = std::str::from_utf8(header.value)
                .ok()
                .map(|s| s.to_string());
        }
    }

    Some(ParsedHttpResponse {
        status_code,
        content_type,
        header_size,
    })
}

/// From multipart/form-data body ExtractUploadFileNameAndsize
pub fn extract_multipart_file_info(content_type: &str, body: &[u8]) -> Option<(String, usize)> {
    let boundary = content_type
        .split("boundary=")
        .nth(1)?
        .split(';')
        .next()?
        .trim()
        .trim_matches('"');

    let boundary_marker = format!("--{}", boundary);

    // Byte filename,Avoid body UTF-8 Verify
    let body_str = String::from_utf8_lossy(body);

    for part in body_str.split(&boundary_marker) {
        if let Some(filename_start) = part.find("filename=\"") {
            let after = &part[filename_start + 10..];
            if let Some(end) = after.find('"') {
                let filename = after[..end].to_string();
                if !filename.is_empty() {
                    let file_size = part
                        .find("\r\n\r\n")
                        .map(|pos| part.len().saturating_sub(pos + 4))
                        .unwrap_or(0);
                    return Some((filename, file_size));
                }
            }
        }
    }
    None
}

/// From URL-encoded form body JSON body MediumExtractSender/recipient Segment
pub fn extract_email_fields(body: &[u8]) -> (Option<String>, Vec<String>) {
    let cap = body.len().min(8192);
    let body_str = match std::str::from_utf8(&body[..cap]) {
        Ok(s) => s,
        Err(_) => return (None, vec![]),
    };

    // JSON Parse
    if body_str.trim_start().starts_with('{') {
        return extract_email_fields_json(body_str);
    }

    // URL-encoded form
    extract_email_fields_form(body_str)
}

/// From URL-encoded form MediumExtract from/to
fn extract_email_fields_form(body_str: &str) -> (Option<String>, Vec<String>) {
    let mut from = None;
    let mut to = Vec::new();

    for pair in body_str.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = match parts.next() {
            Some(k) => k.to_lowercase(),
            None => continue,
        };
        let value = parts.next().unwrap_or("");
        let decoded = urldecode(value);

        match key.as_str() {
            "from" | "sender" | "mail_from" | "mailfrom" | "account" | "returnaddr" => {
                from = Some(decoded)
            }
            "to" | "rcpt" | "recipient" | "recipients" | "rcptto" | "toaddrs" | "rcptaddr" => {
                for addr in decoded.split(',') {
                    let trimmed = addr.trim().to_string();
                    if !trimmed.is_empty() {
                        to.push(trimmed);
                    }
                }
            }
            _ => {}
        }
    }

    (from, to)
}

/// Fromwith NameofemailAddressMediumExtract email
///
/// - `"\"Zhang San\" <zhangsan@corp.com>"` -> `"zhangsan@corp.com"`
/// - `"<user@domain.com>"` -> `"user@domain.com"`
/// - `"user@domain.com"` -> `"user@domain.com"`
fn extract_bare_email(s: &str) -> String {
    if let Some(start) = s.rfind('<')
        && let Some(end) = s.rfind('>')
        && start < end
    {
        return s[start + 1..end].trim().to_string();
    }
    s.trim().trim_matches('"').trim().to_string()
}

/// From JSON body MediumExtract from/to
///
/// JSON structure:
/// -: `{"from":"...", "to":[...]}`
/// - Coremail: `{"attrs":{"account":"...", "to":[...]}, "action":"deliver"}`
fn extract_email_fields_json(body_str: &str) -> (Option<String>, Vec<String>) {
    let value: serde_json::Value = match serde_json::from_str(body_str) {
        Ok(v) => v,
        Err(_) => return (None, vec![]),
    };

    // Coremail email Segment "attrs" Object; System
    let lookup = value.get("attrs").unwrap_or(&value);

    let from = lookup
        .get("from")
        .or_else(|| lookup.get("sender"))
        .or_else(|| lookup.get("mail_from"))
        .or_else(|| lookup.get("account"))
        .or_else(|| lookup.get("returnAddr"))
        .and_then(|v| v.as_str())
        .map(extract_bare_email);

    let mut to = Vec::new();
    let to_field = lookup
        .get("to")
        .or_else(|| lookup.get("recipients"))
        .or_else(|| lookup.get("rcpt"))
        .or_else(|| lookup.get("toAddrs"))
        .or_else(|| lookup.get("rcptAddr"));

    if let Some(val) = to_field {
        if let Some(s) = val.as_str() {
            for addr in s.split(',') {
                let bare = extract_bare_email(addr);
                if !bare.is_empty() {
                    to.push(bare);
                }
            }
        } else if let Some(arr) = val.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    let bare = extract_bare_email(s);
                    if !bare.is_empty() {
                        to.push(bare);
                    }
                }
            }
        }
    }

    (from, to)
}

/// of URL Decode (percent-decode)
fn urldecode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push(hi << 4 | lo);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_post_request() {
        let data = b"POST /coremail/main/compose/save HTTP/1.1\r\n\
            Host: mail.example.com\r\n\
            Content-Type: application/x-www-form-urlencoded\r\n\
            Content-Length: 23\r\n\
            Cookie: sid=abc123\r\n\
            \r\n\
            subject=test&body=hello";

        let req = parse_http_request(data).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.uri, "/coremail/main/compose/save");
        assert_eq!(req.host.as_deref(), Some("mail.example.com"));
        assert_eq!(
            req.content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(req.content_length, Some(23));
        assert_eq!(req.cookie.as_deref(), Some("sid=abc123"));
        assert!(req.body.is_some());
        assert_eq!(
            req.body.as_deref(),
            Some(b"subject=test&body=hello".as_slice())
        );
    }

    #[test]
    fn test_parse_http_get_request() {
        let data = b"GET /inbox?page=1 HTTP/1.1\r\nHost: mail.example.com\r\n\r\n";
        let req = parse_http_request(data).unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/inbox?page=1");
        assert!(req.body.is_none());
    }

    #[test]
    fn test_parse_malformed_data_returns_none() {
        let data = b"this is not http at all";
        assert!(parse_http_request(data).is_none());
    }

    #[test]
    fn test_parse_http_response_200() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>";
        let resp = parse_http_response(data).unwrap();
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn test_parse_http_response_302() {
        let data = b"HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n";
        let resp = parse_http_response(data).unwrap();
        assert_eq!(resp.status_code, 302);
    }

    #[test]
    fn test_parse_http_response_malformed_returns_none() {
        let data = b"not a response";
        assert!(parse_http_response(data).is_none());
    }

    #[test]
    fn test_extract_multipart_filename() {
        let ct = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let body = b"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
            Content-Disposition: form-data; name=\"file\"; filename=\"secret_report.docx\"\r\n\
            Content-Type: application/vnd.openxmlformats\r\n\
            \r\n\
            file content here\r\n\
            ------WebKitFormBoundary7MA4YWxkTrZu0gW--";
        let (name, size) = extract_multipart_file_info(ct, body).unwrap();
        assert_eq!(name, "secret_report.docx");
        assert!(size > 0);
    }

    #[test]
    fn test_extract_multipart_no_file_returns_none() {
        let ct = "multipart/form-data; boundary=abc";
        let body =
            b"--abc\r\nContent-Disposition: form-data; name=\"text\"\r\n\r\nvalue\r\n--abc--";
        assert!(extract_multipart_file_info(ct, body).is_none());
    }

    #[test]
    fn test_extract_email_fields_from_form() {
        let body =
            b"from=alice%40example.com&to=bob%40example.com%2Ccharlie%40example.com&subject=test";
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("alice@example.com"));
        assert_eq!(to.len(), 2);
        assert_eq!(to[0], "bob@example.com");
        assert_eq!(to[1], "charlie@example.com");
    }

    #[test]
    fn test_extract_email_fields_from_json() {
        let body = br#"{"from":"alice@example.com","to":["alice@example.com","bob@example.com"],"subject":"test"}"#;
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("alice@example.com"));
        assert_eq!(to.len(), 2);
    }

    #[test]
    fn test_extract_email_fields_empty_body() {
        let body = b"";
        let (from, to) = extract_email_fields(body);
        assert!(from.is_none());
        assert!(to.is_empty());
    }

    #[test]
    fn test_urldecode_basic() {
        assert_eq!(urldecode("hello%20world"), "hello world");
        assert_eq!(urldecode("a%40b.com"), "a@b.com");
        assert_eq!(urldecode("hello+world"), "hello world");
    }

    #[test]
    fn test_extract_email_fields_coremail_json() {
        // Coremail uses account/toAddrs in some API formats
        let body = br#"{"account":"alice@corp.com","toAddrs":"bob@corp.com","subject":"test"}"#;
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("alice@corp.com"));
        assert_eq!(to.len(), 1);
        assert_eq!(to[0], "bob@corp.com");
    }

    #[test]
    fn test_extract_email_fields_coremail_form() {
        // Coremail URL-encoded form with account/toaddrs
        let body = b"account=alice%40corp.com&toaddrs=bob%40corp.com&subject=test";
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("alice@corp.com"));
        assert_eq!(to.len(), 1);
    }

    #[test]
    fn test_extract_email_fields_coremail_nested_attrs() {
        // Coremail: email Segment attrs Object,AddressContains Name
        let body = r#"{"attrs":{"account":"\"Zhang San\" <zhangsan@corp.com>","to":["\"Zhang San\" <zhangsan@corp.com>"],"subject":"test"},"action":"deliver"}"#;
        let (from, to) = extract_email_fields(body.as_bytes());
        assert_eq!(from.as_deref(), Some("zhangsan@corp.com"));
        assert_eq!(to.len(), 1);
        assert_eq!(to[0], "zhangsan@corp.com");
    }

    #[test]
    fn test_extract_email_fields_coremail_empty_to() {
        // SaveScenario: to possibly Array
        let body =
            br#"{"attrs":{"account":"user@corp.com","to":[],"subject":"draft"},"action":"save"}"#;
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("user@corp.com"));
        assert!(to.is_empty());
    }

    #[test]
    fn test_extract_email_fields_coremail_multiple_recipients() {
        // recipientScenario
        let body = br#"{"attrs":{"account":"sender@corp.com","to":["\"Alice\" <alice@corp.com>","bob@corp.com","<carol@corp.com>"]}}"#;
        let (from, to) = extract_email_fields(body);
        assert_eq!(from.as_deref(), Some("sender@corp.com"));
        assert_eq!(to.len(), 3);
        assert_eq!(to[0], "alice@corp.com");
        assert_eq!(to[1], "bob@corp.com");
        assert_eq!(to[2], "carol@corp.com");
    }

    #[test]
    fn test_extract_bare_email_display_name_formats() {
        // "\"Display Name\" <email>"
        assert_eq!(
            extract_bare_email("\"Zhang San\" <zhangsan@corp.com>"),
            "zhangsan@corp.com"
        );
        // Number
        assert_eq!(extract_bare_email("<user@domain.com>"), "user@domain.com");
        // email
        assert_eq!(extract_bare_email("user@domain.com"), "user@domain.com");
        // with
        assert_eq!(extract_bare_email("  user@domain.com  "), "user@domain.com");
        // Name
        assert_eq!(
            extract_bare_email("\"John Doe\" <john@example.com>"),
            "john@example.com"
        );
    }
}
