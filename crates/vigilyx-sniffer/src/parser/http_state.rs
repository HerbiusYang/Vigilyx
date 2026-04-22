//! HTTP request stream parser state machine.
//!
//! Consumes the contiguous byte stream reassembled by `TcpHalfStream` and
//! extracts complete HTTP requests, including keep-alive traffic on the same
//! TCP connection.
//!
//! State transitions:
//! ```text
//! WaitingHeaders --(header terminator found)--> parse headers
//! WaitingBody    --(enough bytes for Content-Length)--> emit request
//! emit request   --(advance offset)--> WaitingHeaders
//! ```
//!
//! This parser currently uses `Content-Length` to delimit request bodies. It
//! does not assemble chunked transfer encoding or connection-close-delimited
//! bodies.

use tracing::{debug, trace};
use vigilyx_core::HttpMethod;

/// Soft threshold used by tests for the in-memory body retention strategy.
#[allow(dead_code)]
const MAX_BODY_IN_MEMORY: usize = 256 * 1024;

/// Hard upper bound for a single HTTP request body.
const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

/// Maximum number of bytes scanned while searching for the header terminator.
const MAX_HEADER_SCAN: usize = 64 * 1024;

/// HTTP header terminator sequence.
const HEADER_END: &[u8] = b"\r\n\r\n";

/// One fully parsed HTTP request split out of the TCP stream.
#[derive(Debug)]
pub struct ParsedCompleteRequest {
    /// Parsed HTTP method.
    pub method: HttpMethod,
    /// Request URI/path.
    pub uri: String,
    /// `Host` header value.
    pub host: Option<String>,
    /// `Content-Type` header value.
    pub content_type: Option<String>,
    #[allow(dead_code)] // Used by tests and future body-handling strategies.
    pub content_length: Option<usize>,
    /// Raw `Cookie` header, if present.
    pub cookie: Option<String>,
    /// Offset of the body within the original stream buffer.
    pub body_offset: usize,
    /// Body length in bytes.
    pub body_length: usize,
    /// Total request length including headers and body.
    #[allow(dead_code)] // Used by tests and offset validation.
    pub total_length: usize,
}

/// Internal parsing state.
#[derive(Debug)]
enum HttpParseState {
    /// Waiting for a complete request line and headers.
    WaitingHeaders,
    /// Headers are parsed; waiting for the remaining body bytes.
    WaitingBody {
        method: HttpMethod,
        uri: String,
        host: Option<String>,
        content_type: Option<String>,
        content_length: usize,
        cookie: Option<String>,
        header_size: usize,
    },
}

/// HTTP request stream parser state machine.
///
/// Processes the contiguous byte stream returned by `TcpHalfStream::get_data()`
/// and splits it into complete HTTP requests.
///
/// Usage:
/// ```ignore
/// let stream = session_data.client_stream.get_data();
/// let requests = session_data.http_state.process_stream(stream);
/// for req in requests {
///     // `req.body_offset` and `req.body_length` point into the original stream buffer.
///     let body = &stream[req.body_offset..req.body_offset + req.body_length];
/// }
/// ```
pub struct HttpRequestStateMachine {
    state: HttpParseState,
    /// Offset of the first request within the client stream.
    request_start_offset: usize,
    /// Number of parsed requests, used for logging and diagnostics.
    request_count: u32,
}

impl HttpRequestStateMachine {
    pub fn new() -> Self {
        Self {
            state: HttpParseState::WaitingHeaders,
            request_start_offset: 0,
            request_count: 0,
        }
    }

    /// Return the number of bytes already consumed from the stream buffer.
    #[allow(dead_code)] // Used by tests and external synchronization logic.
    pub fn consumed_offset(&self) -> usize {
        self.request_start_offset
    }

    /// Parse newly available bytes and return any completed requests.
    ///
    /// `stream` is the fully reassembled buffer returned by
    /// `TcpHalfStream::get_data()`. Returned `body_offset` values always point
    /// into that same buffer.
    pub fn process_stream(&mut self, stream: &[u8]) -> Vec<ParsedCompleteRequest> {
        let mut results = Vec::new();

        loop {
            match self.state {
                HttpParseState::WaitingHeaders => {
                    if !self.try_parse_headers(stream, &mut results) {
                        break;
                    }
                    // A parsed header may immediately yield a full request or move to `WaitingBody`.
                }
                HttpParseState::WaitingBody { .. } => {
                    if !self.try_complete_body(stream, &mut results) {
                        break;
                    }
                    // Once the body completes we can continue parsing keep-alive requests.
                }
            }
        }

        results
    }

    /// Try to parse a request while in `WaitingHeaders`.
    ///
    /// Returns `true` when the caller should continue looping, and `false` when
    /// more stream data is required.
    fn try_parse_headers(
        &mut self,
        stream: &[u8],
        results: &mut Vec<ParsedCompleteRequest>,
    ) -> bool {
        let offset = self.request_start_offset;

        // Nothing remains to parse from the current buffer snapshot.
        if offset >= stream.len() {
            return false;
        }

        let remaining = &stream[offset..];

        // Cap scanning so pathological headers cannot force unbounded work.
        let scan_len = remaining.len().min(MAX_HEADER_SCAN);
        let scan_data = &remaining[..scan_len];

        // Look for the end of the HTTP header block.
        let header_end_pos = match memchr::memmem::find(scan_data, HEADER_END) {
            Some(pos) => pos + HEADER_END.len(),
            None => {
                // Drop the buffered data if it still does not terminate within the scan limit.
                if scan_len >= MAX_HEADER_SCAN {
                    debug!(
                        offset,
                        "HTTP State machine: header 超 {} Byte未End，hops该Connection",
                        MAX_HEADER_SCAN
                    );
                    // Advance to the end of the current buffer snapshot and resynchronize.
                    self.request_start_offset = stream.len();
                }
                return false;
            }
        };

        let header_data = &remaining[..header_end_pos];

        // Use `httparse` for lightweight header parsing without allocations.
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let parsed_size = match req.parse(header_data) {
            Ok(httparse::Status::Complete(size)) => size,
            Ok(httparse::Status::Partial) => return false, // Defensive fallback.
            Err(_) => {
                // Skip malformed data and continue scanning after the header boundary.
                trace!(offset, "HTTP State machine: httparse ParseFailed，hops");
                self.request_start_offset = offset + header_end_pos;
                return true;
            }
        };

        let method = match req.method {
            Some("GET") => HttpMethod::Get,
            Some("POST") => HttpMethod::Post,
            Some("PUT") => HttpMethod::Put,
            Some("DELETE") => HttpMethod::Delete,
            Some("PATCH") => HttpMethod::Patch,
            Some("OPTIONS") => HttpMethod::Options,
            Some("HEAD") => HttpMethod::Head,
            _ => HttpMethod::Other,
        };

        let uri = req.path.unwrap_or("/").to_string();

        let mut host = None;
        let mut content_type = None;
        let mut content_length: Option<usize> = None;
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

        let body_start_abs = offset + parsed_size;
        let cl = content_length.unwrap_or(0);

        // Refuse oversized bodies before waiting for more data.
        if cl > MAX_BODY_SIZE {
            debug!(
                content_length = cl,
                "HTTP State machine: body 超 {} MB limit，hops",
                MAX_BODY_SIZE / 1024 / 1024
            );
            self.request_start_offset = offset + parsed_size;
            self.state = HttpParseState::WaitingHeaders;
            return true;
        }

        if cl == 0 {
            // Requests with no body can be emitted immediately.
            let total = parsed_size;
            results.push(ParsedCompleteRequest {
                method,
                uri,
                host,
                content_type,
                content_length,
                cookie,
                body_offset: body_start_abs,
                body_length: 0,
                total_length: total,
            });
            self.request_start_offset = offset + total;
            self.request_count += 1;

            debug!(
                request_count = self.request_count,
                "HTTP State machine: Requestcomplete (无 body)"
            );
            // Stay in `WaitingHeaders` so the next request on a keep-alive stream can parse.
            true
        } else {
            // If the body is already buffered, emit now; otherwise transition to `WaitingBody`.
            let available_body = stream.len().saturating_sub(body_start_abs);
            if available_body >= cl {
                // The full body is already present in the current buffer snapshot.
                let total = parsed_size + cl;
                results.push(ParsedCompleteRequest {
                    method,
                    uri,
                    host,
                    content_type,
                    content_length,
                    cookie,
                    body_offset: body_start_abs,
                    body_length: cl,
                    total_length: total,
                });
                self.request_start_offset = offset + total;
                self.request_count += 1;
                self.state = HttpParseState::WaitingHeaders;

                debug!(
                    request_count = self.request_count,
                    body_length = cl,
                    "HTTP State machine: Requestcomplete (Contains body)"
                );
                true
            } else {
                // Headers are complete but the body has not arrived in full yet.
                self.state = HttpParseState::WaitingBody {
                    method,
                    uri,
                    host,
                    content_type,
                    content_length: cl,
                    cookie,
                    header_size: parsed_size,
                };
                false
            }
        }
    }

    /// Try to finish a request while in `WaitingBody`.
    ///
    /// Returns `true` when progress was made and the parse loop may continue.
    fn try_complete_body(
        &mut self,
        stream: &[u8],
        results: &mut Vec<ParsedCompleteRequest>,
    ) -> bool {
        // Copy the stored header metadata out of the state machine.
        let (method, uri, host, content_type, cl, cookie, header_size) = match &self.state {
            HttpParseState::WaitingBody {
                method,
                uri,
                host,
                content_type,
                content_length,
                cookie,
                header_size,
            } => (
                *method,
                uri.clone(),
                host.clone(),
                content_type.clone(),
                *content_length,
                cookie.clone(),
                *header_size,
            ),
            _ => return false,
        };

        let offset = self.request_start_offset;
        let body_start_abs = offset + header_size;
        let available_body = stream.len().saturating_sub(body_start_abs);

        if available_body >= cl {
            let total = header_size + cl;
            results.push(ParsedCompleteRequest {
                method,
                uri,
                host,
                content_type,
                content_length: Some(cl),
                cookie,
                body_offset: body_start_abs,
                body_length: cl,
                total_length: total,
            });
            self.request_start_offset = offset + total;
            self.request_count += 1;
            self.state = HttpParseState::WaitingHeaders;

            debug!(
                request_count = self.request_count,
                body_length = cl,
                "HTTP State machine: body Receivecomplete"
            );
            true
        } else {
            trace!(
                available = available_body,
                expected = cl,
                "HTTP State machine: body waitWaitMedium"
            );
            false
        }
    }
}

impl Default for HttpRequestStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic HTTP request byte stream for parser tests.
    fn make_request(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, uri).as_bytes());
        for (k, v) in headers {
            buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        if let Some(b) = body {
            buf.extend_from_slice(format!("Content-Length: {}\r\n", b.len()).as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        if let Some(b) = body {
            buf.extend_from_slice(b);
        }
        buf
    }

    #[test]
    fn test_parse_single_get_request() {
        let stream = make_request("GET", "/inbox", &[("Host", "mail.example.com")], None);
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Get);
        assert_eq!(results[0].uri, "/inbox");
        assert_eq!(results[0].host.as_deref(), Some("mail.example.com"));
        assert_eq!(results[0].body_length, 0);
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_parse_single_post_request_with_body() {
        let body = b"from=alice%40corp.com&to=bob%40corp.com";
        let stream = make_request(
            "POST",
            "/compose/send",
            &[
                ("Host", "mail.example.com"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            Some(body),
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert_eq!(results[0].uri, "/compose/send");
        assert_eq!(results[0].content_length, Some(body.len()));
        assert_eq!(results[0].body_length, body.len());

        // Verify that body offsets point back into the original stream buffer.
        let extracted =
            &stream[results[0].body_offset..results[0].body_offset + results[0].body_length];
        assert_eq!(extracted, body);
    }

    #[test]
    fn test_parse_keep_alive_multiple_requests() {
        // Two requests share the same TCP stream in a keep-alive scenario.
        let req1 = make_request("GET", "/page1", &[("Host", "mail.corp.com")], None);
        let body2 = b"{\"action\":\"deliver\"}";
        let req2 = make_request(
            "POST",
            "/compose",
            &[
                ("Host", "mail.corp.com"),
                ("Content-Type", "application/json"),
            ],
            Some(body2),
        );

        let mut stream = Vec::new();
        stream.extend_from_slice(&req1);
        stream.extend_from_slice(&req2);

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].method, HttpMethod::Get);
        assert_eq!(results[0].uri, "/page1");
        assert_eq!(results[1].method, HttpMethod::Post);
        assert_eq!(results[1].uri, "/compose");
        assert_eq!(results[1].body_length, body2.len());
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_parse_incremental_body_arrival() {
        // Deliver the body in two chunks to exercise the `WaitingBody` state.
        let body = b"this is the body content here";
        let full = make_request("POST", "/upload", &[("Host", "mail.corp.com")], Some(body));

        let mut sm = HttpRequestStateMachine::new();

        // First pass: the request is still missing the last 10 body bytes.
        let partial_len = full.len() - 10;
        let partial = &full[..partial_len];
        let results = sm.process_stream(partial);
        assert!(
            results.is_empty(),
            "Incomplete body should not produce a request"
        );

        // Second pass: the full body is now present.
        let results = sm.process_stream(&full);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert_eq!(results[0].body_length, body.len());
    }

    #[test]
    fn test_parse_empty_stream() {
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_non_http_data_skipped() {
        let mut sm = HttpRequestStateMachine::new();
        let garbage = b"this is not HTTP at all\r\n\r\n";
        let results = sm.process_stream(garbage);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_request_with_cookie() {
        let stream = make_request(
            "POST",
            "/api/save",
            &[
                ("Host", "mail.corp.com"),
                ("Cookie", "sid=abc123; token=xyz"),
            ],
            Some(b"data"),
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].cookie.as_deref(), Some("sid=abc123; token=xyz"));
    }

    #[test]
    fn test_parse_large_body_within_limit() {
        // A 256 KB body is large but still accepted by the parser.
        let body = vec![b'A'; MAX_BODY_IN_MEMORY];
        let stream = make_request("POST", "/upload", &[("Host", "corp.com")], Some(&body));

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_length, MAX_BODY_IN_MEMORY);
    }

    #[test]
    fn test_parse_body_exceeding_max_size_skipped() {
        // Requests above the hard limit are skipped.
        let header = b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nContent-Length: 52428801\r\n\r\n";
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(header);
        assert!(results.is_empty());
        // The parser advances past the rejected request header.
        assert!(sm.consumed_offset() > 0);
    }

    #[test]
    fn test_parse_put_request() {
        let body = b"file content here";
        let stream = make_request(
            "PUT",
            "/upload/file.txt",
            &[("Host", "corp.com")],
            Some(body),
        );

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Put);
        assert_eq!(results[0].uri, "/upload/file.txt");
    }

    #[test]
    fn test_parse_request_content_type_preserved() {
        let stream = make_request(
            "POST",
            "/api/compose",
            &[
                ("Host", "mail.corp.com"),
                ("Content-Type", "multipart/form-data; boundary=abc123"),
            ],
            Some(b"body"),
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].content_type.as_deref(),
            Some("multipart/form-data; boundary=abc123")
        );
    }

    #[test]
    fn test_consumed_offset_tracks_progress() {
        let req1 = make_request("GET", "/a", &[("Host", "x.com")], None);
        let req2 = make_request("GET", "/b", &[("Host", "x.com")], None);

        let mut stream = Vec::new();
        stream.extend_from_slice(&req1);
        stream.extend_from_slice(&req2);

        let mut sm = HttpRequestStateMachine::new();

        // First call sees only the first request.
        let r = sm.process_stream(&req1);
        assert_eq!(r.len(), 1);
        assert_eq!(sm.consumed_offset(), req1.len());

        // Second call sees only the newly appended request.
        let r = sm.process_stream(&stream);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].uri, "/b");
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_parse_only_header_no_body_post_with_zero_content_length() {
        // make_request doesn't add Content-Length when body is None,
        // so manually construct the request with Content-Length: 0
        let stream = b"POST /api/ping HTTP/1.1\r\nHost: corp.com\r\nContent-Length: 0\r\n\r\n";
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert_eq!(results[0].body_length, 0);
    }

    #[test]
    fn test_parse_coremail_compose_request() {
        // Typical Coremail compose/send request carrying JSON metadata.
        let body = br#"{"attrs":{"account":"user@corp.com","to":["user@corp.com"],"subject":"test"},"action":"deliver"}"#;
        let stream = make_request(
            "POST",
            "/coremail/common/mbox/compose.jsp?sid=abc123",
            &[
                ("Host", "192.168.1.200"),
                ("Content-Type", "application/json"),
                ("Cookie", "Coremail.sid=abc123"),
            ],
            Some(body),
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert!(results[0].uri.contains("compose.jsp"));
        assert_eq!(results[0].body_length, body.len());

        let extracted =
            &stream[results[0].body_offset..results[0].body_offset + results[0].body_length];
        assert_eq!(extracted, body.as_slice());
    }

    #[test]
    fn test_parse_coremail_upload_chunk_request() {
        // Coremail chunk upload request with binary request body.
        let chunk_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        let stream = make_request(
            "POST",
            "/coremail/XT/jsp/upload.jsp?sid=abc&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=0",
            &[
                ("Host", "192.168.1.200"),
                ("Content-Type", "application/octet-stream"),
            ],
            Some(&chunk_data),
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert!(results[0].uri.contains("upload.jsp"));
        assert!(results[0].uri.contains("offset=0"));
        assert_eq!(results[0].body_length, chunk_data.len());
    }
}
