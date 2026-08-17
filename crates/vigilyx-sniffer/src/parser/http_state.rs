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
//! chunked Reject --(malformed framing)--> Desynced (permanent; session layer
//!                 must surface an inspection-limited signal)
//! ```
//!
//! This parser uses `Content-Length` to delimit request bodies and reassembles
//! `Transfer-Encoding: chunked` bodies (TE takes precedence over CL per
//! RFC 9112). Connection-close-delimited bodies are not assembled.
//! Bare-LF chunk line endings are tolerated (browser parity).

use tracing::{debug, trace, warn};
use vigilyx_core::HttpMethod;

/// Soft threshold used by tests for the in-memory body retention strategy.
#[allow(dead_code)]
const MAX_BODY_IN_MEMORY: usize = 256 * 1024;

/// Hard upper bound for a single HTTP request body.
const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

/// Maximum number of bytes scanned while searching for the header terminator.
const MAX_HEADER_SCAN: usize = 64 * 1024;

/// Maximum bytes scanned while looking for the end of a chunked trailer part.
const MAX_TRAILER_SCAN: usize = 8 * 1024;

/// Maximum length of a single chunk-size line before the stream is treated as
/// malformed rather than incomplete. RFC 9112 places no limit on chunk
/// extensions (";name=value" after the hex size), so this must be generous —
/// 64 bytes used to reject legal traffic with long extensions.
const MAX_CHUNK_SIZE_LINE: usize = 8 * 1024;

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
    /// Decoded body owned by the request (chunked transfer encoding). When set,
    /// `body_offset`/`body_length` do not point into the stream buffer because
    /// the decoded bytes are not contiguous there.
    pub body_owned: Option<Vec<u8>>,
}

/// Internal parsing state.
#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
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
    /// Headers are parsed; accumulating a chunked transfer-encoded body.
    WaitingChunkedBody {
        method: HttpMethod,
        uri: String,
        host: Option<String>,
        content_type: Option<String>,
        cookie: Option<String>,
        header_size: usize,
        /// Decoded body bytes accumulated so far.
        decoded: Vec<u8>,
        /// Raw chunked-encoding bytes consumed so far (from body start).
        raw_consumed: usize,
    },
    /// Chunked framing was rejected as malformed: the byte offset of the next
    /// request is unknowable, so HTTP splitting on this connection is stopped
    /// permanently instead of rescanning raw body bytes as fake requests.
    /// The session layer surfaces this as an inspection-limited signal.
    Desynced,
}

/// Outcome of an incremental chunked-body parse pass.
enum ChunkedProgress {
    /// The terminating zero-size chunk (and trailers) were consumed.
    Complete,
    /// More stream bytes are needed.
    NeedMoreData,
    /// Malformed or oversized chunked encoding; the request must be skipped.
    Reject,
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

    /// Whether the parser permanently lost framing synchronization on this
    /// connection (malformed chunked body). No further requests are split;
    /// the caller must treat the connection as an inspection coverage gap.
    pub fn is_desynced(&self) -> bool {
        matches!(self.state, HttpParseState::Desynced)
    }

    /// Reset the state machine after the underlying stream buffer was evicted
    /// (LRU reclaim under reassembly-budget pressure). Offsets tracked here
    /// are coordinates into the evicted buffer, so keeping them would leave
    /// `request_start_offset >= stream.len()` and silently blind the
    /// connection. Also drops any accumulated `WaitingChunkedBody` decoded
    /// buffer (up to MAX_BODY_SIZE) so eviction actually frees memory.
    pub fn reset(&mut self) {
        self.state = HttpParseState::WaitingHeaders;
        self.request_start_offset = 0;
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
                HttpParseState::WaitingChunkedBody { .. } => {
                    if !self.try_complete_chunked_body(stream, &mut results) {
                        break;
                    }
                }
                HttpParseState::Desynced => {
                    // Framing is unrecoverable: consume everything buffered so
                    // we never rescan rejected body bytes as new requests.
                    self.request_start_offset = stream.len();
                    break;
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
        let mut transfer_encoding: Option<String> = None;

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
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding = std::str::from_utf8(header.value)
                    .ok()
                    .map(|s| s.to_string());
            }
        }

        let body_start_abs = offset + parsed_size;

        let is_chunked = transfer_encoding
            .as_deref()
            .map(|te| {
                te.to_ascii_lowercase()
                    .split(',')
                    .any(|token| token.trim() == "chunked")
            })
            .unwrap_or(false);

        if is_chunked && content_length.is_some() {
            // RFC 9112 §6.3: Transfer-Encoding overrides Content-Length. The
            // combination is also the classic request-smuggling primitive.
            warn!(
                uri = %uri,
                "HTTP protocol anomaly: Transfer-Encoding: chunked with Content-Length; TE takes precedence"
            );
        }

        if is_chunked {
            let mut decoded = Vec::new();
            let mut raw_consumed = 0usize;
            match Self::parse_chunked_body(stream, body_start_abs, &mut raw_consumed, &mut decoded)
            {
                ChunkedProgress::Complete => {
                    let body_length = decoded.len();
                    let total = parsed_size + raw_consumed;
                    results.push(ParsedCompleteRequest {
                        method,
                        uri,
                        host,
                        content_type,
                        content_length: Some(body_length),
                        cookie,
                        body_offset: body_start_abs,
                        body_length,
                        total_length: total,
                        body_owned: Some(decoded),
                    });
                    self.request_start_offset = offset + total;
                    self.request_count += 1;
                    debug!(
                        request_count = self.request_count,
                        body_length, "HTTP State machine: Requestcomplete (chunked body)"
                    );
                    return true;
                }
                ChunkedProgress::NeedMoreData => {
                    self.state = HttpParseState::WaitingChunkedBody {
                        method,
                        uri,
                        host,
                        content_type,
                        cookie,
                        header_size: parsed_size,
                        decoded,
                        raw_consumed,
                    };
                    return false;
                }
                ChunkedProgress::Reject => {
                    warn!(
                        uri = %uri,
                        "HTTP state machine: malformed/oversized chunked body; connection desynced, HTTP splitting stopped"
                    );
                    self.enter_desynced(stream);
                    return false;
                }
            }
        }

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
                body_owned: None,
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
                    body_owned: None,
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
                body_owned: None,
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
    /// Try to finish a request while in `WaitingChunkedBody`.
    fn try_complete_chunked_body(
        &mut self,
        stream: &[u8],
        results: &mut Vec<ParsedCompleteRequest>,
    ) -> bool {
        let (method, uri, host, content_type, cookie, header_size, mut decoded, mut raw_consumed) =
            match std::mem::replace(&mut self.state, HttpParseState::WaitingHeaders) {
                HttpParseState::WaitingChunkedBody {
                    method,
                    uri,
                    host,
                    content_type,
                    cookie,
                    header_size,
                    decoded,
                    raw_consumed,
                } => (
                    method,
                    uri,
                    host,
                    content_type,
                    cookie,
                    header_size,
                    decoded,
                    raw_consumed,
                ),
                other => {
                    self.state = other;
                    return false;
                }
            };

        let offset = self.request_start_offset;
        let body_start_abs = offset + header_size;

        match Self::parse_chunked_body(stream, body_start_abs, &mut raw_consumed, &mut decoded) {
            ChunkedProgress::Complete => {
                let body_length = decoded.len();
                let total = header_size + raw_consumed;
                results.push(ParsedCompleteRequest {
                    method,
                    uri,
                    host,
                    content_type,
                    content_length: Some(body_length),
                    cookie,
                    body_offset: body_start_abs,
                    body_length,
                    total_length: total,
                    body_owned: Some(decoded),
                });
                self.request_start_offset = offset + total;
                self.request_count += 1;
                self.state = HttpParseState::WaitingHeaders;
                debug!(
                    request_count = self.request_count,
                    body_length, "HTTP State machine: chunked body Receivecomplete"
                );
                true
            }
            ChunkedProgress::NeedMoreData => {
                self.state = HttpParseState::WaitingChunkedBody {
                    method,
                    uri,
                    host,
                    content_type,
                    cookie,
                    header_size,
                    decoded,
                    raw_consumed,
                };
                false
            }
            ChunkedProgress::Reject => {
                warn!(
                    uri = %uri,
                    "HTTP state machine: malformed/oversized chunked body; connection desynced, HTTP splitting stopped"
                );
                self.enter_desynced(stream);
                false
            }
        }
    }

    /// Transition to `Desynced`: framing is unrecoverable for this connection.
    /// Consume the entire current buffer so rejected body bytes are never
    /// rescanned as candidate request headers.
    fn enter_desynced(&mut self, stream: &[u8]) {
        self.request_start_offset = stream.len();
        self.state = HttpParseState::Desynced;
    }

    /// Incrementally decode a chunked transfer-encoded body.
    ///
    /// `raw_consumed` tracks how many chunked-encoding bytes (size lines, chunk
    /// data, CRLF delimiters, trailers) have been consumed from `body_start_abs`;
    /// `decoded` accumulates the plain body bytes. Both are updated in place so
    /// the caller can resume across packet boundaries.
    ///
    /// Tolerates bare-LF line endings (RFC 9112 mandates CRLF, but real-world
    /// senders and middleboxes emit LF-only chunks; browsers accept them).
    fn parse_chunked_body(
        stream: &[u8],
        body_start_abs: usize,
        raw_consumed: &mut usize,
        decoded: &mut Vec<u8>,
    ) -> ChunkedProgress {
        loop {
            let pos = body_start_abs.saturating_add(*raw_consumed);
            if pos >= stream.len() {
                return ChunkedProgress::NeedMoreData;
            }

            // Chunk-size line: hex number with optional chunk extensions (";..."),
            // terminated by CRLF or a bare LF.
            let Some(line) = Self::read_chunk_line(stream, pos) else {
                if stream.len() - pos > MAX_CHUNK_SIZE_LINE {
                    return ChunkedProgress::Reject;
                }
                return ChunkedProgress::NeedMoreData;
            };
            let size_token = line
                .content
                .split(|&b| b == b';')
                .next()
                .unwrap_or(line.content);
            let size = match std::str::from_utf8(size_token)
                .ok()
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
            {
                Some(size) if size <= MAX_BODY_SIZE => size,
                _ => return ChunkedProgress::Reject,
            };
            let line_len = line.total_len;

            if size == 0 {
                // Trailer section: empty (immediate line end) or header-like
                // lines terminated by an empty line.
                let trailer_start = pos + line_len;
                let Some(available) = stream.len().checked_sub(trailer_start) else {
                    return ChunkedProgress::NeedMoreData;
                };
                if available < 1 {
                    return ChunkedProgress::NeedMoreData;
                }
                if let Some(eol) = Self::line_ending_len(&stream[trailer_start..]) {
                    *raw_consumed += line_len + eol;
                    return ChunkedProgress::Complete;
                }
                return match Self::find_trailer_end(&stream[trailer_start..]) {
                    Some(trailer_len) => {
                        *raw_consumed += line_len + trailer_len;
                        ChunkedProgress::Complete
                    }
                    None => {
                        if available > MAX_TRAILER_SCAN {
                            ChunkedProgress::Reject
                        } else {
                            ChunkedProgress::NeedMoreData
                        }
                    }
                };
            }

            let Some(data_start) = pos.checked_add(line_len) else {
                return ChunkedProgress::Reject;
            };
            let Some(data_end) = data_start.checked_add(size) else {
                return ChunkedProgress::Reject;
            };
            if stream.len() < data_end + 1 {
                // Chunk data (or at least its terminator) has not arrived yet.
                return ChunkedProgress::NeedMoreData;
            }
            // Chunk data is followed by CRLF (or a tolerated bare LF). A lone
            // CR at the buffer edge may be the first half of a split CRLF.
            let Some(term_len) = Self::line_ending_len(&stream[data_end..]) else {
                if stream.get(data_end) == Some(&b'\r') && stream.len() == data_end + 1 {
                    return ChunkedProgress::NeedMoreData;
                }
                return ChunkedProgress::Reject;
            };
            if decoded.len().saturating_add(size) > MAX_BODY_SIZE {
                return ChunkedProgress::Reject;
            }
            decoded.extend_from_slice(&stream[data_start..data_end]);
            *raw_consumed += line_len + size + term_len;
        }
    }

    /// Length of the line ending at the start of `data`: 2 for CRLF, 1 for a
    /// tolerated bare LF, `None` otherwise.
    fn line_ending_len(data: &[u8]) -> Option<usize> {
        if data.starts_with(b"\r\n") {
            Some(2)
        } else if data.first() == Some(&b'\n') {
            Some(1)
        } else {
            None
        }
    }

    /// Read one chunk-size line starting at `pos`, accepting CRLF or bare LF.
    /// Returns `None` when no line ending is present yet (caller decides
    /// between NeedMoreData and Reject via MAX_CHUNK_SIZE_LINE).
    fn read_chunk_line(stream: &[u8], pos: usize) -> Option<ChunkLine<'_>> {
        let rel_lf = memchr::memchr(b'\n', stream.get(pos..)?)?;
        if rel_lf + 1 > MAX_CHUNK_SIZE_LINE {
            // Line ending exists but is too far out: report an empty-content
            // line so the size parse fails and the stream is rejected.
            return Some(ChunkLine {
                content: b"",
                total_len: rel_lf + 1,
            });
        }
        let mut content = stream.get(pos..pos + rel_lf)?;
        if content.ends_with(b"\r") {
            content = content.get(..content.len() - 1)?;
        }
        Some(ChunkLine {
            content,
            total_len: rel_lf + 1,
        })
    }

    /// Find the end of a trailer section (empty line), accepting CRLF/CRLF and
    /// bare LF/LF. Returns the total trailer byte length including the
    /// terminating line ending.
    fn find_trailer_end(data: &[u8]) -> Option<usize> {
        let crlf = memchr::memmem::find(data, HEADER_END).map(|p| p + HEADER_END.len());
        let lf = memchr::memmem::find(data, b"\n\n").map(|p| p + 2);
        match (crlf, lf) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (only, None) => only,
            (None, only) => only,
        }
    }
}

/// One chunk-size line read from the stream.
struct ChunkLine<'a> {
    /// Line content without the line ending (and without a trailing CR).
    content: &'a [u8],
    /// Total bytes consumed including the line ending.
    total_len: usize,
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

    /// Build a chunked-encoded HTTP request byte stream.
    fn make_chunked_request(
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        chunks: &[&[u8]],
        trailer: Option<&[u8]>,
        extra_headers: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method, uri).as_bytes());
        for (k, v) in headers {
            buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        for (k, v) in extra_headers {
            buf.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        buf.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
        for chunk in chunks {
            buf.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            buf.extend_from_slice(chunk);
            buf.extend_from_slice(b"\r\n");
        }
        buf.extend_from_slice(b"0\r\n");
        if let Some(t) = trailer {
            buf.extend_from_slice(t);
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }

    #[test]
    fn test_parse_chunked_post_body_reassembled() {
        // PoC (R4A legacy-3): a chunked POST carrying sensitive data must reach
        // analysis in full; previously cl=0 emitted an empty body immediately.
        let sensitive = b"id_card=110101199003077721&card_no=6222021234567890123&memo=salary";
        let c1 = &sensitive[..17];
        let c2 = &sensitive[17..40];
        let c3 = &sensitive[40..];
        let stream = make_chunked_request(
            "POST",
            "/api/profile/update",
            &[("Host", "webmail.corp.com"), ("Content-Type", "application/x-www-form-urlencoded")],
            &[c1, c2, c3],
            None,
            &[],
        );

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, HttpMethod::Post);
        assert_eq!(results[0].body_length, sensitive.len());
        assert_eq!(results[0].body_owned.as_deref(), Some(&sensitive[..]));
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_parse_chunked_incremental_arrival() {
        let body = b"chunked body split across tcp segments";
        let full = make_chunked_request(
            "POST",
            "/upload",
            &[("Host", "corp.com")],
            &[&body[..15], &body[15..]],
            None,
            &[],
        );

        let mut sm = HttpRequestStateMachine::new();
        // First pass: cut in the middle of the second chunk's data.
        let partial_len = full.len() - 10;
        let results = sm.process_stream(&full[..partial_len]);
        assert!(results.is_empty(), "incomplete chunked body must wait");

        let results = sm.process_stream(&full);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_owned.as_deref(), Some(&body[..]));
        assert_eq!(sm.consumed_offset(), full.len());
    }

    #[test]
    fn test_parse_chunked_with_trailer_then_keep_alive_request() {
        let body = b"hello trailer world";
        let mut stream = make_chunked_request(
            "POST",
            "/upload",
            &[("Host", "corp.com")],
            &[body],
            Some(b"X-Checksum: abc123\r\n"),
            &[],
        );
        let next = make_request("GET", "/inbox", &[("Host", "corp.com")], None);
        stream.extend_from_slice(&next);

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].body_owned.as_deref(), Some(&body[..]));
        assert_eq!(results[1].method, HttpMethod::Get);
        assert_eq!(results[1].uri, "/inbox");
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_chunked_te_takes_precedence_over_content_length() {
        // RFC 9112: when both are present, chunked framing wins. The CL value
        // here disagrees with the real chunked body on purpose.
        let body = b"actual chunked payload";
        let stream = make_chunked_request(
            "POST",
            "/api/save",
            &[("Host", "corp.com")],
            &[body],
            None,
            &[("Content-Length", "4")],
        );

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_owned.as_deref(), Some(&body[..]));
        assert_eq!(results[0].content_length, Some(body.len()));
    }

    #[test]
    fn test_chunked_malformed_size_line_rejected() {
        let stream = b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\nZZZnothex\r\nbody\r\n0\r\n\r\n";
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(stream);
        assert!(results.is_empty(), "malformed chunk size must be rejected");
        assert!(sm.consumed_offset() > 0, "parser must not stall on the request");
    }

    #[test]
    fn test_chunked_oversized_body_rejected() {
        let stream = format!(
            "POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_BODY_SIZE + 1
        );
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(stream.as_bytes());
        assert!(results.is_empty(), "oversized chunk must be rejected");
        assert!(sm.consumed_offset() > 0);
    }

    #[test]
    fn test_chunked_empty_body_zero_chunk_only() {
        let stream = b"POST /ping HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(stream);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_length, 0);
        assert_eq!(results[0].body_owned.as_deref(), Some(&b""[..]));
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    // ── R5 A4: chunk framing tolerance + desync-on-reject ───────────────

    #[test]
    fn test_chunked_long_extension_line_accepted() {
        // RFC 9112 places no limit on chunk extensions. A size line carrying a
        // long (but bounded) extension must parse; the old 64-byte cap rejected
        // this legal traffic and dropped the whole request from DLP.
        let sensitive = b"id_card=110101199003077721";
        let ext = format!("1a;{}", "x".repeat(300));
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /api/profile HTTP/1.1\r\nHost: webmail.corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        stream.extend_from_slice(ext.as_bytes());
        stream.extend_from_slice(b"\r\n");
        stream.extend_from_slice(sensitive);
        stream.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert_eq!(results.len(), 1, "long chunk extension must be accepted");
        assert_eq!(results[0].body_owned.as_deref(), Some(&sensitive[..]));
        assert!(!sm.is_desynced());
    }

    #[test]
    fn test_chunked_size_line_over_8k_rejected_and_desynced() {
        let ext = format!("1a;{}", "x".repeat(9 * 1024));
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        stream.extend_from_slice(ext.as_bytes());
        stream.extend_from_slice(b"\r\nAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n");

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert!(results.is_empty());
        assert!(sm.is_desynced(), "oversized size line must desync");
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_chunked_bare_lf_line_endings_accepted() {
        // Browsers tolerate LF-only chunk framing; the parser must too,
        // otherwise an LF-only sender blinds DLP for the whole body.
        let sensitive = b"card_no=6222021234567890123";
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /api/save HTTP/1.1\r\nHost: webmail.corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        stream.extend_from_slice(format!("{:x}\n", sensitive.len()).as_bytes());
        stream.extend_from_slice(sensitive);
        stream.extend_from_slice(b"\n0\n\n");

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert_eq!(results.len(), 1, "bare-LF chunked body must parse");
        assert_eq!(results[0].body_owned.as_deref(), Some(&sensitive[..]));
        assert_eq!(sm.consumed_offset(), stream.len());
    }

    #[test]
    fn test_chunked_bare_lf_with_trailer_accepted() {
        let body = b"payload-with-trailer";
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        stream.extend_from_slice(format!("{:x}\n", body.len()).as_bytes());
        stream.extend_from_slice(body);
        stream.extend_from_slice(b"\n0\nX-Checksum: abc\n\n");

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_owned.as_deref(), Some(&body[..]));
    }

    #[test]
    fn test_chunked_reject_desyncs_connection_no_random_rescan() {
        // A4: after a malformed chunked body the parser must NOT keep scanning
        // the raw body bytes as new request headers — that both loses the real
        // content and can manufacture fake requests out of attacker bytes.
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        // Garbage chunk size, followed by bytes that look like a valid request.
        stream.extend_from_slice(b"ZZZnothex\r\n");
        stream.extend_from_slice(
            b"GET /inbox HTTP/1.1\r\nHost: corp.com\r\n\r\n",
        );

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert!(
            results.is_empty(),
            "bytes after a rejected chunked body must not be reparsed as requests"
        );
        assert!(sm.is_desynced());

        // Later keep-alive traffic on the same connection is also not split.
        let more = make_request("GET", "/later", &[("Host", "corp.com")], None);
        let mut grown = stream.clone();
        grown.extend_from_slice(&more);
        let results = sm.process_stream(&grown);
        assert!(results.is_empty(), "desync is permanent for the connection");
        assert_eq!(sm.consumed_offset(), grown.len());
    }

    #[test]
    fn test_reset_after_buffer_eviction_recovers_parsing() {
        // A2: LRU eviction clears the reassembly buffer and the session layer
        // resets processed offsets to 0; the state machine must be reset too,
        // otherwise request_start_offset points past the new buffer end and
        // the connection stays blind forever.
        let req1 = make_request("POST", "/save", &[("Host", "corp.com")], Some(b"alpha-body"));
        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&req1);
        assert_eq!(results.len(), 1);
        assert_eq!(sm.consumed_offset(), req1.len());

        sm.reset();
        assert_eq!(sm.consumed_offset(), 0);

        // Post-eviction stream restarts from fresh bytes (new buffer begins
        // at offset 0).
        let req2 = make_request("POST", "/save", &[("Host", "corp.com")], Some(b"beta-body"));
        let results = sm.process_stream(&req2);
        assert_eq!(results.len(), 1, "parser must recover after eviction reset");
        assert_eq!(results[0].body_length, b"beta-body".len());
        assert_eq!(sm.consumed_offset(), req2.len());
    }

    #[test]
    fn test_reset_releases_waiting_chunked_decoded_buffer() {
        // A2: eviction must also free the in-flight decoded buffer (up to
        // MAX_BODY_SIZE) held by WaitingChunkedBody.
        let mut stream = Vec::new();
        stream.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        // One complete 1KB chunk, then an incomplete chunk: the parser holds
        // the decoded bytes while waiting for more data.
        let chunk = vec![b'A'; 1024];
        stream.extend_from_slice(b"400\r\n");
        stream.extend_from_slice(&chunk);
        stream.extend_from_slice(b"\r\n100\r\npartial");

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&stream);
        assert!(results.is_empty(), "incomplete chunked body must wait");

        sm.reset();
        assert_eq!(sm.consumed_offset(), 0);
        assert!(!sm.is_desynced());

        // A fresh, unrelated request parses cleanly after the reset.
        let req = make_request("GET", "/inbox", &[("Host", "corp.com")], None);
        let results = sm.process_stream(&req);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].uri, "/inbox");
    }

    #[test]
    fn test_chunked_split_cr_before_lf_waits_for_more_data() {
        // A chunk-data terminator split across packets (CR at buffer end, LF
        // in the next packet) must wait instead of rejecting.
        let body = b"split-terminator";
        let mut part1 = Vec::new();
        part1.extend_from_slice(
            b"POST /upload HTTP/1.1\r\nHost: corp.com\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        part1.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        part1.extend_from_slice(body);
        part1.extend_from_slice(b"\r"); // half of the trailing CRLF

        let mut sm = HttpRequestStateMachine::new();
        let results = sm.process_stream(&part1);
        assert!(results.is_empty(), "split terminator must wait");

        let mut full = part1.clone();
        full.extend_from_slice(b"\n0\r\n\r\n");
        let results = sm.process_stream(&full);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].body_owned.as_deref(), Some(&body[..]));
    }
}
