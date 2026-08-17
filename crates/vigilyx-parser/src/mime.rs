//! MIME Parsehandler (Performanceoptimized version)
//!
//! Parseemailof MIME structure,Extract:
//! - emailHeader (Subject, From, To, Date wait)
//! - Plain textbody (text/plain)
//! - HTML body (text/html)
//! - AttachmentFile
//! - emailMediumoflinkConnect
//!
//! ofEncode:
//! - Base64
//! - Quoted-Printable
//! - 7bit/8bit ()
//!
//! Performance notes:
//! - Base64 Decode: hops ConnectDecode, Medium Vec Allocate
//! - Headerlookup: Time/CountTraverseExtract Header, Time/Count O(n)
//! - to_lowercase: Use eq_ignore_ascii_case Allocate
//! - linkConnectDeduplicate: HashSet O(1) Vec O(n)
//! - multipart: Add depthlimitprevent Overflow
//! - from_utf8_lossy: from_utf8, Failed fallback

use encoding_rs::Encoding;
use memchr::memmem;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tracing::{debug, warn};
use vigilyx_core::magic_bytes::split_uuencode_frame;
use vigilyx_core::{EmailAttachment, EmailContent, EmailLink};

/// Hard upper bound for message parsing size (prevents OOM).
/// Messages above this size are rejected. Normal business mail is <10MB, and large-attachment mail is usually <50MB.
const MAX_EMAIL_SIZE: usize = 100 * 1024 * 1024; // 100 MB

/// largeHeadersize (64KB)
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// largeAttachmentCount
const MAX_ATTACHMENTS: usize = 100;

/// Full-audit mode: save ALL attachment content for scanning.
/// Every attachment must pass through AV/YARA/Sandbox/content scanning.
const MAX_ATTACHMENT_SAVE_SIZE: usize = 32 * 1024 * 1024;

/// Cumulative decoded attachment bytes retained for one message. This bounds the peak
/// created by keeping decoded bytes while hashing and producing a Base64 copy.
const MAX_TOTAL_ATTACHMENT_DECODED_BYTES: usize = 32 * 1024 * 1024;

/// Cumulative decoded body bytes (body_text + body_html) retained for one
/// message (SEC M-4, 2026-08-15 red-team scan). Bounds the heap peak created
/// by charset lossy expansion (one invalid input byte becomes a three-byte
/// U+FFFD) and by merging every MIME alternative into the retained strings.
const MAX_TOTAL_DECODED_BODY_BYTES: usize = 20 * 1024 * 1024;

/// multipart large depth
const MAX_MULTIPART_DEPTH: usize = 10;

/// levelProcessof MIME part total,prevent O(k^2)
const MAX_TOTAL_PARTS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MultipartDelimiter {
    start: usize,
    content_start: usize,
    closing: bool,
}

/// MIME Classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimePartType {
    /// Plain text
    TextPlain,
    /// HTML
    TextHtml,
    /// Attachment
    Attachment,
    /// multipart handler
    Multipart,

    Other,
}

/// ContentTransmissionEncode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransferEncoding {
    /// 7bit ASCII
    #[default]
    SevenBit,
    /// 8bit
    EightBit,
    /// Base64
    Base64,
    /// Quoted-Printable
    QuotedPrintable,
    /// Binary
    Binary,
    /// uuencode (`begin <mode> <name>` ... `end` frame)
    Uuencode,
}

/// Decoded part body plus the signals recovered during transport decoding.
struct DecodedContent {
    /// Decoded payload bytes.
    data: Vec<u8>,
    /// Filename carried by a uuencode `begin` frame, when the body held one.
    uuencode_filename: Option<String>,
    /// Text surrounding a uuencode frame (preamble + trailer), when non-blank.
    surrounding_text: Option<Vec<u8>>,
}

impl DecodedContent {
    fn plain(data: Vec<u8>) -> Self {
        Self {
            data,
            uuencode_filename: None,
            surrounding_text: None,
        }
    }
}

/// MIME
#[derive(Debug, Clone)]
pub struct MimePart {
    /// ContentType (if "text/plain; charset=utf-8")
    pub content_type: String,
    /// Parse ofType
    pub part_type: MimePartType,
    /// TransmissionEncode
    pub encoding: TransferEncoding,
    /// characters
    pub charset: Option<String>,
    /// FileName (Attachment)
    pub filename: Option<String>,
    /// Content
    pub content: Vec<u8>,
    /// (multipart)
    pub parts: Vec<MimePart>,
}

/// Time/CountTraverseExtractof HeaderIndex
struct HeaderIndex {
    content_type: Option<usize>,
    content_transfer_encoding: Option<usize>,
    content_disposition: Option<usize>,
    content_id: Option<usize>,
    ambiguous_security_header: bool,
}

impl HeaderIndex {
    /// Time/CountTraverse Index, Time/Count find() of O(n*m)
    fn build(headers: &[(String, String)]) -> Self {
        let mut idx = HeaderIndex {
            content_type: None,
            content_transfer_encoding: None,
            content_disposition: None,
            content_id: None,
            ambiguous_security_header: false,
        };
        for (i, (name, _)) in headers.iter().enumerate() {
            if name.eq_ignore_ascii_case("Content-Type") {
                // Duplicate security headers used to abort the whole parse
                // (AmbiguousSecurityHeaders), which turned two header lines
                // into the cheapest full-blindness primitive in mirror mode.
                // Degrade instead: keep the FIRST occurrence like MUAs do and
                // flag the ambiguity so it is still visible in the logs.
                if idx.content_type.is_none() {
                    idx.content_type = Some(i);
                } else {
                    idx.ambiguous_security_header = true;
                }
            } else if name.eq_ignore_ascii_case("Content-Transfer-Encoding") {
                if idx.content_transfer_encoding.is_none() {
                    idx.content_transfer_encoding = Some(i);
                } else {
                    idx.ambiguous_security_header = true;
                }
            } else if name.eq_ignore_ascii_case("Content-Disposition") {
                if idx.content_disposition.is_none() {
                    idx.content_disposition = Some(i);
                } else {
                    idx.ambiguous_security_header = true;
                }
            } else if name.eq_ignore_ascii_case("Content-ID") && idx.content_id.is_none() {
                // Content-ID is not security-classification-critical; a
                // duplicate does not create a parser differential worth
                // rejecting the message over. Keep the first occurrence.
                idx.content_id = Some(i);
            }
        }
        idx
    }

    fn content_type<'a>(&self, headers: &'a [(String, String)]) -> &'a str {
        self.content_type
            .map(|i| headers[i].1.as_str())
            .unwrap_or("text/plain")
    }

    fn encoding(&self, headers: &[(String, String)]) -> TransferEncoding {
        self.content_transfer_encoding
            .map(|i| MimeParser::parse_encoding(&headers[i].1))
            .unwrap_or_default()
    }

    fn disposition<'a>(&self, headers: &'a [(String, String)]) -> &'a str {
        self.content_disposition
            .map(|i| headers[i].1.as_str())
            .unwrap_or("")
    }

    fn content_id<'a>(&self, headers: &'a [(String, String)]) -> Option<&'a str> {
        self.content_id.map(|i| headers[i].1.as_str())
    }
}

/// MIME Parsehandler
pub struct MimeParser {
    /// linedelimited lookuphandler (\r\n\r\n)
    header_end_finder: memmem::Finder<'static>,
    /// linedelimited lookuphandler (\n\n, Used for Unix email)
    header_end_finder_lf: memmem::Finder<'static>,
}

impl MimeParser {
    pub fn new() -> Self {
        Self {
            header_end_finder: memmem::Finder::new(b"\r\n\r\n").into_owned(),
            header_end_finder_lf: memmem::Finder::new(b"\n\n").into_owned(),
        }
    }

    /// ParseCompleteemail
    pub fn parse(&self, data: &[u8]) -> Result<EmailContent, MimeError> {
        if data.len() > MAX_EMAIL_SIZE {
            return Err(MimeError::TooLarge);
        }

        let mut content = EmailContent::new();
        content.raw_size = data.len();

        // HeaderAndbody
        let (headers_bytes, body_bytes) = self.split_headers_body(data)?;

        // ParseHeader
        let headers = self.parse_headers(headers_bytes)?;
        for (name, value) in &headers {
            content.add_header(name.clone(), value.clone());
        }

        // Time/CountIndexlookup Header
        let idx = HeaderIndex::build(&headers);
        if idx.ambiguous_security_header {
            // Keep parsing with the first occurrence (see HeaderIndex::build):
            // rejecting here would drop the entire message from mirror-mode
            // scanning while MUAs still render it.
            warn!("重复安全头（Content-Type/CTE/Content-Disposition）— 降级取首个头继续解析");
        }
        let content_type = idx.content_type(&headers);
        let encoding = idx.encoding(&headers);
        let missing_top_level_content_type = idx.content_type.is_none();

        // Parsebody (Use ascii_starts_with_ci Avoid to_lowercase Allocate)
        if ascii_starts_with_ci(content_type, "multipart/") {
            let mut total_parts = 0usize;
            self.parse_multipart_inner(
                &mut content,
                content_type,
                body_bytes,
                0,
                &mut total_parts,
            )?;
        } else {
            let decoded = self.decode_content(body_bytes, encoding)?;
            let content_disposition = idx.disposition(&headers);
            let content_id = idx.content_id(&headers);
            let is_attachment =
                Self::is_attachment_part(content_type, content_disposition, content_id);

            // A valid MIME message does not need to be multipart to carry an
            // attachment. Route the top-level entity through the same
            // classification path as child parts so a single-part payload
            // cannot disappear from attachment scanning.
            self.apply_decoded_part(
                &mut content,
                content_type,
                content_disposition,
                content_id,
                is_attachment,
                decoded,
            )?;

            if missing_top_level_content_type && !is_attachment {
                self.try_salvage_embedded_multipart(&mut content, body_bytes)?;
            }
        }

        // Bare-HTML sniffing: with no top-level Content-Type the entity
        // defaults to text/plain, leaving body_html empty and html_scan
        // not_applicable — while Outlook/Apple Mail sniff and render a bare
        // `<html>` body. Mirror that for detection only.
        if content.body_html.is_none()
            && let Some(text) = &content.body_text
            && Self::looks_like_html_document(text)
        {
            content.body_html = Some(text.clone());
        }

        // ExtractlinkConnect
        content.extract_links_from_html();

        // FromPlain textMedium ExtractlinkConnect
        if let Some(ref text) = content.body_text {
            self.extract_links_from_text(text, &mut content.links);
        }

        content.is_complete = true;
        Ok(content)
    }

    fn try_salvage_embedded_multipart(
        &self,
        content: &mut EmailContent,
        body: &[u8],
    ) -> Result<(), MimeError> {
        if !Self::looks_like_embedded_multipart_body(body) {
            return Ok(());
        }

        let Some(boundary) = Self::extract_embedded_boundary(body) else {
            return Ok(());
        };

        let mut salvaged = EmailContent::new();
        let mut total_parts = 0usize;
        let synthetic_content_type = format!("multipart/mixed; boundary=\"{}\"", boundary);
        self.parse_multipart_inner(
            &mut salvaged,
            &synthetic_content_type,
            body,
            0,
            &mut total_parts,
        )?;

        let relaxed = self.salvage_embedded_parts_relaxed(body)?;
        if salvaged.body_text.is_none() {
            salvaged.body_text = relaxed.body_text;
        }
        if salvaged.body_html.is_none() {
            salvaged.body_html = relaxed.body_html;
        }
        if !relaxed.attachments.is_empty() {
            let mut seen_hashes: HashSet<String> = salvaged
                .attachments
                .iter()
                .map(|att| att.hash.clone())
                .collect();
            for attachment in relaxed.attachments {
                if seen_hashes.insert(attachment.hash.clone()) {
                    if Self::ensure_attachment_budget(&salvaged, attachment.size).is_err() {
                        // Budget merge guard: skip the surplus attachment but
                        // keep the salvaged body — never fail the message.
                        salvaged.truncated = true;
                        salvaged.dropped_attachments += 1;
                        continue;
                    }
                    salvaged.attachments.push(attachment);
                }
            }
        }

        if salvaged.body_text.is_none()
            && salvaged.body_html.is_none()
            && salvaged.attachments.is_empty()
        {
            return Ok(());
        }

        content.body_text = salvaged.body_text;
        content.body_html = salvaged.body_html;
        content.attachments = salvaged.attachments;
        content.truncated |= salvaged.truncated;
        content.dropped_attachments += salvaged.dropped_attachments;
        Ok(())
    }

    fn salvage_embedded_parts_relaxed(&self, body: &[u8]) -> Result<EmailContent, MimeError> {
        let trimmed = Self::trim_ascii_leading_newlines(body);
        let mut content = EmailContent::new();
        let mut cursor = 0usize;
        let mut total_parts = 0usize;

        while let Some(boundary_start) = Self::find_boundary_line_start(trimmed, cursor) {
            if total_parts >= MAX_TOTAL_PARTS {
                // Same degrade rule as the main multipart walker: keep the
                // parts already salvaged and flag the coverage gap.
                content.truncated = true;
                break;
            }
            total_parts += 1;
            let boundary_line_end = Self::line_end_index(trimmed, boundary_start);
            let boundary_line = Self::trim_line_ending(&trimmed[boundary_start..boundary_line_end]);

            cursor = boundary_line_end;
            if boundary_line.ends_with(b"--") {
                continue;
            }

            while cursor < trimmed.len() && matches!(trimmed[cursor], b'\r' | b'\n') {
                cursor += 1;
            }
            if cursor >= trimmed.len() {
                break;
            }

            let next_boundary =
                Self::find_boundary_line_start(trimmed, cursor).unwrap_or(trimmed.len());
            let part_bytes = &trimmed[cursor..next_boundary];
            cursor = next_boundary;

            let Ok((part_headers, part_body)) = self.split_headers_body(part_bytes) else {
                continue;
            };
            let headers = self.parse_headers(part_headers).unwrap_or_default();
            if headers.is_empty() {
                continue;
            }

            let idx = HeaderIndex::build(&headers);
            if idx.ambiguous_security_header {
                warn!("重复安全头（嵌入 part 级）— 降级取首个头继续解析");
            }
            let part_content_type = idx.content_type(&headers);
            let part_encoding = idx.encoding(&headers);
            let decoded = self.decode_content(part_body, part_encoding)?;
            let content_disposition = idx.disposition(&headers);
            let content_id = idx.content_id(&headers);
            let is_attachment =
                Self::is_attachment_part(part_content_type, content_disposition, content_id);

            self.apply_decoded_part(
                &mut content,
                part_content_type,
                content_disposition,
                content_id,
                is_attachment,
                decoded,
            )?;
        }

        Ok(content)
    }

    fn looks_like_embedded_multipart_body(body: &[u8]) -> bool {
        let trimmed = Self::trim_ascii_leading_newlines(body);
        if trimmed.len() < 32 || !trimmed.starts_with(b"--") {
            return false;
        }

        let preview_len = trimmed.len().min(2048);
        let preview = String::from_utf8_lossy(&trimmed[..preview_len]);
        let preview_lower = preview.to_ascii_lowercase();
        let marker_count = [
            "content-type:",
            "content-transfer-encoding:",
            "content-disposition:",
        ]
        .iter()
        .filter(|needle| preview_lower.contains(**needle))
        .count();

        let boundary_like = preview
            .lines()
            .next()
            .map(|line| line.trim_start().starts_with("--"))
            .unwrap_or(false);

        boundary_like && marker_count >= 2
    }

    fn extract_embedded_boundary(body: &[u8]) -> Option<String> {
        let trimmed = Self::trim_ascii_leading_newlines(body);
        let first_line = trimmed
            .split(|&b| b == b'\n')
            .next()
            .unwrap_or(trimmed)
            .strip_suffix(b"\r")
            .unwrap_or(trimmed);
        let boundary_line = std::str::from_utf8(first_line).ok()?.trim();
        let boundary = boundary_line.strip_prefix("--")?;
        let boundary = boundary.strip_suffix("--").unwrap_or(boundary).trim();
        if !Self::is_valid_boundary(boundary) {
            return None;
        }
        Some(boundary.to_string())
    }

    fn trim_ascii_leading_newlines(bytes: &[u8]) -> &[u8] {
        let start = bytes
            .iter()
            .position(|b| !matches!(b, b'\r' | b'\n'))
            .unwrap_or(bytes.len());
        &bytes[start..]
    }

    fn find_boundary_line_start(bytes: &[u8], from: usize) -> Option<usize> {
        if from >= bytes.len() {
            return None;
        }

        let mut pos = from;
        while pos < bytes.len() {
            if (pos == 0 || bytes[pos - 1] == b'\n')
                && bytes.get(pos) == Some(&b'-')
                && bytes.get(pos + 1) == Some(&b'-')
                && bytes
                    .get(pos + 2)
                    .is_some_and(|b| !matches!(b, b'\r' | b'\n'))
            {
                return Some(pos);
            }
            pos += 1;
        }
        None
    }

    fn line_end_index(bytes: &[u8], start: usize) -> usize {
        start
            + bytes[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|idx| idx + 1)
                .unwrap_or(bytes.len() - start)
    }

    fn trim_line_ending(line: &[u8]) -> &[u8] {
        line.strip_suffix(b"\n")
            .and_then(|rest| rest.strip_suffix(b"\r").or(Some(rest)))
            .unwrap_or(line)
    }

    /// HeaderAndbody (\r\n\r\n And \n\n delimited)
    fn split_headers_body<'a>(&self, data: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), MimeError> {
        // priority \r\n\r\n
        if let Some(pos) = self.header_end_finder.find(data) {
            if pos > MAX_HEADER_SIZE {
                // An oversized header block (e.g. a 70KB X-Pad, still inside
                // Postfix's 100KB header limit) used to abort the whole parse,
                // blinding mirror mode while the MUA rendered the body.
                // Degrade: truncate the header block, keep the real body.
                warn!(header_bytes = pos, "邮件Header超限 — 截断头块，保留正文继续解析");
                return Ok((&data[..MAX_HEADER_SIZE], &data[pos + 4..]));
            }
            return Ok((&data[..pos], &data[pos + 4..]));
        }
        // : \n\n (Unix, MTA Use \r)
        if let Some(pos) = self.header_end_finder_lf.find(data) {
            if pos > MAX_HEADER_SIZE {
                warn!(header_bytes = pos, "邮件Header超限 — 截断头块，保留正文继续解析");
                return Ok((&data[..MAX_HEADER_SIZE], &data[pos + 2..]));
            }
            return Ok((&data[..pos], &data[pos + 2..]));
        }
        // not find linedelimited,possiblyonly Header
        if data.len() > MAX_HEADER_SIZE {
            // No delimiter inside the budget: parse the first 64KB as headers
            // and treat the remainder as body instead of dropping it.
            warn!("未找到Header/body分隔且超过头块上限 — 截断头块，剩余字节按正文解析");
            Ok((&data[..MAX_HEADER_SIZE], &data[MAX_HEADER_SIZE..]))
        } else {
            Ok((data, &[]))
        }
    }

    /// ParseHeader (Performance notes: clone,Use std::mem::take)
    fn parse_headers(&self, data: &[u8]) -> Result<Vec<(String, String)>, MimeError> {
        let text = String::from_utf8_lossy(data);
        let mut headers = Vec::new();
        let mut current_name = String::new();
        let mut current_value = String::new();

        for line in text.lines() {
            if line.is_empty() {
                break;
            }

            // line (Header)
            if line.starts_with(' ') || line.starts_with('\t') {
                if !current_name.is_empty() {
                    current_value.push(' ');
                    current_value.push_str(line.trim());
                }
                continue;
            }

            // Save firstofHeader (take clone,)
            if !current_name.is_empty() {
                headers.push((
                    std::mem::take(&mut current_name),
                    std::mem::take(&mut current_value),
                ));
            }

            // ParseNewHeader
            if let Some(colon_pos) = line.find(':') {
                current_name = line[..colon_pos].trim().to_string();
                current_value = line[colon_pos + 1..].trim().to_string();
            }
        }

        // Savelast1Header
        if !current_name.is_empty() {
            headers.push((current_name, current_value));
        }

        Ok(headers)
    }

    /// Parse multipart email (with depthlimit + part totallimit)
    fn parse_multipart_inner(
        &self,
        content: &mut EmailContent,
        content_type: &str,
        body: &[u8],
        depth: usize,
        total_parts: &mut usize,
    ) -> Result<(), MimeError> {
        if depth >= MAX_MULTIPART_DEPTH {
            // Degrade, never bubble: a full-parse Err is mirror mode's biggest
            // amplifier (the MUA still renders the message). Keep everything
            // parsed so far and flag the coverage gap.
            warn!("multipart 递归depth超限 ({}) — 降级保留已解析内容", depth);
            content.truncated = true;
            return Ok(());
        }

        if *total_parts >= MAX_TOTAL_PARTS {
            warn!(
                "multipart 总 part 数超限 ({}) — 降级保留已解析内容",
                *total_parts
            );
            content.truncated = true;
            return Ok(());
        }

        // Extract boundary
        let boundary = Self::extract_boundary(content_type).ok_or(MimeError::NoBoundary)?;
        let marker = format!("--{boundary}");
        let finder = memmem::Finder::new(marker.as_bytes());
        let mut delimiters = finder
            .find_iter(body)
            .filter_map(|start| Self::multipart_delimiter_at(body, marker.len(), start));
        let Some(mut delimiter) = delimiters.next() else {
            return Err(MimeError::BoundaryNotFound);
        };

        loop {
            if delimiter.closing {
                return Ok(());
            }

            let Some(next_delimiter) = delimiters.next() else {
                // Many MUAs render an otherwise valid multipart message when
                // the final RFC 2046 closing delimiter is omitted. SMTP DATA
                // termination still gives us a trusted message boundary, so
                // scan the complete final part through EOF instead of dropping
                // every already-captured part. Fail closed if that final part
                // cannot itself be parsed.
                if *total_parts >= MAX_TOTAL_PARTS {
                    warn!(
                        "multipart 总 part 数超限 ({}) — 降级保留已解析内容",
                        *total_parts
                    );
                    content.truncated = true;
                    return Ok(());
                }
                *total_parts += 1;
                let final_part = body
                    .get(delimiter.content_start..)
                    .filter(|part| !part.is_empty())
                    .ok_or(MimeError::MissingClosingBoundary)?;
                if !self.parse_multipart_part(content, final_part, depth, total_parts)? {
                    return Err(MimeError::MissingClosingBoundary);
                }
                return Ok(());
            };

            // Check total parts budget before processing each part
            if *total_parts >= MAX_TOTAL_PARTS {
                warn!(
                    "multipart 总 part 数超限 ({}) — 降级保留已解析内容",
                    *total_parts
                );
                content.truncated = true;
                return Ok(());
            }
            *total_parts += 1;

            let part_start = delimiter.content_start;
            let part_end = next_delimiter.start;
            delimiter = next_delimiter;

            if part_start >= part_end {
                continue;
            }

            let part_data = &body[part_start..part_end];

            if part_data.is_empty() {
                continue;
            }

            let _ = self.parse_multipart_part(content, part_data, depth, total_parts)?;
        }
    }

    fn parse_multipart_part(
        &self,
        content: &mut EmailContent,
        part_data: &[u8],
        depth: usize,
        total_parts: &mut usize,
    ) -> Result<bool, MimeError> {
        let Ok((part_headers, part_body)) = self.split_headers_body(part_data) else {
            return Ok(false);
        };
        let headers = self.parse_headers(part_headers).unwrap_or_default();
        if headers.is_empty() && part_body.is_empty() {
            return Ok(false);
        }
        let idx = HeaderIndex::build(&headers);
        if idx.ambiguous_security_header {
            warn!("重复安全头（multipart part 级）— 降级取首个头继续解析");
        }

        let part_content_type = idx.content_type(&headers);
        let part_encoding = idx.encoding(&headers);

        if ascii_starts_with_ci(part_content_type, "multipart/") {
            match self.parse_multipart_inner(
                content,
                part_content_type,
                part_body,
                depth + 1,
                total_parts,
            ) {
                Ok(()) => return Ok(true),
                Err(MimeError::BoundaryNotFound) => {
                    // A nested multipart reusing an ancestor boundary leaves no
                    // inner delimiter inside this part: the ancestor scan
                    // already consumed every `--boundary` line. MUAs still
                    // render the inner entity, so degrade the bytes to leaf
                    // handling below instead of failing the entire message
                    // (a full-parse Err is mirror mode's biggest amplifier).
                    warn!("内层 multipart 找不到声明的 boundary（疑似复用外层 boundary）— 降级为 leaf part 宽松处理");
                }
                // Safety budgets (depth / total parts) now degrade inside
                // parse_multipart_inner itself (truncated flag + Ok); any
                // error that still reaches this arm is a structural failure
                // and stays fail-closed.
                Err(err) => return Err(err),
            }
            // multipart/* matches neither text/plain nor text/html in
            // apply_decoded_part, so the normal body-merge would discard these
            // bytes. Scan them as plain text instead; attachments still go
            // through the regular attachment path.
            let decoded = self.decode_content(part_body, part_encoding)?;
            let content_disposition = idx.disposition(&headers);
            let content_id = idx.content_id(&headers);
            let is_attachment =
                Self::is_attachment_part(part_content_type, content_disposition, content_id);
            if is_attachment {
                self.apply_decoded_part(
                    content,
                    part_content_type,
                    content_disposition,
                    content_id,
                    true,
                    decoded,
                )?;
            } else if !decoded.data.iter().all(|b| b.is_ascii_whitespace()) {
                let (text, decode_truncated) = decode_charset(
                    &decoded.data,
                    part_content_type,
                    body_budget_remaining(content),
                );
                Self::merge_body_part(
                    content,
                    BodyTarget::Text,
                    text,
                    decode_truncated,
                    "plain",
                );
            }
            return Ok(true);
        }

        let decoded = self.decode_content(part_body, part_encoding)?;
        let content_disposition = idx.disposition(&headers);
        let content_id = idx.content_id(&headers);
        let is_attachment =
            Self::is_attachment_part(part_content_type, content_disposition, content_id);

        self.apply_decoded_part(
            content,
            part_content_type,
            content_disposition,
            content_id,
            is_attachment,
            decoded,
        )?;
        Ok(true)
    }

    /// Validate one delimiter candidate without collecting every match in the message.
    fn multipart_delimiter_at(
        body: &[u8],
        marker_len: usize,
        start: usize,
    ) -> Option<MultipartDelimiter> {
        if start != 0 && body[start - 1] != b'\n' {
            return None;
        }

        let mut cursor = start.checked_add(marker_len)?;
        let closing = body.get(cursor..cursor + 2) == Some(b"--");
        if closing {
            cursor += 2;
        }

        while matches!(body.get(cursor), Some(b' ' | b'\t')) {
            cursor += 1;
        }

        let content_start = if body.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor + 2
        } else if body.get(cursor) == Some(&b'\n') {
            cursor + 1
        } else if cursor == body.len() {
            cursor
        } else {
            // Reject boundary-prefix collisions and non-whitespace suffixes.
            return None;
        };

        Some(MultipartDelimiter {
            start,
            content_start,
            closing,
        })
    }

    fn apply_decoded_part(
        &self,
        content: &mut EmailContent,
        part_content_type: &str,
        content_disposition: &str,
        content_id: Option<&str>,
        is_attachment: bool,
        decoded: DecodedContent,
    ) -> Result<(), MimeError> {
        // A uuencode `begin <mode> <name>` frame IS an attachment to every MUA
        // that still supports it; the declared part classification must not be
        // able to talk us out of registering it.
        let is_attachment = is_attachment || decoded.uuencode_filename.is_some();
        if is_attachment {
            if content.attachments.len() >= MAX_ATTACHMENTS {
                // Degrade instead of failing the whole message: keep the body
                // and the attachments already collected so detectors still
                // see them. Returning an error here turned a 101-attachment
                // message into a parse failure whose entire content vanished
                // from mirror-mode scanning. The drop is recorded so
                // downstream modules surface the coverage gap.
                content.dropped_attachments += 1;
                warn!(
                    limit = MAX_ATTACHMENTS,
                    dropped = content.dropped_attachments,
                    "AttachmentCount超限 — 停止收集新附件，保留已解析内容"
                );
                return Ok(());
            }

            let filename = Self::extract_filename(content_disposition)
                .or_else(|| Self::extract_filename(part_content_type))
                .or_else(|| decoded.uuencode_filename.clone())
                .or_else(|| {
                    content_id.map(|cid| {
                        Self::synthesize_filename_from_content_id(cid, part_content_type)
                    })
                })
                .unwrap_or_else(|| format!("attachment_{}", content.attachments.len()));

            let hash = Self::compute_hash(&decoded.data);
            let size = decoded.data.len();

            if size > MAX_ATTACHMENT_SAVE_SIZE {
                // Oversized attachment: retain metadata + hash (hash-based
                // detection still applies), skip the payload, and flag the
                // coverage gap. This previously failed the WHOLE message via
                // the cumulative budget error — one 33MB attachment must not
                // blind every other detector.
                content.truncated = true;
                warn!(
                    filename = %filename,
                    size_bytes = size,
                    limit_bytes = MAX_ATTACHMENT_SAVE_SIZE,
                    "SEC: Oversized attachment — content scanning bypassed, only hash/metadata checks apply"
                );
                content.attachments.push(EmailAttachment {
                    filename,
                    content_type: Self::extract_mime_type(part_content_type).to_string(),
                    size,
                    hash,
                    content_base64: None,
                });
                return Ok(());
            }

            if Self::ensure_attachment_budget(content, size).is_err() {
                // Cumulative decoded-byte budget exhausted: drop this
                // attachment but keep the message and everything parsed so
                // far (same degrade rule as the count budget above).
                content.dropped_attachments += 1;
                content.truncated = true;
                warn!(
                    size_bytes = size,
                    limit_bytes = MAX_TOTAL_ATTACHMENT_DECODED_BYTES,
                    "attachment decoded-byte budget exhausted — dropping attachment, continuing parse"
                );
                return Ok(());
            }

            let content_base64 = Some(Self::encode_base64(&decoded.data));

            content.attachments.push(EmailAttachment {
                filename,
                content_type: Self::extract_mime_type(part_content_type).to_string(),
                size,
                hash,
                content_base64,
            });

            if let Some(att) = content.attachments.last() {
                debug!(
                    "ExtractAttachment: {} ({} bytes, Contentalready{})",
                    att.filename,
                    size,
                    if att.content_base64.is_some() {
                        "Save"
                    } else {
                        "hops"
                    }
                );
            }

            // A uuencode frame can ride inside a text body; the prose around
            // the frame still belongs to the body scanners.
            if let Some(surrounding) = decoded.surrounding_text {
                if ascii_contains_ci(part_content_type, "text/html") {
                    let (html, decode_truncated) = decode_charset(
                        &surrounding,
                        part_content_type,
                        body_budget_remaining(content),
                    );
                    Self::merge_body_part(
                        content,
                        BodyTarget::Html,
                        html,
                        decode_truncated,
                        "html",
                    );
                } else {
                    let (text, decode_truncated) = decode_charset(
                        &surrounding,
                        part_content_type,
                        body_budget_remaining(content),
                    );
                    Self::merge_body_part(
                        content,
                        BodyTarget::Text,
                        text,
                        decode_truncated,
                        "plain",
                    );
                }
            }

            return Ok(());
        }

        if ascii_contains_ci(part_content_type, "text/plain") {
            let (text, decode_truncated) = decode_charset(
                &decoded.data,
                part_content_type,
                body_budget_remaining(content),
            );
            Self::merge_body_part(
                content,
                BodyTarget::Text,
                text,
                decode_truncated,
                "plain",
            );
        } else if ascii_contains_ci(part_content_type, "text/html") {
            let (html, decode_truncated) = decode_charset(
                &decoded.data,
                part_content_type,
                body_budget_remaining(content),
            );
            Self::merge_body_part(
                content,
                BodyTarget::Html,
                html,
                decode_truncated,
                "html",
            );
        }
        Ok(())
    }

    /// Whether a plain-text body actually starts an HTML document. Used to
    /// expose bare-HTML bodies (no declared Content-Type) to html_scan.
    fn looks_like_html_document(text: &str) -> bool {
        let trimmed = text.trim_start();
        ascii_starts_with_ci(trimmed, "<html")
            || ascii_starts_with_ci(trimmed, "<!doctype")
            || ascii_starts_with_ci(trimmed, "<body")
    }

    fn is_attachment_part(
        content_type: &str,
        content_disposition: &str,
        content_id: Option<&str>,
    ) -> bool {
        ascii_contains_ci(content_disposition, "attachment")
            || Self::extract_filename(content_disposition).is_some()
            || Self::extract_filename(content_type).is_some()
            // RFC 2046 message/rfc822 entities are rendered as encapsulated
            // messages even when Content-Disposition is omitted. Preserve the
            // raw entity so nested-message scanners cannot be bypassed by
            // removing an optional filename.
            || Self::extract_mime_type(content_type).eq_ignore_ascii_case("message/rfc822")
            // Inline non-text parts referenced only by Content-ID (typical:
            // QR-code images inside multipart/related with no filename) carry
            // the only copy of their payload bytes. Dropping them here would
            // make attach_qr_scan / YARA / ClamAV blind to the attachment.
            // text/plain and text/html keep merging into the body below.
            || (content_id.is_some() && Self::is_inline_payload_type(content_type))
    }

    /// Whether a part without filename/disposition should still be preserved
    /// as an attachment when it carries a Content-ID. Body text alternatives
    /// (text/plain, text/html) are excluded so body merging is unchanged.
    fn is_inline_payload_type(content_type: &str) -> bool {
        let mime_type = Self::extract_mime_type(content_type);
        !mime_type.eq_ignore_ascii_case("text/plain") && !mime_type.eq_ignore_ascii_case("text/html")
    }

    /// Build a stable filename for a Content-ID-only inline part. The
    /// Content-ID value is sanitized to a conservative ASCII charset and a
    /// type-derived extension is appended so extension-based routing in
    /// downstream modules keeps working.
    fn synthesize_filename_from_content_id(content_id: &str, content_type: &str) -> String {
        let mut stem: String = content_id
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .take(64)
            .collect();
        if stem.is_empty() {
            stem.push_str("inline");
        }
        let ext = match Self::extract_mime_type(content_type).to_ascii_lowercase().as_str() {
            "image/png" => ".png",
            "image/jpeg" | "image/jpg" => ".jpg",
            "image/gif" => ".gif",
            "image/bmp" => ".bmp",
            "image/webp" => ".webp",
            "image/tiff" => ".tiff",
            "application/pdf" => ".pdf",
            _ => "",
        };
        format!("cid_{stem}{ext}")
    }

    /// Merge one decoded body alternative into the retained body strings,
    /// enforcing the cumulative decoded-body budget (SEC M-4). Exceeding the
    /// budget clips at a char boundary and flags the message `truncated` so
    /// downstream coverage gaps stay visible.
    fn merge_body_part(
        content: &mut EmailContent,
        target: BodyTarget,
        decoded: String,
        decode_truncated: bool,
        media_kind: &str,
    ) {
        if decode_truncated {
            content.truncated = true;
        }
        let existing_bytes = body_bytes(&content.body_text) + body_bytes(&content.body_html);
        let remaining = MAX_TOTAL_DECODED_BODY_BYTES.saturating_sub(existing_bytes);
        let slot = match target {
            BodyTarget::Text => &mut content.body_text,
            BodyTarget::Html => &mut content.body_html,
        };
        match slot {
            None => {
                let (decoded, clipped) = truncate_char_boundary(&decoded, remaining);
                if clipped {
                    content.truncated = true;
                    warn!(
                        limit_bytes = MAX_TOTAL_DECODED_BODY_BYTES,
                        "decoded body byte budget exhausted — clipping MIME body alternative"
                    );
                }
                *slot = Some(decoded.to_owned());
            }
            Some(existing) if existing == &decoded => {}
            Some(existing) => {
                if decoded.is_empty() {
                    return;
                }
                // Scan every body alternative. Selecting only the first or last
                // creates a parser differential because mail clients may render
                // a different alternative than the detector. A visible-neutral
                // separator keeps every leaf available to the existing modules.
                // The separator itself consumes the same cumulative byte budget.
                let separator = if media_kind == "html" {
                    "\n<!-- vigilyx:mime-alternative -->\n"
                } else {
                    "\n\n--- vigilyx:mime-alternative ---\n\n"
                };
                let payload_budget = remaining.saturating_sub(separator.len());
                let (decoded, clipped) = truncate_char_boundary(&decoded, payload_budget);
                if clipped || remaining < separator.len() {
                    content.truncated = true;
                    warn!(
                        limit_bytes = MAX_TOTAL_DECODED_BODY_BYTES,
                        "decoded body byte budget exhausted — clipping MIME body alternative"
                    );
                }
                // Never consume the last bytes with a separator that carries no
                // decoded content. This keeps the retained body useful while
                // preserving the hard byte invariant.
                if decoded.is_empty() {
                    return;
                }
                existing.push_str(separator);
                existing.push_str(decoded);
            }
        }
    }

    fn ensure_attachment_budget(
        content: &EmailContent,
        additional_bytes: usize,
    ) -> Result<(), MimeError> {
        let current_bytes = content
            .attachments
            .iter()
            .try_fold(0usize, |total, attachment| {
                total.checked_add(attachment.size)
            })
            .ok_or(MimeError::AttachmentBudgetExceeded)?;
        let total_bytes = current_bytes
            .checked_add(additional_bytes)
            .ok_or(MimeError::AttachmentBudgetExceeded)?;
        if total_bytes > MAX_TOTAL_ATTACHMENT_DECODED_BYTES {
            warn!(
                current_bytes,
                additional_bytes,
                limit_bytes = MAX_TOTAL_ATTACHMENT_DECODED_BYTES,
                "decoded attachment byte budget exceeded"
            );
            return Err(MimeError::AttachmentBudgetExceeded);
        }
        Ok(())
    }

    /// Extract boundary Parameter
    fn extract_boundary(content_type: &str) -> Option<String> {
        let boundary = Self::extract_mime_parameter(content_type, "boundary")?;
        // RFC 2046 allows trailing WSP inside a quoted boundary parameter;
        // the delimiter line itself carries any real transport padding.
        // Rejecting the trailing space here turned `boundary="abc "` into a
        // NoBoundary full-parse failure, so trim before validating.
        let boundary = boundary.trim_end().to_string();
        if !Self::is_valid_boundary(&boundary) {
            return None;
        }
        Some(boundary)
    }

    /// RFC 2046 boundary values are 1-70 ASCII `bchars`, with no trailing space.
    fn is_valid_boundary(boundary: &str) -> bool {
        !boundary.is_empty()
            && boundary.len() <= 70
            && !boundary.ends_with(' ')
            && boundary.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'\''
                            | b'('
                            | b')'
                            | b'+'
                            | b'_'
                            | b','
                            | b'-'
                            | b'.'
                            | b'/'
                            | b':'
                            | b'='
                            | b'?'
                            | b' '
                    )
            })
    }

    /// ExtractFileName (Performance notes: 1ofsizewrite)
    fn extract_filename(s: &str) -> Option<String> {
        // RFC 2231 continuation segments (`filename*0*=` / `filename*1*=`)
        // take precedence over every other form — MUAs honor them, so an
        // executable name split across segments must not hide behind a benign
        // legacy `filename=` or a single-section `filename*=`.
        for base in ["filename", "name"] {
            if let Some(value) = Self::extract_continued_parameter(s, base)
                && !value.is_empty()
            {
                return Some(value);
            }
        }

        // RFC 2231 extended parameters take precedence over their legacy
        // counterparts. MUAs follow this rule, so selecting `filename=` first
        // would let a benign legacy name hide an executable `filename*=`.
        for extended_name in ["filename*", "name*"] {
            if let Some(value) = Self::extract_mime_parameter(s, extended_name)
                && let Some(decoded) = Self::decode_extended_parameter(&value)
                && !decoded.is_empty()
            {
                return Some(decoded);
            }
        }

        for legacy_name in ["filename", "name"] {
            if let Some(value) = Self::extract_mime_parameter(s, legacy_name)
                && !value.is_empty()
            {
                return Some(decode_rfc2047(&value));
            }
        }

        None
    }

    /// Reassemble an RFC 2231 continuation series: `base*0[*]=`, `base*1[*]=`,
    /// ... in index order. Returns None when no `base*0` segment exists.
    /// When the first segment is starred it carries the `charset'lang'`
    /// prefix and the encoded octets of ALL segments concatenate before
    /// percent-decoding; unstarred segments are literal text.
    fn extract_continued_parameter(input: &str, base: &str) -> Option<String> {
        const MAX_CONTINUATION_SEGMENTS: usize = 32;
        let mut segments: Vec<(String, bool)> = Vec::new();
        for index in 0..MAX_CONTINUATION_SEGMENTS {
            let starred = Self::extract_mime_parameter(input, &format!("{base}*{index}*"));
            let plain = Self::extract_mime_parameter(input, &format!("{base}*{index}"));
            match (starred, plain) {
                (Some(value), _) => segments.push((value, true)),
                (None, Some(value)) => segments.push((value, false)),
                (None, None) => break,
            }
        }
        if segments.is_empty() {
            return None;
        }

        if segments[0].1 {
            let first = &segments[0].0;
            let mut fields = first.splitn(3, '\'');
            let charset = fields.next()?;
            let language = fields.next()?;
            let first_value = fields.next()?;
            let mut combined = String::with_capacity(first_value.len() * segments.len());
            combined.push_str(first_value);
            for (value, _) in &segments[1..] {
                combined.push_str(value);
            }
            Self::decode_extended_parameter(&format!("{charset}'{language}'{combined}"))
        } else {
            let mut combined = String::new();
            for (value, _) in &segments {
                combined.push_str(value);
            }
            if segments.iter().any(|(_, starred)| *starred) {
                // Mixed plain/starred series: percent-decode the concatenation.
                urlencoding::decode(&combined)
                    .ok()
                    .map(|decoded| decoded.into_owned())
            } else {
                Some(decode_rfc2047(&combined))
            }
        }
    }

    /// Parse a MIME parameter using browser/MUA-compatible whitespace and
    /// quoted-value handling. Security classification must not depend on the
    /// exact spelling `name=value`; RFC grammar also permits `name = value`.
    fn extract_mime_parameter(input: &str, wanted_name: &str) -> Option<String> {
        let bytes = input.as_bytes();
        let mut cursor = 0usize;

        while cursor < bytes.len() {
            while cursor < bytes.len()
                && (bytes[cursor] == b';' || bytes[cursor].is_ascii_whitespace())
            {
                cursor += 1;
            }
            let name_start = cursor;
            while cursor < bytes.len() && !matches!(bytes[cursor], b'=' | b';') {
                cursor += 1;
            }
            if cursor >= bytes.len() {
                break;
            }
            if bytes[cursor] == b';' {
                cursor += 1;
                continue;
            }

            let parameter_name = input[name_start..cursor].trim();
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }

            let value = if matches!(bytes.get(cursor), Some(b'"' | b'\'')) {
                let quote = bytes[cursor];
                cursor += 1;
                let mut value = Vec::new();
                while cursor < bytes.len() {
                    match bytes[cursor] {
                        byte if byte == quote => {
                            cursor += 1;
                            break;
                        }
                        b'\\' if cursor + 1 < bytes.len() => {
                            cursor += 1;
                            value.push(bytes[cursor]);
                            cursor += 1;
                        }
                        byte => {
                            value.push(byte);
                            cursor += 1;
                        }
                    }
                }
                String::from_utf8_lossy(&value).into_owned()
            } else {
                let value_start = cursor;
                while cursor < bytes.len() && bytes[cursor] != b';' {
                    cursor += 1;
                }
                input[value_start..cursor].trim().to_string()
            };

            if parameter_name.eq_ignore_ascii_case(wanted_name) {
                return Some(value);
            }
        }

        None
    }

    fn decode_extended_parameter(value: &str) -> Option<String> {
        let mut fields = value.splitn(3, '\'');
        let _charset = fields.next()?;
        let _language = fields.next()?;
        let encoded = fields.next()?;
        urlencoding::decode(encoded)
            .ok()
            .map(|decoded| decoded.into_owned())
    }

    /// Extract MIME Type (ContainsParameter)
    fn extract_mime_type(content_type: &str) -> &str {
        content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
    }

    /// ParseTransmissionEncode (Use eq_ignore_ascii_case Avoid to_lowercase Allocate)
    fn parse_encoding(s: &str) -> TransferEncoding {
        // Some MUAs accept obsolete comments or stray parameters after the
        // transfer-encoding token. Parse the authoritative first token so the
        // detector decodes the same payload instead of scanning encoded text.
        let token = s
            .trim()
            .split(|ch: char| ch.is_ascii_whitespace() || matches!(ch, ';' | '('))
            .next()
            .unwrap_or_default();
        if token.eq_ignore_ascii_case("base64") {
            TransferEncoding::Base64
        } else if token.eq_ignore_ascii_case("quoted-printable") {
            TransferEncoding::QuotedPrintable
        } else if token.eq_ignore_ascii_case("8bit") {
            TransferEncoding::EightBit
        } else if token.eq_ignore_ascii_case("binary") {
            TransferEncoding::Binary
        } else if token.eq_ignore_ascii_case("uuencode")
            || token.eq_ignore_ascii_case("x-uuencode")
            || token.eq_ignore_ascii_case("uue")
            || token.eq_ignore_ascii_case("x-uue")
        {
            TransferEncoding::Uuencode
        } else {
            TransferEncoding::SevenBit
        }
    }

    /// DecodeContent
    fn decode_content(
        &self,
        data: &[u8],
        encoding: TransferEncoding,
    ) -> Result<DecodedContent, MimeError> {
        match encoding {
            TransferEncoding::Base64 => Self::decode_base64(data).map(DecodedContent::plain),
            TransferEncoding::QuotedPrintable => {
                Self::decode_quoted_printable(data).map(DecodedContent::plain)
            }
            TransferEncoding::Uuencode
            | TransferEncoding::SevenBit
            | TransferEncoding::EightBit
            | TransferEncoding::Binary => {
                // Unknown/7bit CTE used to pass uuencode frames straight
                // through: a `begin 644 evil.exe ... end` body stayed encoded
                // text and no attachment was ever registered, while classic
                // MUAs auto-extract it. Decode the frame when the body
                // strictly validates as one (every data line must be
                // well-formed — prose mentioning "begin 644 x" is untouched).
                match split_uuencode_frame(data, MAX_ATTACHMENT_SAVE_SIZE) {
                    Some(frame) => {
                        let mut surrounding = frame.preamble;
                        surrounding.extend_from_slice(&frame.trailer);
                        Ok(DecodedContent {
                            data: frame.payload,
                            uuencode_filename: Some(frame.filename),
                            surrounding_text: if surrounding
                                .iter()
                                .all(|b| b.is_ascii_whitespace())
                            {
                                None
                            } else {
                                Some(surrounding)
                            },
                        })
                    }
                    None => Ok(DecodedContent::plain(data.to_vec())),
                }
            }
        }
    }

    /// Base64 Decode (Performance notes: hops ConnectDecode, Medium Vec Allocate)
    fn decode_base64(data: &[u8]) -> Result<Vec<u8>, MimeError> {
        const DECODE_TABLE: [i8; 256] = {
            let mut table = [-1i8; 256];
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut i = 0;
            while i < 64 {
                table[chars[i] as usize] = i as i8;
                i += 1;
            }
            table[b'=' as usize] = 0;
            table
        };

        // Outputsize (base64 Encode 4/3 size)
        let mut output = Vec::with_capacity(data.len() * 3 / 4);
        let mut buffer = 0u32;
        let mut bits = 0u8;

        // ConnectTraverse data,hops AndInvalidcharacters (Medium Vec Allocate)
        for &byte in data {
            // padding
            if byte == b'=' {
                break;
            }

            // hops characters (Judge filter + collect)
            if byte.is_ascii_whitespace() {
                continue;
            }

            let value = DECODE_TABLE[byte as usize];
            if value < 0 {
                continue;
            }

            buffer = (buffer << 6) | (value as u32);
            bits += 6;

            if bits >= 8 {
                bits -= 8;
                output.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }

        Ok(output)
    }

    /// Base64 Encode (Used for Attachment2Base/Radixdata storeofString)
    fn encode_base64(data: &[u8]) -> String {
        const ENCODE_TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        let mut output = String::with_capacity(data.len().div_ceil(3) * 4);
        let chunks = data.chunks_exact(3);
        let remainder = chunks.remainder();

        for chunk in chunks {
            let n = (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | (chunk[2] as u32);
            output.push(ENCODE_TABLE[((n >> 18) & 0x3F) as usize] as char);
            output.push(ENCODE_TABLE[((n >> 12) & 0x3F) as usize] as char);
            output.push(ENCODE_TABLE[((n >> 6) & 0x3F) as usize] as char);
            output.push(ENCODE_TABLE[(n & 0x3F) as usize] as char);
        }

        match remainder.len() {
            1 => {
                let n = (remainder[0] as u32) << 16;
                output.push(ENCODE_TABLE[((n >> 18) & 0x3F) as usize] as char);
                output.push(ENCODE_TABLE[((n >> 12) & 0x3F) as usize] as char);
                output.push('=');
                output.push('=');
            }
            2 => {
                let n = (remainder[0] as u32) << 16 | (remainder[1] as u32) << 8;
                output.push(ENCODE_TABLE[((n >> 18) & 0x3F) as usize] as char);
                output.push(ENCODE_TABLE[((n >> 12) & 0x3F) as usize] as char);
                output.push(ENCODE_TABLE[((n >> 6) & 0x3F) as usize] as char);
                output.push('=');
            }
            _ => {}
        }

        output
    }

    /// Quoted-Printable Decode (Performance notes: memchr bit '=' ByteBranch)
    fn decode_quoted_printable(data: &[u8]) -> Result<Vec<u8>, MimeError> {
        let mut output = Vec::with_capacity(data.len());
        let mut pos = 0;

        while pos < data.len() {
            // Use memchr hops 1 '='(SIMD Add)
            match memchr::memchr(b'=', &data[pos..]) {
                Some(offset) => {
                    // Batch '=' firstof Byte (Branch)
                    output.extend_from_slice(&data[pos..pos + offset]);
                    let eq_pos = pos + offset;

                    if eq_pos + 2 < data.len()
                        && let (Some(h), Some(l)) = (
                            Self::hex_value(data[eq_pos + 1]),
                            Self::hex_value(data[eq_pos + 2]),
                        )
                    {
                        output.push((h << 4) | l);
                        pos = eq_pos + 3;
                        continue;
                    }
                    // line (=\r\n =\n)
                    if eq_pos + 1 < data.len()
                        && (data[eq_pos + 1] == b'\r' || data[eq_pos + 1] == b'\n')
                    {
                        pos = eq_pos
                            + if data[eq_pos + 1] == b'\r'
                                && eq_pos + 2 < data.len()
                                && data[eq_pos + 2] == b'\n'
                            {
                                3
                            } else {
                                2
                            };
                        continue;
                    }
                    // of '=', keep
                    output.push(b'=');
                    pos = eq_pos + 1;
                }
                None => {
                    // not '=',Batch remainingdata
                    output.extend_from_slice(&data[pos..]);
                    break;
                }
            }
        }

        Ok(output)
    }

    /// 6Base/Radixcharacters value (function)
    #[inline(always)]
    fn hex_value(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'A'..=b'F' => Some(b - b'A' + 10),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }

    /// SHA256 Hash
    fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// FromPlain textMediumExtractlinkConnect (Performance notes: HashSet Deduplicate O(1) Vec O(n))
    fn extract_links_from_text(&self, text: &str, links: &mut Vec<EmailLink>) {
        // Use owned String of HashSet Avoid borrow checker
        let mut seen: HashSet<String> = HashSet::with_capacity(links.len());
        for link in links.iter() {
            seen.insert(link.url.clone());
        }

        let prefixes = ["http://", "https://"];

        for prefix in prefixes {
            let mut pos = 0;
            while let Some(start) = find_ascii_case_insensitive(&text[pos..], prefix) {
                let url_start = pos + start;
                let rest = &text[url_start..];
                let suffix = &rest[prefix.len()..];
                let trimmed_suffix = suffix.trim_start_matches(|c: char| c.is_whitespace());
                let skipped_ws = suffix.len() - trimmed_suffix.len();

                let url_end = trimmed_suffix
                    .find(|c: char| {
                        c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == '<'
                    })
                    .unwrap_or(trimmed_suffix.len());

                let url = format!("{prefix}{}", &trimmed_suffix[..url_end]);
                let url = url.trim_end_matches(['.', ',', ';', ')', ']']);

                if url.len() > 10 && !seen.contains(url) {
                    let url_owned = url.to_string();
                    seen.insert(url_owned.clone());
                    let suspicious = EmailContent::is_suspicious_url(url);
                    links.push(EmailLink {
                        url: url_owned,
                        text: None,
                        suspicious,
                    });
                }

                pos = url_start + prefix.len() + skipped_ws + url_end;
            }
        }
    }
}

impl Default for MimeParser {
    fn default() -> Self {
        Self::new()
    }
}

// ---- Allocateof function ----

/// ASCII sizewrite of starts_with (Allocate to_lowercase().starts_with())
#[inline]
fn ascii_starts_with_ci(haystack: &str, needle: &str) -> bool {
    haystack.len() >= needle.len()
        && haystack.as_bytes()[..needle.len()].eq_ignore_ascii_case(needle.as_bytes())
}

/// ASCII sizewrite of contains (Allocate to_lowercase().contains())
#[inline]
fn ascii_contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let needle_bytes = needle.as_bytes();
    haystack
        .as_bytes()
        .windows(needle_bytes.len())
        .any(|w| w.eq_ignore_ascii_case(needle_bytes))
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// From Content-Type MediumExtract charset Parameter
/// : "text/plain; charset=GBK" -> Some("GBK")
/// : "text/html; charset=\"UTF-8\"" -> Some("UTF-8")
fn extract_charset(content_type: &str) -> Option<String> {
    MimeParser::extract_mime_parameter(content_type, "charset")
        .filter(|charset| !charset.is_empty())
}

/// according to Content-Type Mediumof charset ByteDecode UTF-8 String
/// GBK, GB2312, GB18030, Big5, ISO-8859-*, Shift_JIS wait Encode
/// Which retained body string a decoded alternative merges into (SEC M-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyTarget {
    Text,
    Html,
}

/// Retained byte length of an optional body string.
fn body_bytes(value: &Option<String>) -> usize {
    value.as_deref().map_or(0, str::len)
}

/// Remaining decoded-body budget for this message (SEC M-4).
fn body_budget_remaining(content: &EmailContent) -> usize {
    MAX_TOTAL_DECODED_BODY_BYTES
        .saturating_sub(body_bytes(&content.body_text) + body_bytes(&content.body_html))
}

/// Truncate `value` to at most `max_bytes` on a UTF-8 char boundary.
/// Returns the prefix and whether clipping occurred.
fn truncate_char_boundary(value: &str, max_bytes: usize) -> (&str, bool) {
    if value.len() <= max_bytes {
        return (value, false);
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    (&value[..end], true)
}

/// Stateful bounded decode through an encoding_rs decoder (SEC M-4): stops at
/// `max_output_bytes` so a hostile charset declaration cannot expand a large
/// part into an unbounded String before the merge-side budget ever runs.
/// Output semantics (replacement chars for invalid sequences) match
/// `Encoding::decode` with replacement handling.
fn decode_with_encoding_bounded(
    encoding: &'static encoding_rs::Encoding,
    data: &[u8],
    max_output_bytes: usize,
) -> (String, bool) {
    let mut decoder = encoding.new_decoder();
    let mut output = String::with_capacity(data.len().min(max_output_bytes + 4));
    let mut source = data;
    loop {
        if source.is_empty() {
            return (output, false);
        }
        if output.len() >= max_output_bytes {
            return (output, true);
        }
        // Worst-case expansion is one source byte -> one replacement char
        // (3 UTF-8 bytes), so this chunk cannot overshoot by much; the merge
        // side clips to the exact budget.
        let room = max_output_bytes - output.len();
        let mut chunk_len = (room / 3).clamp(1, source.len());
        let mut read = 0usize;
        while chunk_len <= source.len() {
            let is_last = chunk_len == source.len();
            output.reserve(4 * chunk_len + 4);
            let (_result, consumed, _replaced) = decoder.decode_to_string(
                &source[..chunk_len],
                &mut output,
                is_last,
            );
            read = consumed;
            if read > 0 || is_last {
                break;
            }
            // A partial multibyte sequence needs more context than the
            // budget-derived chunk; the decoder consumed nothing, so it is
            // safe to re-feed a larger prefix.
            chunk_len = (chunk_len.saturating_mul(2)).clamp(chunk_len + 1, source.len());
        }
        if read == 0 {
            // Defensive: the final flush consumed nothing (empty or
            // pathological input); stop rather than loop.
            return (output, !source.is_empty());
        }
        source = &source[read..];
    }
}

/// Decode body bytes for a charset label with a bounded output (SEC M-4).
/// Returns the decoded string and whether it was clipped at the cap.
fn decode_charset(data: &[u8], content_type: &str, max_output_bytes: usize) -> (String, bool) {
    if max_output_bytes == 0 {
        return (String::new(), !data.is_empty());
    }
    // UTF-7 must be decoded BEFORE the UTF-8 fast path: UTF-7 is pure ASCII,
    // so from_utf8 always succeeds and would return the `+AGE-` ciphertext
    // verbatim, blinding every keyword layer (classic Outlook desktop render).
    if let Some(charset_name) = extract_charset(content_type)
        && is_utf7_label(&charset_name)
    {
        return decode_utf7(data, max_output_bytes);
    }

    // UTF-8 (, Scenario)
    if let Ok(s) = std::str::from_utf8(data) {
        let (prefix, truncated) = truncate_char_boundary(s, max_output_bytes);
        return (prefix.to_owned(), truncated);
    }

    // Extract charset Parameter
    if let Some(charset_name) = extract_charset(content_type) {
        // encoding_rs lookupEncodehandler (Name: gbk/gb2312 -> GBK, big5, shift_jis, iso-8859-1 wait)
        if let Some(encoding) = Encoding::for_label(charset_name.as_bytes()) {
            return decode_with_encoding_bounded(encoding, data, max_output_bytes);
        }
        warn!("Unknowncharacters集: {}, 回退到 GB18030/UTF-8 lossy", charset_name);
    }

    // charset 未声明（或标签未知）且 UTF-8 解码失败：中文 MUA 经常省略
    // charset 直接发送 GBK/GB18030 正文，UTF-8 lossy 会把正文变成 mojibake
    // 使关键词检测完全失效。GB18030 是 GBK/GB2312 的超集解码器，先试它再
    // 回退 UTF-8 lossy。
    decode_with_encoding_bounded(encoding_rs::GB18030, data, max_output_bytes)
}

/// Whether a charset label names UTF-7 (RFC 2152). encoding_rs (WHATWG)
/// deliberately excludes UTF-7, so `Encoding::for_label` can never decode it.
fn is_utf7_label(label: &str) -> bool {
    let label = label.trim();
    label.eq_ignore_ascii_case("utf-7") || label.eq_ignore_ascii_case("unicode-1-1-utf-7")
}

/// Decode UTF-7 (RFC 2152) to a Rust String.
///
/// Grammar: printable ASCII passes through; `+` starts a modified-base64
/// shift sequence (no padding) carrying UTF-16BE units, terminated by `-` or
/// by the first byte outside the base64 alphabet (which is then processed as
/// a literal); `+-` encodes a literal `+`. Trailing partial bits are ignored.
///
/// Bounded output (SEC M-4): decoding stops once `max_output_bytes` is
/// reached — the non-ASCII lossy path expands one input byte to a three-byte
/// replacement character, which previously allowed a large part to expand to
/// 3x before any budget check ran.
fn decode_utf7(data: &[u8], max_output_bytes: usize) -> (String, bool) {
    fn shift_value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut result = String::with_capacity(data.len().min(max_output_bytes + 4));
    let mut i = 0usize;
    while i < data.len() {
        if result.len() >= max_output_bytes {
            return (result, true);
        }
        let byte = data[i];
        if byte != b'+' {
            // Direct-printable ASCII; keep non-ASCII bytes lossy-visible
            // rather than dropping them.
            if byte.is_ascii() {
                result.push(byte as char);
            } else {
                result.push(char::REPLACEMENT_CHARACTER);
            }
            i += 1;
            continue;
        }
        if data.get(i + 1) == Some(&b'-') {
            result.push('+');
            i += 2;
            continue;
        }

        let mut units: Vec<u16> = Vec::new();
        let mut accumulator = 0u32;
        let mut bits = 0u8;
        let mut j = i + 1;
        while j < data.len() {
            let current = data[j];
            if current == b'-' {
                j += 1;
                break;
            }
            match shift_value(current) {
                Some(value) => {
                    accumulator = (accumulator << 6) | value;
                    bits += 6;
                    if bits >= 16 {
                        bits -= 16;
                        units.push((accumulator >> bits) as u16);
                        accumulator &= (1u32 << bits) - 1;
                    }
                    j += 1;
                }
                // The first non-alphabet byte ends the shift sequence and is
                // processed again as a literal on the next outer iteration.
                // EOF also ends it; collected units are decoded either way.
                None => break,
            }
        }
        match String::from_utf16(&units) {
            Ok(decoded) => result.push_str(&decoded),
            Err(_) => result.push_str(&String::from_utf16_lossy(&units)),
        }
        i = j;
    }
    (result, false)
}

/// Decode RFC 2047 encoded-word
/// : =?charset?encoding?encoded_text?=
/// encoding: B = Base64, Q = Quoted-Printable
/// Example: =?utf-8?B?5Yqe5YWs5qW8?= -> " "
pub fn decode_rfc2047(input: &str) -> String {
    // path: if packetContains encoded-word Mark, ConnectReturn
    if !input.contains("=?") {
        return input.to_string();
    }

    let mut result = String::with_capacity(input.len());
    let mut pos = 0;
    let bytes = input.as_bytes();

    while pos < bytes.len() {
        // lookup =? StartMark
        if let Some(start) = input[pos..].find("=?") {
            let abs_start = pos + start;

            // Add encoded-word firstofText
            result.push_str(&input[pos..abs_start]);

            // Parse =?charset?encoding?text?=
            let rest = &input[abs_start + 2..];

            // lookup charset
            if let Some(q1) = rest.find('?') {
                let charset_name = &rest[..q1];
                let after_charset = &rest[q1 + 1..];

                // lookup encoding (B or Q)
                if after_charset.len() >= 2 && after_charset.as_bytes()[1] == b'?' {
                    let encoding_char = after_charset.as_bytes()[0].to_ascii_uppercase();
                    let after_enc = &after_charset[2..];

                    // lookupEndMark?=
                    if let Some(end) = after_enc.find("?=") {
                        let encoded_text = &after_enc[..end];
                        let next_pos = abs_start + 2 + q1 + 1 + 2 + end + 2;

                        // Decode
                        let decoded_bytes = match encoding_char {
                            b'B' => MimeParser::decode_base64(encoded_text.as_bytes()).ok(),
                            b'Q' => decode_rfc2047_q(encoded_text),
                            _ => None,
                        };

                        if let Some(raw_bytes) = decoded_bytes {
                            // according to charset Convert UTF-8
                            let text = if charset_name.eq_ignore_ascii_case("utf-8")
                                || charset_name.eq_ignore_ascii_case("utf8")
                            {
                                String::from_utf8_lossy(&raw_bytes).into_owned()
                            } else if is_utf7_label(charset_name) {
                                // WHATWG excludes UTF-7, so for_label can never
                                // decode it; without this branch the encoded
                                // subject falls back to lossy ASCII ciphertext.
                                // Encoded words live in headers (≤64KB), so the
                                // bounded decode cap covers the worst expansion.
                                let (decoded, _truncated) =
                                    decode_utf7(&raw_bytes, MAX_HEADER_SIZE);
                                decoded
                            } else if let Some(encoding) =
                                Encoding::for_label(charset_name.as_bytes())
                            {
                                let (decoded, _, _) = encoding.decode(&raw_bytes);
                                decoded.into_owned()
                            } else {
                                String::from_utf8_lossy(&raw_bytes).into_owned()
                            };
                            result.push_str(&text);
                        } else {
                            // DecodeFailed,keep
                            result.push_str(&input[abs_start..next_pos]);
                        }

                        // hops encoded-word of (RFC 2047 section 6.2)
                        pos = next_pos;
                        let remaining = &input[pos..];
                        let trimmed = remaining.trim_start_matches([' ', '\t']);
                        if trimmed.starts_with("=?") {
                            pos = input.len() - trimmed.len();
                        }
                        continue;
                    }
                }
            }

            // ParseFailed,keep =?
            result.push_str("=?");
            pos = abs_start + 2;
        } else {
            // not encoded-word
            result.push_str(&input[pos..]);
            break;
        }
    }

    result
}

/// RFC 2047 Q encoding Decode (Class QP,But _ table)
fn decode_rfc2047_q(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'_' => {
                output.push(b' ');
                i += 1;
            }
            b'=' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (
                    MimeParser::hex_value(bytes[i + 1]),
                    MimeParser::hex_value(bytes[i + 2]),
                ) {
                    output.push((h << 4) | l);
                    i += 3;
                } else {
                    output.push(b'=');
                    i += 1;
                }
            }
            b => {
                output.push(b);
                i += 1;
            }
        }
    }

    Some(output)
}

/// MIME ParseError
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MimeError {
    /// email large
    TooLarge,
    /// Header large (retained for API compatibility: oversized headers are
    /// now degraded to truncation + body preservation, not a parse error)
    #[allow(dead_code)]
    HeaderTooLarge,
    /// Invalidof UTF-8
    InvalidUtf8,
    /// boundary
    NoBoundary,
    /// Declared boundary never appears in the body.
    BoundaryNotFound,
    /// Multipart content has no terminating closing boundary.
    MissingClosingBoundary,
    /// Multipart nesting exceeded the parser safety limit.
    MultipartTooDeep,
    /// Multipart part count exceeded the parser safety limit.
    TooManyParts,
    /// Cumulative decoded attachment bytes exceeded the per-message safety limit.
    AttachmentBudgetExceeded,
    /// Duplicate MIME security headers (retained for API compatibility: they
    /// are now degraded to first-header-wins with a warning, not a parse error)
    #[allow(dead_code)]
    AmbiguousSecurityHeaders,
    /// Base64 DecodeError
    Base64DecodeError,
    /// Quoted-Printable DecodeError
    QuotedPrintableError,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // ── SEC M-4 round-4: chunked-decoder adversarial pinning ────────────

    #[test]
    fn m4_gb18030_multibyte_survives_chunk_boundaries() {
        // GB18030 four-byte sequences (0x81.. 0x30.. 0x81.. 0x30..) decode
        // to supplementary-plane chars; a bounded max forces tiny chunks, so
        // sequences necessarily straddle chunk boundaries. The stateful
        // decoder must neither loop, nor drop, nor duplicate them.
        let mut hostile = Vec::new();
        for _ in 0..512 {
            hostile.extend_from_slice(&[0x81, 0x30, 0x81, 0x30]);
        }
        hostile.extend_from_slice(b"tail");
        // Small cap ⇒ chunk_len = room/3 stays small across iterations.
        let (decoded, _truncated) = decode_charset(&hostile, "text/plain; charset=gb18030", 97);
        assert!(
            decoded.chars().count() >= 20,
            "decoder made progress across chunk boundaries: {} chars",
            decoded.chars().count()
        );
        assert!(decoded.len() <= 97 + 4, "overshoot bounded to one char");
        // Unbounded decode of the same input must agree on the prefix.
        let (full, _) = decode_charset(&hostile, "text/plain; charset=gb18030", 20 * 1024);
        assert!(
            full.starts_with(decoded.trim_end_matches('\u{fffd}')),
            "bounded decode must be a prefix of the unbounded decode (ignoring the clipped partial char)"
        );
    }

    #[test]
    fn m4_latin1_expansion_is_capped() {
        // ISO-8859-1 invalid-for-utf8 bytes expand 1→2 bytes per char; the
        // cap must hold at the source, not after a full-materialize.
        let hostile: Vec<u8> = vec![0xfe; 32 * 1024];
        let (decoded, truncated) = decode_charset(&hostile, "text/plain; charset=iso-8859-1", 1024);
        assert!(truncated);
        assert!(decoded.len() <= 1024 + 4, "got {}", decoded.len());
    }

    #[test]
    fn m4_utf7_shift_sequence_split_across_cap() {
        // A UTF-7 shift sequence opened just before the cap: the decoder
        // stops cleanly without panicking on the dangling '+'.
        let mut hostile = b"prefix ".to_vec();
        hostile.extend_from_slice(&vec![b'a'; 90]);
        hostile.extend_from_slice(b"+AGE-");
        let (decoded, _truncated) = decode_charset(&hostile, "text/plain; charset=utf-7", 97);
        assert!(decoded.len() <= 97 + 4);
        assert!(decoded.starts_with("prefix "));
    }

    // ── SEC M-4: decoded-body budget regression tests ──────────────────

    #[test]
    fn m4_charset_lossy_expansion_is_bounded_at_source() {
        // PoC (M-4): a UTF-7 (or lossy) body expands one invalid input byte
        // into a three-byte U+FFFD. Without the cap a ~100MB part decoded to
        // ~300MB before any budget check ran.
        let hostile: Vec<u8> = vec![0xff; 64 * 1024];
        let (decoded, truncated) = decode_charset(&hostile, "text/plain; charset=utf-7", 64 * 1024);
        assert!(truncated, "decoding must report clipping at the cap");
        assert!(
            decoded.len() <= 64 * 1024 + 4,
            "output must not exceed the cap by more than one character, got {}",
            decoded.len()
        );
    }

    #[test]
    fn m4_utf8_body_is_clipped_at_char_boundary() {
        let body = "账".repeat(4096); // 3 bytes per char
        let (prefix, truncated) = decode_charset(body.as_bytes(), "text/plain; charset=utf-8", 100);
        assert!(truncated);
        assert!(prefix.len() <= 100);
        assert!(prefix.is_char_boundary(prefix.len()));
    }

    #[test]
    fn m4_merge_body_part_enforces_cumulative_budget() {
        let mut content = EmailContent::default();
        let big = "a".repeat(MAX_TOTAL_DECODED_BODY_BYTES - 8);
        content.body_text = Some(big);
        MimeParser::merge_body_part(&mut content, BodyTarget::Text, "b".repeat(1024), false, "plain");
        assert!(content.truncated, "budget overflow must set the truncated flag");
        let retained = content.body_text.as_ref().map(|t| t.len()).unwrap_or(0)
            + content.body_html.as_ref().map(|h| h.len()).unwrap_or(0);
        assert!(
            retained <= MAX_TOTAL_DECODED_BODY_BYTES,
            "retained body bytes {} must stay within the budget",
            retained
        );
    }

    #[test]
    fn m4_merge_body_part_does_not_append_separator_without_payload_budget() {
        let mut content = EmailContent::default();
        content.body_text = Some("a".repeat(MAX_TOTAL_DECODED_BODY_BYTES - 1));
        MimeParser::merge_body_part(
            &mut content,
            BodyTarget::Text,
            "账".to_string(),
            false,
            "plain",
        );
        assert!(content.truncated);
        assert_eq!(
            content.body_text.as_ref().map(String::len),
            Some(MAX_TOTAL_DECODED_BODY_BYTES - 1)
        );
    }

    #[test]
    fn m4_decode_truncation_flags_message() {
        let mut content = EmailContent::default();
        MimeParser::merge_body_part(
            &mut content,
            BodyTarget::Text,
            "x".repeat(16),
            true,
            "plain",
        );
        assert!(content.truncated, "decode-side clipping must flag the message");
        assert_eq!(content.body_text.as_deref(), Some("xxxxxxxxxxxxxxxx"));
    }

    fn nested_multipart_message(depth: usize) -> Vec<u8> {
        assert!(depth > 0);
        let mut email = b"Content-Type: multipart/mixed; boundary=BOUND_0\r\n\r\n".to_vec();
        for level in 0..depth {
            email.extend_from_slice(format!("--BOUND_{level}\r\n").as_bytes());
            if level + 1 < depth {
                email.extend_from_slice(
                    format!(
                        "Content-Type: multipart/mixed; boundary=BOUND_{}\r\n\r\n",
                        level + 1
                    )
                    .as_bytes(),
                );
            } else {
                email.extend_from_slice(b"Content-Type: text/plain\r\n\r\nstable\r\n");
            }
        }
        for level in (0..depth).rev() {
            email.extend_from_slice(format!("--BOUND_{level}--\r\n").as_bytes());
        }
        email
    }

    #[test]
    fn test_simple_email() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
                     To: recipient@example.com\r\n\
                     Subject: Test Email\r\n\
                     Content-Type: text/plain\r\n\
                     \r\n\
                     Hello, this is a test email.\r\n\
                     Visit https:// example.com for more info.";

        let content = parser.parse(email).unwrap();

        assert!(content.body_text.is_some());
        assert!(content.body_text.as_ref().unwrap().contains("test email"));
        assert_eq!(content.links.len(), 1);
        assert_eq!(content.links[0].url, "https://example.com");
    }

    #[test]
    fn test_base64_decode() {
        let input = b"SGVsbG8gV29ybGQh"; // "Hello World!"
        let decoded = MimeParser::decode_base64(input).unwrap();
        assert_eq!(&decoded, b"Hello World!");
    }

    #[test]
    fn test_base64_with_whitespace() {
        let input = b"SGVs\r\nbG8g\r\nV29y\r\nbGQh";
        let decoded = MimeParser::decode_base64(input).unwrap();
        assert_eq!(&decoded, b"Hello World!");
    }

    #[test]
    fn test_transfer_encoding_uses_first_mime_token() {
        assert_eq!(
            MimeParser::parse_encoding("Base64 (legacy comment)"),
            TransferEncoding::Base64
        );
        assert_eq!(
            MimeParser::parse_encoding("quoted-printable; x-legacy=yes"),
            TransferEncoding::QuotedPrintable
        );
    }

    #[test]
    fn test_quoted_printable() {
        let input = b"Hello=20World=21";
        let decoded = MimeParser::decode_quoted_printable(input).unwrap();
        assert_eq!(&decoded, b"Hello World!");
    }

    #[test]
    fn test_extract_boundary() {
        let ct = "multipart/mixed; boundary=\"----=_Part_123\"";
        let boundary = MimeParser::extract_boundary(ct);
        assert_eq!(boundary, Some("----=_Part_123".to_string()));
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary = \"SPACED\""),
            Some("SPACED".to_string())
        );
        assert_eq!(
            extract_charset("text/plain; charset = \"GBK\"").as_deref(),
            Some("GBK")
        );
    }

    #[test]
    fn test_rejects_empty_oversized_and_illegal_boundaries() {
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary=\"\""),
            None
        );
        assert_eq!(
            MimeParser::extract_boundary(&format!(
                "multipart/mixed; boundary=\"{}\"",
                "a".repeat(71)
            )),
            None
        );
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary=\"bad[boundary\""),
            None
        );
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary=\"边界\""),
            None
        );
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary=\"valid interior space\""),
            Some("valid interior space".to_string())
        );
    }

    #[test]
    fn test_multipart_stops_at_total_part_budget() {
        // PoC bypass (R4C): exceeding the part budget used to bubble
        // TooManyParts and drop the ENTIRE message from mirror-mode scanning
        // while the MUA rendered it. The parser must keep the parts already
        // scanned and flag the truncation instead.
        let mut email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n".to_vec();
        for _ in 0..=MAX_TOTAL_PARTS {
            email.extend_from_slice(b"--BOUND\r\nContent-Type: text/plain\r\n\r\nx\r\n");
        }
        email.extend_from_slice(b"--BOUND--\r\n");

        let content = MimeParser::new()
            .parse(&email)
            .expect("part budget must degrade, not fail the parse");
        assert!(content.truncated, "part budget overflow must be flagged");
        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains('x')),
            "already-parsed parts must survive: {:?}",
            content.body_text
        );
    }

    #[test]
    fn test_boundary_substring_flood_does_not_create_parts() {
        let mut email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n".to_vec();
        for _ in 0..20_000 {
            email.extend_from_slice(b"payload--BOUNDsuffix\r\n");
        }

        let error = MimeParser::new()
            .parse(&email)
            .expect_err("boundary substrings are not delimiter lines");
        assert_eq!(error, MimeError::BoundaryNotFound);
    }

    #[test]
    fn test_multipart_depth_limit_is_stable_and_parser_remains_reusable() {
        // PoC bypass (R4C): nesting past MAX_MULTIPART_DEPTH used to bubble
        // MultipartTooDeep and drop the whole message. Now it degrades: keep
        // the outer layers, flag truncated, and the parser stays reusable.
        let parser = MimeParser::new();
        let content = parser
            .parse(&nested_multipart_message(MAX_MULTIPART_DEPTH + 1))
            .expect("nesting over the limit must degrade, not fail the parse");
        assert!(content.truncated, "depth overflow must be flagged");

        for _ in 0..100 {
            let content = parser
                .parse(b"Content-Type: text/plain\r\n\r\nstill healthy")
                .expect("an adversarial message must not poison parser reuse");
            assert_eq!(content.body_text.as_deref(), Some("still healthy"));
            assert!(!content.truncated);
        }
    }

    #[test]
    fn perf_boundary_substring_flood_remains_linear_and_bounded() {
        let mut email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n".to_vec();
        for _ in 0..250_000 {
            email.extend_from_slice(b"x--BOUND-not-a-delimiter\r\n");
        }
        let started = Instant::now();

        let error = MimeParser::new()
            .parse(&email)
            .expect_err("no valid boundary delimiter exists");
        assert_eq!(error, MimeError::BoundaryNotFound);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "streamed boundary scan exceeded the generous performance ceiling"
        );
    }

    #[test]
    fn test_attachment_budget_is_cumulative_without_allocating_payload() {
        let mut content = EmailContent::new();
        content.attachments.push(EmailAttachment {
            filename: "existing.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            size: MAX_TOTAL_ATTACHMENT_DECODED_BYTES,
            hash: "hash".to_string(),
            content_base64: None,
        });

        assert_eq!(
            MimeParser::ensure_attachment_budget(&content, 1),
            Err(MimeError::AttachmentBudgetExceeded)
        );
    }

    #[test]
    fn test_declared_multipart_boundary_must_exist() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
                     Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
                     \r\n\
                     This body never contains the declared delimiter.\r\n";

        let err = parser
            .parse(email)
            .expect_err("missing boundary should fail");

        assert_eq!(err, MimeError::BoundaryNotFound);
    }

    #[test]
    fn test_multipart_boundary_must_be_a_complete_delimiter_line() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
This line contains prefix--BOUNDsuffix and must remain intact.\r\n\
--BOUND--\r\n";

        let content = parser.parse(email).unwrap();

        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("prefix--BOUNDsuffix"))
        );
    }

    #[test]
    fn test_multipart_boundary_prefix_collision_is_rejected() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
not a BOUND part\r\n\
--BOUNDARY--\r\n";

        let err = parser
            .parse(email)
            .expect_err("a longer delimiter must not match a boundary prefix");

        assert_eq!(err, MimeError::BoundaryNotFound);
    }

    #[test]
    fn test_multipart_uses_message_eof_for_valid_final_part() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\
\r\n\
unterminated body\r\n";

        let content = parser
            .parse(email)
            .expect("a valid final MIME part should be scanned through message EOF");

        assert_eq!(content.body_text.as_deref(), Some("unterminated body\r\n"));
    }

    #[test]
    fn test_multipart_invalid_final_part_without_close_still_fails() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND\r\n\
not-a-valid-mime-part";

        let err = parser
            .parse(email)
            .expect_err("unparseable EOF content must not become a successful inspection");

        assert_eq!(err, MimeError::MissingClosingBoundary);
    }

    #[test]
    fn test_multipart_accepts_transport_padding_after_boundary() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND \t\r\n\
Content-Type: text/plain\r\n\
\r\n\
body\r\n\
--BOUND-- \t\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("body\r\n"));
    }

    #[test]
    fn test_salvages_embedded_multipart_body_without_top_level_content_type() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Business Card\r\n\
\r\n\
------=_NextPart_123\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
5b6u5a2Q55m7\r\n\
\r\n\
------=_NextPart_123\r\n\
Content-Type: text/html; charset=\"utf-8\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGRpdj48Yj5XZWljaTwvYj48L2Rpdj4=\r\n\
\r\n\
------=_NextPart_123--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("微子登"));
        assert_eq!(
            content.body_html.as_deref(),
            Some("<div><b>Weici</b></div>")
        );
    }

    #[test]
    fn test_salvages_fragmented_embedded_mime_parts_without_top_level_content_type() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Warning\r\n\
\r\n\
------=_NextPart_alt\r\n\
Content-Transfer-Encoding: base64\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=\"utf-8\"\r\n\
\r\n\
6K+l6YKu5Lu25Y+v6IO95a2Y5Zyo5oG25oSP5YaF5a6577yM6K+36LCo5oWO55SE5Yir6YKu5Lu277yM5aaC5pyJ55aR6Zeu77yM6K+36IGU57O76YKu5Lu257O757uf566h55CG5ZGY44CC6K+35rOo5oSP77yM5LiA5a6a5LuU57uG5qC45a+55Y+R5Lu25Lq65Zyw5Z2A5piv5ZCm5Li65q2j56Gu5Zyw5Z2A77yM5LiN6KaB5Zyo5aSW572R55S16ISR5Y2V5Ye75Lu75L2V6ZO+5o6l44CCCgrmo4DmtYvnu5PmnpzvvJrlnoPlnLrpgq7ku7bjgIIK\r\n\
------=_NextPart_alt\r\n\
Content-Transfer-Encoding: base64\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/html; charset=\"utf-8\"\r\n\
\r\n\
PHAgc3R5bGU9ImZvbnQtc2l6ZToxMDAlO2NvbG9yOiNGRjAwMDAiPuivpemCruS7tuWPr+iDveWtmOWcqOaBtuaEj+WGheWuue+8jOivt+iwqOaFjueUhOWIq+mCruS7tu+8jOWmguacieeWkemXru+8jOivt+iBlOezu+mCruS7tuezu+e7n+euoeeQhuWRmOOAguivt+azqOaEj++8jOS4gOWumuS7lOe7huaguOWvueWPkeS7tuS6uuWcsOWdgOaYr+WQpuS4uuato+ehruWcsOWdgO+8jOS4jeimgeWcqOWklue9keeUteiEkeWNleWHu+S7u+S9lemTvuaOpeOAgjwvcD48Zm9udCBzdHlsZT0iZm9udC1zaXplOjEwMCU7Y29sb3I6I0ZGMDAwMCI+5qOA5rWL57uT5p6c77ya5Z6D5Zy+6YKu5Lu244CCPC9mb250PjxkaXY+PGJyICAvPjwvZGl2PjxkaXY+PCEtLWVtcHR5c2lnbi0tPjwvZGl2Pg==\r\n\
------=_NextPart_alt--\r\n\
\r\n\
------=_NextPart_attach\r\n\
Content-Type: application/octet-stream; name=\"warn.jpg\"\r\n\
Content-Disposition: attachment; filename=\"warn.jpg\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAA==\r\n\
------=_NextPart_attach--\r\n";

        let content = parser.parse(email).unwrap();

        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("该邮件可能存在恶意内容"))
        );
        assert!(
            content
                .body_html
                .as_deref()
                .is_some_and(|body| body.contains("检测结果：垃圾邮件"))
        );
        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].filename, "warn.jpg");
        assert!(content.attachments[0].content_base64.is_some());
    }

    #[test]
    fn test_header_folding_and_case_insensitive_lookup() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
Subject: Security\r\n\
\tNotice\r\n\
X-Custom: first\r\n\
\x20second\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Body";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.get_header("subject"), Some("Security Notice"));
        assert_eq!(content.get_header("x-custom"), Some("first second"));
        assert_eq!(content.body_text.as_deref(), Some("Body"));
    }

    #[test]
    fn test_conflicting_security_headers_degrade_to_first_header() {
        // PoC bypass (R3A): duplicate security headers used to abort the whole
        // parse (AmbiguousSecurityHeaders) — two header lines produced the
        // cheapest full-blindness primitive in mirror mode while MUAs rendered
        // the message. The parser must keep the FIRST header and continue.
        let parser = MimeParser::new();
        let top_level = b"Content-Type: text/plain\r\n\
Content-Type: text/html\r\n\
\r\n\
conflicting body";
        let content = parser
            .parse(top_level)
            .expect("duplicate Content-Type must degrade, not fail the parse");
        assert_eq!(content.body_text.as_deref(), Some("conflicting body"));
        assert!(content.body_html.is_none());

        let dup_cte = b"Content-Type: text/plain\r\n\
Content-Transfer-Encoding: 7bit\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8=";
        let content = parser
            .parse(dup_cte)
            .expect("duplicate CTE must degrade, not fail the parse");
        // First CTE (7bit) wins: the body is NOT base64-decoded.
        assert_eq!(content.body_text.as_deref(), Some("SGVsbG8="));

        let multipart = b"Content-Type: multipart/mixed; boundary=X\r\n\
\r\n\
--X\r\n\
Content-Type: text/plain\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
payload\r\n\
--X--\r\n";
        let content = parser
            .parse(multipart)
            .expect("duplicate part Content-Type must degrade, not fail the parse");
        assert_eq!(content.body_text.as_deref(), Some("payload\r\n"));
    }

    #[test]
    fn test_text_plain_gbk_charset_decodes_to_utf8() {
        let parser = MimeParser::new();
        let mut email = b"Content-Type: text/plain; charset=gbk\r\n\r\n".to_vec();
        email.extend_from_slice(&[0xc4, 0xe3, 0xba, 0xc3]); // 你好 in GBK

        let content = parser.parse(&email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("你好"));
    }

    #[test]
    fn test_text_plain_no_charset_gbk_body_decodes_via_gb18030() {
        // PoC bypass: a GBK body with no charset declaration previously went
        // straight to UTF-8 lossy, turning the phishing text into mojibake
        // that no keyword could match. GB18030 must decode it instead.
        let parser = MimeParser::new();
        let mut email = b"Content-Type: text/plain\r\n\r\n".to_vec();
        // 您的账户异常 in GBK.
        email.extend_from_slice(&[
            0xc4, 0xfa, 0xb5, 0xc4, 0xd5, 0xcb, 0xbb, 0xa7, 0xd2, 0xec, 0xb3, 0xa3,
        ]);

        let content = parser.parse(&email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("您的账户异常"));
    }

    #[test]
    fn test_text_plain_no_charset_utf8_body_unchanged() {
        // Guard: valid UTF-8 bodies must not be re-interpreted as GB18030.
        let parser = MimeParser::new();
        let email = "Content-Type: text/plain\r\n\r\n您的账户异常".as_bytes();

        let content = parser.parse(email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("您的账户异常"));
    }

    #[test]
    fn test_attachment_count_overflow_degrades_instead_of_failing() {
        // PoC bypass: more than MAX_ATTACHMENTS attachments previously made
        // the whole parse fail, so the body and every attachment disappeared
        // from scanning. The parser must keep the body and the first
        // MAX_ATTACHMENTS attachments and skip the rest.
        let parser = MimeParser::new();
        let mut email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n".to_vec();
        email.extend_from_slice(b"--BOUND\r\nContent-Type: text/plain\r\n\r\nbody survives\r\n");
        for index in 0..(MAX_ATTACHMENTS + 1) {
            email.extend_from_slice(
                format!(
                    "--BOUND\r\nContent-Type: application/octet-stream; name=\"f{index}.bin\"\r\nContent-Disposition: attachment; filename=\"f{index}.bin\"\r\n\r\nx\r\n"
                )
                .as_bytes(),
            );
        }
        email.extend_from_slice(b"--BOUND--\r\n");

        let content = parser
            .parse(&email)
            .expect("attachment overflow must degrade, not fail the parse");

        assert_eq!(content.body_text.as_deref(), Some("body survives\r\n"));
        assert_eq!(content.attachments.len(), MAX_ATTACHMENTS);
        assert_eq!(
            content.dropped_attachments, 1,
            "the skipped 101st attachment must be counted"
        );
        assert!(content.is_complete);
    }

    #[test]
    fn test_plain_text_links_deduplicate_and_trim_punctuation() {
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Open https:// example.com/login. Then open https://example.com/login, and http://10.0.0.1/verify)";

        let content = parser.parse(email).unwrap();

        let urls = content
            .links
            .iter()
            .map(|link| (link.url.as_str(), link.suspicious))
            .collect::<Vec<_>>();
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&("https://example.com/login", true)));
        assert!(urls.contains(&("http://10.0.0.1/verify", true)));
    }

    #[test]
    fn test_plain_text_link_scheme_is_case_insensitive() {
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Open HTTPS://evil.example/login";

        let content = parser.parse(email).unwrap();

        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.example/login")
        );
    }

    #[test]
    fn test_html_links_extract_anchor_text_and_image_src() {
        let parser = MimeParser::new();
        let email = b"Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><a HREF='https://evil.example/login'><span>Review</span> invoice</a><img SRC=\"https://cdn.example/pixel.png\"></body></html>";

        let content = parser.parse(email).unwrap();

        let login = content
            .links
            .iter()
            .find(|link| link.url == "https://evil.example/login")
            .expect("anchor href should be extracted");
        assert_eq!(login.text.as_deref(), Some("Review invoice"));
        assert!(login.suspicious);
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://cdn.example/pixel.png")
        );
    }

    #[test]
    fn test_multipart_attachment_filename_star_is_percent_decoded() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Body\r\n\
--BOUND\r\n\
Content-Type: application/pdf; name*=utf-8''%E6%B5%8B%E8%AF%95.pdf\r\n\
Content-Disposition: attachment; filename*=utf-8''%E6%B5%8B%E8%AF%95.pdf\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8=\r\n\
--BOUND--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("Body\r\n"));
        assert_eq!(content.attachments.len(), 1);
        let attachment = &content.attachments[0];
        assert_eq!(attachment.filename, "测试.pdf");
        assert_eq!(attachment.content_type, "application/pdf");
        assert_eq!(attachment.size, 5);
        assert_eq!(attachment.content_base64.as_deref(), Some("SGVsbG8="));
    }

    #[test]
    fn test_spaced_name_parameter_cannot_hide_single_part_attachment() {
        let parser = MimeParser::new();
        let email = b"Content-Type: application/octet-stream; name = \"invoice.exe\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8=";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].filename, "invoice.exe");
        assert!(content.body_text.is_none());
    }

    #[test]
    fn test_extended_filename_overrides_conflicting_legacy_filename() {
        let disposition =
            "attachment; filename=quarterly-report.pdf; filename*=utf-8''payload%2Eexe";

        assert_eq!(
            MimeParser::extract_filename(disposition).as_deref(),
            Some("payload.exe")
        );
        assert_eq!(
            MimeParser::extract_filename("attachment; filename = \"semi;colon.exe\"").as_deref(),
            Some("semi;colon.exe")
        );
    }

    #[test]
    fn test_single_part_top_level_attachment_is_not_dropped() {
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
To: recipient@example.com\r\n\
Subject: Report\r\n\
Content-Type: application/octet-stream; name=\"report.bin\"\r\n\
Content-Disposition: attachment; filename=\"report.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8=";

        let content = parser.parse(email).unwrap();

        assert!(content.body_text.is_none());
        assert!(content.body_html.is_none());
        assert_eq!(content.attachments.len(), 1);
        let attachment = &content.attachments[0];
        assert_eq!(attachment.filename, "report.bin");
        assert_eq!(attachment.content_type, "application/octet-stream");
        assert_eq!(attachment.size, 5);
        assert_eq!(attachment.content_base64.as_deref(), Some("SGVsbG8="));
    }

    #[test]
    fn test_all_same_type_mime_alternatives_remain_visible_to_detectors() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/alternative; boundary=ALT\r\n\
\r\n\
--ALT\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Benign preview</p>\r\n\
--ALT\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<a href=\"https://evil.example/login\">Reset password</a>\r\n\
--ALT--\r\n";

        let content = parser.parse(email).unwrap();
        let html = content.body_html.as_deref().unwrap();

        assert!(html.contains("Benign preview"));
        assert!(html.contains("Reset password"));
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.example/login")
        );
    }

    #[test]
    fn test_inline_message_rfc822_part_is_preserved_for_nested_scanning() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=OUTER\r\n\
\r\n\
--OUTER\r\n\
Content-Type: text/plain\r\n\
\r\n\
Forwarded message attached\r\n\
--OUTER\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
From: attacker@example.net\r\n\
Subject: Reset password\r\n\
Content-Type: text/plain\r\n\
\r\n\
Open https://evil.example/login\r\n\
--OUTER--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].content_type, "message/rfc822");
        assert!(content.attachments[0].content_base64.is_some());
    }

    #[test]
    fn test_content_id_inline_image_is_preserved_as_attachment() {
        // PoC bypass: a QR-code image inside multipart/related carries only a
        // Content-ID (no filename, no name parameter, disposition "inline").
        // Before the fix the part was dropped entirely, so attach_qr_scan /
        // YARA / ClamAV never saw its bytes.
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/related; boundary=REL\r\n\
\r\n\
--REL\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Scan to login <img src=\"cid:qr0001@evil.example\"></p>\r\n\
--REL\r\n\
Content-Type: image/png\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-ID: <qr0001@evil.example>\r\n\
Content-Disposition: inline\r\n\
\r\n\
iVBORw0KGgo=\r\n\
--REL--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        let attachment = &content.attachments[0];
        assert_eq!(attachment.content_type, "image/png");
        assert!(
            attachment.filename.starts_with("cid_"),
            "synthetic filename should derive from Content-ID, got {}",
            attachment.filename
        );
        assert!(
            attachment.filename.ends_with(".png"),
            "synthetic filename should carry a type-derived extension, got {}",
            attachment.filename
        );
        assert_eq!(
            attachment.content_base64.as_deref(),
            Some("iVBORw0KGgo=")
        );
        // Body merging must be unaffected: the HTML part still lands in body_html.
        let html = content.body_html.as_deref().unwrap_or("");
        assert!(html.contains("Scan to login"));
    }

    #[test]
    fn test_content_id_inline_image_without_disposition_is_preserved() {
        // Many MUAs omit Content-Disposition on multipart/related images;
        // Content-ID alone must still preserve the payload as an attachment.
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/related; boundary=REL\r\n\
\r\n\
--REL\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
See the attached image.\r\n\
--REL\r\n\
Content-Type: image/jpeg\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-ID: <img2>\r\n\
\r\n\
/9j/4AAQ\r\n\
--REL--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        let attachment = &content.attachments[0];
        assert_eq!(attachment.filename, "cid_img2.jpg");
        assert_eq!(attachment.content_type, "image/jpeg");
        // text/plain body merging is unchanged.
        assert_eq!(content.body_text.as_deref(), Some("See the attached image.\r\n"));
    }

    #[test]
    fn test_content_id_on_text_parts_does_not_break_body_merging() {
        // A text/html part with a Content-ID header must still merge into the
        // body instead of becoming an attachment (existing behavior preserved).
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/related; boundary=REL\r\n\
\r\n\
--REL\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-ID: <body1>\r\n\
\r\n\
<p>Hello</p>\r\n\
--REL--\r\n";

        let content = parser.parse(email).unwrap();

        assert!(content.attachments.is_empty());
        assert_eq!(content.body_html.as_deref(), Some("<p>Hello</p>\r\n"));
    }

    #[test]
    fn test_content_id_filename_sanitization() {
        // Hostile Content-ID values must not smuggle path separators or
        // control characters into the synthesized filename.
        assert_eq!(
            MimeParser::synthesize_filename_from_content_id(
                "<../../etc/passwd>\r\nX-Injected: 1",
                "image/png"
            ),
            "cid_....etcpasswdX-Injected1.png"
        );
        assert_eq!(
            MimeParser::synthesize_filename_from_content_id("<qr@x>", "application/pdf"),
            "cid_qrx.pdf"
        );
        assert_eq!(
            MimeParser::synthesize_filename_from_content_id("<>", "application/octet-stream"),
            "cid_inline"
        );
    }

    #[test]
    fn test_oversized_header_truncates_but_keeps_body() {
        // PoC bypass (R3A): a 70KB X-Pad header (inside Postfix's default
        // 100KB header limit) used to fail the whole parse with
        // HeaderTooLarge, blinding mirror mode while the MUA rendered the
        // body. The parser must truncate the header block and keep the body.
        let parser = MimeParser::new();
        let mut email = Vec::new();
        email.extend_from_slice(b"Content-Type: text/plain\r\nX-Pad: ");
        email.extend_from_slice(&vec![b'a'; 70 * 1024]);
        email.extend_from_slice(b"\r\n\r\n");
        email.extend_from_slice("真实正文 body".as_bytes());

        let content = parser
            .parse(&email)
            .expect("oversized header must degrade, not fail the parse");

        let body = content.body_text.as_deref().unwrap_or_default();
        assert!(
            body.contains("真实正文 body"),
            "body must survive header truncation, got: {body:?}"
        );
    }

    #[test]
    fn test_missing_header_delimiter_over_budget_keeps_remainder_as_body() {
        // No \r\n\r\n inside the 64KB header budget: the remainder must be
        // scanned as body instead of being dropped.
        let parser = MimeParser::new();
        let mut email = Vec::new();
        email.extend_from_slice(b"Content-Type: text/plain\r\nX-Pad: ");
        email.extend_from_slice(&vec![b'a'; MAX_HEADER_SIZE]);
        email.extend_from_slice(b"phishing payload without delimiter");

        let content = parser
            .parse(&email)
            .expect("missing delimiter over budget must degrade, not drop the body");

        let body = content.body_text.as_deref().unwrap_or_default();
        assert!(
            body.contains("phishing payload without delimiter"),
            "remainder must be scanned as body, got: {body:?}"
        );
    }

    #[test]
    fn test_rfc2047_base64() {
        // =?utf-8?B?5Yqe5YWs5qW8?= -> " "
        let input = "=?utf-8?B?5Yqe5YWs5qW8?=";
        let decoded = decode_rfc2047(input);
        assert_eq!(decoded, "办公楼");
    }

    #[test]
    fn test_rfc2047_multiple() {
        // Multiple encoded words should be joined (whitespace between them collapsed)
        let input = "=?utf-8?B?5Yqe5YWs5qW4?= =?utf-8?B?MjY=?=";
        let decoded = decode_rfc2047(input);
        assert!(decoded.contains("26"));
    }

    #[test]
    fn test_rfc2047_plain() {
        // Plain text should pass through unchanged
        let input = "Hello World";
        let decoded = decode_rfc2047(input);
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_rfc2047_q_encoding() {
        let input = "=?utf-8?Q?Hello_World?=";
        let decoded = decode_rfc2047(input);
        assert_eq!(decoded, "Hello World");
    }

    #[test]
    fn test_ascii_helpers() {
        assert!(ascii_starts_with_ci("Multipart/Mixed", "multipart/"));
        assert!(ascii_contains_ci("text/PLAIN; charset=utf-8", "text/plain"));
        assert!(!ascii_contains_ci("text/html", "text/plain"));
    }

    #[test]
    fn test_nested_multipart_reusing_outer_boundary_degrades_to_leaf() {
        // PoC bypass (R3A): an inner multipart declaring the SAME boundary as
        // its ancestor leaves no inner delimiter inside the part (the outer
        // scan consumed every `--X` line). The recursive BoundaryNotFound used
        // to bubble up and fail the entire message while Gmail/Outlook render
        // the inner entity. The inner base64 HTML must still be extracted.
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=X\r\n\
\r\n\
--X\r\n\
Content-Type: multipart/mixed; boundary=X\r\n\
\r\n\
--X\r\n\
Content-Type: text/html; charset=\"utf-8\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGRpdj48Yj5XZWljaTwvYj48L2Rpdj4=\r\n\
--X--\r\n";

        let content = parser
            .parse(email)
            .expect("same-boundary nesting must degrade, not fail the parse");

        assert_eq!(
            content.body_html.as_deref(),
            Some("<div><b>Weici</b></div>")
        );
    }

    #[test]
    fn test_boundary_with_trailing_space_is_accepted() {
        // PoC bypass (R3A): a quoted boundary carrying RFC-permitted trailing
        // WSP used to fail validation -> NoBoundary -> whole message dropped.
        let parser = MimeParser::new();
        assert_eq!(
            MimeParser::extract_boundary("multipart/mixed; boundary=\"abc \""),
            Some("abc".to_string())
        );

        let email = b"Content-Type: multipart/mixed; boundary=\"abc \"\r\n\
\r\n\
--abc\r\n\
Content-Type: text/plain\r\n\
\r\n\
trailing-space boundary body\r\n\
--abc--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(
            content.body_text.as_deref(),
            Some("trailing-space boundary body\r\n")
        );
    }

    #[test]
    fn test_utf7_body_decodes_chinese_phishing_text() {
        // PoC bypass (R3A): charset=utf-7 is pure ASCII, so the UTF-8 fast
        // path returned the `+...-` ciphertext verbatim and every keyword
        // layer went blind (classic Outlook desktop rendering).
        // +YKh2hI0mYjdfAl44- is UTF-7 for 您的账户异常 (UTF-16BE, modified
        // base64, no padding).
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain; charset=utf-7\r\n\r\n+YKh2hI0mYjdfAl44-";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.body_text.as_deref(), Some("您的账户异常"));
    }

    #[test]
    fn test_utf7_decoder_edge_cases() {
        const TEST_MAX_OUTPUT_BYTES: usize = 1024;

        assert_eq!(
            decode_utf7(b"plain ascii", TEST_MAX_OUTPUT_BYTES).0,
            "plain ascii"
        );
        assert_eq!(decode_utf7(b"+-", TEST_MAX_OUTPUT_BYTES).0, "+");
        assert_eq!(decode_utf7(b"a+-b", TEST_MAX_OUTPUT_BYTES).0, "a+b");
        // Shift sequence terminated by a literal (no '-'): 您 then 'x'.
        assert_eq!(decode_utf7(b"+YKh2-x", TEST_MAX_OUTPUT_BYTES).0, "您x");
        // Unterminated shift sequence at EOF still decodes.
        assert_eq!(decode_utf7(b"+YKh2", TEST_MAX_OUTPUT_BYTES).0, "您");
    }

    #[test]
    fn test_rfc2047_utf7_subject() {
        // PoC bypass (R3A): =?UTF-7?Q?...?= subjects fell through to lossy
        // ASCII because WHATWG excludes UTF-7 from Encoding::for_label.
        let decoded = decode_rfc2047("=?UTF-7?Q?+YKh2hI0mYjdfAl44-?=");
        assert_eq!(decoded, "您的账户异常");
    }

    #[test]
    fn test_bare_html_body_without_content_type_is_exposed_as_html() {
        // PoC bypass (R3A): with no top-level Content-Type the entity defaults
        // to text/plain, leaving body_html empty and html_scan not_applicable
        // — while Outlook/Apple Mail sniff and render a bare <html> body.
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
Subject: verify\r\n\
\r\n\
<html><body><a href=\"https://evil.example/login\">verify account</a></body></html>";

        let content = parser.parse(email).unwrap();

        let html = content
            .body_html
            .as_deref()
            .expect("bare HTML body must populate body_html");
        assert!(html.contains("<html>"));
        assert!(
            content
                .links
                .iter()
                .any(|link| link.url == "https://evil.example/login")
        );
    }

    #[test]
    fn test_plain_text_body_is_not_misclassified_as_html() {
        // Guard: ordinary text that merely mentions HTML later must not be
        // exposed as body_html (only leading <html>/<!doctype/<body sniff).
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain\r\n\
\r\n\
Just text mentioning <html> later in the sentence.";

        let content = parser.parse(email).unwrap();

        assert!(content.body_html.is_none());
    }

    // ─── R4C: uuencode frame decoding (item C-02) ───

    #[test]
    fn test_uuencode_cte_decodes_to_named_attachment() {
        // PoC bypass (R4C): `Content-Transfer-Encoding: x-uuencode` used to
        // fall through parse_encoding to 7bit passthrough, so the encoded
        // `begin 644 evil.exe` payload stayed opaque text and NO attachment
        // was ever registered — dangerous-extension / magic-bytes / YARA all
        // went blind while classic MUAs auto-extract the file.
        // "#35J0" is the hand-verified uuencode of the 3 bytes "MZ\x90".
        let parser = MimeParser::new();
        let email = b"From: sender@example.com\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: x-uuencode\r\n\
\r\n\
begin 644 evil.exe\r\n\
#35J0\r\n\
`\r\n\
end\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1, "frame must become an attachment");
        let attachment = &content.attachments[0];
        assert_eq!(
            attachment.filename, "evil.exe",
            "the frame's own filename must drive extension checks"
        );
        assert_eq!(
            attachment.content_base64.as_deref(),
            Some("TVqQ"),
            "payload must decode to the PE prefix (base64 of MZ\\x90)"
        );
    }

    #[test]
    fn test_uuencode_frame_sniffed_in_7bit_body_with_preamble() {
        // PoC bypass (R4C): no CTE at all — a text/plain body carrying a
        // uuencode frame after a prose preamble. Old MUAs extract the file;
        // the parser must too, and keep the prose visible to body scanners.
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain\r\n\
\r\n\
Here is the invoice you requested.\r\n\
begin 644 invoice.exe\r\n\
#35J0\r\n\
`\r\n\
end\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].filename, "invoice.exe");
        assert_eq!(content.attachments[0].content_base64.as_deref(), Some("TVqQ"));
        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("Here is the invoice you requested.")),
            "preamble text must stay in the body: {:?}",
            content.body_text
        );
    }

    #[test]
    fn test_uuencode_prose_is_not_decoded() {
        // Guard: prose that merely resembles a frame header must not be
        // swallowed into a phantom attachment.
        let parser = MimeParser::new();
        let email = b"Content-Type: text/plain\r\n\
\r\n\
We begin 644 days of celebration next week.\r\n\
The agenda follows.\r\n";

        let content = parser.parse(email).unwrap();

        assert!(content.attachments.is_empty());
        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("The agenda follows."))
        );

        // Header-shaped line with non-uuencode following text: rejected.
        let email = b"Content-Type: text/plain\r\n\
\r\n\
begin 644 notes\r\n\
then we talked about the roadmap for next year.\r\n";
        let content = parser.parse(email).unwrap();
        assert!(content.attachments.is_empty());
        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("roadmap"))
        );
    }

    // ─── R4C: RFC 2231 continuation filenames (item C-04) ───

    #[test]
    fn test_rfc2231_continued_filename_is_reassembled() {
        // PoC bypass (R4C): a filename split across RFC 2231 continuation
        // segments used to be invisible (only single-section filename* was
        // recognized), so `攻 击.exe` split mid-name escaped the dangerous
        // extension check entirely.
        let disposition =
            "attachment; filename*0*=utf-8''%E6%94%BB%E5%87%BB; filename*1*=%2Eexe";
        assert_eq!(
            MimeParser::extract_filename(disposition).as_deref(),
            Some("攻击.exe")
        );

        // Unstarred plain segments concatenate literally.
        assert_eq!(
            MimeParser::extract_filename("attachment; filename*0=pay; filename*1=load.exe")
                .as_deref(),
            Some("payload.exe")
        );
    }

    #[test]
    fn test_rfc2231_continuation_overrides_benign_legacy_filename() {
        // MUAs honor the continuation series over `filename=`; selecting the
        // legacy name first would let "innocent.pdf" hide "evil.exe".
        let disposition =
            "attachment; filename=innocent.pdf; filename*0*=utf-8''evil; filename*1*=.exe";
        assert_eq!(
            MimeParser::extract_filename(disposition).as_deref(),
            Some("evil.exe")
        );
    }

    #[test]
    fn test_rfc2231_continued_filename_in_multipart() {
        let parser = MimeParser::new();
        let email = b"Content-Type: multipart/mixed; boundary=BOUND\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain\r\n\
\r\n\
Body\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename*0*=utf-8''%E6%94%BB%E5%87%BB; filename*1*=%2Eexe\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
SGVsbG8=\r\n\
--BOUND--\r\n";

        let content = parser.parse(email).unwrap();

        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].filename, "攻击.exe");
        assert_eq!(content.body_text.as_deref(), Some("Body\r\n"));
    }

    // ─── R4C: truncation / coverage-gap flags (item 6) ───

    #[test]
    fn test_oversized_attachment_keeps_metadata_and_flags_truncated() {
        // PoC bypass (R4C): a >32MB attachment used to fail the WHOLE parse
        // via the cumulative budget error. It must become a metadata-only
        // attachment (hash still usable) with the truncated flag set.
        let parser = MimeParser::new();
        let mut content = EmailContent::new();
        let oversized = DecodedContent::plain(vec![0u8; MAX_ATTACHMENT_SAVE_SIZE + 1]);
        parser
            .apply_decoded_part(
                &mut content,
                "application/octet-stream; name=\"big.bin\"",
                "attachment; filename=\"big.bin\"",
                None,
                true,
                oversized,
            )
            .expect("oversized attachment must degrade, not fail");

        assert!(content.truncated);
        assert_eq!(content.attachments.len(), 1);
        assert!(content.attachments[0].content_base64.is_none());
        assert_eq!(content.attachments[0].size, MAX_ATTACHMENT_SAVE_SIZE + 1);
    }

    #[test]
    fn test_deeply_nested_message_keeps_outer_layers() {
        // PoC bypass (R4C): content parked past depth 10 used to kill the
        // whole parse. The outer text part must still be scanned.
        let parser = MimeParser::new();
        let mut email = b"Content-Type: multipart/mixed; boundary=L0\r\n\r\n".to_vec();
        email.extend_from_slice(b"--L0\r\nContent-Type: text/plain\r\n\r\nouter body survives\r\n");
        for level in 1..=12 {
            email.extend_from_slice(
                format!(
                    "--L{}\r\nContent-Type: multipart/mixed; boundary=L{}\r\n\r\n",
                    level - 1,
                    level
                )
                .as_bytes(),
            );
        }
        email.extend_from_slice(b"--L12\r\nContent-Type: text/plain\r\n\r\nhidden deep\r\n");
        for level in (0..=12).rev() {
            email.extend_from_slice(format!("--L{level}--\r\n").as_bytes());
        }

        let content = parser
            .parse(&email)
            .expect("deep nesting must degrade, not fail the parse");
        assert!(content.truncated);
        assert!(
            content
                .body_text
                .as_deref()
                .is_some_and(|body| body.contains("outer body survives")),
            "outer layers must survive depth degradation: {:?}",
            content.body_text
        );
    }
}
