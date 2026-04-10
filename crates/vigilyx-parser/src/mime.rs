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
const MAX_ATTACHMENT_SAVE_SIZE: usize = 1024 * 1024 * 1024; // 1 GB

/// multipart large depth
const MAX_MULTIPART_DEPTH: usize = 10;

/// levelProcessof MIME part total,prevent O(k^2)
const MAX_TOTAL_PARTS: usize = 200;

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
}

impl HeaderIndex {
   /// Time/CountTraverse Index, Time/Count find() of O(n*m)
    fn build(headers: &[(String, String)]) -> Self {
        let mut idx = HeaderIndex {
            content_type: None,
            content_transfer_encoding: None,
            content_disposition: None,
        };
        for (i, (name, _)) in headers.iter().enumerate() {
            if idx.content_type.is_none() && name.eq_ignore_ascii_case("Content-Type") {
                idx.content_type = Some(i);
            } else if idx.content_transfer_encoding.is_none()
                && name.eq_ignore_ascii_case("Content-Transfer-Encoding")
            {
                idx.content_transfer_encoding = Some(i);
            } else if idx.content_disposition.is_none()
                && name.eq_ignore_ascii_case("Content-Disposition")
            {
                idx.content_disposition = Some(i);
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

            if ascii_contains_ci(content_type, "text/plain") {
                content.body_text = Some(decode_charset(&decoded, content_type));
            } else if ascii_contains_ci(content_type, "text/html") {
                content.body_html = Some(decode_charset(&decoded, content_type));
            }

            if missing_top_level_content_type {
                self.try_salvage_embedded_multipart(&mut content, body_bytes)?;
            }
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
        Ok(())
    }

    fn salvage_embedded_parts_relaxed(&self, body: &[u8]) -> Result<EmailContent, MimeError> {
        let trimmed = Self::trim_ascii_leading_newlines(body);
        let mut content = EmailContent::new();
        let mut cursor = 0usize;

        while let Some(boundary_start) = Self::find_boundary_line_start(trimmed, cursor) {
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

            let next_boundary = Self::find_boundary_line_start(trimmed, cursor).unwrap_or(trimmed.len());
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
            let part_content_type = idx.content_type(&headers);
            let part_encoding = idx.encoding(&headers);
            let decoded = self.decode_content(part_body, part_encoding)?;
            let content_disposition = idx.disposition(&headers);
            let is_attachment = ascii_contains_ci(content_disposition, "attachment")
                || Self::extract_filename(content_disposition).is_some()
                || Self::extract_filename(part_content_type).is_some();

            self.apply_decoded_part(
                &mut content,
                part_content_type,
                content_disposition,
                is_attachment,
                decoded,
            );
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
        if boundary.is_empty() || boundary.contains(char::is_whitespace) {
            return None;
        }
        let boundary = boundary.strip_suffix("--").unwrap_or(boundary).trim();
        if boundary.len() < 3 {
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
                && bytes.get(pos + 2).is_some_and(|b| !matches!(b, b'\r' | b'\n'))
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
                return Err(MimeError::HeaderTooLarge);
            }
            return Ok((&data[..pos], &data[pos + 4..]));
        }
       // : \n\n (Unix, MTA Use \r)
        if let Some(pos) = self.header_end_finder_lf.find(data) {
            if pos > MAX_HEADER_SIZE {
                return Err(MimeError::HeaderTooLarge);
            }
            return Ok((&data[..pos], &data[pos + 2..]));
        }
       // not find linedelimited,possiblyonly Header
        if data.len() > MAX_HEADER_SIZE {
            Ok((&data[..MAX_HEADER_SIZE], &[]))
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
            warn!("multipart 递归depth超限 ({}), hops", depth);
            return Ok(());
        }

        if *total_parts >= MAX_TOTAL_PARTS {
            warn!("multipart 总 part 数超限 ({}), hops后续部分", *total_parts);
            return Ok(());
        }

       // Extract boundary
        let boundary = Self::extract_boundary(content_type).ok_or(MimeError::NoBoundary)?;
        let boundary_marker = format!("--{}", boundary);
        let boundary_bytes = boundary_marker.as_bytes();

       // SIMD boundary bit (Iterate collect)
        let finder = memmem::Finder::new(boundary_bytes);
        let positions: Vec<usize> = finder.find_iter(body).collect();

        for i in 0..positions.len() {
           // Check total parts budget before processing each part
            if *total_parts >= MAX_TOTAL_PARTS {
                warn!("multipart 总 part 数超限 ({}), hops后续部分", *total_parts);
                break;
            }
           *total_parts += 1;

            let part_start = positions[i] + boundary_bytes.len();
            let part_end = positions.get(i + 1).copied().unwrap_or(body.len());

            if part_start >= part_end {
                continue;
            }

            let part_data = &body[part_start..part_end];

           // Checkwhether EndMark (--boundary--)
            if part_data.starts_with(b"--") {
                continue;
            }

           // hops CRLF
            let part_data = if part_data.starts_with(b"\r\n") {
                &part_data[2..]
            } else if part_data.starts_with(b"\n") {
                &part_data[1..]
            } else {
                part_data
            };

            if part_data.is_empty() {
                continue;
            }

           // Parse ofHeaderAndContent
            if let Ok((part_headers, part_body)) = self.split_headers_body(part_data) {
                let headers = self.parse_headers(part_headers).unwrap_or_default();
                let idx = HeaderIndex::build(&headers);

                let part_content_type = idx.content_type(&headers);
                let part_encoding = idx.encoding(&headers);

               // of multipart (depthlimit)
                if ascii_starts_with_ci(part_content_type, "multipart/") {
                    self.parse_multipart_inner(
                        content,
                        part_content_type,
                        part_body,
                        depth + 1,
                        total_parts,
                    )?;
                    continue;
                }

               // DecodeContent
                let decoded = self.decode_content(part_body, part_encoding)?;

               // Judge Attachment body
                let content_disposition = idx.disposition(&headers);

                let is_attachment = ascii_contains_ci(content_disposition, "attachment")
                    || Self::extract_filename(content_disposition).is_some()
                    || Self::extract_filename(part_content_type).is_some();

                self.apply_decoded_part(
                    content,
                    part_content_type,
                    content_disposition,
                    is_attachment,
                    decoded,
                );
            }
        }

        Ok(())
    }

    fn apply_decoded_part(
        &self,
        content: &mut EmailContent,
        part_content_type: &str,
        content_disposition: &str,
        is_attachment: bool,
        decoded: Vec<u8>,
    ) {
        if is_attachment {
            if content.attachments.len() >= MAX_ATTACHMENTS {
                warn!("AttachmentCount超限，hops");
                return;
            }

            let filename = Self::extract_filename(content_disposition)
                .or_else(|| Self::extract_filename(part_content_type))
                .unwrap_or_else(|| format!("attachment_{}", content.attachments.len()));

            let hash = Self::compute_hash(&decoded);
            let size = decoded.len();

            let content_base64 = if size <= MAX_ATTACHMENT_SAVE_SIZE {
                Some(Self::encode_base64(&decoded))
            } else {
                warn!(
                    filename = %filename,
                    size_bytes = size,
                    limit_bytes = MAX_ATTACHMENT_SAVE_SIZE,
                    "SEC: Oversized attachment — content scanning bypassed, only hash/metadata checks apply"
                );
                None
            };

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

            return;
        }

        if ascii_contains_ci(part_content_type, "text/plain") && content.body_text.is_none() {
            content.body_text = Some(decode_charset(&decoded, part_content_type));
        } else if ascii_contains_ci(part_content_type, "text/html") && content.body_html.is_none()
        {
            content.body_html = Some(decode_charset(&decoded, part_content_type));
        }
    }

   /// Extract boundary Parameter
    fn extract_boundary(content_type: &str) -> Option<String> {
       // sizewrite "boundary=" (Avoid to_lowercase Allocate)
        let bytes = content_type.as_bytes();
        let needle = b"boundary=";
        let pos = bytes.windows(needle.len()).position(|w| {
            w.iter()
                .zip(needle.iter())
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })?;

        let rest = &content_type[pos + 9..];
        let boundary = if let Some(stripped) = rest.strip_prefix('"') {
            stripped.split('"').next()?
        } else {
            rest.split(';').next()?.split_whitespace().next()?
        };
        Some(boundary.to_string())
    }

   /// ExtractFileName (Performance notes: 1ofsizewrite)
    fn extract_filename(s: &str) -> Option<String> {
        let bytes = s.as_bytes();

       // filename="xxx"
        if let Some(pos) = ascii_find_ci(bytes, b"filename=") {
           // Exclude filename*= (1 Process)
            if pos + 9 < bytes.len() && bytes[pos + 9] != b'*' {
                let rest = &s[pos + 9..];
                let filename = if let Some(stripped) = rest.strip_prefix('"') {
                    stripped.split('"').next()?
                } else {
                    rest.split(';').next()?.split_whitespace().next()?
                };
                if !filename.is_empty() {
                    return Some(filename.to_string());
                }
            }
        }

       // filename*=utf-8''xxx
        if let Some(pos) = ascii_find_ci(bytes, b"filename*=") {
            let rest = &s[pos + 10..];
            if let Some(quote_pos) = rest.find("''") {
                let encoded = rest[quote_pos + 2..].split(';').next()?;
                if let Ok(decoded) = urlencoding::decode(encoded) {
                    return Some(decoded.to_string());
                }
            }
        }

       // name="xxx"
        if let Some(pos) = ascii_find_ci(bytes, b"name=") {
            let rest = &s[pos + 5..];
            let name = if let Some(stripped) = rest.strip_prefix('"') {
                stripped.split('"').next()?
            } else {
                rest.split(';').next()?.split_whitespace().next()?
            };
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }

        None
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
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("base64") {
            TransferEncoding::Base64
        } else if trimmed.eq_ignore_ascii_case("quoted-printable") {
            TransferEncoding::QuotedPrintable
        } else if trimmed.eq_ignore_ascii_case("8bit") {
            TransferEncoding::EightBit
        } else if trimmed.eq_ignore_ascii_case("binary") {
            TransferEncoding::Binary
        } else {
            TransferEncoding::SevenBit
        }
    }

   /// DecodeContent
    fn decode_content(
        &self,
        data: &[u8],
        encoding: TransferEncoding,
    ) -> Result<Vec<u8>, MimeError> {
        match encoding {
            TransferEncoding::Base64 => Self::decode_base64(data),
            TransferEncoding::QuotedPrintable => Self::decode_quoted_printable(data),
            _ => Ok(data.to_vec()),
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
            while let Some(start) = text[pos..].find(prefix) {
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

/// ByteArrayMediumsizewrite (ReturnFirstmatchbit)
#[inline]
fn ascii_find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

/// From Content-Type MediumExtract charset Parameter
/// : "text/plain; charset=GBK" -> Some("GBK")
/// : "text/html; charset=\"UTF-8\"" -> Some("UTF-8")
fn extract_charset(content_type: &str) -> Option<&str> {
   // lookup "charset=" (sizewrite Sensitive)
    let lower = content_type.as_bytes();
    let needle = b"charset=";
    let pos = lower
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))?;
    let rest = &content_type[pos + needle.len()..];
   // possiblyof Number
    let rest = rest.trim_start_matches('"').trim_start_matches('\'');
   // Get delimited
    let end = rest
        .find([';', ' ', '"', '\'', '\r', '\n'])
        .unwrap_or(rest.len());
    let charset = &rest[..end];
    if charset.is_empty() {
        None
    } else {
        Some(charset)
    }
}

/// according to Content-Type Mediumof charset ByteDecode UTF-8 String
/// GBK, GB2312, GB18030, Big5, ISO-8859-*, Shift_JIS wait Encode
fn decode_charset(data: &[u8], content_type: &str) -> String {
   // UTF-8 (, Scenario)
    if let Ok(s) = std::str::from_utf8(data) {
        return s.to_owned();
    }

   // Extract charset Parameter
    if let Some(charset_name) = extract_charset(content_type) {
       // encoding_rs lookupEncodehandler (Name: gbk/gb2312 -> GBK, big5, shift_jis, iso-8859-1 wait)
        if let Some(encoding) = Encoding::for_label(charset_name.as_bytes()) {
            let (decoded, _, had_errors) = encoding.decode(data);
            if !had_errors {
                return decoded.into_owned();
            }
           // immediately Error UTF-8 lossy
            return decoded.into_owned();
        }
        warn!("Unknowncharacters集: {}, 回退到 UTF-8 lossy", charset_name);
    }

   // charset UnknownEncode: UTF-8 lossy
    String::from_utf8_lossy(data).into_owned()
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
   /// Header large
    HeaderTooLarge,
   /// Invalidof UTF-8
    InvalidUtf8,
   /// boundary
    NoBoundary,
   /// Base64 DecodeError
    Base64DecodeError,
   /// Quoted-Printable DecodeError
    QuotedPrintableError,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(content.body_html.as_deref(), Some("<div><b>Weici</b></div>"));
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

        assert!(content
            .body_text
            .as_deref()
            .is_some_and(|body| body.contains("该邮件可能存在恶意内容")));
        assert!(content
            .body_html
            .as_deref()
            .is_some_and(|body| body.contains("检测结果：垃圾邮件")));
        assert_eq!(content.attachments.len(), 1);
        assert_eq!(content.attachments[0].filename, "warn.jpg");
        assert!(content.attachments[0].content_base64.is_some());
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
        assert_eq!(
            ascii_find_ci(b"Content-Type: text", b"content-type"),
            Some(0)
        );
    }
}
