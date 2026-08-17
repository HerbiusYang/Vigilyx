//! Document text extraction module.
//!
//! Extracts plain text from DOCX/XLSX/PPTX/PDF/OLE binary files
//! for DLP module sensitive data scanning.
//!
//! Supported formats:
//! - OOXML (DOCX/XLSX/PPTX) - ZIP decompression + XML parsing
//! - PDF - text stream extraction (Tj/TJ text operators)
//! - OLE (.doc/.xls) - lossy UTF-8 readable string extraction
//!
//! Output is capped at 50 MB of extracted text.

use std::io::Read;
use tracing::debug;
use vigilyx_core::magic_bytes::DetectedFileType;

/// Hard limit for total extracted document text size (prevents zip-bomb OOM).
const MAX_EXTRACT_LEN: usize = 50 * 1024 * 1024; // 50 MB total

/// Hard limit for the decompressed size of a single ZIP entry.
const MAX_ENTRY_SIZE: usize = 10 * 1024 * 1024; // 10 MB per entry

/// Chunk size for streaming reads (avoids preallocating based on file.size()).
const STREAM_CHUNK_SIZE: usize = 64 * 1024; // 64 KB

/// Extract plain text from binary file data.
///
/// Automatically selects the extraction method based on `file_type`.
/// Returns `None` if extraction is not supported or yields no text.
pub fn extract_text(data: &[u8], file_type: Option<DetectedFileType>) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let ft = file_type?;

    let result = match ft {
        DetectedFileType::ZipArchive => extract_ooxml_text(data),
        DetectedFileType::Pdf => extract_pdf_text(data),
        DetectedFileType::OleCompound => extract_ole_text(data),
        DetectedFileType::Rtf => extract_rtf_text(data),
        _ => None,
    };

    // Truncate if over limit
    result
        .map(|text| {
            if text.len() > MAX_EXTRACT_LEN {
                let mut end = MAX_EXTRACT_LEN;
                while end > 0 && !text.is_char_boundary(end) {
                    end -= 1;
                }
                text[..end].to_string()
            } else {
                text
            }
        })
        .filter(|t| !t.trim().is_empty())
}

/// Safely read a ZIP entry: stream the contents, do not trust file.size(), and enforce dual limits.
/// Prevents a zip bomb from triggering large allocations by forging the entry size.
fn safe_read_zip_entry<R: Read>(
    mut entry: zip::read::ZipFile<'_, R>,
    remaining_budget: usize,
) -> Option<String> {
    let limit = remaining_budget.min(MAX_ENTRY_SIZE);
    let mut buf = Vec::with_capacity(STREAM_CHUNK_SIZE.min(limit));
    let mut total = 0usize;
    let mut chunk = [0u8; STREAM_CHUNK_SIZE];

    loop {
        let to_read = chunk.len().min(limit - total);
        if to_read == 0 {
            break;
        }
        match entry.read(&mut chunk[..to_read]) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                total += n;
                if total >= limit {
                    debug!(entry_name = ?entry.name(), total, limit, "ZIP entry hit size limit, truncating");
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if buf.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// From OOXML (DOCX/XLSX/PPTX) ExtractText

/// OOXML File ZIP packet, Contains XML File:
/// - DOCX: `word/document.xml`
/// - XLSX: `xl/sharedStrings.xml` + `xl/worksheets/sheet*.xml`
/// - PPTX: `ppt/slides/slide*.xml`
fn extract_ooxml_text(data: &[u8]) -> Option<String> {
    let cursor = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;

    let mut all_text = String::with_capacity(8192);

    // According toprioritylevel readGet Same OOXML ofTextFile
    let target_files = [
        // DOCX
        "word/document.xml",
        // XLSX - shared strings packetContains Yuan Text
        "xl/sharedStrings.xml",
    ];

    for &name in &target_files {
        if let Ok(file) = archive.by_name(name) {
            if all_text.len() >= MAX_EXTRACT_LEN {
                break;
            }
            if let Some(content) = safe_read_zip_entry(file, MAX_EXTRACT_LEN - all_text.len()) {
                let text = strip_xml_tags(&content);
                if !text.is_empty() {
                    if !all_text.is_empty() {
                        all_text.push('\n');
                    }
                    all_text.push_str(&text);
                }
            }
        }
    }

    // PPTX: enumerate every slide, not just slide1-3 — lure text parked on
    // slide 4+ must not become a blind spot. Names are collected first so
    // the archive borrow ends before entry reads.
    const MAX_OOXML_SLIDES: usize = 256;
    let mut slide_names: Vec<String> = Vec::new();
    for index in 0..archive.len() {
        let Ok(entry) = archive.by_index(index) else {
            continue;
        };
        let name = entry.name();
        if name.starts_with("ppt/slides/slide") && name.ends_with(".xml") {
            slide_names.push(name.to_string());
        }
    }
    slide_names.sort();
    slide_names.truncate(MAX_OOXML_SLIDES);
    for name in &slide_names {
        if all_text.len() >= MAX_EXTRACT_LEN {
            break;
        }
        if let Ok(file) = archive.by_name(name)
            && let Some(content) = safe_read_zip_entry(file, MAX_EXTRACT_LEN - all_text.len())
        {
            let text = strip_xml_tags(&content);
            if !text.is_empty() {
                if !all_text.is_empty() {
                    all_text.push('\n');
                }
                all_text.push_str(&text);
            }
        }
    }

    for i in 1..=10 {
        let sheet_name = format!("xl/worksheets/sheet{}.xml", i);
        if let Ok(file) = archive.by_name(&sheet_name) {
            if all_text.len() >= MAX_EXTRACT_LEN {
                break;
            }
            if let Some(content) = safe_read_zip_entry(file, MAX_EXTRACT_LEN - all_text.len()) {
                let text = strip_xml_tags(&content);
                if !text.is_empty() {
                    all_text.push('\n');
                    all_text.push_str(&text);
                }
            }
        } else {
            // A missing intermediate sheet number just means a sheet was
            // deleted; later sheets still exist and must be scanned.
            continue;
        }
    }

    if all_text.is_empty() {
        debug!("OOXML: no text content extracted");
        None
    } else {
        debug!(len = all_text.len(), "OOXML: text extraction successful");
        Some(all_text)
    }
}

/// From PDF MediumExtractText

/// Method: PDF MediumofTextOperations (Tj, TJ, ')
/// And Number of (literal strings).
/// CIDFont/ToUnicode Mappingof PDF,But Processlarge PDF.
///
/// Real-world PDFs compress their content streams with FlateDecode, which
/// hides EVERY text operator from the raw byte view. After the raw pass we
/// inflate each FlateDecode stream (long form `/FlateDecode` and the ISO 32000
/// abbreviation `/Fl`; bounded count + total budget, zip-bomb safe) and run
/// the same literal/hex string extraction on the decoded layer.
fn extract_pdf_text(data: &[u8]) -> Option<String> {
    let mut text = String::with_capacity(4096);

    extract_pdf_text_operators(&String::from_utf8_lossy(data), &mut text);

    for layer in inflate_pdf_flate_streams(data) {
        extract_pdf_text_operators(&String::from_utf8_lossy(&layer), &mut text);
        if text.len() >= MAX_EXTRACT_LEN {
            break;
        }
    }

    if text.is_empty() {
        debug!("PDF: no text content extracted");
        None
    } else {
        debug!(len = text.len(), "PDF: text extraction successful");
        Some(text)
    }
}

/// Upper bound of FlateDecode streams inflated per PDF (CPU budget).
///
/// 64 -> 512 (A3): 攻击者曾可用 64 个 1 字节良性流把载荷推到第 65 个流
/// 逃逸检查。总解压字节由 MAX_PDF_TOTAL_INFLATE_BYTES 兜底, 放宽个数
/// 不放宽总量。
const MAX_PDF_STREAMS_TO_INFLATE: usize = 512;
/// Per-stream decompressed size budget (zip-bomb guard).
const MAX_PDF_STREAM_INFLATE_BYTES: usize = 8 * 1024 * 1024;
/// 单个 PDF 全部流共享的总解压预算 (A3: 按流大小分配预算, 小流多放行,
/// 大流提前耗尽预算即停)。
const MAX_PDF_TOTAL_INFLATE_BYTES: usize = 32 * 1024 * 1024;
/// 从 `stream` 关键字回溯定位所属字典的范围上限 (A3: 原为固定 512B 窗口,
/// 攻击者塞 >512B 合法无关键即可把 /Filter 推出窗口)。
const PDF_STREAM_DICT_MAX_BACKTRACK: usize = 256 * 1024;

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Locate the dictionary that owns a `stream` keyword at `keyword` (A3).
///
/// The dictionary is the last *balanced* `<< ... >>` block closing before the
/// keyword; a depth-counter scan tolerates both arbitrarily large dictionaries
/// (>512B of inert keys no longer push `/Filter` out of view) and nested
/// dictionaries. Falls back to the old 512-byte window for malformed input.
fn stream_dict_span(data: &[u8], keyword: usize) -> (usize, usize) {
    let region_start = keyword.saturating_sub(PDF_STREAM_DICT_MAX_BACKTRACK);
    let region = &data[region_start..keyword];

    let mut depth = 0usize;
    let mut open_at = 0usize;
    let mut span: Option<(usize, usize)> = None;
    let mut i = 0usize;
    while i + 1 < region.len() {
        if region[i] == b'<' && region[i + 1] == b'<' {
            if depth == 0 {
                open_at = i;
            }
            depth += 1;
            i += 2;
        } else if region[i] == b'>' && region[i + 1] == b'>' {
            if depth > 0 {
                depth -= 1;
                if depth == 0 {
                    span = Some((open_at, i + 2));
                }
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    match span {
        Some((s, e)) => (region_start + s, region_start + e),
        None => (keyword.saturating_sub(512), keyword),
    }
}

/// True when the (name-escape-normalized) stream dictionary declares
/// FlateDecode — long form `/FlateDecode` or the ISO 32000 abbreviation
/// `/Fl` (A3). `/Fl` requires a non-name byte right after it, so lookalike
/// names such as `/FlXxx` never match.
fn dict_declares_flate(dict: &[u8]) -> bool {
    if dict
        .windows(b"/FlateDecode".len())
        .any(|w| w == b"/FlateDecode")
    {
        return true;
    }
    let mut i = 0usize;
    while i + 3 <= dict.len() {
        if &dict[i..i + 3] == b"/Fl" {
            // '#' excluded: `/Fl#61teDecode` normalizes to `/FlateDecode`
            // (handled above); a *truncated* escape like `/Fl#6` must not
            // count as the `/Fl` abbreviation.
            let boundary = dict
                .get(i + 3)
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'#');
            if boundary {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Inflate the FlateDecode streams of a PDF, each bounded by
/// MAX_PDF_STREAM_INFLATE_BYTES and all together by
/// MAX_PDF_TOTAL_INFLATE_BYTES. Streams failing to inflate are skipped;
/// extraction continues on the remaining layers.
fn inflate_pdf_flate_streams(data: &[u8]) -> Vec<Vec<u8>> {
    use flate2::read::ZlibDecoder;

    let mut layers = Vec::new();
    let mut cursor = 0usize;
    let mut total_budget = MAX_PDF_TOTAL_INFLATE_BYTES;

    while layers.len() < MAX_PDF_STREAMS_TO_INFLATE && total_budget > 0 {
        let Some(relative) = find_subslice(&data[cursor..], b"stream") else {
            break;
        };
        let keyword = cursor + relative;
        cursor = keyword + 6;
        // "endstream" contains "stream" — skip over it.
        if keyword >= 3 && &data[keyword - 3..keyword] == b"end" {
            continue;
        }

        // The stream dictionary precedes the keyword; filter names tolerate
        // `#hh` escapes (e.g. /Fl#61teDecode) and the ISO 32000 short form
        // `/Fl`. The dictionary span is found by balanced `<<`/`>>` scanning
        // instead of a fixed 512-byte window (A3). The legacy 512-byte window
        // is checked as a union fallback so edge cases the old code caught
        // (e.g. literal `>>` inside a dict string confusing the balance scan)
        // cannot regress.
        let (dict_start, dict_end) = stream_dict_span(data, keyword);
        let dict =
            vigilyx_core::magic_bytes::normalize_pdf_name_escapes(&data[dict_start..dict_end]);
        let win_start = keyword.saturating_sub(512);
        let legacy_window =
            vigilyx_core::magic_bytes::normalize_pdf_name_escapes(&data[win_start..keyword]);
        if !dict_declares_flate(&dict) && !dict_declares_flate(&legacy_window) {
            continue;
        }

        // Stream data starts after the EOL that follows the `stream` keyword.
        // ISO 32000 allows CRLF, LF, or a lone CR (old Mac EOL, tolerated by
        // readers); skipping lone CR used to blind the whole stream (A3).
        let data_start = if data.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor + 2
        } else if matches!(data.get(cursor), Some(&c) if c == b'\n' || c == b'\r') {
            cursor + 1
        } else {
            continue;
        };
        let Some(relative_end) = find_subslice(&data[data_start..], b"endstream") else {
            break;
        };
        let data_end = data_start + relative_end;
        cursor = data_end + 9;

        // 按流分配预算: 单流不超过 per-stream 上限, 也不超过剩余总预算
        let stream_budget = MAX_PDF_STREAM_INFLATE_BYTES.min(total_budget) as u64;
        let mut layer = Vec::new();
        let decoder = ZlibDecoder::new(&data[data_start..data_end]);
        if decoder
            .take(stream_budget)
            .read_to_end(&mut layer)
            .is_ok()
            && !layer.is_empty()
        {
            total_budget = total_budget.saturating_sub(layer.len());
            layers.push(layer);
        }
    }

    layers
}

/// Extract text operators (`(literal) Tj`, `<hex> Tj`) from one PDF content
/// view (raw bytes or an inflated stream layer).
fn extract_pdf_text_operators(content: &str, text: &mut String) {
    // Extract Number ofText: (Hello World) Tj
    let mut in_paren = false;
    let mut depth = 0u32;
    let mut current = String::new();

    for ch in content.chars() {
        if ch == '(' && !in_paren {
            in_paren = true;
            depth = 1;
            current.clear();
        } else if in_paren {
            if ch == '(' {
                depth += 1;
                current.push(ch);
            } else if ch == ')' {
                depth -= 1;
                if depth == 0 {
                    in_paren = false;
                    // TextContent (characters, Streamwait)
                    push_pdf_string(&current, text);
                } else {
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        }

        if text.len() >= MAX_EXTRACT_LEN {
            break;
        }
    }

    // Hex strings: `<48656C6C6F> Tj` and TJ arrays carry the same text for
    // CID-keyed fonts; the raw byte view never decodes them. `<<` (dict open)
    // is skipped, and tokens are size-capped so embedded hex blobs cannot
    // flood the extractor.
    let bytes = content.as_bytes();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        if text.len() >= MAX_EXTRACT_LEN {
            break;
        }
        if bytes[cursor] != b'<' {
            cursor += 1;
            continue;
        }
        if bytes.get(cursor + 1) == Some(&b'<') {
            cursor += 2;
            continue;
        }
        let token_start = cursor + 1;
        let mut token_end = token_start;
        while token_end < bytes.len() && bytes[token_end] != b'>' {
            token_end += 1;
        }
        cursor = token_end + 1;
        let token = &content[token_start..token_end.min(content.len())];
        if token.len() < 4 || token.len() > 8192 {
            continue;
        }
        let hex_digits: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        if hex_digits.len() < 4
            || !hex_digits.len().is_multiple_of(2)
            || !hex_digits.chars().all(|c| c.is_ascii_hexdigit())
        {
            continue;
        }
        let raw: Vec<u8> = (0..hex_digits.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex_digits[i..i + 2], 16).ok())
            .collect();
        if raw.len() < 2 || raw.len() > 4096 {
            continue;
        }
        // CID-font hex strings are usually UTF-16BE; ASCII hex strings decode
        // directly. Prefer UTF-16BE only when it decodes strictly AND the
        // UTF-8 view is degraded (replacement chars / no alphanumerics) —
        // otherwise even-length ASCII ("48656C6C" = "Hell") would flip into
        // bogus CJK.
        let utf8 = String::from_utf8_lossy(&raw).into_owned();
        let utf8_degraded = utf8.contains(char::REPLACEMENT_CHARACTER)
            || !utf8.chars().any(|c| c.is_alphanumeric() || c > '\u{4e00}');
        let decoded = if raw.len().is_multiple_of(2) && utf8_degraded {
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            match String::from_utf16(&units) {
                Ok(text) => text,
                Err(_) => utf8,
            }
        } else {
            utf8
        };
        push_pdf_string(&decoded, text);
    }
}

/// Push one extracted PDF string candidate into the output, applying the same
/// textiness filter for literal and hex forms.
fn push_pdf_string(candidate: &str, text: &mut String) {
    let trimmed = candidate.trim();
    if !trimmed.is_empty()
        && trimmed.len() >= 2
        && trimmed
            .chars()
            .any(|c| c.is_alphanumeric() || c > '\u{4e00}')
    {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(trimmed);
    }
}

/// From OLE Documentation (.doc/.xls) MediumExtract readString

/// OLE, ofMethod:
/// 2Base/RadixdataMediumcontiguousof UTF-8/ASCII readString(>= 4 characters)
fn extract_ole_text(data: &[u8]) -> Option<String> {
    let mut text = String::with_capacity(4096);
    let mut current = String::new();

    for &byte in data {
        let ch = byte as char;
        // readcharacters: Chinese UTF-8 ByteBy lossy Process
        if ch.is_ascii_graphic() || ch == ' ' || ch == '\t' {
            current.push(ch);
        } else {
            if current.len() >= 4 && current.chars().any(|c| c.is_alphanumeric()) {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(current.trim());
            }
            current.clear();
        }

        if text.len() >= MAX_EXTRACT_LEN {
            break;
        }
    }

    // Processlast1Segment
    if current.len() >= 4 && current.chars().any(|c| c.is_alphanumeric()) {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str(current.trim());
    }

    // OLE ChineseContent: From lossy UTF-8 MediumExtract
    let lossy = String::from_utf8_lossy(data);
    let mut chinese_parts = String::new();
    for ch in lossy.chars() {
        if ch > '\u{4e00}' && ch < '\u{9fff}' {
            chinese_parts.push(ch);
        } else if !chinese_parts.is_empty() {
            if chinese_parts.len() >= 2 {
                text.push(' ');
                text.push_str(&chinese_parts);
            }
            chinese_parts.clear();
        }
    }
    if chinese_parts.len() >= 2 {
        text.push(' ');
        text.push_str(&chinese_parts);
    }

    // UTF-16LE sliding-window pass: legacy .doc bodies store text as
    // UTF-16LE, which the ASCII and lossy-UTF-8 passes above cannot see at
    // all — a Chinese .doc carrying 身份证/银行卡 content produced zero DLP
    // signal. Decode both alignments and keep runs of printable UTF-16 units.
    // Collision guard: two printable-ASCII bytes also form a CJK-range unit
    // ("ac" = U+6361), so a run is only kept when it carries CJK units that
    // are NOT ASCII-pair collisions, or is dominated by zero-high-byte
    // (true UTF-16 ASCII) units.
    for alignment in 0..2usize {
        let mut run = Utf16Run::default();
        let mut offset = alignment;
        while offset + 1 < data.len() {
            let unit = u16::from_le_bytes([data[offset], data[offset + 1]]);
            offset += 2;
            let valid = char::from_u32(u32::from(unit)).is_some_and(|ch| {
                ch.is_ascii_graphic()
                    || ch == ' '
                    || ch == '\t'
                    || ('\u{3000}'..='\u{303f}').contains(&ch)
                    || ('\u{4e00}'..='\u{9fff}').contains(&ch)
                    || ('\u{ff00}'..='\u{ffef}').contains(&ch)
            });
            if valid {
                run.push(unit);
            } else {
                run.flush(&mut text);
            }
            if text.len() >= MAX_EXTRACT_LEN {
                break;
            }
        }
        run.flush(&mut text);
        if text.len() >= MAX_EXTRACT_LEN {
            break;
        }
    }

    if text.is_empty() {
        debug!("OLE: no text content extracted");
        None
    } else {
        debug!(len = text.len(), "OLE: text extraction successful");
        Some(text)
    }
}

/// One UTF-16LE candidate run plus the collision statistics used to decide
/// whether it is real document text (see extract_ole_text).
#[derive(Default)]
struct Utf16Run {
    text: String,
    units: usize,
    /// Units with high byte 0x00 — true UTF-16 encoded ASCII.
    zero_high: usize,
    /// CJK/fullwidth units that are NOT two-printable-ASCII-byte collisions.
    strong_cjk: usize,
}

impl Utf16Run {
    fn push(&mut self, unit: u16) {
        self.units += 1;
        let [low, high] = unit.to_le_bytes();
        if high == 0 {
            self.zero_high += 1;
        }
        let ascii_pair_collision = low.is_ascii_graphic() && high.is_ascii_graphic();
        if matches!(unit, 0x3000..=0x303f | 0x4e00..=0x9fff | 0xff00..=0xffef)
            && !ascii_pair_collision
        {
            self.strong_cjk += 1;
        }
        if let Some(ch) = char::from_u32(u32::from(unit)) {
            self.text.push(ch);
        }
    }

    fn flush(&mut self, text: &mut String) {
        let trimmed = self.text.trim();
        // Real text: >= 2 non-collision CJK units, or a longer run dominated
        // by zero-high-byte (UTF-16 ASCII) units with some alphanumerics.
        let keep = self.strong_cjk >= 2
            || (self.units >= 8
                && self.zero_high * 5 >= self.units * 4
                && trimmed.chars().any(|c| c.is_ascii_alphanumeric()));
        if keep && !trimmed.is_empty() && text.len() < MAX_EXTRACT_LEN {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(trimmed);
        }
        *self = Utf16Run::default();
    }
}

fn extract_rtf_text(data: &[u8]) -> Option<String> {
    let source = String::from_utf8_lossy(data);
    if !source.trim_start().starts_with("{\\rtf") {
        return None;
    }

    let mut out = String::with_capacity(source.len().min(8192));
    let mut chars = source.chars().peekable();
    let mut ignorable_stack: Vec<bool> = Vec::new();
    let mut ignorable = false;
    let mut uc_skip = 1usize;
    let mut pending_unicode_fallback = 0usize;

    while let Some(ch) = chars.next() {
        if pending_unicode_fallback > 0 {
            if ch != '\\' {
                pending_unicode_fallback -= 1;
                continue;
            }

            // RTF Unicode fallback characters may themselves be escaped. Consume
            // the complete ANSI escape as one fallback character instead of
            // emitting it alongside the decoded Unicode scalar.
            match chars.peek().copied() {
                Some('\'') => {
                    chars.next();
                    chars.next();
                    chars.next();
                    pending_unicode_fallback -= 1;
                    continue;
                }
                Some('\\' | '{' | '}') => {
                    chars.next();
                    pending_unicode_fallback -= 1;
                    continue;
                }
                _ => {
                    // Control words are not fallback bytes; process normally.
                }
            }
        }

        match ch {
            '{' => {
                ignorable_stack.push(ignorable);
            }
            '}' => {
                ignorable = ignorable_stack.pop().unwrap_or(false);
            }
            '\\' => {
                let Some(next) = chars.next() else {
                    break;
                };

                match next {
                    '\\' | '{' | '}' => {
                        if !ignorable {
                            out.push(next);
                        }
                    }
                    '\'' => {
                        let hi = chars.next().and_then(|c| c.to_digit(16));
                        let lo = chars.next().and_then(|c| c.to_digit(16));
                        if !ignorable && let (Some(hi), Some(lo)) = (hi, lo) {
                            out.push(((hi << 4 | lo) as u8) as char);
                        }
                    }
                    '*' => {
                        ignorable = true;
                    }
                    '\n' | '\r' => {}
                    c if c.is_ascii_alphabetic() => {
                        let mut word = String::new();
                        word.push(c);
                        while let Some(peek) = chars.peek().copied() {
                            if peek.is_ascii_alphabetic() {
                                word.push(peek);
                                chars.next();
                            } else {
                                break;
                            }
                        }

                        let mut negative = false;
                        if chars.peek() == Some(&'-') {
                            negative = true;
                            chars.next();
                        }
                        let mut number = String::new();
                        while let Some(peek) = chars.peek().copied() {
                            if peek.is_ascii_digit() {
                                number.push(peek);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                        if chars.peek() == Some(&' ') {
                            chars.next();
                        }

                        if is_rtf_ignored_destination(&word) {
                            ignorable = true;
                            continue;
                        }

                        if ignorable {
                            continue;
                        }

                        match word.as_str() {
                            "par" | "line" => out.push('\n'),
                            "tab" => out.push('\t'),
                            "emdash" => out.push('-'),
                            "endash" => out.push('-'),
                            "bullet" => out.push('*'),
                            "uc" => {
                                if let Ok(value) = number.parse::<usize>() {
                                    uc_skip = value.min(8);
                                }
                            }
                            "u" => {
                                if let Ok(mut value) = number.parse::<i32>() {
                                    if negative {
                                        value = -value;
                                    }
                                    let scalar = if value < 0 {
                                        (value + 65536) as u32
                                    } else {
                                        value as u32
                                    };
                                    if let Some(decoded) = char::from_u32(scalar) {
                                        out.push(decoded);
                                    }
                                    pending_unicode_fallback = uc_skip;
                                }
                            }
                            _ => {}
                        }
                    }
                    c => {
                        if !ignorable && !c.is_control() {
                            out.push(c);
                        }
                    }
                }
            }
            c => {
                if !ignorable {
                    out.push(c);
                }
            }
        }

        if out.len() >= MAX_EXTRACT_LEN {
            break;
        }
    }

    let cleaned = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn is_rtf_ignored_destination(word: &str) -> bool {
    // `header`/`footer` deliberately absent: phish kits hide lure text in
    // RTF header/footer groups precisely because extractors skip them.
    matches!(
        word,
        "fonttbl"
            | "colortbl"
            | "stylesheet"
            | "info"
            | "pict"
            | "object"
            | "datastore"
            | "datafield"
            | "generator"
            | "xmlnstbl"
            | "annotation"
            | "shp"
            | "nonshppict"
    )
}

/// Strip XML tags and extract plain text content.
fn strip_xml_tags(xml: &str) -> String {
    let mut result = String::with_capacity(xml.len() / 3);
    let mut in_tag = false;

    for ch in xml.chars() {
        if ch == '<' {
            in_tag = true;
            // firstof delimited
            if !result.is_empty() && !result.ends_with(' ') && !result.ends_with('\n') {
                result.push(' ');
            }
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }

    // Cleanup
    let cleaned: String = result.split_whitespace().collect::<Vec<_>>().join(" ");

    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_xml_tags_basic() {
        let xml = "<w:t>Hello</w:t><w:t> World</w:t>";
        assert_eq!(strip_xml_tags(xml), "Hello World");
    }

    #[test]
    fn test_strip_xml_tags_nested() {
        let xml =
            "<w:r><w:rPr><w:sz val=\"24\"/></w:rPr><w:t>ID number 110101199001011237</w:t></w:r>";
        let text = strip_xml_tags(xml);
        assert!(text.contains("ID number"));
        assert!(text.contains("110101199001011237"));
    }

    #[test]
    fn test_strip_xml_tags_empty() {
        assert_eq!(strip_xml_tags(""), "");
        assert_eq!(strip_xml_tags("<tag/>"), "");
    }

    #[test]
    fn test_extract_text_empty_data() {
        assert!(extract_text(&[], Some(DetectedFileType::Pdf)).is_none());
    }

    #[test]
    fn test_extract_text_unknown_type() {
        assert!(extract_text(b"some data", Some(DetectedFileType::Jpeg)).is_none());
    }

    #[test]
    fn test_extract_text_no_type() {
        assert!(extract_text(b"some data", None).is_none());
    }

    #[test]
    fn test_extract_ole_text_ascii_strings() {
        // OLE FileMedium of ASCII readString
        let mut data = vec![0u8; 100];
        // readString
        let text = b"account: 1234567890";
        data[20..20 + text.len()].copy_from_slice(text);
        let result = extract_ole_text(&data);
        assert!(result.is_some());
        assert!(result.unwrap().contains("account: 1234567890"));
    }

    #[test]
    fn test_extract_ole_text_utf16le_chinese() {
        // PoC bypass (R4C): legacy .doc bodies store text as UTF-16LE; the
        // ASCII and lossy-UTF-8 passes were completely blind to it, so a
        // Chinese .doc carrying sensitive terms produced zero DLP signal.
        let mut data = vec![0u8; 64];
        let phrase = "身份证号：110101199001011237，请勿外传";
        let utf16: Vec<u8> = phrase
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0u8; 32]);

        let text = extract_ole_text(&data).expect("UTF-16LE text must be extracted");
        assert!(text.contains("身份证号"), "got: {text}");
        assert!(text.contains("110101199001011237"), "got: {text}");

        // End-to-end: the extracted text must drive the real DLP scanner.
        let dlp_result = crate::data_security::dlp::scan_text(&text);
        assert!(
            dlp_result.matches.contains(&"id_number".to_string()),
            "UTF-16LE extracted ID must hit DLP id_number: {:?}",
            dlp_result.matches
        );
    }

    #[test]
    fn test_extract_ole_text_utf16le_ascii_collision_guard() {
        // Guard: plain ASCII strings inside binary data must NOT come back as
        // bogus CJK runs ("ac" = U+6361 collision), and true UTF-16LE ASCII
        // text (English .doc) must still be extracted.
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"account: 1234567890");
        data.extend_from_slice(&[0u8; 16]);
        let utf16: Vec<u8> = "Transfer Reference AB-2026"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        data.extend_from_slice(&utf16);
        data.extend_from_slice(&[0u8; 16]);

        let text = extract_ole_text(&data).expect("text expected");
        assert!(text.contains("account: 1234567890"), "got: {text}");
        assert!(
            text.contains("Transfer Reference AB-2026"),
            "true UTF-16LE ASCII text must be extracted: {text}"
        );
        // The misread of "account: ..." as CJK pairs must be filtered out.
        assert!(
            !text.contains('\u{6361}'),
            "ASCII-pair CJK collision must not leak into output: {text}"
        );
    }

    #[test]
    fn test_extract_rtf_text_basic_control_words() {
        let rtf = br"{\rtf1\ansi This is \b urgent\b0 \par Please verify your account.}";
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert!(text.contains("urgent"));
        assert!(text.contains("Please verify your account."));
    }

    #[test]
    fn test_extract_rtf_text_unicode_and_ignored_pict() {
        let rtf = "{\\rtf1\\ansi\\uc1 \\u20320?好{\\pict\\pngblip 41424344}\\par payment change}"
            .as_bytes();
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert!(text.contains("你好"));
        assert!(text.contains("payment change"));
        assert!(!text.contains("41424344"));
    }

    #[test]
    fn test_extract_rtf_text_skips_hex_escaped_unicode_fallback() {
        let rtf = br"{\rtf1\ansi\uc1 \u20320\'3f payment}";
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert_eq!(text, "你 payment");
        assert!(!text.contains('?'), "ANSI fallback must not be duplicated");
    }

    #[test]
    fn test_extract_rtf_text_honors_uc_zero_and_negative_unicode() {
        let rtf = br"{\rtf1\ansi\uc0 \u-25896\u22909  payment}";
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert_eq!(text, "高好 payment");
    }

    #[test]
    fn test_extract_rtf_text_tolerates_unbalanced_groups() {
        let rtf = br"{\rtf1\ansi visible {\*\generator hidden; still visible";
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert!(text.contains("visible"));
        assert!(!text.contains("hidden"));
    }

    #[test]
    fn test_extract_pdf_text_literal_strings() {
        let pdf = "%PDF-1.4 (Customer ID: 110101199001011237) Tj (Phone: 13812345678) Tj";
        let result = extract_pdf_text(pdf.as_bytes());
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(
            text.contains("110101199001011237"),
            "should extract ID number"
        );
        assert!(text.contains("13812345678"), "should extract phone number");
    }

    #[test]
    fn test_extract_ooxml_creates_valid_text() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w.start_file("word/document.xml", options).unwrap();
        use std::io::Write;
        let xml = "<?xml version=\"1.0\"?><w:document><w:body><w:r><w:t>Test ID: 110101199001011237</w:t></w:r></w:body></w:document>";
        zip_w.write_all(xml.as_bytes()).unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_ooxml_text(&data);
        assert!(text.is_some(), "should extract text from DOCX");
        assert!(text.unwrap().contains("110101199001011237"));
    }

    #[test]
    fn test_extract_text_integrates_with_dlp() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w.start_file("word/document.xml", options).unwrap();
        use std::io::Write;
        let xml = "<?xml version=\"1.0\"?><w:document><w:body><w:r><w:t>password: secret123, ID 110101199001011237</w:t></w:r></w:body></w:document>";
        zip_w.write_all(xml.as_bytes()).unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_text(&data, Some(DetectedFileType::ZipArchive));
        assert!(text.is_some());

        let dlp_result = crate::data_security::dlp::scan_text(text.as_deref().unwrap());
        assert!(
            dlp_result.matches.contains(&"id_number".to_string()),
            "should detect ID number"
        );
        assert!(
            dlp_result.matches.contains(&"credential_leak".to_string()),
            "should detect credential"
        );
    }

    // Test: Extract Security

    #[test]
    fn test_extract_text_corrupt_zip_returns_none() {
        // Invalid ZIP data
        let corrupt = b"\x50\x4B\x03\x04INVALID_ZIP_DATA";
        let result = extract_text(corrupt, Some(DetectedFileType::ZipArchive));
        assert!(
            result.is_none(),
            "Corrupt ZIP should return None gracefully"
        );
    }

    #[test]
    fn test_extract_text_corrupt_pdf_returns_none() {
        // Invalid PDF data
        let corrupt = b"%PDF-1.4 CORRUPT DATA WITH NO TEXT OPERATORS";
        let result = extract_text(corrupt, Some(DetectedFileType::Pdf));
        // PDF ExtractpossiblyReturn (Tj/TJ Operations) -> filter trim None
        assert!(
            result.is_none() || result.as_deref() == Some(""),
            "Corrupt PDF with no text ops should return None or empty"
        );
    }

    #[test]
    fn test_extract_ole_all_binary_no_text() {
        // 2Base/Radix readString
        let data = vec![0x00u8; 200];
        let result = extract_ole_text(&data);
        assert!(
            result.as_deref().is_none_or(|s| s.trim().is_empty()),
            "Pure binary data should not produce text"
        );
    }

    #[test]
    fn test_extract_pdf_hex_strings() {
        // PDF <hex> string carrying ASCII text ("Hello").
        let pdf = "%PDF-1.4 <48656C6C6F> Tj";
        let result = extract_pdf_text(pdf.as_bytes());
        assert_eq!(result.as_deref(), Some("Hello"));

        // CID-font form: UTF-16BE hex string (8EAB 4EFD = 身份).
        let pdf = "%PDF-1.4 <8EAB4EFD> Tj";
        let result = extract_pdf_text(pdf.as_bytes());
        assert!(
            result.as_deref().is_some_and(|t| t.contains("身份")),
            "UTF-16BE hex string must decode: {result:?}"
        );
    }

    #[test]
    fn test_extract_pdf_text_flate_decode_stream() {
        // PoC bypass (R4C): real PDFs compress content streams with
        // FlateDecode; the raw-byte literal scan saw only zlib ciphertext and
        // every keyword / DLP check went blind.
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;

        let content_stream =
            b"BT /F1 12 Tf 72 720 Td (Customer ID: 110101199001011237) Tj (phone 13812345678) Tj ET";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content_stream).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Length ");
        pdf.extend_from_slice(compressed.len().to_string().as_bytes());
        pdf.extend_from_slice(b" /Filter /FlateDecode >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        let text = extract_pdf_text(&pdf).expect("FlateDecode stream text must be extracted");
        assert!(text.contains("110101199001011237"), "got: {text}");
        assert!(text.contains("13812345678"), "got: {text}");

        let dlp_result = crate::data_security::dlp::scan_text(&text);
        assert!(
            dlp_result.matches.contains(&"id_number".to_string()),
            "inflated PDF text must hit DLP id_number: {:?}",
            dlp_result.matches
        );
    }

    #[test]
    fn test_extract_pdf_flate_zip_bomb_is_bounded() {
        // Guard: a tiny stream inflating past the per-stream budget must be
        // truncated, never exhaust memory.
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![b'A'; MAX_PDF_STREAM_INFLATE_BYTES + 4096])
            .unwrap();
        let compressed = encoder.finish().unwrap();

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        // Must complete quickly and stay within the global extract cap.
        let result = extract_pdf_text(&pdf);
        if let Some(text) = result {
            assert!(text.len() <= MAX_EXTRACT_LEN);
        }
    }

    #[test]
    fn test_extract_pdf_flate_escaped_filter_name() {
        // PoC: /Fl#61teDecode (ISO 32000 name escape) must still inflate.
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;

        let content_stream = b"BT (verify account password) Tj ET";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content_stream).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /Fl#61teDecode >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf).expect("escaped FlateDecode must inflate");
        assert!(text.contains("verify account password"), "got: {text}");
    }

    #[test]
    fn test_extract_ooxml_xlsx_shared_strings() {
        // XLSX ofText xl/sharedStrings.xml Medium
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w.start_file("xl/sharedStrings.xml", options).unwrap();
        use std::io::Write;
        let xml = r#"<?xml version="1.0"?><sst><si><t>员工Serial number</t></si><si><t>EMP001</t></si></sst>"#;
        zip_w.write_all(xml.as_bytes()).unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_ooxml_text(&data);
        assert!(
            text.is_some(),
            "Should extract text from XLSX sharedStrings.xml"
        );
        let t = text.unwrap();
        assert!(
            t.contains("员工Serial number"),
            "Should extract Chinese text from XLSX"
        );
        assert!(t.contains("EMP001"), "Should extract ID from XLSX");
    }

    #[test]
    fn test_extract_ooxml_pptx() {
        // PPTX ofText ppt/slides/slide*.xml Medium
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w.start_file("ppt/slides/slide1.xml", options).unwrap();
        use std::io::Write;
        let xml = r#"<?xml version="1.0"?><p:sld><p:sp><p:txBody><a:p><a:r><a:t>Password: admin123</a:t></a:r></a:p></p:txBody></p:sp></p:sld>"#;
        zip_w.write_all(xml.as_bytes()).unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_ooxml_text(&data);
        assert!(text.is_some(), "Should extract text from PPTX slide");
        assert!(
            text.unwrap().contains("Password"),
            "Should extract slide content"
        );
    }

    #[test]
    fn test_extract_ooxml_pptx_reads_beyond_slide3() {
        // PoC bypass: lure text parked on slide 4+ was invisible because only
        // slide1-3 were read.
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        use std::io::Write;
        for slide in 1..=5 {
            zip_w
                .start_file(format!("ppt/slides/slide{slide}.xml"), options)
                .unwrap();
            let body = if slide == 5 {
                "UrgentWireTransfer1234"
            } else {
                "Agenda"
            };
            let xml = format!(
                r#"<?xml version="1.0"?><p:sld><p:sp><p:txBody><a:p><a:r><a:t>{body}</a:t></a:r></a:p></p:txBody></p:sp></p:sld>"#
            );
            zip_w.write_all(xml.as_bytes()).unwrap();
        }

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_ooxml_text(&data).expect("PPTX text");
        assert!(
            text.contains("UrgentWireTransfer1234"),
            "slide 5 content must be extracted: {text}"
        );
    }

    #[test]
    fn test_extract_ooxml_xlsx_missing_sheet_does_not_stop_scan() {
        // PoC bypass: a deleted sheet2 previously broke the sheet loop, so
        // sheet3 content was never extracted.
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        use std::io::Write;
        zip_w.start_file("xl/worksheets/sheet1.xml", options).unwrap();
        zip_w
            .write_all(br#"<?xml version="1.0"?><worksheet><sheetData><row><c><v>1</v></c></row></sheetData></worksheet>"#)
            .unwrap();
        // sheet2 deliberately absent.
        zip_w.start_file("xl/worksheets/sheet3.xml", options).unwrap();
        zip_w
            .write_all(br#"<?xml version="1.0"?><worksheet><sheetData><row><c><v>HiddenSheet3Marker</v></c></row></sheetData></worksheet>"#)
            .unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_ooxml_text(&data).expect("XLSX text");
        assert!(
            text.contains("HiddenSheet3Marker"),
            "sheet3 content must survive the missing sheet2: {text}"
        );
    }

    #[test]
    fn test_extract_rtf_text_includes_header_footer_groups() {
        // PoC bypass: lure text inside {\header ...} / {\footer ...} groups
        // was discarded as an "ignored destination".
        let rtf = br"{\rtf1\ansi{\header Verify your account password immediately}{\footer call 400-555-0100} plain body}";
        let text = extract_text(rtf, Some(DetectedFileType::Rtf)).expect("RTF text");

        assert!(
            text.contains("Verify your account password immediately"),
            "RTF header group text must be extracted: {text}"
        );
        assert!(
            text.contains("call 400-555-0100"),
            "RTF footer group text must be extracted: {text}"
        );
        assert!(text.contains("plain body"));
    }

    #[test]
    fn test_extract_text_truncates_at_limit() {
        // largeText Break/Judge MAX_EXTRACT_LEN
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut zip_w = zip::ZipWriter::new(cursor);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_w.start_file("word/document.xml", options).unwrap();
        use std::io::Write;
        // generate 512KB of XML
        let mut xml = String::from("<?xml version=\"1.0\"?><w:document><w:body>");
        for i in 0..100_000 {
            xml.push_str(&format!(
                "<w:r><w:t>Line {} with some padding text to fill space</w:t></w:r>",
                i
            ));
        }
        xml.push_str("</w:body></w:document>");
        zip_w.write_all(xml.as_bytes()).unwrap();

        let result = zip_w.finish().unwrap();
        let data = result.into_inner();

        let text = extract_text(&data, Some(DetectedFileType::ZipArchive));
        if let Some(ref t) = text {
            assert!(
                t.len() <= MAX_EXTRACT_LEN,
                "Extracted text should be truncated to {} bytes, got {}",
                MAX_EXTRACT_LEN,
                t.len()
            );
        }
    }

    #[test]
    fn test_strip_xml_tags_preserves_chinese() {
        let xml = "<w:t>客户Name</w:t><w:t>Zhang San</w:t>";
        let text = strip_xml_tags(xml);
        assert!(
            text.contains("客户Name"),
            "Chinese text should be preserved"
        );
        assert!(
            text.contains("Zhang San"),
            "Chinese name should be preserved"
        );
    }

    // ─── A3: PDF FlateDecode 三个隐藏通道 ──────────────────────────────

    /// 测试辅助: zlib 压缩一段 PDF 内容流
    fn zlib_compress(content: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(content).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn test_extract_pdf_flate_abbreviated_filter_name() {
        // A3(a) PoC (修复前可绕过): ISO 32000 合法缩写 `/Fl` 不被识别,
        // 流内 Tj 文本完全不可见。流内藏真实格式身份证号。
        let compressed = zlib_compress("BT (身份证号：110101199001011237) Tj ET".as_bytes());

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n1 0 obj\n<< /Length ");
        pdf.extend_from_slice(compressed.len().to_string().as_bytes());
        pdf.extend_from_slice(b" /Filter /Fl >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        let text = extract_pdf_text(&pdf).expect("/Fl abbreviated stream must inflate");
        assert!(text.contains("110101199001011237"), "got: {text}");

        let dlp_result = crate::data_security::dlp::scan_text(&text);
        assert!(
            dlp_result.matches.contains(&"id_number".to_string()),
            "/Fl 流内身份证号必须被 DLP 检出: {:?}",
            dlp_result.matches
        );
    }

    #[test]
    fn test_extract_pdf_flate_abbreviation_word_boundary() {
        // A3(a) 反误报护栏: `/FlXxx` 形式的相似名字不得误判为 /Fl。
        let compressed = zlib_compress(b"BT (SecretMarkerPayload) Tj ET");

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /FlXyZ >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf).unwrap_or_default();
        assert!(
            !text.contains("SecretMarkerPayload"),
            "/FlXyZ 不得按 /Fl 解压: {text}"
        );
    }

    #[test]
    fn test_extract_pdf_flate_filter_pushed_beyond_window() {
        // A3(b) PoC (修复前可绕过): /Filter 后塞 >512B 合法无关键,
        // 把 /FlateDecode 推出原来的 512B 回溯窗口。
        let compressed = zlib_compress(b"BT (payload account password verify) Tj ET");
        let junk = "A".repeat(600);

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /FlateDecode /J");
        pdf.extend_from_slice(junk.as_bytes());
        pdf.extend_from_slice(b" 1 >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf)
            .expect("filter pushed past 512B window must still inflate");
        assert!(text.contains("payload account password verify"), "got: {text}");
    }

    #[test]
    fn test_extract_pdf_flate_nested_dict_before_filter() {
        // A3(b) 边界: 字典内含嵌套字典时, 平衡扫描必须定位到外层字典
        // (朴素"最近的 <<" 会把 /Filter 切掉)。
        let compressed = zlib_compress(b"BT (NestedDictMarker text) Tj ET");

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /FlateDecode /X << /Y 1 >> >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf)
            .expect("nested dict must not cut off /Filter");
        assert!(text.contains("NestedDictMarker text"), "got: {text}");
    }

    #[test]
    fn test_extract_pdf_payload_in_stream_beyond_old_cap() {
        // A3(c) PoC (修复前可绕过): 前 64 个 1 字节良性流耗尽旧上限,
        // 载荷在第 65 个流。修复后 512 流上限 + 总预算放行小流。
        let decoy = zlib_compress(b"x");
        let payload = zlib_compress(b"BT (LateStreamPayload 110101199001011237) Tj ET");

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n");
        for _ in 0..80 {
            pdf.extend_from_slice(b"<< /Filter /FlateDecode >>\nstream\n");
            pdf.extend_from_slice(&decoy);
            pdf.extend_from_slice(b"\nendstream\n");
        }
        pdf.extend_from_slice(b"<< /Filter /FlateDecode >>\nstream\n");
        pdf.extend_from_slice(&payload);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf)
            .expect("payload past the old 64-stream cap must be reached");
        assert!(text.contains("LateStreamPayload"), "got: {text}");
        assert!(text.contains("110101199001011237"), "got: {text}");
    }

    #[test]
    fn test_extract_pdf_stream_lone_cr_eol() {
        // A3(d) PoC (修复前可绕过): `stream` 关键字后跟 lone CR (旧 Mac EOL,
        // 阅读器容忍) 曾导致整条流被跳过。
        let compressed = zlib_compress(b"BT (LoneCrMarker content here) Tj ET");

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n<< /Filter /FlateDecode >>\nstream\r");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\n");

        let text = extract_pdf_text(&pdf).expect("lone CR after stream must be tolerated");
        assert!(text.contains("LoneCrMarker content here"), "got: {text}");
    }

    #[test]
    fn test_dict_declares_flate_unit() {
        assert!(dict_declares_flate(b"<< /Filter /FlateDecode >>"));
        assert!(dict_declares_flate(b"<< /Filter /Fl >>"));
        assert!(dict_declares_flate(b"<< /Filter [/Fl] >>"));
        assert!(!dict_declares_flate(b"<< /Filter /FlXyZ >>"));
        assert!(!dict_declares_flate(b"<< /Filter /Fl#6 >>"));
        assert!(!dict_declares_flate(b"<< /Length 42 >>"));
    }
}
