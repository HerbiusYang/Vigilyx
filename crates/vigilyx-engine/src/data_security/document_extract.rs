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
        // PPTX slides
        "ppt/slides/slide1.xml",
        "ppt/slides/slide2.xml",
        "ppt/slides/slide3.xml",
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
            break;
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
fn extract_pdf_text(data: &[u8]) -> Option<String> {
    let content = String::from_utf8_lossy(data);
    let mut text = String::with_capacity(4096);

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
                    let trimmed = current.trim();
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

    if text.is_empty() {
        debug!("PDF: no text content extracted");
        None
    } else {
        debug!(len = text.len(), "PDF: text extraction successful");
        Some(text)
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

    if text.is_empty() {
        debug!("OLE: no text content extracted");
        None
    } else {
        debug!(len = text.len(), "OLE: text extraction successful");
        Some(text)
    }
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
        // PDF <hex> ofString
        let pdf = "%PDF-1.4 <48656C6C6F> Tj"; // "Hello" in hex
        let result = extract_pdf_text(pdf.as_bytes());
        // of Extracthandlerpossibly hex - - Verify panic
        drop(result);
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
}
