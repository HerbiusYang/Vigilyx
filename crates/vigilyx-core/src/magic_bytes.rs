//! Magic byte / file signature detection module

//! Identifies the actual file type from the first N bytes of binary data, used for:
//! - Detecting executable files uploaded via webmail
//! - Detecting file extension disguises (e.g., PE renamed to.xlsx)
//! - Deciding whether to perform DLP text scanning on the body

//! # Safety invariants

//! - **Read-only**: input `&[u8]` is never modified
//! - **Bounded**: reads at most the first 16 bytes; text heuristic reads at most 512 bytes
//! - **No parsing**: detects MZ header but does not parse PE sections; detects PK header but does not decompress ZIP
//! - **No execution**: captured binary content is never passed to any executor

use serde::{Deserialize, Serialize};

/// File type detected via magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectedFileType {
    /// Windows PE executable (MZ: 0x4D5A)
    PeExecutable,
    /// ELF binary (Linux/Unix: 0x7F454C46)
    ElfBinary,
    /// Mach-O binary (macOS: 0xFEEDFACE/CF)
    MachOBinary,
    /// ZIP archive (includes DOCX/XLSX/PPTX/JAR: 0x504B0304)
    ZipArchive,
    /// PDF document (%PDF: 0x25504446)
    Pdf,
    /// RAR archive (Rar!: 0x526172211A07)
    RarArchive,
    /// 7-Zip archive (0x377ABCAF271C)
    SevenZipArchive,
    /// GZip compressed (0x1F8B)
    Gzip,
    /// Microsoft OLE2 compound document (legacy DOC/XLS/PPT: 0xD0CF11E0)
    OleCompound,
    /// JPEG image (0xFFD8FF)
    Jpeg,
    /// PNG image (0x89504E47)
    Png,
    /// GIF image (GIF87a/GIF89a)
    Gif,
    /// BMP image (BM: 0x424D)
    Bmp,
    /// TIFF image (II/MM)
    Tiff,
    /// SQLite database ("SQLite")
    Sqlite,
    /// Windows shortcut (.lnk: 0x4C000000)
    WindowsShortcut,
    /// Java Class file (0xCAFEBABE)
    JavaClass,
    /// RTF document ({\rtf: 0x7B5C727466)
    Rtf,
    /// ISO 9660 disk image (CD001 at offset 0x8001)
    Iso,
    /// Script text (shebang `#!`, `<?php`, `<script`)
    ScriptText,
    /// HTML document (`<!DOCTYPE` or `<html`)
    HtmlDocument,
    /// Plain text (heuristic:>90% printable characters)
    PlainText,
    /// Unknown binary (no known signature)
    UnknownBinary,
}

/// File type risk level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileTypeRisk {
    /// Safe: images, plain text
    Safe,
    /// Low: common documents (PDF, Office)
    Low,
    /// Medium: archives (may contain executables)
    Medium,
    /// High: executables, scripts, disk images
    High,
}

impl DetectedFileType {
    /// Base risk level for this file type
    pub fn base_risk(&self) -> FileTypeRisk {
        match self {
            Self::PeExecutable
            | Self::ElfBinary
            | Self::MachOBinary
            | Self::WindowsShortcut
            | Self::JavaClass
            | Self::Iso
            | Self::ScriptText => FileTypeRisk::High,

            Self::ZipArchive
            | Self::RarArchive
            | Self::SevenZipArchive
            | Self::Gzip
            | Self::Sqlite => FileTypeRisk::Medium,

            Self::Pdf | Self::OleCompound | Self::Rtf | Self::HtmlDocument => FileTypeRisk::Low,

            Self::Jpeg | Self::Png | Self::Gif | Self::Bmp | Self::Tiff | Self::PlainText => {
                FileTypeRisk::Safe
            }

            Self::UnknownBinary => FileTypeRisk::Medium,
        }
    }

    /// Whether the detected type is an executable or script that can run code
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::PeExecutable
                | Self::ElfBinary
                | Self::MachOBinary
                | Self::WindowsShortcut
                | Self::JavaClass
                | Self::ScriptText
        )
    }

    /// Whether the detected type is a disk image or installer
    pub fn is_installer_or_image(&self) -> bool {
        matches!(self, Self::Iso)
    }

    /// Whether DLP text scanning is meaningful
    ///
    /// Running regex on binary formats only produces false positives; should be skipped.
    pub fn is_text_scannable(&self) -> bool {
        matches!(
            self,
            Self::PlainText | Self::ScriptText | Self::HtmlDocument
        )
    }

    /// Whether text content can be extracted (office files: DOCX/XLSX/PPTX/PDF/OLE/RTF)
    pub fn is_extractable_document(&self) -> bool {
        matches!(
            self,
            Self::ZipArchive | Self::Pdf | Self::OleCompound | Self::Rtf
        )
    }

    /// Human-readable display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::PeExecutable => "PE Executable",
            Self::ElfBinary => "ELF Executable",
            Self::MachOBinary => "Mach-O Executable",
            Self::ZipArchive => "ZIP Archive",
            Self::Pdf => "PDF Document",
            Self::RarArchive => "RAR Archive",
            Self::SevenZipArchive => "7-Zip Archive",
            Self::Gzip => "GZip Compressed",
            Self::OleCompound => "OLE Document (Legacy Office)",
            Self::Jpeg => "JPEG Image",
            Self::Png => "PNG Image",
            Self::Gif => "GIF Image",
            Self::Bmp => "BMP Image",
            Self::Tiff => "TIFF Image",
            Self::Sqlite => "SQLite Database",
            Self::WindowsShortcut => "Windows Shortcut",
            Self::JavaClass => "Java Class File",
            Self::Rtf => "RTF Document",
            Self::Iso => "ISO Disk Image",
            Self::ScriptText => "Script File",
            Self::HtmlDocument => "HTML Document",
            Self::PlainText => "Plain Text",
            Self::UnknownBinary => "Unknown Binary",
        }
    }

    /// Valid file extensions for this type
    pub fn expected_extensions(&self) -> &'static [&'static str] {
        match self {
            Self::PeExecutable => &["exe", "dll", "sys", "scr", "com"],
            Self::ElfBinary => &["so", "elf", "bin", "out"],
            Self::MachOBinary => &["dylib", "app", "bundle"],
            Self::ZipArchive => &[
                "zip", "xlsx", "docx", "pptx", "jar", "apk", "odt", "ods", "odp", "epub", "xpi",
                "aar",
            ],
            Self::Pdf => &["pdf"],
            Self::RarArchive => &["rar"],
            Self::SevenZipArchive => &["7z"],
            Self::Gzip => &["gz", "tgz", "tar.gz"],
            Self::OleCompound => &["doc", "xls", "ppt", "msg", "msi"],
            Self::Jpeg => &["jpg", "jpeg", "jpe", "jfif"],
            Self::Png => &["png"],
            Self::Gif => &["gif"],
            Self::Bmp => &["bmp", "dib"],
            Self::Tiff => &["tif", "tiff"],
            Self::Sqlite => &["db", "sqlite", "sqlite3"],
            Self::WindowsShortcut => &["lnk"],
            Self::JavaClass => &["class"],
            Self::Rtf => &["rtf"],
            Self::Iso => &["iso", "img"],
            Self::ScriptText => &[
                "sh", "bash", "php", "js", "vbs", "ps1", "bat", "cmd", "py", "rb", "pl",
            ],
            Self::HtmlDocument => &["html", "htm", "xhtml", "hta"],
            Self::PlainText => &[
                "txt", "csv", "log", "md", "json", "xml", "css", "sql", "ini", "cfg", "yaml",
                "yml", "toml",
            ],
            Self::UnknownBinary => &[],
        }
    }
}

/// Detect file type from the first N bytes of binary data
///
/// Only reads the first 16 bytes for signature matching; text heuristic reads at most 512 bytes.
/// ISO detection checks offset 0x8001 for "CD001" signature.
/// Returns None when input is empty.
pub fn detect_file_type(data: &[u8]) -> Option<DetectedFileType> {
    if data.is_empty() {
        return None;
    }

    let len = data.len();

    // 8-byte signatures (check long signatures first to avoid prefix mismatches)
    if len >= 8 {
        if data[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
            return Some(DetectedFileType::OleCompound);
        }
        if data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return Some(DetectedFileType::Png);
        }
    }

    // 6-byte signatures
    if len >= 6 {
        if data[..6] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] {
            return Some(DetectedFileType::RarArchive);
        }
        if data[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return Some(DetectedFileType::SevenZipArchive);
        }
        if &data[..6] == b"SQLite" {
            return Some(DetectedFileType::Sqlite);
        }
    }

    // 5-byte signatures
    if len >= 5 && data[..5] == [0x7B, 0x5C, 0x72, 0x74, 0x66] {
        // {\rtf
        return Some(DetectedFileType::Rtf);
    }

    // 4-byte signatures
    if len >= 4 {
        if data[..4] == [0x7F, 0x45, 0x4C, 0x46] {
            return Some(DetectedFileType::ElfBinary);
        }
        if data[..4] == [0xFE, 0xED, 0xFA, 0xCE] || data[..4] == [0xFE, 0xED, 0xFA, 0xCF] {
            return Some(DetectedFileType::MachOBinary);
        }
        if data[..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
            // Mach-O fat binary vs Java class: fat binary's byte[4..8] values are typically small
            if len >= 8 && data[4..8].iter().all(|&b| b < 0x40) {
                return Some(DetectedFileType::MachOBinary);
            }
            return Some(DetectedFileType::JavaClass);
        }
        if data[..4] == [0x50, 0x4B, 0x03, 0x04] || data[..4] == [0x50, 0x4B, 0x05, 0x06] {
            return Some(DetectedFileType::ZipArchive);
        }
        if data[..4] == [0x25, 0x50, 0x44, 0x46] {
            return Some(DetectedFileType::Pdf);
        }
        if data[..4] == [0x47, 0x49, 0x46, 0x38] {
            return Some(DetectedFileType::Gif);
        }
        if data[..4] == [0x49, 0x49, 0x2A, 0x00] || data[..4] == [0x4D, 0x4D, 0x00, 0x2A] {
            return Some(DetectedFileType::Tiff);
        }
        if data[..4] == [0x4C, 0x00, 0x00, 0x00] {
            return Some(DetectedFileType::WindowsShortcut);
        }
    }

    // 3-byte signatures
    if len >= 3 && data[..3] == [0xFF, 0xD8, 0xFF] {
        return Some(DetectedFileType::Jpeg);
    }

    // 2-byte signatures
    if len >= 2 {
        if data[..2] == [0x4D, 0x5A] {
            return Some(DetectedFileType::PeExecutable);
        }
        if data[..2] == [0x1F, 0x8B] {
            return Some(DetectedFileType::Gzip);
        }
        if data[..2] == [0x42, 0x4D] {
            return Some(DetectedFileType::Bmp);
        }
    }

    // ISO 9660: "CD001" signature at offset 0x8001 (sector 16 system area + 1 byte)
    if len > 0x8005 && &data[0x8001..0x8006] == b"CD001" {
        return Some(DetectedFileType::Iso);
    }

    // Text-based format detection: check if first 512 bytes are mostly printable
    let check_len = len.min(512);
    let sample = &data[..check_len];
    if std::str::from_utf8(sample).is_ok() {
        let printable = sample
            .iter()
            .filter(|&&b| b >= 0x20 || b == b'\n' || b == b'\r' || b == b'\t')
            .count();
        // >90% printable -> text-based, now classify further
        if printable * 10 >= check_len * 9 {
            // Trim leading whitespace/BOM for pattern matching
            let trimmed = strip_bom(sample);
            let trimmed = trimmed.trim_ascii_start();

            // Script detection: shebang, PHP opening
            if trimmed.starts_with(b"#!") {
                return Some(DetectedFileType::ScriptText);
            }
            if trimmed.len() >= 5 {
                let lower5: Vec<u8> = trimmed[..5.min(trimmed.len())]
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                if lower5.starts_with(b"<?php") {
                    return Some(DetectedFileType::ScriptText);
                }
            }

            // HTML detection: <!DOCTYPE or <html — must come BEFORE bare <script>
            // check, because an HTML document containing <script> tags is HTML
            // smuggling (HtmlDocument), not a raw script file (ScriptText).
            if trimmed.len() >= 9 {
                let lower_prefix: Vec<u8> = trimmed[..15.min(trimmed.len())]
                    .iter()
                    .map(|b| b.to_ascii_lowercase())
                    .collect();
                if lower_prefix.starts_with(b"<!doctype") || lower_prefix.starts_with(b"<html") {
                    return Some(DetectedFileType::HtmlDocument);
                }
            }

            // Bare <script> tag without HTML wrapper → standalone script file
            if contains_ascii_ci(trimmed, b"<script") {
                return Some(DetectedFileType::ScriptText);
            }

            return Some(DetectedFileType::PlainText);
        }
    }

    Some(DetectedFileType::UnknownBinary)
}

/// Strip UTF-8 BOM if present
fn strip_bom(data: &[u8]) -> &[u8] {
    if data.len() >= 3 && data[..3] == [0xEF, 0xBB, 0xBF] {
        &data[3..]
    } else {
        data
    }
}

/// Case-insensitive search for an ASCII needle in a byte slice (bounded to first 512 bytes)
fn contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    let search_len = haystack.len().min(512);
    if needle.len() > search_len {
        return false;
    }
    haystack[..search_len].windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Determine whether a detected file type disguised as a claimed extension is a high-risk
/// combination (+0.30 penalty). Returns true for executables/scripts/installers masquerading
/// as documents, images, or other benign types.
///
/// This is the core logic for attachment magic bytes cross-validation.
pub fn is_high_risk_disguise(actual: DetectedFileType, claimed_ext: &str) -> bool {
    let ext = claimed_ext.to_lowercase();

    // Document and image extensions that executables commonly masquerade as
    const DOCUMENT_EXTS: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt", "ods", "odp", "txt",
        "csv", "log",
    ];
    const IMAGE_EXTS: &[&str] = &[
        "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "svg", "ico", "webp",
    ];
    const ARCHIVE_EXTS: &[&str] = &["zip", "rar", "7z", "gz", "tar"];

    let is_doc_or_image =
        DOCUMENT_EXTS.contains(&ext.as_str()) || IMAGE_EXTS.contains(&ext.as_str());
    let is_benign = is_doc_or_image || ARCHIVE_EXTS.contains(&ext.as_str());

    match actual {
        // EXE/DLL/SCR/ELF/Mach-O/LNK/JavaClass → document/image/archive = high-risk disguise
        DetectedFileType::PeExecutable
        | DetectedFileType::ElfBinary
        | DetectedFileType::MachOBinary
        | DetectedFileType::WindowsShortcut
        | DetectedFileType::JavaClass => is_benign,

        // Script disguised as non-script extension
        DetectedFileType::ScriptText => {
            // Script extensions are expected for scripts
            let script_exts = DetectedFileType::ScriptText.expected_extensions();
            !script_exts.contains(&ext.as_str())
                && !matches!(ext.as_str(), "html" | "htm" | "xhtml" | "hta")
        }

        // ISO/disk image disguised as non-installer extension
        DetectedFileType::Iso => {
            let iso_exts = DetectedFileType::Iso.expected_extensions();
            !iso_exts.contains(&ext.as_str())
        }

        // HTML with potential smuggling: HTML file disguised as non-HTML extension
        // (HTML smuggling uses JavaScript in HTML to deliver payloads)
        DetectedFileType::HtmlDocument => {
            let html_exts = DetectedFileType::HtmlDocument.expected_extensions();
            !html_exts.contains(&ext.as_str()) && is_doc_or_image
        }

        _ => false,
    }
}

/// Check if an HTML document contains embedded scripts (potential HTML smuggling).
///
/// Searches the first 8KB for `<script` tags. This is a lightweight heuristic—
/// full HTML parsing is done by `html_scan` module.
pub fn html_has_scripts(data: &[u8]) -> bool {
    let search_len = data.len().min(8192);
    contains_ascii_ci(&data[..search_len], b"<script")
}

/// Detect if archive is encrypted
///
/// Determines encryption by parsing header flags:
/// - **ZIP**: Local File Header offset 6-7 General Purpose Bit Flag, bit 0 = encrypted
/// - **RAR4**: Main Archive Header (type 0x73) HEAD_FLAGS, bit 7 = block headers encrypted
///
/// Encrypted archives may be used to bypass DLP scanning (content cannot be inspected).
/// Requires at least 8 bytes (ZIP) or 12 bytes (RAR) to determine; returns `false` when data is insufficient.
pub fn is_encrypted_archive(data: &[u8]) -> bool {
    let len = data.len();

    // ZIP: PK\x03\x04 at offset 0, General Purpose Bit Flag at offset 6-7
    if len >= 8 && data[..4] == [0x50, 0x4B, 0x03, 0x04] {
        let flags = u16::from_le_bytes([data[6], data[7]]);
        return flags & 0x0001 != 0; // bit 0 = encrypted
    }

    // RAR4: Rar!\x1A\x07\x00, Main Archive Header at offset 7
    // Header: CRC(2) + TYPE(1) + FLAGS(2) + SIZE(2)
    // TYPE 0x73 = MAIN_ARCHIVE_HEADER, FLAGS bit 7 = block headers encrypted
    if len >= 12 && data[..7] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
        let header_type = data[9];
        if header_type == 0x73 {
            let flags = u16::from_le_bytes([data[10], data[11]]);
            return flags & 0x0080 != 0; // bit 7 = encrypted headers
        }
    }

    // RAR5: Rar!\x1A\x07\x01\x00, encryption header type = 4
    if len >= 13 && data[..8] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
        // RAR5 header encryption: search first 64 bytes for encryption marker (header type 4)
        if data[8..len.min(64)].contains(&0x04) {
            return true;
        }
    }

    // 7-Zip: 7z\xBC\xAF\x27\x1C - AES-256 encryption
    if len >= 32 && data[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        // Heuristic: when encrypted, header region is mostly unreadable
        let non_printable = data[12..len.min(32)]
            .iter()
            .filter(|&&b| !(0x20..=0x7E).contains(&b))
            .count();
        if non_printable > 12 {
            return true;
        }
    }

    false
}

/// Detect if PDF is password protected
///
/// Determines password protection by searching for /Encrypt dictionary in PDF
pub fn is_encrypted_pdf(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // PDF must start with %PDF
    if &data[..4] != b"%PDF" {
        return false;
    }
    // Search for /Encrypt keyword (within first 4KB, usually in trailer or xref)
    let search_len = data.len().min(4096);
    let haystack = &data[..search_len];
    haystack.windows(8).any(|w| w == b"/Encrypt")
}

/// Check if magic byte detection result conflicts with file extension
///
/// Returns `Some("description")` if disguised.
/// Returns `None` if type is compatible with extension (or cannot be determined).
pub fn check_extension_mismatch(detected: DetectedFileType, filename: &str) -> Option<String> {
    // Extract extension (no dot means no extension)
    let ext = match filename.rfind('.') {
        Some(pos) if pos + 1 < filename.len() => filename[pos + 1..].to_lowercase(),
        _ => return None,
    };

    // UnknownBinary and PlainText skip mismatch detection
    if matches!(
        detected,
        DetectedFileType::UnknownBinary | DetectedFileType::PlainText
    ) {
        return None;
    }

    let expected = detected.expected_extensions();
    if expected.is_empty() {
        return None;
    }

    // Check if extension is in allowed list
    if expected.iter().any(|&e| e == ext) {
        return None;
    }

    Some(format!(
        "File extension .{} does not match actual content (detected as {})",
        ext,
        detected.display_name()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Signature Detection ===

    #[test]
    fn test_detect_pe_executable() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert_eq!(
            detect_file_type(&data),
            Some(DetectedFileType::PeExecutable)
        );
    }

    #[test]
    fn test_detect_elf_binary() {
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::ElfBinary));
    }

    #[test]
    fn test_detect_macho_64() {
        let data = [0xFE, 0xED, 0xFA, 0xCF, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::MachOBinary));
    }

    #[test]
    fn test_detect_macho_fat_vs_java() {
        // Fat binary: bytes 4..8 are small
        let fat = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02];
        assert_eq!(detect_file_type(&fat), Some(DetectedFileType::MachOBinary));

        // Java class: bytes 4..8 have larger values (version number)
        let java = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x41];
        assert_eq!(detect_file_type(&java), Some(DetectedFileType::JavaClass));
    }

    #[test]
    fn test_detect_zip_archive() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::ZipArchive));
    }

    #[test]
    fn test_detect_pdf() {
        assert_eq!(
            detect_file_type(b"%PDF-1.4 something"),
            Some(DetectedFileType::Pdf)
        );
    }

    #[test]
    fn test_detect_rar() {
        let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::RarArchive));
    }

    #[test]
    fn test_detect_7z() {
        let data = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        assert_eq!(
            detect_file_type(&data),
            Some(DetectedFileType::SevenZipArchive)
        );
    }

    #[test]
    fn test_detect_gzip() {
        let data = [0x1F, 0x8B, 0x08, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Gzip));
    }

    #[test]
    fn test_detect_ole_compound() {
        let data = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::OleCompound));
    }

    #[test]
    fn test_detect_jpeg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Jpeg));
    }

    #[test]
    fn test_detect_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Png));
    }

    #[test]
    fn test_detect_gif() {
        assert_eq!(
            detect_file_type(b"GIF89a\x00\x00\x00\x00"),
            Some(DetectedFileType::Gif)
        );
    }

    #[test]
    fn test_detect_bmp() {
        let data = [0x42, 0x4D, 0x36, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Bmp));
    }

    #[test]
    fn test_detect_tiff_little_endian() {
        let data = [0x49, 0x49, 0x2A, 0x00, 0x08, 0x00, 0x00, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Tiff));
    }

    #[test]
    fn test_detect_sqlite() {
        assert_eq!(
            detect_file_type(b"SQLite format 3\x00"),
            Some(DetectedFileType::Sqlite)
        );
    }

    #[test]
    fn test_detect_windows_shortcut() {
        let data = [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
        assert_eq!(
            detect_file_type(&data),
            Some(DetectedFileType::WindowsShortcut)
        );
    }

    #[test]
    fn test_detect_plain_text() {
        let data = b"Hello, this is plain text content.\nLine two.\nLine three.";
        assert_eq!(detect_file_type(data), Some(DetectedFileType::PlainText));
    }

    #[test]
    fn test_detect_plain_text_json() {
        let data = br#"{"action":"deliver","attrs":{"account":"user@corp.com"}}"#;
        assert_eq!(
            detect_file_type(data.as_slice()),
            Some(DetectedFileType::PlainText)
        );
    }

    // === Edge Cases ===

    #[test]
    fn test_detect_empty_input() {
        assert_eq!(detect_file_type(&[]), None);
    }

    #[test]
    fn test_detect_single_byte() {
        // Single 0xFF does not match any complete signature -> UnknownBinary (non-text)
        assert_eq!(
            detect_file_type(&[0xFF]),
            Some(DetectedFileType::UnknownBinary)
        );
    }

    #[test]
    fn test_detect_unknown_binary() {
        let data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(
            detect_file_type(&data),
            Some(DetectedFileType::UnknownBinary)
        );
    }

    // === Extension Matching ===

    #[test]
    fn test_mismatch_pe_disguised_as_xlsx() {
        let result = check_extension_mismatch(DetectedFileType::PeExecutable, "report.xlsx");
        assert!(result.is_some());
        let desc = result.unwrap();
        assert!(desc.contains(".xlsx"));
        assert!(desc.contains("PE"));
    }

    #[test]
    fn test_no_mismatch_zip_as_xlsx() {
        // XLSX is essentially ZIP, should not report mismatch
        assert!(check_extension_mismatch(DetectedFileType::ZipArchive, "report.xlsx").is_none());
    }

    #[test]
    fn test_no_mismatch_zip_as_docx() {
        assert!(check_extension_mismatch(DetectedFileType::ZipArchive, "doc.docx").is_none());
    }

    #[test]
    fn test_no_mismatch_pdf_as_pdf() {
        assert!(check_extension_mismatch(DetectedFileType::Pdf, "document.pdf").is_none());
    }

    #[test]
    fn test_no_mismatch_ole_as_doc() {
        assert!(check_extension_mismatch(DetectedFileType::OleCompound, "old.doc").is_none());
    }

    #[test]
    fn test_mismatch_elf_as_jpg() {
        let result = check_extension_mismatch(DetectedFileType::ElfBinary, "photo.jpg");
        assert!(result.is_some());
    }

    #[test]
    fn test_no_mismatch_pe_as_exe() {
        assert!(check_extension_mismatch(DetectedFileType::PeExecutable, "setup.exe").is_none());
    }

    #[test]
    fn test_mismatch_pe_as_pdf() {
        assert!(check_extension_mismatch(DetectedFileType::PeExecutable, "report.pdf").is_some());
    }

    #[test]
    fn test_no_mismatch_no_extension() {
        assert!(check_extension_mismatch(DetectedFileType::PeExecutable, "noext").is_none());
    }

    #[test]
    fn test_unknown_binary_no_mismatch() {
        assert!(check_extension_mismatch(DetectedFileType::UnknownBinary, "any.xyz").is_none());
    }

    // === Risk Levels ===

    #[test]
    fn test_pe_is_high_risk() {
        assert_eq!(
            DetectedFileType::PeExecutable.base_risk(),
            FileTypeRisk::High
        );
    }

    #[test]
    fn test_elf_is_high_risk() {
        assert_eq!(DetectedFileType::ElfBinary.base_risk(), FileTypeRisk::High);
    }

    #[test]
    fn test_pdf_is_low_risk() {
        assert_eq!(DetectedFileType::Pdf.base_risk(), FileTypeRisk::Low);
    }

    #[test]
    fn test_jpeg_is_safe() {
        assert_eq!(DetectedFileType::Jpeg.base_risk(), FileTypeRisk::Safe);
    }

    #[test]
    fn test_zip_is_medium_risk() {
        assert_eq!(
            DetectedFileType::ZipArchive.base_risk(),
            FileTypeRisk::Medium
        );
    }

    // === text scannable ===

    #[test]
    fn test_plain_text_is_scannable() {
        assert!(DetectedFileType::PlainText.is_text_scannable());
    }

    #[test]
    fn test_pe_is_not_scannable() {
        assert!(!DetectedFileType::PeExecutable.is_text_scannable());
    }

    #[test]
    fn test_pdf_is_not_scannable() {
        assert!(!DetectedFileType::Pdf.is_text_scannable());
    }

    #[test]
    fn test_zip_is_not_scannable() {
        assert!(!DetectedFileType::ZipArchive.is_text_scannable());
    }

    // === Encrypted Archive Detection ===

    #[test]
    fn test_encrypted_zip_detected() {
        // ZIP Local File Header with encryption bit set
        // PK\x03\x04 + version(2) + flags(2) where flags bit 0 = 1
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        assert!(
            is_encrypted_archive(&data),
            "ZIP with encryption flag should be detected"
        );
    }

    #[test]
    fn test_unencrypted_zip_not_detected() {
        // ZIP Local File Header with NO encryption bit
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00];
        assert!(
            !is_encrypted_archive(&data),
            "Unencrypted ZIP should NOT be detected"
        );
    }

    #[test]
    fn test_encrypted_zip_with_other_flags() {
        // ZIP with encryption (bit 0) + data descriptor (bit 3) + UTF-8 (bit 11)
        // flags = 0x0809 (little endian: 0x09, 0x08)
        let data = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x09, 0x08];
        assert!(
            is_encrypted_archive(&data),
            "ZIP with multiple flags including encryption should be detected"
        );
    }

    #[test]
    fn test_encrypted_rar4_detected() {
        // RAR4 signature + Main Archive Header with encryption
        // Rar!\x1A\x07\x00 + CRC(2) + TYPE=0x73 + FLAGS=0x0080 (encrypted headers)
        let data = [
            0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, // signature
            0x00, 0x00, // CRC (placeholder)
            0x73, // type = MAIN_ARCHIVE_HEADER
            0x80, 0x00, // flags = 0x0080 (encrypted)
        ];
        assert!(
            is_encrypted_archive(&data),
            "RAR4 with encrypted headers should be detected"
        );
    }

    #[test]
    fn test_unencrypted_rar4_not_detected() {
        // RAR4 without encryption
        let data = [
            0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0x00, 0x00, 0x73, 0x00, 0x00,
        ];
        assert!(
            !is_encrypted_archive(&data),
            "Unencrypted RAR4 should NOT be detected"
        );
    }

    #[test]
    fn test_encrypted_archive_insufficient_data() {
        // Too short to determine
        assert!(!is_encrypted_archive(&[0x50, 0x4B, 0x03, 0x04]));
        assert!(!is_encrypted_archive(&[]));
    }

    #[test]
    fn test_non_archive_not_detected() {
        // PE file should not be detected as encrypted archive
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert!(!is_encrypted_archive(&data));
    }

    // === Serde Round-trip ===

    #[test]
    fn test_serde_roundtrip() {
        let ft = DetectedFileType::PeExecutable;
        let json = serde_json::to_string(&ft).expect("serialize");
        assert_eq!(json, "\"pe_executable\"");
        let back: DetectedFileType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ft, back);
    }
}
