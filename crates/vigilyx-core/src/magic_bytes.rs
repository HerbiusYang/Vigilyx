//! Magic byte / file signature detection module

//! Identifies the actual file type from the first N bytes of binary data, used for:
//! - Detecting executable files uploaded via webmail
//! - Detecting file extension disguises (e.g., PE renamed to.xlsx)
//! - Deciding whether to perform DLP text scanning on the body

//! # Safety invariants

//! - **Read-only**: input `&[u8]` is never modified
//! - **Bounded**: signature matching reads at most the first 1024 bytes (PDF
//!   header window per ISO 32000); text heuristic reads at most 512 bytes;
//!   `/Encrypt` probing additionally reads the trailing 4 KiB
//! - **No parsing**: detects MZ header but does not parse PE sections; detects PK header but does not decompress ZIP
//! - **No execution**: captured binary content is never passed to any executor

use serde::{Deserialize, Serialize};

/// ISO 32000 allows the `%PDF` header to appear anywhere within the first
/// 1024 bytes of the file; prefix-junk PDFs are a common signature-evasion
/// trick, so header anchoring must search this window instead of offset 0.
const PDF_HEADER_SEARCH_WINDOW: usize = 1024;

/// The `/Encrypt` dictionary is conventionally referenced from the document
/// trailer at the end of the file, so encryption probing searches both the
/// leading and the trailing window.
const PDF_ENCRYPT_SEARCH_WINDOW: usize = 4096;

/// Trailing-window bound for ZIP End Of Central Directory (EOCD) discovery.
/// ZIP readers (7-Zip, Windows Explorer, the `zip` crate) locate an archive
/// from the EOCD record at the tail of the file, tolerating arbitrary
/// prepended data; 64 KiB covers the maximum 64 KiB EOCD comment plus slack.
const ZIP_EOCD_SEARCH_WINDOW: usize = 64 * 1024;

/// Upper bound on how many ZIP local file headers `is_encrypted_archive`
/// walks. A plaintext decoy first entry must not hide encryption on a later
/// entry; real archives place their first entries well within this bound.
const ZIP_LOCAL_HEADER_SCAN_MAX: usize = 10;

/// Byte window bound for the ZIP local-header walk in `is_encrypted_archive`.
const ZIP_LOCAL_HEADER_SCAN_WINDOW: usize = 64 * 1024;

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
    /// TNEF transport-neutral encapsulation (winmail.dat: 0x789F3E22)
    Tnef,
    /// AppleSingle archive (0x00051600)
    AppleSingle,
    /// AppleDouble archive (0x00051607)
    AppleDouble,
    /// Uuencoded payload (`begin <mode> <name>` frame)
    Uuencode,
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
            | Self::Sqlite
            // Opaque/packed containers: not executable themselves, but their
            // inner payload bypasses content inspection.
            | Self::Tnef
            | Self::AppleSingle
            | Self::AppleDouble
            | Self::Uuencode => FileTypeRisk::Medium,

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
            Self::Tnef => "TNEF Container (winmail.dat)",
            Self::AppleSingle => "AppleSingle Archive",
            Self::AppleDouble => "AppleDouble Archive",
            Self::Uuencode => "Uuencoded File",
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
            Self::Tnef => &["dat", "tnef"],
            Self::AppleSingle => &["as"],
            Self::AppleDouble => &[],
            Self::Uuencode => &["uue", "uu"],
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
/// Signature matching reads at most the first 1024 bytes; the PDF header may
/// legally appear anywhere within that window (ISO 32000) and RTF may be
/// preceded by whitespace. The text heuristic reads at most 512 bytes.
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

    // 5-byte signatures: {\rtf — leading whitespace before the RTF control
    // word is legal and is used to evade offset-0 signature checks, so trim
    // ASCII whitespace before matching.
    let trimmed_start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(len);
    if let Some(rtf_sig) = data.get(trimmed_start..trimmed_start.saturating_add(5))
        && rtf_sig == b"{\\rtf"
    {
        // {\rtf
        return Some(DetectedFileType::Rtf);
    }

    // PDF: ISO 32000 allows the %PDF- header to appear anywhere within the
    // first 1024 bytes, so a prefix-junk PDF must still be recognized. The
    // full "%PDF-" header (with version dash) is required beyond offset 0 to
    // limit false positives on text that merely mentions PDFs; the plain
    // 4-byte "%PDF" case at offset 0 is handled by the 4-byte block below.
    {
        let window = len.min(PDF_HEADER_SEARCH_WINDOW);
        if len >= 5 && data[..window].windows(5).any(|w| w == b"%PDF-") {
            return Some(DetectedFileType::Pdf);
        }
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
        // TNEF (winmail.dat) — an opaque Microsoft transport container; the
        // inner RTF/MIME payload is invisible to text-level scanning.
        if data[..4] == [0x78, 0x9F, 0x3E, 0x22] {
            return Some(DetectedFileType::Tnef);
        }
        // AppleSingle / AppleDouble — macOS resource-fork containers that can
        // smuggle a second data fork past extension-based routing.
        if data[..4] == [0x00, 0x05, 0x16, 0x00] {
            return Some(DetectedFileType::AppleSingle);
        }
        if data[..4] == [0x00, 0x05, 0x16, 0x07] {
            return Some(DetectedFileType::AppleDouble);
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

            // uuencode frame (`begin 644 payload.exe` + encoded data lines):
            // printable-ASCII container that would otherwise fall through to
            // PlainText and skip every binary cross-check. Checked before the
            // bare-<script> rule because the uuencode alphabet can contain
            // "<script" byte sequences by coincidence.
            if has_uuencode_frame_prefix(trimmed) {
                return Some(DetectedFileType::Uuencode);
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

/// Locate a ZIP End Of Central Directory (EOCD) record at the tail of `data`.
///
/// ZIP readers (7-Zip, Windows Explorer, the `zip` crate) resolve an archive
/// from the EOCD record near the end of the file and tolerate arbitrary
/// prepended bytes, so `cat photo.jpg payload.zip > invoice.jpg` yields a
/// polyglot that offset-0 magic misclassifies as a plain image while archive
/// tools happily unpack the payload. Returns the absolute offset of the
/// `PK\x05\x06` signature when a structurally consistent EOCD record exists
/// within the trailing 64 KiB.
///
/// False-positive control: the record's 16-bit comment-length field must
/// account for every byte up to the end of the buffer, i.e. the EOCD must be
/// the final structure of the file. Random trailing bytes (image entropy,
/// compressed data) essentially never satisfy that invariant.
pub fn find_trailing_zip_eocd(data: &[u8]) -> Option<usize> {
    const EOCD_SIGNATURE: &[u8] = b"PK\x05\x06";
    const EOCD_FIXED_LEN: usize = 22;
    if data.len() < EOCD_FIXED_LEN {
        return None;
    }
    let window_start = data.len().saturating_sub(ZIP_EOCD_SEARCH_WINDOW);
    let tail = &data[window_start..];
    // Scan backwards: the EOCD is the last structure in a well-formed file,
    // so the last signature that passes the length check is the real one.
    for relative in (0..=tail.len() - EOCD_FIXED_LEN).rev() {
        if tail.get(relative..relative.saturating_add(4)) != Some(EOCD_SIGNATURE) {
            continue;
        }
        let comment_len =
            u16::from_le_bytes([tail[relative + 20], tail[relative + 21]]) as usize;
        if relative + EOCD_FIXED_LEN + comment_len == tail.len() {
            return Some(window_start + relative);
        }
    }
    None
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

    // ZIP: walk up to the first `ZIP_LOCAL_HEADER_SCAN_MAX` local file
    // headers (bounded to the first `ZIP_LOCAL_HEADER_SCAN_WINDOW` bytes).
    // Checking only the header at offset 0 lets a plaintext decoy first
    // entry hide encryption on a later entry; any entry with General
    // Purpose Bit Flag bit 0 set marks the archive as encrypted.
    if len >= 8 && data[..4] == [0x50, 0x4B, 0x03, 0x04] {
        // Lenient first-header check preserved for truncated captures that
        // carry only the flag bytes (see existing 8-byte test vectors).
        let flags = u16::from_le_bytes([data[6], data[7]]);
        if flags & 0x0001 != 0 {
            return true;
        }
        let window = len.min(ZIP_LOCAL_HEADER_SCAN_WINDOW);
        let mut cursor = 0usize;
        for _ in 0..ZIP_LOCAL_HEADER_SCAN_MAX {
            let Some(header) = data.get(cursor..cursor.saturating_add(30)) else {
                break;
            };
            if header[..4] != [0x50, 0x4B, 0x03, 0x04] {
                break;
            }
            let flags = u16::from_le_bytes([header[6], header[7]]);
            if flags & 0x0001 != 0 {
                return true;
            }
            // Bit 3 (data descriptor): the sizes trail the entry data, so the
            // next header cannot be located reliably from here.
            if flags & 0x0008 != 0 {
                break;
            }
            let compressed_size =
                u32::from_le_bytes([header[18], header[19], header[20], header[21]]) as usize;
            let name_len = u16::from_le_bytes([header[26], header[27]]) as usize;
            let extra_len = u16::from_le_bytes([header[28], header[29]]) as usize;
            let Some(next) = cursor
                .checked_add(30)
                .and_then(|base| base.checked_add(name_len))
                .and_then(|base| base.checked_add(extra_len))
                .and_then(|base| base.checked_add(compressed_size))
            else {
                break;
            };
            if next >= window {
                break;
            }
            cursor = next;
        }
        return false;
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

/// Decode PDF name-object `#hh` hex escapes (ISO 32000 §7.3.5).
///
/// Attackers spell `/FlateDecode` as `/Fl#61teDecode` or `/Encrypt` as
/// `/#45ncrypt` so raw byte/token matching misses names that every PDF
/// reader resolves back to the original form. Token checks must run on the
/// escaped-decoded view. `#` not followed by two hex digits stays literal.
pub fn normalize_pdf_name_escapes(data: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if !data.contains(&b'#') {
        return std::borrow::Cow::Borrowed(data);
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(data.len());
    let mut cursor = 0usize;
    while cursor < data.len() {
        if data[cursor] == b'#'
            && let (Some(&hi), Some(&lo)) = (data.get(cursor + 1), data.get(cursor + 2))
            && let (Some(h), Some(l)) = (hex_value(hi), hex_value(lo))
        {
            out.push((h << 4) | l);
            cursor += 3;
            continue;
        }
        out.push(data[cursor]);
        cursor += 1;
    }
    std::borrow::Cow::Owned(out)
}

/// Detect if PDF is password protected
///
/// Determines password protection by searching for /Encrypt dictionary in PDF.
/// The `%PDF` header may appear anywhere within the first 1024 bytes
/// (ISO 32000), and the `/Encrypt` reference conventionally lives in the
/// trailer at the end of the file, so both the leading and trailing 4 KiB
/// windows are searched. Name tokens are matched after `#hh` escape decoding
/// so `/#45ncrypt` cannot hide the encryption dictionary.
pub fn is_encrypted_pdf(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // PDF must carry a %PDF header within the first 1024 bytes.
    let header_window = data.len().min(PDF_HEADER_SEARCH_WINDOW);
    if !data[..header_window].windows(4).any(|w| w == b"%PDF") {
        return false;
    }
    // Search for /Encrypt in the leading 4 KiB and the trailing 4 KiB.
    let head = normalize_pdf_name_escapes(&data[..data.len().min(PDF_ENCRYPT_SEARCH_WINDOW)]);
    let tail = normalize_pdf_name_escapes(&data[data.len().saturating_sub(PDF_ENCRYPT_SEARCH_WINDOW)..]);
    head.windows(8).any(|w| w == b"/Encrypt") || tail.windows(8).any(|w| w == b"/Encrypt")
}

/// A decoded uuencode frame (`begin <mode> <name>` ... `end`).
#[derive(Debug)]
pub struct UuencodeFrame {
    /// File name carried by the `begin` header line.
    pub filename: String,
    /// Decoded payload bytes (bounded by the caller-supplied cap).
    pub payload: Vec<u8>,
    /// Message text preceding the `begin` line.
    pub preamble: Vec<u8>,
    /// Text following the terminating `end` line (empty when the capture was
    /// truncated before `end` arrived).
    pub trailer: Vec<u8>,
}

/// Parse a uuencode `begin` header line: `begin <mode> <name>`.
///
/// The mode must be 3-4 octal digits starting with 6 or 7 (real permission
/// bits), so prose such as "begin 60 years ago" cannot satisfy the shape.
fn parse_uuencode_begin(line: &[u8]) -> Option<&[u8]> {
    let rest = line.strip_prefix(b"begin ")?;
    let mode_len = rest
        .iter()
        .take_while(|byte| matches!(byte, b'0'..=b'7'))
        .count();
    if !(3..=4).contains(&mode_len) || !matches!(rest.first(), Some(b'6' | b'7')) {
        return None;
    }
    if rest.get(mode_len) != Some(&b' ') {
        return None;
    }
    let name = &rest[mode_len + 1..];
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Structural validation for one uuencode data line: a length byte in the
/// 0x20..=0x60 alphabet, enough payload characters for the declared length,
/// and only space/backtick padding beyond them.
fn is_uuencode_data_line(line: &[u8]) -> Option<usize> {
    let first = *line.first()?;
    if !(0x20..=0x60).contains(&first) {
        return None;
    }
    let declared = usize::from((first - 0x20) & 0x3f);
    if declared == 0 {
        return None;
    }
    let needed = 1 + (declared * 8).div_ceil(6);
    if line.len() < needed {
        return None;
    }
    if !line[1..needed].iter().all(|b| (0x20..=0x60).contains(b)) {
        return None;
    }
    if !line[needed..].iter().all(|b| matches!(b, b' ' | b'`')) {
        return None;
    }
    Some(declared)
}

/// Decode one validated uuencode data line into `out`.
fn decode_uuencode_data_line(line: &[u8], declared: usize, out: &mut Vec<u8>) {
    let needed = 1 + (declared * 8).div_ceil(6);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let start = out.len();
    for &byte in &line[1..needed] {
        let value = u32::from((byte - 0x20) & 0x3f);
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits) - 1;
        }
    }
    out.truncate(start + declared);
}

/// Lightweight signature check: a `begin` header at offset 0 of the trimmed
/// buffer plus at least one structurally valid data line.
fn has_uuencode_frame_prefix(trimmed: &[u8]) -> bool {
    if !trimmed.starts_with(b"begin ") {
        return false;
    }
    let Some(relative_end) = trimmed.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let header = trim_ascii_cr(&trimmed[..relative_end]);
    if parse_uuencode_begin(header).is_none() {
        return false;
    }
    let rest = &trimmed[relative_end + 1..];
    let line_end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    is_uuencode_data_line(trim_ascii_cr(&rest[..line_end])).is_some()
}

fn trim_ascii_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Split and decode a uuencode frame that may sit behind a short text
/// preamble (classic "here is the file" bodies). Every data line must pass
/// structural validation; otherwise the content is NOT a frame and `None` is
/// returned — prose that happens to mention "begin 644 x" must not be
/// swallowed into a phantom attachment. A frame truncated by capture limits
/// (no terminating `end`) is still accepted once at least one data line
/// decoded. `payload_cap` bounds the decoded output.
pub fn split_uuencode_frame(data: &[u8], payload_cap: usize) -> Option<UuencodeFrame> {
    const MAX_PREAMBLE_SCAN: usize = 8 * 1024;
    let begin_at = if data.starts_with(b"begin ") {
        0
    } else {
        let window = data.get(..data.len().min(MAX_PREAMBLE_SCAN))?;
        let pos = window
            .windows(b"\nbegin ".len())
            .position(|w| w == b"\nbegin ")?;
        pos + 1
    };

    let header_end = data[begin_at..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| begin_at + p)
        .unwrap_or(data.len());
    let header = trim_ascii_cr(&data[begin_at..header_end]);
    let name = parse_uuencode_begin(header)?;
    let filename = String::from_utf8_lossy(name).trim().to_string();
    if filename.is_empty() {
        return None;
    }

    let preamble = data[..begin_at].to_vec();
    let mut payload = Vec::new();
    let mut data_lines = 0usize;
    let mut cursor = if header_end < data.len() {
        header_end + 1
    } else {
        data.len()
    };
    let mut trailer = Vec::new();

    'lines: while cursor < data.len() {
        let line_end = data[cursor..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| cursor + p)
            .unwrap_or(data.len());
        let line = trim_ascii_cr(&data[cursor..line_end]);
        let after_line = if line_end < data.len() {
            line_end + 1
        } else {
            data.len()
        };

        if line == b"end" {
            trailer = data[after_line..].to_vec();
            break 'lines;
        }
        if line.is_empty() {
            // Strict: blank lines inside the data section invalidate the frame.
            return None;
        }
        let first = line[0];
        if !(0x20..=0x60).contains(&first) {
            return None;
        }
        let declared = usize::from((first - 0x20) & 0x3f);
        if declared == 0 {
            // Zero-length terminator (` ` or `` ` ``): an optional `end` line
            // may follow; everything after it is trailer text.
            let rest = &data[after_line..];
            let end_line_end = rest
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| after_line + p)
                .unwrap_or(data.len());
            if trim_ascii_cr(&data[after_line..end_line_end]) == b"end" {
                trailer = data[(if end_line_end < data.len() {
                    end_line_end + 1
                } else {
                    data.len()
                })..]
                    .to_vec();
            } else {
                trailer = data[after_line..].to_vec();
            }
            break 'lines;
        }

        let declared = is_uuencode_data_line(line)?;
        if payload.len() < payload_cap {
            let before = payload.len();
            decode_uuencode_data_line(line, declared, &mut payload);
            payload.truncate(payload_cap.max(before));
        }
        data_lines += 1;
        cursor = after_line;
    }

    if data_lines == 0 {
        return None;
    }
    Some(UuencodeFrame {
        filename,
        payload,
        preamble,
        trailer,
    })
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
    fn test_detect_tnef_winmail_dat() {
        // PoC bypass (R4C): TNEF (winmail.dat) was an UnknownBinary blind
        // spot — the inner RTF/MIME payload never reached content scanning.
        let data = [0x78, 0x9F, 0x3E, 0x22, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Tnef));
    }

    #[test]
    fn test_detect_apple_single_double() {
        // PoC bypass (R4C): AppleSingle/AppleDouble resource-fork containers
        // had no signature at all.
        let single = [0x00, 0x05, 0x16, 0x00, 0x00, 0x02, 0x00, 0x00];
        let double = [0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00];
        assert_eq!(
            detect_file_type(&single),
            Some(DetectedFileType::AppleSingle)
        );
        assert_eq!(
            detect_file_type(&double),
            Some(DetectedFileType::AppleDouble)
        );
    }

    #[test]
    fn test_detect_uuencode_frame() {
        // PoC bypass (R4C): a printable-ASCII uuencode container used to fall
        // through to PlainText, skipping every binary cross-check.
        // Hand-verified vector: "!``" is the 1-byte payload 0x00.
        let data = b"begin 755 loader.sh\n!``\n`\nend\n";
        assert_eq!(detect_file_type(data), Some(DetectedFileType::Uuencode));
    }

    #[test]
    fn test_prose_begin_sentence_is_not_uuencode() {
        // Guard: prose starting with "begin" must not be misclassified.
        let data = b"begin 60 years ago the story of our company started small and grew.\nMore text here.";
        assert_eq!(
            detect_file_type(data),
            Some(DetectedFileType::PlainText),
            "prose mentioning 'begin 60 ...' must not become a uuencode finding"
        );
        // A header-shaped line without a valid data line is prose too.
        let data = b"begin 644 notes\nthen we talked about the roadmap for next year.\n";
        assert_eq!(detect_file_type(data), Some(DetectedFileType::PlainText));
    }

    /// Spec-correct uuencode encoder used to build test corpora (BSD format,
    /// backtick for zero). Independent from the decoder under test.
    fn uuencode_body(payload: &[u8]) -> String {
        let mut out = String::new();
        for chunk in payload.chunks(45) {
            out.push((chunk.len() as u8 + 0x20) as char);
            for trio in chunk.chunks(3) {
                let mut buf = [0u8; 3];
                buf[..trio.len()].copy_from_slice(trio);
                let n = u32::from(buf[0]) << 16 | u32::from(buf[1]) << 8 | u32::from(buf[2]);
                let groups = (trio.len() * 8).div_ceil(6);
                for i in 0..groups {
                    let value = ((n >> (18 - 6 * i)) & 0x3f) as u8;
                    out.push(if value == 0 {
                        '`'
                    } else {
                        (value + 0x20) as char
                    });
                }
            }
            out.push('\n');
        }
        out.push_str("`\nend\n");
        out
    }

    #[test]
    fn test_uuencode_decoder_hand_verified_single_byte() {
        // Anchor vector: "!``" must decode to exactly [0x00].
        let frame = split_uuencode_frame(b"begin 644 x.bin\n!``\n`\nend\n", 1024)
            .expect("valid frame must decode");
        assert_eq!(frame.filename, "x.bin");
        assert_eq!(frame.payload, vec![0x00]);
    }

    #[test]
    fn test_split_uuencode_frame_decodes_payload() {
        // Real-corpus shape: preamble text + `begin 644 evil.exe` + data,
        // carrying a PE header (MZ\x90...) as the hidden payload.
        let payload: Vec<u8> = (0u8..=255).collect();
        let data = format!(
            "Here is the report you asked for.\r\nbegin 644 evil.exe\r\n{}thanks\r\n",
            uuencode_body(&payload)
        );
        let frame = split_uuencode_frame(data.as_bytes(), 1024 * 1024)
            .expect("valid frame must decode");
        assert_eq!(frame.filename, "evil.exe");
        assert_eq!(frame.payload, payload, "decode must round-trip the spec encoder");
        assert!(
            String::from_utf8_lossy(&frame.preamble).contains("Here is the report"),
            "preamble must be preserved: {:?}",
            frame.preamble
        );
        assert!(
            String::from_utf8_lossy(&frame.trailer).contains("thanks"),
            "trailer must be preserved: {:?}",
            frame.trailer
        );
    }

    #[test]
    fn test_split_uuencode_frame_rejects_corrupt_lines() {
        // Guard: one invalid data line invalidates the whole frame — partial
        // decoding would let an attacker poison the attachment stream.
        let good = uuencode_body(b"MZ\x90 payload");
        let good_line = good.lines().next().expect("uuencode body has a data line");
        let data = format!("begin 644 x.bin\n{good_line}\nnot a uuencode line at all !!!\nend\n");
        // The trailing `end` after the junk line never arrives in-frame; the
        // junk line itself fails validation and must reject the whole frame.
        let corrupt = format!("begin 644 x.bin\n{good_line}\nQQQQ\u{80}invalid\nend\n");
        assert!(split_uuencode_frame(data.as_bytes(), 1024).is_none());
        assert!(split_uuencode_frame(corrupt.as_bytes(), 1024).is_none());
    }

    #[test]
    fn test_split_uuencode_frame_accepts_truncated_capture() {
        // Mirror-mode captures can truncate before the terminating `end`;
        // the decoded prefix must still be usable for scanning.
        let payload = b"MZ\x90\x00truncated-capture";
        let body = uuencode_body(payload);
        // Drop the final "`\nend\n" terminator (cut on a line boundary).
        let without_end = &body[..body.len() - 6];
        let data = format!("begin 644 x.bin\n{without_end}");
        let frame =
            split_uuencode_frame(data.as_bytes(), 1024).expect("truncated frame must decode");
        assert_eq!(frame.payload, payload);
        assert!(frame.trailer.is_empty());
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

    // === Trailing ZIP EOCD discovery (polyglot regression) ===

    fn zip_eocd(comment: &[u8]) -> Vec<u8> {
        let mut eocd = Vec::with_capacity(22 + comment.len());
        eocd.extend_from_slice(b"PK\x05\x06");
        eocd.extend_from_slice(&[0u8; 16]); // disk numbers + entry counts + cd size/offset
        eocd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        eocd.extend_from_slice(comment);
        eocd
    }

    #[test]
    fn test_find_trailing_zip_eocd_detects_appended_archive() {
        // PoC bypass: `cat photo.jpg payload.zip > invoice.jpg` — offset-0
        // magic sees Jpeg, but archive tools unpack from the tail EOCD.
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        data.extend_from_slice(&vec![0xAB; 512]); // JPEG entropy
        data.extend_from_slice(b"PK\x03\x04 fake local header bytes");
        let eocd_offset = data.len();
        data.extend_from_slice(&zip_eocd(b""));
        assert_eq!(find_trailing_zip_eocd(&data), Some(eocd_offset));

        // EOCD with a trailing comment is still located.
        let mut data = vec![0xFF, 0xD8, 0xFF];
        data.extend_from_slice(&[0x11; 128]);
        let eocd_offset = data.len();
        data.extend_from_slice(&zip_eocd(b"archive comment"));
        assert_eq!(find_trailing_zip_eocd(&data), Some(eocd_offset));
    }

    #[test]
    fn test_find_trailing_zip_eocd_quiet_on_plain_jpeg_tail() {
        // Normal JPEG: random trailing bytes must not produce a hit, even
        // when a stray PK\x05\x06 pattern appears without a consistent
        // comment-length field.
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0];
        data.extend_from_slice(&vec![0x7C; 4096]);
        assert_eq!(find_trailing_zip_eocd(&data), None);

        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0xFF; 18]); // comment_len field = 0xFFFF ≠ 0
        assert_eq!(find_trailing_zip_eocd(&data), None);
    }

    // === ZIP multi-entry encryption walk (decoy-first-entry regression) ===

    fn zip_local_entry(name: &[u8], payload: &[u8], flags: u16) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(b"PK\x03\x04");
        entry.extend_from_slice(&20u16.to_le_bytes()); // version
        entry.extend_from_slice(&flags.to_le_bytes());
        entry.extend_from_slice(&[0u8; 2]); // method: stored
        entry.extend_from_slice(&[0u8; 4]); // time/date
        entry.extend_from_slice(&[0u8; 4]); // crc
        entry.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entry.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entry.extend_from_slice(&(name.len() as u16).to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes()); // extra len
        entry.extend_from_slice(name);
        entry.extend_from_slice(payload);
        entry
    }

    #[test]
    fn test_encrypted_zip_second_entry_detected() {
        // PoC bypass: plaintext decoy first entry + encrypted second entry
        // previously passed as unencrypted because only the first local
        // header was inspected.
        let mut data = zip_local_entry(b"readme.txt", b"nothing to see here", 0x0000);
        data.extend_from_slice(&zip_local_entry(b"payload.exe", b"MZ-secret", 0x0001));
        assert!(
            is_encrypted_archive(&data),
            "encrypted second entry must mark the archive encrypted"
        );
    }

    #[test]
    fn test_unencrypted_zip_two_entries_still_quiet() {
        let mut data = zip_local_entry(b"a.txt", b"hello", 0x0000);
        data.extend_from_slice(&zip_local_entry(b"b.txt", b"world", 0x0000));
        assert!(
            !is_encrypted_archive(&data),
            "fully plaintext archive must not be flagged"
        );
    }

    #[test]
    fn test_encrypted_zip_first_entry_short_circuit_unchanged() {
        let data = zip_local_entry(b"secret.bin", b"data", 0x0001);
        assert!(is_encrypted_archive(&data));
    }

    // === PDF/RTF header anchoring (prefix-evasion regression) ===

    #[test]
    fn test_detect_pdf_with_prefix_junk() {
        // PoC bypass: ISO 32000 allows the %PDF- header anywhere in the first
        // 1024 bytes; attackers prepend junk so offset-0 signature checks miss.
        let mut data = vec![b'X'; 64];
        data.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< >>\nendobj\n");
        assert_eq!(detect_file_type(&data), Some(DetectedFileType::Pdf));
    }

    #[test]
    fn test_detect_pdf_header_beyond_window_is_not_matched() {
        // The window is bounded: a %PDF- header past byte 1024 must not
        // classify the file as PDF (keeps text-with-pdf-mention behavior).
        let mut data = vec![b'a'; 1100];
        data.extend_from_slice(b"%PDF-1.7\n");
        assert_ne!(detect_file_type(&data), Some(DetectedFileType::Pdf));
    }

    #[test]
    fn test_detect_pdf_bare_header_at_offset_zero_still_matches() {
        // Legacy behavior: bare "%PDF" (no version dash) at offset 0.
        assert_eq!(
            detect_file_type(b"%PDF"),
            Some(DetectedFileType::Pdf)
        );
    }

    #[test]
    fn test_detect_rtf_with_leading_whitespace() {
        // PoC bypass: whitespace before the {\rtf control word is legal RTF
        // and evades offset-0 signature checks.
        let data = b"  \r\n\t{\\rtf1\\ansi attacker payload}";
        assert_eq!(detect_file_type(data), Some(DetectedFileType::Rtf));
    }

    #[test]
    fn test_detect_rtf_at_offset_zero_unchanged() {
        let data = b"{\\rtf1\\ansi normal document}";
        assert_eq!(detect_file_type(data), Some(DetectedFileType::Rtf));
    }

    #[test]
    fn test_encrypted_pdf_prefix_junk_and_trailer_encrypt() {
        // PoC bypass: prefix junk moves %PDF off offset 0, and /Encrypt only
        // appears in the trailer at the end of the file (past the first 4KB).
        let mut data = vec![b'J'; 32];
        data.extend_from_slice(b"%PDF-1.7\n");
        data.extend_from_slice(&vec![b'x'; 8192]); // body pushes trailer past 4KB
        data.extend_from_slice(b"trailer\n<< /Root 1 0 R /Encrypt 9 0 R >>\n%%EOF\n");
        assert!(
            is_encrypted_pdf(&data),
            "encrypted PDF with prefix junk and tail trailer /Encrypt must be detected"
        );
    }

    #[test]
    fn test_encrypted_pdf_offset_zero_unchanged() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\n";
        assert!(is_encrypted_pdf(data));
    }

    #[test]
    fn test_encrypted_pdf_hash_escape_variant_detected() {
        // PoC bypass: ISO 32000 name escapes spell /Encrypt as /#45ncrypt,
        // which previously slipped past the raw /Encrypt byte search.
        let data = b"%PDF-1.7\n1 0 obj\n<< /#45ncrypt 2 0 R >>\nendobj\n";
        assert!(
            is_encrypted_pdf(data),
            "/#45ncrypt must resolve to /Encrypt after #hh decoding"
        );
        // Fully escaped variant.
        let data = b"%PDF-1.7\n1 0 obj\n<< /#45#6e#63#72#79#70#74 2 0 R >>\nendobj\n";
        assert!(is_encrypted_pdf(data));
    }

    #[test]
    fn test_pdf_name_escape_normalization() {
        assert_eq!(
            normalize_pdf_name_escapes(b"/Fl#61teDecode").as_ref(),
            b"/FlateDecode"
        );
        assert_eq!(
            normalize_pdf_name_escapes(b"/#45ncrypt").as_ref(),
            b"/Encrypt"
        );
        // '#' not followed by two hex digits stays literal.
        assert_eq!(
            normalize_pdf_name_escapes(b"100% #1 top #zz").as_ref(),
            b"100% #1 top #zz"
        );
        // No escape present → borrowed, unchanged.
        assert_eq!(
            normalize_pdf_name_escapes(b"/Encrypt").as_ref(),
            b"/Encrypt"
        );
    }

    #[test]
    fn test_unencrypted_pdf_hash_literal_not_misread() {
        // A literal '#' that is not a valid escape must not decode into a
        // spurious /Encrypt match.
        let data = b"%PDF-1.7\n1 0 obj\n<< /Note (#45 is the hex of E) >>\nendobj\n";
        assert!(!is_encrypted_pdf(data));
    }

    #[test]
    fn test_encrypted_pdf_without_header_in_window_not_detected() {
        let mut data = vec![b'z'; 1100];
        data.extend_from_slice(b"%PDF-1.7\n<< /Encrypt 2 0 R >>\n");
        assert!(!is_encrypted_pdf(&data));
    }

    #[test]
    fn test_unencrypted_pdf_with_trailer_not_detected() {
        let mut data = Vec::from(&b"%PDF-1.7\n"[..]);
        data.extend_from_slice(&vec![b'x'; 4200]);
        data.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
        assert!(!is_encrypted_pdf(&data));
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
