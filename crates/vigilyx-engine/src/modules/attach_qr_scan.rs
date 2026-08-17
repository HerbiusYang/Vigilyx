//! Attachment QR-code scan module.
//!
//! Detects QR codes in image attachments (PNG, JPEG, GIF, BMP, WebP, TIFF)
//! and ASCII block-character QR codes in email body text.
//! Scores phishing-specific QR lures such as login/OAuth/device-code landing pages.

use std::io::{Cursor, Read};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use flate2::read::ZlibDecoder;
use regex::Regex;
use tracing::warn;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::decode_base64_bytes_limited;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};
use crate::modules::link_content::analyze_url;

const MAX_QR_IMAGE_DIM: u32 = 1024;
/// Reject implausibly large source canvases before the image decoder allocates them.
/// Legitimate QR screenshots are resized to `MAX_QR_IMAGE_DIM` after decoding.
const MAX_QR_SOURCE_IMAGE_DIM: u32 = 4096;
const MAX_QR_SOURCE_PIXELS: u64 = 16 * 1024 * 1024;
const MAX_QR_IMAGE_DECODE_ALLOC_BYTES: u64 = 64 * 1024 * 1024;
const MAX_QR_ATTACHMENT_DECODE_BYTES: usize = 10 * 1024 * 1024;
const MAX_EMBEDDED_QR_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_EMBEDDED_QR_IMAGES_PER_ATTACHMENT: usize = 12;
const MAX_QR_IMAGES_PER_MESSAGE: usize = 32;
/// Minimum pixel dimension for an image to be a plausible QR carrier. A
/// version-1 QR code is 21x21 modules; with the mandatory quiet zone it
/// cannot render below ~29px. Smaller images (1x1 tracking pixels, spacer
/// GIFs) are decoys: scanning them wastes the per-message budget, so they
/// are skipped without counting against it.
const MIN_QR_CARRIER_DIM: u32 = 32;
const MAX_QR_SOURCE_BYTES_PER_MESSAGE: usize = 32 * 1024 * 1024;
const MAX_QR_ARCHIVE_ENTRIES_EXAMINED: usize = 256;
const MAX_TEXT_CARRIER_SCAN_BYTES: usize = 2 * 1024 * 1024;
const JPEG_SIGNATURE: &[u8; 3] = b"\xFF\xD8\xFF";
const STRUCTURAL_QR_PAYLOAD_TERMS: &[&str] = &[
    "microsoft.com/devicelogin",
    "login.microsoftonline.com",
    "/login",
    "oauth2",
    "client_id=",
    "redirect_uri=",
    "prompt=consent",
    "scope=",
];
const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

/// Minimum consecutive block characters on a single line to consider it part of an ASCII QR.
const ASCII_QR_MIN_BLOCK_RUN: usize = 10;
/// Minimum rows of block characters to consider a valid ASCII QR region.
const ASCII_QR_MIN_ROWS: usize = 10;
/// Maximum pixel dimensions for rendered ASCII QR bitmaps (prevent abuse).
const ASCII_QR_MAX_RENDER_DIM: usize = 512;
const MAX_ASCII_QR_SCAN_BYTES: usize = 512 * 1024;
const MAX_ASCII_QR_BLOCKS: usize = 4;

/// Unicode block characters used in ASCII-art QR codes.
/// Dark characters map to black, everything else maps to white.
const DARK_BLOCK_CHARS: &[char] = &[
    '\u{2588}', // █ FULL BLOCK
    '\u{2580}', // ▀ UPPER HALF BLOCK
    '\u{2584}', // ▄ LOWER HALF BLOCK
    '\u{258C}', // ▌ LEFT HALF BLOCK
    '\u{2590}', // ▐ RIGHT HALF BLOCK
    '\u{2593}', // ▓ DARK SHADE
    '\u{2592}', // ▒ MEDIUM SHADE (treat as dark for QR)
];
/// Light shade character — explicitly white.
const LIGHT_BLOCK_CHARS: &[char] = &[
    '\u{2591}', // ░ LIGHT SHADE
];

/// Regex to detect lines predominantly composed of block characters and spaces.
/// Matches a line containing at least `ASCII_QR_MIN_BLOCK_RUN` block chars (possibly
/// interspersed with spaces).
static RE_BLOCK_LINE: LazyLock<Regex> = LazyLock::new(|| {
    // Match lines that have at least 10 block-like characters (full/half blocks, shades)
    Regex::new(r"[\u{2588}\u{2580}\u{2584}\u{258C}\u{2590}\u{2591}\u{2592}\u{2593} ]{10,}")
        .expect("valid block line regex")
});

static RE_DATA_IMAGE_URI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)data:image/(png|jpe?g|gif|bmp|webp|tiff?);base64,([A-Za-z0-9+/=\r\n\t ]{32,})"#,
    )
    .expect("valid data image URI regex")
});

pub struct AttachmentQrScanModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
}

impl Default for AttachmentQrScanModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AttachmentQrScanModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        let mut phishing_keywords = effective.phishing_keywords;
        for keyword in effective.weak_phishing_keywords {
            if !phishing_keywords.contains(&keyword) {
                phishing_keywords.push(keyword);
            }
        }
        Self {
            meta: ModuleMetadata {
                id: "attach_qr_scan".to_string(),
                name: "Attachment QR Scan".to_string(),
                description:
                    "Detect QR codes in image attachments and ASCII art, score phishing QR lures"
                        .to_string(),
                pillar: Pillar::Attachment,
                depends_on: vec!["attach_scan".to_string()],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: false,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords,
        }
    }
}

#[derive(Debug, Clone)]
struct QrImageFinding {
    width: u32,
    height: u32,
    grid_count: usize,
    decoded_payloads: Vec<String>,
}

struct GrayscaleImage {
    width: usize,
    height: usize,
    pixels: Vec<u8>,
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn build_email_context(ctx: &SecurityContext) -> String {
    let mut context = String::new();
    if let Some(subject) = ctx.session.subject.as_deref() {
        context.push_str(subject);
        context.push(' ');
    }
    if let Some(body) = ctx.session.content.body_text.as_deref() {
        context.push_str(body);
        context.push(' ');
    }
    if let Some(body_html) = ctx.session.content.body_html.as_deref() {
        context.push_str(body_html);
        context.push(' ');
    }
    for link in &ctx.session.content.links {
        if let Some(text) = link.text.as_deref() {
            context.push_str(text);
            context.push(' ');
        }
    }
    for attachment in &ctx.session.content.attachments {
        context.push_str(&attachment.filename);
        context.push(' ');
    }
    context.to_lowercase()
}

fn has_explicit_qr_lure_context(text: &str) -> bool {
    // Generic phishing keywords (for example "please check" or "notice")
    // appear in ordinary vendor signatures and must not turn a decorative QR
    // image into a lure.  Require wording that actually instructs the user to
    // scan/use the QR code or ties it to an authentication flow.
    const QR_LURE_TERMS: &[&str] = &[
        "qr code",
        "scan qr",
        "scan the code",
        "scan to login",
        "scan to sign in",
        "scan to verify",
        "二维码",
        "扫描二维码",
        "扫码",
        "扫码登录",
        "扫码验证",
    ];

    let normalized = normalize_text(text);
    QR_LURE_TERMS
        .iter()
        .any(|term| normalized.contains(term))
}

/// Check whether the attachment is a raster image that could contain a QR code.
/// Supports PNG, JPEG, GIF, BMP, TIFF, and WebP.
fn is_raster_qr_candidate(content_type: &str, file_type: Option<DetectedFileType>) -> bool {
    // Check by magic-byte detected type first (most reliable).
    if matches!(
        file_type,
        Some(
            DetectedFileType::Png
                | DetectedFileType::Jpeg
                | DetectedFileType::Gif
                | DetectedFileType::Bmp
                | DetectedFileType::Tiff
        )
    ) {
        return true;
    }
    // Fall back to Content-Type header for formats not in magic_bytes (e.g. WebP).
    let ct = content_type.to_ascii_lowercase();
    ct.starts_with("image/png")
        || ct.starts_with("image/jpeg")
        || ct.starts_with("image/jpg")
        || ct.starts_with("image/gif")
        || ct.starts_with("image/bmp")
        || ct.starts_with("image/tiff")
        || ct.starts_with("image/webp")
}

/// Header-only check: is this image too small to possibly carry a QR code?
/// Images whose declared dimensions are unreadable are *not* skipped — the
/// conservative choice keeps malformed decoys on the normal scan path.
fn is_below_qr_carrier_size(bytes: &[u8]) -> bool {
    let Ok(reader) = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format() else {
        return false;
    };
    match reader.into_dimensions() {
        Ok((width, height)) => width.min(height) < MIN_QR_CARRIER_DIM,
        Err(_) => false,
    }
}

fn extension_from_filename(filename: &str) -> &str {
    filename
        .rsplit('.')
        .next()
        .filter(|ext| *ext != filename)
        .unwrap_or("")
}

fn is_zip_document_qr_candidate(filename: &str, content_type: &str) -> bool {
    let ext = extension_from_filename(filename).to_ascii_lowercase();
    let ct = content_type.to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp"
    ) || ct.contains("officedocument")
        || ct.contains("opendocument")
}

fn is_pdf_qr_candidate(
    filename: &str,
    content_type: &str,
    file_type: Option<DetectedFileType>,
) -> bool {
    let ext = extension_from_filename(filename).to_ascii_lowercase();
    let ct = content_type.to_ascii_lowercase();
    file_type == Some(DetectedFileType::Pdf)
        || ext == "pdf"
        || ct.contains("application/pdf")
        || ct.contains("application/x-pdf")
}

fn is_text_image_carrier_qr_candidate(
    filename: &str,
    content_type: &str,
    file_type: Option<DetectedFileType>,
) -> bool {
    let ext = extension_from_filename(filename).to_ascii_lowercase();
    let ct = content_type.to_ascii_lowercase();
    matches!(ext.as_str(), "svg" | "html" | "htm" | "xhtml")
        || ct.contains("image/svg")
        || ct.contains("text/html")
        || ct.contains("application/xhtml")
        || file_type == Some(DetectedFileType::HtmlDocument)
        || file_type == Some(DetectedFileType::PlainText)
}

fn is_qr_candidate_by_metadata(filename: &str, content_type: &str) -> bool {
    let ext = extension_from_filename(filename).to_ascii_lowercase();
    let ct = content_type.to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "bmp"
            | "webp"
            | "tif"
            | "tiff"
            | "pdf"
            | "docx"
            | "xlsx"
            | "pptx"
            | "odt"
            | "ods"
            | "odp"
            | "svg"
            | "html"
            | "htm"
            | "xhtml"
    ) || ct.starts_with("image/")
        || ct.contains("pdf")
        || ct.contains("officedocument")
        || ct.contains("opendocument")
        || ct.contains("svg")
        || ct.contains("html")
        || ct.contains("application/octet-stream")
}

fn is_embedded_media_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let in_media_dir = lower.contains("/media/")
        || lower.starts_with("word/media/")
        || lower.starts_with("ppt/media/")
        || lower.starts_with("xl/media/");
    if !in_media_dir {
        return false;
    }
    matches!(
        extension_from_filename(&lower),
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "tif" | "tiff"
    )
}

fn find_bytes(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start >= haystack.len() || haystack.len() < needle.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset)
}

fn find_png_end(data: &[u8], start: usize) -> Option<usize> {
    if start.checked_add(PNG_SIGNATURE.len())? > data.len()
        || &data[start..start + PNG_SIGNATURE.len()] != PNG_SIGNATURE
    {
        return None;
    }

    let mut cursor = start + PNG_SIGNATURE.len();
    while cursor + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().ok()?) as usize;
        let chunk_type = &data[cursor + 4..cursor + 8];
        let payload_start = cursor + 8;
        let next = payload_start.checked_add(chunk_len)?.checked_add(4)?;
        if next > data.len() || next - start > MAX_EMBEDDED_QR_IMAGE_BYTES {
            return None;
        }
        if chunk_type == b"IEND" {
            return Some(next);
        }
        cursor = next;
    }
    None
}

fn find_jpeg_end(data: &[u8], start: usize) -> Option<usize> {
    if start.checked_add(JPEG_SIGNATURE.len())? > data.len()
        || &data[start..start + JPEG_SIGNATURE.len()] != JPEG_SIGNATURE
    {
        return None;
    }

    let max_end = data.len().min(start + MAX_EMBEDDED_QR_IMAGE_BYTES);
    let mut cursor = start + JPEG_SIGNATURE.len();
    while cursor + 1 < max_end {
        if data[cursor] == 0xFF && data[cursor + 1] == 0xD9 {
            return Some(cursor + 2);
        }
        cursor += 1;
    }
    None
}

fn find_bmp_end(data: &[u8], start: usize) -> Option<usize> {
    if start + 6 > data.len() || &data[start..start + 2] != b"BM" {
        return None;
    }
    let file_size = u32::from_le_bytes(data[start + 2..start + 6].try_into().ok()?) as usize;
    if file_size == 0 || file_size > MAX_EMBEDDED_QR_IMAGE_BYTES {
        return None;
    }
    start
        .checked_add(file_size)
        .filter(|end| *end <= data.len())
}

fn find_webp_end(data: &[u8], start: usize) -> Option<usize> {
    if start + 12 > data.len() || &data[start..start + 4] != b"RIFF" {
        return None;
    }
    if &data[start + 8..start + 12] != b"WEBP" {
        return None;
    }
    let riff_len = u32::from_le_bytes(data[start + 4..start + 8].try_into().ok()?) as usize;
    let file_size = riff_len.checked_add(8)?;
    if file_size == 0 || file_size > MAX_EMBEDDED_QR_IMAGE_BYTES {
        return None;
    }
    start
        .checked_add(file_size)
        .filter(|end| *end <= data.len())
}

fn next_embedded_raster(data: &[u8], start: usize) -> Option<(&'static str, usize, usize)> {
    let candidates = [
        (
            "png",
            find_bytes(data, PNG_SIGNATURE, start),
            find_png_end as fn(&[u8], usize) -> Option<usize>,
        ),
        (
            "jpeg",
            find_bytes(data, JPEG_SIGNATURE, start),
            find_jpeg_end as fn(&[u8], usize) -> Option<usize>,
        ),
        (
            "bmp",
            find_bytes(data, b"BM", start),
            find_bmp_end as fn(&[u8], usize) -> Option<usize>,
        ),
        (
            "webp",
            find_bytes(data, b"RIFF", start),
            find_webp_end as fn(&[u8], usize) -> Option<usize>,
        ),
    ];

    candidates
        .into_iter()
        .filter_map(|(kind, image_start, find_end)| {
            let image_start = image_start?;
            let image_end = find_end(data, image_start)?;
            Some((kind, image_start, image_end))
        })
        .min_by_key(|(_, image_start, _)| *image_start)
}

fn decode_embedded_qr_images_from_binary(
    data: &[u8],
    label_prefix: &str,
    max_images: usize,
) -> (usize, Vec<(String, QrImageFinding)>, bool) {
    let mut findings = Vec::new();
    let mut scanned = 0usize;
    let mut cursor = 0usize;
    let image_limit = max_images.min(MAX_EMBEDDED_QR_IMAGES_PER_ATTACHMENT);

    while scanned < image_limit {
        let Some((kind, image_start, image_end)) = next_embedded_raster(data, cursor) else {
            break;
        };
        cursor = image_end.max(image_start + 1);
        let image_bytes = &data[image_start..image_end];
        if image_bytes.len() > MAX_EMBEDDED_QR_IMAGE_BYTES
            || !is_raster_qr_candidate(&format!("image/{kind}"), detect_file_type(image_bytes))
        {
            continue;
        }

        // 1x1 placeholder / tracking-pixel decoys cannot carry a QR code;
        // they only exist to exhaust the embedded-image budget, so skip them
        // without charging the budget.
        if is_below_qr_carrier_size(image_bytes) {
            continue;
        }
        scanned += 1;
        if let Some(qr) = decode_qr_from_image_bytes(image_bytes) {
            findings.push((format!("{label_prefix}_{kind}_{}", scanned), qr));
        }
    }

    let limited = scanned >= image_limit && next_embedded_raster(data, cursor).is_some();
    (scanned, findings, limited)
}

fn read_zip_entry_limited<R: Read>(
    mut entry: zip::read::ZipFile<'_, R>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    if entry.size() > max_bytes as u64 {
        return None;
    }
    let mut data = Vec::with_capacity((entry.size() as usize).min(max_bytes));
    let mut limited = (&mut entry).take(max_bytes as u64 + 1);
    limited.read_to_end(&mut data).ok()?;
    if data.len() > max_bytes {
        return None;
    }
    Some(data)
}

fn decode_embedded_qr_images_from_zip(
    data: &[u8],
    max_images: usize,
) -> (usize, Vec<(String, QrImageFinding)>, bool) {
    let cursor = Cursor::new(data);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(_) => return (0, Vec::new(), false),
    };

    let mut findings = Vec::new();
    let mut scanned = 0usize;
    let image_limit = max_images.min(MAX_EMBEDDED_QR_IMAGES_PER_ATTACHMENT);
    let entry_limit = archive.len().min(MAX_QR_ARCHIVE_ENTRIES_EXAMINED);
    let mut limited = archive.len() > entry_limit;
    for idx in 0..entry_limit {
        if scanned >= image_limit {
            limited = true;
            break;
        }
        let Ok(entry) = archive.by_index(idx) else {
            continue;
        };
        let name = entry.name().to_string();
        if !is_embedded_media_path(&name) {
            continue;
        }
        let Some(bytes) = read_zip_entry_limited(entry, MAX_EMBEDDED_QR_IMAGE_BYTES) else {
            continue;
        };
        if !is_raster_qr_candidate("application/octet-stream", detect_file_type(&bytes)) {
            continue;
        }
        // Skip placeholder-sized decoys without charging the budget.
        if is_below_qr_carrier_size(&bytes) {
            continue;
        }
        scanned += 1;
        if let Some(qr) = decode_qr_from_image_bytes(&bytes) {
            findings.push((name, qr));
        }
    }

    (scanned, findings, limited)
}

fn decode_data_uri_qr_images_from_text(
    text: &str,
    max_images: usize,
) -> (usize, Vec<(String, QrImageFinding)>, bool) {
    let scan_text = if text.len() <= MAX_TEXT_CARRIER_SCAN_BYTES {
        text
    } else {
        let mut end = MAX_TEXT_CARRIER_SCAN_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    };

    let mut findings = Vec::new();
    let mut scanned = 0usize;
    let image_limit = max_images.min(MAX_EMBEDDED_QR_IMAGES_PER_ATTACHMENT);
    let mut limited = text.len() > scan_text.len();
    for (idx, caps) in RE_DATA_IMAGE_URI.captures_iter(scan_text).enumerate() {
        if scanned >= image_limit {
            limited = true;
            break;
        }
        let image_type = caps.get(1).map(|m| m.as_str()).unwrap_or("unknown");
        let Some(payload) = caps.get(2).map(|m| m.as_str()) else {
            continue;
        };
        let Some(bytes) = decode_base64_bytes_limited(payload, MAX_EMBEDDED_QR_IMAGE_BYTES) else {
            continue;
        };
        if !is_raster_qr_candidate(&format!("image/{image_type}"), detect_file_type(&bytes)) {
            continue;
        }
        // Skip placeholder-sized decoys without charging the budget.
        if is_below_qr_carrier_size(&bytes) {
            continue;
        }
        scanned += 1;
        if let Some(qr) = decode_qr_from_image_bytes(&bytes) {
            findings.push((format!("data_uri_image_{}", idx + 1), qr));
        }
    }

    (scanned, findings, limited)
}

fn paeth_predictor(left: u8, up: u8, up_left: u8) -> u8 {
    let left = left as i32;
    let up = up as i32;
    let up_left = up_left as i32;
    let predictor = left + up - up_left;
    let left_distance = (predictor - left).abs();
    let up_distance = (predictor - up).abs();
    let up_left_distance = (predictor - up_left).abs();

    if left_distance <= up_distance && left_distance <= up_left_distance {
        left as u8
    } else if up_distance <= up_left_distance {
        up as u8
    } else {
        up_left as u8
    }
}

/// Minimal manual PNG decoder (handles 8-bit grayscale, RGB, gray+alpha, RGBA;
/// non-interlaced only). Retained for backward compatibility and zero-alloc efficiency
/// on the most common QR-code PNG variant.
fn decode_png_grayscale(data: &[u8]) -> Option<GrayscaleImage> {
    if data.len() < PNG_SIGNATURE.len() || &data[..PNG_SIGNATURE.len()] != PNG_SIGNATURE {
        return None;
    }

    let mut cursor = PNG_SIGNATURE.len();
    let mut width = 0usize;
    let mut height = 0usize;
    let mut channels = 0usize;
    let mut idat = Vec::new();

    while cursor + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes(data[cursor..cursor + 4].try_into().ok()?) as usize;
        cursor += 4;
        let chunk_type = &data[cursor..cursor + 4];
        cursor += 4;

        if cursor + chunk_len + 4 > data.len() {
            return None;
        }
        let chunk_data = &data[cursor..cursor + chunk_len];
        cursor += chunk_len;
        cursor += 4; // Skip CRC.

        match chunk_type {
            b"IHDR" => {
                if chunk_data.len() != 13 {
                    return None;
                }
                width = u32::from_be_bytes(chunk_data[0..4].try_into().ok()?) as usize;
                height = u32::from_be_bytes(chunk_data[4..8].try_into().ok()?) as usize;
                let bit_depth = chunk_data[8];
                let color_type = chunk_data[9];
                let compression = chunk_data[10];
                let filter = chunk_data[11];
                let interlace = chunk_data[12];

                if width == 0
                    || height == 0
                    || width > MAX_QR_SOURCE_IMAGE_DIM as usize
                    || height > MAX_QR_SOURCE_IMAGE_DIM as usize
                    || (width as u64).checked_mul(height as u64)? > MAX_QR_SOURCE_PIXELS
                    || bit_depth != 8
                    || compression != 0
                    || filter != 0
                    || interlace != 0
                {
                    return None;
                }

                channels = match color_type {
                    0 => 1,
                    2 => 3,
                    4 => 2,
                    6 => 4,
                    _ => return None,
                };
            }
            b"IDAT" => idat.extend_from_slice(chunk_data),
            b"IEND" => break,
            _ => {}
        }
    }

    if width == 0 || height == 0 || channels == 0 || idat.is_empty() {
        return None;
    }

    // SECURITY: Cap decompressed size to 10 MB to prevent zlib bomb (CWE-400).
    // A legitimate QR-code PNG rarely exceeds a few hundred KB uncompressed.
    const MAX_DECOMPRESSED: u64 = 10 * 1024 * 1024;
    let mut inflated = Vec::new();
    ZlibDecoder::new(idat.as_slice())
        .take(MAX_DECOMPRESSED)
        .read_to_end(&mut inflated)
        .ok()?;

    let row_bytes = width.checked_mul(channels)?;
    let expected_len = height.checked_mul(row_bytes + 1)?;
    if inflated.len() < expected_len {
        return None;
    }

    let mut reconstructed = vec![0u8; height.checked_mul(row_bytes)?];
    for row in 0..height {
        let src_offset = row * (row_bytes + 1);
        let filter = inflated[src_offset];
        let src_row = &inflated[src_offset + 1..src_offset + 1 + row_bytes];
        let dst_offset = row * row_bytes;

        for column in 0..row_bytes {
            let left = if column >= channels {
                reconstructed[dst_offset + column - channels]
            } else {
                0
            };
            let up = if row > 0 {
                reconstructed[dst_offset + column - row_bytes]
            } else {
                0
            };
            let up_left = if row > 0 && column >= channels {
                reconstructed[dst_offset + column - row_bytes - channels]
            } else {
                0
            };

            reconstructed[dst_offset + column] = match filter {
                0 => src_row[column],
                1 => src_row[column].wrapping_add(left),
                2 => src_row[column].wrapping_add(up),
                3 => src_row[column].wrapping_add(((left as u16 + up as u16) / 2) as u8),
                4 => src_row[column].wrapping_add(paeth_predictor(left, up, up_left)),
                _ => return None,
            };
        }
    }

    let mut pixels = Vec::with_capacity(width.checked_mul(height)?);
    for pixel in reconstructed.chunks_exact(channels) {
        let grayscale = match channels {
            1 | 2 => pixel[0],
            3 | 4 => {
                ((pixel[0] as u32 * 299 + pixel[1] as u32 * 587 + pixel[2] as u32 * 114 + 500)
                    / 1000) as u8
            }
            _ => return None,
        };
        pixels.push(grayscale);
    }

    Some(GrayscaleImage {
        width,
        height,
        pixels,
    })
}

/// Decode any supported image format (JPEG, GIF, BMP, WebP, TIFF, and PNG as fallback)
/// to grayscale using the `image` crate.
///
/// SECURITY: dimensions and total pixels are inspected before full decoding. Decoder
/// allocation limits provide a second layer of protection against malformed images.
fn decode_image_crate_grayscale(data: &[u8]) -> Option<GrayscaleImage> {
    // SECURITY: reject excessively large input (10 MB compressed should be more than enough
    // for any legitimate QR-code image).
    const MAX_INPUT_BYTES: usize = 10 * 1024 * 1024;
    if data.len() > MAX_INPUT_BYTES {
        warn!(
            len = data.len(),
            "attach_qr_scan: rejecting oversized image input ({} bytes)",
            data.len()
        );
        return None;
    }

    // Post-decode resizing is too late for a compressed image that declares a huge canvas.
    let (source_width, source_height) = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()?;
    let source_pixels = u64::from(source_width).checked_mul(u64::from(source_height))?;
    if source_width == 0
        || source_height == 0
        || source_width > MAX_QR_SOURCE_IMAGE_DIM
        || source_height > MAX_QR_SOURCE_IMAGE_DIM
        || source_pixels > MAX_QR_SOURCE_PIXELS
    {
        warn!(
            source_width,
            source_height,
            source_pixels,
            "attach_qr_scan: rejecting unsafe source image dimensions"
        );
        return None;
    }

    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_QR_SOURCE_IMAGE_DIM);
    limits.max_image_height = Some(MAX_QR_SOURCE_IMAGE_DIM);
    limits.max_alloc = Some(MAX_QR_IMAGE_DECODE_ALLOC_BYTES);
    reader.limits(limits);

    let dynamic_image = match reader.decode() {
        Ok(img) => img,
        Err(e) => {
            warn!(error = %e, "attach_qr_scan: image crate failed to decode image");
            return None;
        }
    };

    // Cap dimensions.
    let max = MAX_QR_IMAGE_DIM;
    let (w, h) = (dynamic_image.width(), dynamic_image.height());
    if w == 0 || h == 0 {
        return None;
    }
    let dynamic_image = if w > max || h > max {
        dynamic_image.resize(max, max, image::imageops::FilterType::Nearest)
    } else {
        dynamic_image
    };

    let luma = dynamic_image.to_luma8();
    let width = luma.width() as usize;
    let height = luma.height() as usize;
    Some(GrayscaleImage {
        width,
        height,
        pixels: luma.into_raw(),
    })
}

fn downscale_grayscale_nearest(image: GrayscaleImage, max_dim: u32) -> GrayscaleImage {
    let max_dim = max_dim as usize;
    if image.width.max(image.height) <= max_dim || max_dim == 0 {
        return image;
    }

    let dominant = image.width.max(image.height);
    let new_width = (image.width * max_dim / dominant).max(1);
    let new_height = (image.height * max_dim / dominant).max(1);
    let mut pixels = vec![255u8; new_width * new_height];

    for y in 0..new_height {
        let src_y = y * image.height / new_height;
        for x in 0..new_width {
            let src_x = x * image.width / new_width;
            pixels[y * new_width + x] = image.pixels[src_y * image.width + src_x];
        }
    }

    GrayscaleImage {
        width: new_width,
        height: new_height,
        pixels,
    }
}

fn finder_pattern_matches(
    image: &GrayscaleImage,
    start_x: usize,
    start_y: usize,
    module: usize,
) -> Option<usize> {
    if module == 0 {
        return None;
    }
    let finder_extent = 7usize.checked_mul(module)?;
    if start_x.checked_add(finder_extent)? > image.width
        || start_y.checked_add(finder_extent)? > image.height
    {
        return None;
    }

    let mut matches = 0usize;
    for row in 0..7 {
        for col in 0..7 {
            let mut sum = 0u64;
            for y in 0..module {
                for x in 0..module {
                    let px = start_x + col * module + x;
                    let py = start_y + row * module + y;
                    sum += image.pixels[py * image.width + px] as u64;
                }
            }
            let avg = sum / (module * module) as u64;
            let is_dark = avg < 128;
            let expected_dark = row == 0
                || row == 6
                || col == 0
                || col == 6
                || ((2..=4).contains(&row) && (2..=4).contains(&col));
            if is_dark == expected_dark {
                matches += 1;
            }
        }
    }

    Some(matches)
}

fn has_qr_finder_patterns(image: &GrayscaleImage) -> bool {
    let min_dim = image.width.min(image.height);
    if min_dim < 21 {
        return false;
    }

    let max_module = (min_dim / 11).clamp(2, 32);
    for module in 2..=max_module {
        for quiet in 2..=6 {
            let span = (quiet + 7) * module;
            if span > image.width || span > image.height {
                continue;
            }

            let top_left = finder_pattern_matches(image, quiet * module, quiet * module, module);
            let top_right =
                finder_pattern_matches(image, image.width - span, quiet * module, module);
            let bottom_left =
                finder_pattern_matches(image, quiet * module, image.height - span, module);

            if top_left.is_some_and(|score| score >= 44)
                && top_right.is_some_and(|score| score >= 44)
                && bottom_left.is_some_and(|score| score >= 44)
            {
                return true;
            }
        }
    }

    false
}

/// Apply a simple binary threshold to a grayscale image.
fn binarize_at_threshold(image: &GrayscaleImage, threshold: u8) -> GrayscaleImage {
    let pixels = image
        .pixels
        .iter()
        .map(|&p| if p < threshold { 0 } else { 255 })
        .collect();
    GrayscaleImage {
        width: image.width,
        height: image.height,
        pixels,
    }
}

/// Attempt QR decoding from a grayscale image using `rqrr`.
/// Returns `(grid_count, decoded_payloads)`.
fn try_rqrr_decode(grayscale: &GrayscaleImage) -> (usize, Vec<String>) {
    run_rqrr_guarded(grayscale, || try_rqrr_decode_inner(grayscale))
}

fn run_rqrr_guarded<F>(grayscale: &GrayscaleImage, decoder: F) -> (usize, Vec<String>)
where
    F: FnOnce() -> (usize, Vec<String>),
{
    match catch_unwind(AssertUnwindSafe(decoder)) {
        Ok(result) => result,
        Err(payload) => {
            let panic_message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("unknown panic");
            warn!(
                width = grayscale.width,
                height = grayscale.height,
                panic = panic_message,
                "attach_qr_scan: rqrr rejected a malformed QR candidate; skipping it"
            );

            let grid_count = usize::from(has_qr_finder_patterns(grayscale));
            (grid_count, Vec::new())
        }
    }
}

fn try_rqrr_decode_inner(grayscale: &GrayscaleImage) -> (usize, Vec<String>) {
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(grayscale.width, grayscale.height, |x, y| {
            grayscale.pixels[y * grayscale.width + x]
        });
    let grids = prepared.detect_grids();

    let mut decoded_payloads = Vec::new();
    for grid in grids.iter() {
        if let Ok((_meta, content)) = grid.decode() {
            let payload = content.trim();
            if !payload.is_empty()
                && !decoded_payloads
                    .iter()
                    .any(|existing: &String| existing == payload)
            {
                decoded_payloads.push(payload.to_string());
            }
        }
    }

    let grid_count = if grids.is_empty() && has_qr_finder_patterns(grayscale) {
        1
    } else {
        grids.len()
    };
    (grid_count, decoded_payloads)
}

/// Try to decode a QR code from raw image bytes.
///
/// Strategy:
/// 1. For PNG: try the fast manual decoder first, then fall back to `image` crate.
/// 2. For all other formats: use the `image` crate directly.
/// 3. If the first `rqrr` attempt fails to decode payloads, retry with adaptive
///    binarization at multiple thresholds (64, 128, 192) to handle damaged/low-contrast QR codes.
fn decode_qr_from_image_bytes(data: &[u8]) -> Option<QrImageFinding> {
    let is_png = data.len() >= PNG_SIGNATURE.len() && &data[..PNG_SIGNATURE.len()] == PNG_SIGNATURE;

    // Step 1: Obtain grayscale image.
    let grayscale = if is_png {
        // Try the fast manual PNG decoder first.
        decode_png_grayscale(data)
            .map(|g| downscale_grayscale_nearest(g, MAX_QR_IMAGE_DIM))
            .or_else(|| {
                // Fall back to image crate for PNGs the manual parser can't handle
                // (e.g. interlaced, 16-bit, palette-indexed).
                decode_image_crate_grayscale(data)
            })
    } else {
        // Non-PNG: use image crate (JPEG, GIF, BMP, WebP, TIFF).
        decode_image_crate_grayscale(data)
    };
    let grayscale = grayscale?;

    // Step 2: Try rqrr decode on the original grayscale.
    let (grid_count, decoded_payloads) = try_rqrr_decode(&grayscale);

    if grid_count > 0 && !decoded_payloads.is_empty() {
        return Some(QrImageFinding {
            width: grayscale.width as u32,
            height: grayscale.height as u32,
            grid_count,
            decoded_payloads,
        });
    }

    // Step 3: Adaptive binarization retry — try multiple thresholds to handle
    // damaged or low-contrast QR codes.
    if grid_count > 0 && decoded_payloads.is_empty() {
        // We detected grids but couldn't decode. Try sharper binarization.
        for threshold in [64u8, 128, 192] {
            let binary = binarize_at_threshold(&grayscale, threshold);
            let (_, payloads) = try_rqrr_decode(&binary);
            if !payloads.is_empty() {
                return Some(QrImageFinding {
                    width: grayscale.width as u32,
                    height: grayscale.height as u32,
                    grid_count,
                    decoded_payloads: payloads,
                });
            }
        }
        // Still couldn't decode — return the finding with grid detection only.
        return Some(QrImageFinding {
            width: grayscale.width as u32,
            height: grayscale.height as u32,
            grid_count,
            decoded_payloads: Vec::new(),
        });
    }

    // Step 4: No grids detected — one more attempt with binarization in case the
    // original image was very noisy.
    for threshold in [64u8, 128, 192] {
        let binary = binarize_at_threshold(&grayscale, threshold);
        let (gc, payloads) = try_rqrr_decode(&binary);
        if gc > 0 {
            return Some(QrImageFinding {
                width: grayscale.width as u32,
                height: grayscale.height as u32,
                grid_count: gc,
                decoded_payloads: payloads,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// ASCII block-character QR code detection
// ---------------------------------------------------------------------------

/// Returns true if `ch` is a "dark" block character used in ASCII QR codes.
fn is_dark_block(ch: char) -> bool {
    DARK_BLOCK_CHARS.contains(&ch)
}

/// Returns true if `ch` is a "light" block character or a space (white in QR).
fn is_light_or_space(ch: char) -> bool {
    ch == ' ' || LIGHT_BLOCK_CHARS.contains(&ch)
}

/// Returns true if `ch` is any block character or space that could be part of an ASCII QR.
fn is_block_or_space(ch: char) -> bool {
    is_dark_block(ch) || is_light_or_space(ch)
}

/// Extract contiguous rectangular regions of block characters from body text.
/// Returns a list of 2D char grids (each grid = Vec of rows of chars).
fn extract_ascii_qr_blocks(text: &str) -> Vec<Vec<Vec<char>>> {
    let scan_text = if text.len() <= MAX_ASCII_QR_SCAN_BYTES {
        text
    } else {
        let mut end = MAX_ASCII_QR_SCAN_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        &text[..end]
    };
    let lines: Vec<&str> = scan_text.lines().collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < lines.len() && results.len() < MAX_ASCII_QR_BLOCKS {
        // Check if this line has a block-character run.
        if !RE_BLOCK_LINE.is_match(lines[i]) {
            i += 1;
            continue;
        }
        // Find the contiguous region of block lines.
        let start = i;
        while i < lines.len() && RE_BLOCK_LINE.is_match(lines[i]) {
            i += 1;
        }
        let end = i;
        if end - start < ASCII_QR_MIN_ROWS {
            continue;
        }

        // Extract the character grid. Normalize width to the maximum row length.
        let rows: Vec<Vec<char>> = lines[start..end]
            .iter()
            .map(|line| {
                line.chars()
                    .filter(|ch| is_block_or_space(*ch))
                    .collect::<Vec<_>>()
            })
            .collect();

        // Ensure each row has at least the minimum block run.
        let qualifying_rows = rows
            .iter()
            .filter(|r| r.len() >= ASCII_QR_MIN_BLOCK_RUN)
            .count();
        if qualifying_rows >= ASCII_QR_MIN_ROWS {
            results.push(rows);
        }
    }
    results
}

/// Render an ASCII block-character grid to a grayscale bitmap suitable for QR decoding.
/// Each character becomes a `scale x scale` pixel block.
fn render_ascii_qr_to_image(grid: &[Vec<char>], scale: usize) -> Option<GrayscaleImage> {
    if grid.is_empty() || scale == 0 {
        return None;
    }
    let grid_width = grid.iter().map(|r| r.len()).max().unwrap_or(0);
    if grid_width == 0 {
        return None;
    }
    let grid_height = grid.len();

    // Add a quiet zone of 4 modules around the QR code.
    let quiet = 4;
    let img_width = (grid_width + quiet * 2) * scale;
    let img_height = (grid_height + quiet * 2) * scale;

    // Prevent oversized renders.
    if img_width > ASCII_QR_MAX_RENDER_DIM || img_height > ASCII_QR_MAX_RENDER_DIM {
        return None;
    }

    // White background (quiet zone).
    let mut pixels = vec![255u8; img_width * img_height];

    for (row_idx, row) in grid.iter().enumerate() {
        for (col_idx, &ch) in row.iter().enumerate() {
            let val = if is_dark_block(ch) { 0u8 } else { 255u8 };
            let base_x = (col_idx + quiet) * scale;
            let base_y = (row_idx + quiet) * scale;
            for dy in 0..scale {
                for dx in 0..scale {
                    let px = base_x + dx;
                    let py = base_y + dy;
                    if px < img_width && py < img_height {
                        pixels[py * img_width + px] = val;
                    }
                }
            }
        }
    }

    Some(GrayscaleImage {
        width: img_width,
        height: img_height,
        pixels,
    })
}

/// Attempt to detect and decode QR codes from ASCII block-character art in email body text.
fn decode_ascii_qr_from_text(text: &str) -> Vec<QrImageFinding> {
    let grids = extract_ascii_qr_blocks(text);
    let mut findings = Vec::new();

    for grid in &grids {
        // Try rendering at multiple scales for robustness.
        for scale in [4, 8, 2] {
            let Some(rendered) = render_ascii_qr_to_image(grid, scale) else {
                continue;
            };
            let (grid_count, decoded_payloads) = try_rqrr_decode(&rendered);
            if grid_count > 0 {
                findings.push(QrImageFinding {
                    width: rendered.width as u32,
                    height: rendered.height as u32,
                    grid_count,
                    decoded_payloads,
                });
                break; // No need to try more scales for this grid.
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Scoring helpers
// ---------------------------------------------------------------------------

/// Score a single QR finding's decoded payloads against phishing indicators.
/// Returns `(added_score, new_categories, new_evidence)`.
fn score_qr_payloads(
    finding: &QrImageFinding,
    source_label: &str,
    qr_lure_context: bool,
    rcpt_to: &[String],
    phishing_keywords: &[String],
) -> (f64, Vec<String>, Vec<Evidence>) {
    let _ = phishing_keywords; // reserved for future per-payload keyword matching
    let mut score = 0.0_f64;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();

    // QR presence is a carrier observation, not a threat conviction. QR codes
    // are routine in invoices, property reports, signatures and mobile-app
    // onboarding. Risk begins only when the surrounding lure or decoded
    // destination supplies an actionable phishing fact.
    categories.push("attachment_qr_code".to_string());
    evidence.push(Evidence {
        description: format!(
            "{} contains QR-like image patterns ({} grid(s), {}x{})",
            source_label, finding.grid_count, finding.width, finding.height
        ),
        location: Some(source_label.to_string()),
        snippet: None,
    });

    if qr_lure_context {
        score += 0.18;
        categories.push("attachment_qr_lure".to_string());
    }

    if finding.decoded_payloads.is_empty() {
        return (score, categories, evidence);
    }

    categories.push("attachment_qr_decoded".to_string());

    for payload in finding.decoded_payloads.iter().take(3) {
        let payload_lower = payload.to_lowercase();
        let has_recipient = rcpt_to.iter().any(|rcpt| {
            let rcpt_lower = rcpt.to_lowercase();
            payload_lower.contains(&rcpt_lower)
                || payload_lower.contains(&rcpt_lower.replace('@', "%40"))
        });
        if has_recipient {
            // Personalised QR payloads are common in legitimate ticketing and
            // payment systems. Keep this weak unless URL/content checks agree.
            score += 0.05;
            categories.push("attachment_qr_targeted".to_string());
        }
        if contains_any(&payload_lower, STRUCTURAL_QR_PAYLOAD_TERMS) {
            score += 0.12;
            categories.push("attachment_qr_login_lure".to_string());
        }
        if qr_lure_context && payload_lower.contains("microsoft.com/devicelogin") {
            score += 0.25;
            categories.push("device_code_phishing".to_string());
        }

        // URL safety analysis on QR-decoded URLs.
        if payload_lower.starts_with("http://") || payload_lower.starts_with("https://") {
            let (url_score, url_cats) = analyze_url(payload);
            if url_score > 0.0 {
                score += url_score.min(0.30);
                for (cat, _detail) in &url_cats {
                    categories.push(format!("qr_{}", cat));
                }
            }
        }

        evidence.push(Evidence {
            description: format!(
                "{} QR decoded payload: {}{}",
                source_label,
                payload,
                if has_recipient {
                    " (contains recipient address)"
                } else {
                    ""
                }
            ),
            location: Some(source_label.to_string()),
            snippet: Some(payload.clone()),
        });
    }

    (score, categories, evidence)
}

#[async_trait]
impl SecurityModule for AttachmentQrScanModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let email_context = build_email_context(ctx);
        let qr_lure_context = has_explicit_qr_lure_context(&email_context);

        let mut total_score = 0.0_f64;
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut scanned_images = 0usize;
        let mut source_bytes_scanned = 0usize;
        let mut inspection_limited = false;
        let mut payloads = Vec::new();

        // --- Phase 1: Scan image attachments and embedded document/SVG images ---
        for attachment in &ctx.session.content.attachments {
            if !is_qr_candidate_by_metadata(&attachment.filename, &attachment.content_type) {
                continue;
            }
            if scanned_images >= MAX_QR_IMAGES_PER_MESSAGE {
                inspection_limited = true;
                break;
            }
            let remaining_source_bytes =
                MAX_QR_SOURCE_BYTES_PER_MESSAGE.saturating_sub(source_bytes_scanned);
            let attachment_decode_limit =
                MAX_QR_ATTACHMENT_DECODE_BYTES.min(remaining_source_bytes);
            if attachment_decode_limit == 0 || attachment.size > attachment_decode_limit {
                inspection_limited = true;
                continue;
            }
            let Some(b64) = attachment.content_base64.as_deref() else {
                continue;
            };
            let Some(bytes) = decode_base64_bytes_limited(b64, attachment_decode_limit) else {
                inspection_limited = true;
                continue;
            };
            source_bytes_scanned += bytes.len();
            let file_type = detect_file_type(&bytes);

            if is_raster_qr_candidate(&attachment.content_type, file_type) {
                // Placeholder-sized images (1x1 trackers, spacer pixels)
                // cannot carry a QR code; attackers spray them to exhaust the
                // per-message image budget before the real QR image. Skip
                // them without charging the budget.
                if is_below_qr_carrier_size(&bytes) {
                    continue;
                }
                scanned_images += 1;
                let Some(qr) = decode_qr_from_image_bytes(&bytes) else {
                    continue;
                };

                payloads.extend(qr.decoded_payloads.iter().cloned());
                let (s, cats, evs) = score_qr_payloads(
                    &qr,
                    &format!("attachment:{}", attachment.filename),
                    qr_lure_context,
                    &ctx.session.rcpt_to,
                    &self.phishing_keywords,
                );
                total_score += s;
                categories.extend(cats);
                evidence.extend(evs);
                continue;
            }

            if is_pdf_qr_candidate(&attachment.filename, &attachment.content_type, file_type) {
                let remaining_images = MAX_QR_IMAGES_PER_MESSAGE - scanned_images;
                let (scanned, embedded_findings, limited) = decode_embedded_qr_images_from_binary(
                    &bytes,
                    "pdf_embedded_image",
                    remaining_images,
                );
                scanned_images += scanned;
                inspection_limited |= limited;
                for (label, qr) in embedded_findings {
                    payloads.extend(qr.decoded_payloads.iter().cloned());
                    let (s, cats, evs) = score_qr_payloads(
                        &qr,
                        &format!("attachment:{}:{}", attachment.filename, label),
                        qr_lure_context,
                        &ctx.session.rcpt_to,
                        &self.phishing_keywords,
                    );
                    total_score += s;
                    categories.extend(cats);
                    categories.push("pdf_embedded_qr".to_string());
                    evidence.extend(evs);
                }
                continue;
            }

            if file_type == Some(DetectedFileType::ZipArchive)
                && is_zip_document_qr_candidate(&attachment.filename, &attachment.content_type)
            {
                let remaining_images = MAX_QR_IMAGES_PER_MESSAGE - scanned_images;
                let (scanned, embedded_findings, limited) =
                    decode_embedded_qr_images_from_zip(&bytes, remaining_images);
                scanned_images += scanned;
                inspection_limited |= limited;
                for (path, qr) in embedded_findings {
                    payloads.extend(qr.decoded_payloads.iter().cloned());
                    let (s, cats, evs) = score_qr_payloads(
                        &qr,
                        &format!("attachment:{}:{}", attachment.filename, path),
                        qr_lure_context,
                        &ctx.session.rcpt_to,
                        &self.phishing_keywords,
                    );
                    total_score += s;
                    categories.extend(cats);
                    categories.push("document_embedded_qr".to_string());
                    evidence.extend(evs);
                }
                continue;
            }

            if is_text_image_carrier_qr_candidate(
                &attachment.filename,
                &attachment.content_type,
                file_type,
            ) {
                let text = String::from_utf8_lossy(&bytes);
                let remaining_images = MAX_QR_IMAGES_PER_MESSAGE - scanned_images;
                let (scanned, data_uri_findings, limited) =
                    decode_data_uri_qr_images_from_text(&text, remaining_images);
                scanned_images += scanned;
                inspection_limited |= limited;
                for (label, qr) in data_uri_findings {
                    payloads.extend(qr.decoded_payloads.iter().cloned());
                    let (s, cats, evs) = score_qr_payloads(
                        &qr,
                        &format!("attachment:{}:{}", attachment.filename, label),
                        qr_lure_context,
                        &ctx.session.rcpt_to,
                        &self.phishing_keywords,
                    );
                    total_score += s;
                    categories.extend(cats);
                    categories.push("embedded_data_uri_qr".to_string());
                    evidence.extend(evs);
                }
            }
        }

        // --- Phase 2: Scan email body for ASCII block-character QR codes ---
        let mut ascii_qr_scanned = false;
        if let Some(body) = ctx.session.content.body_text.as_deref()
            && body.len() >= ASCII_QR_MIN_BLOCK_RUN * ASCII_QR_MIN_ROWS
        {
            let body_scan = if body.len() <= MAX_ASCII_QR_SCAN_BYTES {
                body
            } else {
                inspection_limited = true;
                let mut end = MAX_ASCII_QR_SCAN_BYTES;
                while end > 0 && !body.is_char_boundary(end) {
                    end -= 1;
                }
                &body[..end]
            };
            let ascii_findings = decode_ascii_qr_from_text(body_scan);
            if !ascii_findings.is_empty() {
                ascii_qr_scanned = true;
            }
            for finding in &ascii_findings {
                payloads.extend(finding.decoded_payloads.iter().cloned());
                let (s, cats, evs) = score_qr_payloads(
                    finding,
                    "body:ascii_qr",
                    qr_lure_context,
                    &ctx.session.rcpt_to,
                    &self.phishing_keywords,
                );
                total_score += s;
                categories.extend(cats);
                evidence.extend(evs);
                // ASCII QR in email body is inherently suspicious — bonus score.
                total_score += 0.10;
                categories.push("ascii_qr_in_body".to_string());
            }
        }

        if inspection_limited {
            // Coverage loss is operational state, not malicious evidence.
            categories.push("attachment_qr_inspection_limited".to_string());
            evidence.push(Evidence {
                description: "QR inspection reached its per-message image, byte, or archive-entry budget; remaining content requires deferred sandbox scanning"
                    .to_string(),
                location: Some("attachments".to_string()),
                snippet: None,
            });
        }

        if scanned_images == 0 && !ascii_qr_scanned && !inspection_limited {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No image, document-embedded, or body QR content with retained data",
                start.elapsed().as_millis() as u64,
            ));
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();
        payloads.sort();
        payloads.dedup();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);
        if threat_level == ThreatLevel::Safe {
            let observed_categories = categories.clone();
            let mut result = ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "Scanned {} image attachment(s){}, no QR phishing signals found",
                    scanned_images,
                    if ascii_qr_scanned { " + body text" } else { "" }
                ),
                duration_ms,
            );
            result.evidence = evidence;
            result.categories = observed_categories.clone();
            result.details = serde_json::json!({
                "score": total_score,
                "scanned_images": scanned_images,
                "source_bytes_scanned": source_bytes_scanned,
                "inspection_budget_exhausted": inspection_limited,
                "ascii_qr_detected": ascii_qr_scanned,
                "decoded_payloads": payloads,
                "observed_categories": observed_categories,
            });
            return Ok(result);
        }

        Ok(ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: if payloads.is_empty() { 0.72 } else { 0.88 },
            categories,
            summary: format!(
                "Attachment QR analysis found {} findings across {} image attachment(s){}",
                evidence.len(),
                scanned_images,
                if ascii_qr_scanned {
                    " + body ASCII QR"
                } else {
                    ""
                }
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "scanned_images": scanned_images,
                "source_bytes_scanned": source_bytes_scanned,
                "inspection_budget_exhausted": inspection_limited,
                "ascii_qr_detected": ascii_qr_scanned,
                "decoded_payloads": payloads,
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    use base64::Engine as _;
    use flate2::{Compression, write::ZlibEncoder};
    use vigilyx_core::models::{EmailAttachment, EmailContent, EmailSession, Protocol};

    fn make_ctx(
        attachments: Vec<EmailAttachment>,
        subject: Option<&str>,
        body: Option<&str>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = subject.map(str::to_string);
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            body_text: body.map(str::to_string),
            attachments,
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_module_with_keywords(keywords: &[&str]) -> AttachmentQrScanModule {
        AttachmentQrScanModule::new_with_keyword_lists(EffectiveKeywordLists {
            phishing_keywords: keywords
                .iter()
                .map(|keyword| normalize_text(&keyword.to_lowercase()))
                .collect(),
            ..Default::default()
        })
    }

    fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], payload: &[u8]) {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(payload);

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(chunk_type);
        hasher.update(payload);
        out.extend_from_slice(&hasher.finalize().to_be_bytes());
    }

    fn encode_grayscale_png(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
        let width = width as usize;
        let height = height as usize;
        assert_eq!(pixels.len(), width * height);

        let mut raw = Vec::with_capacity(height * (width + 1));
        for row in pixels.chunks_exact(width) {
            raw.push(0); // Filter type 0.
            raw.extend_from_slice(row);
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&raw).expect("zlib write");
        let compressed = encoder.finish().expect("zlib finish");

        let mut png = Vec::new();
        png.extend_from_slice(PNG_SIGNATURE);

        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&(width as u32).to_be_bytes());
        ihdr.extend_from_slice(&(height as u32).to_be_bytes());
        ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
        write_png_chunk(&mut png, b"IHDR", &ihdr);
        write_png_chunk(&mut png, b"IDAT", &compressed);
        write_png_chunk(&mut png, b"IEND", &[]);
        png
    }

    fn build_qr_like_png(module_size: u32) -> Vec<u8> {
        let qr_size = 25u32;
        let quiet_zone = 4u32;
        let image_size = (qr_size + quiet_zone * 2) * module_size;
        let mut pixels = vec![255u8; (image_size * image_size) as usize];

        for row in 0..qr_size {
            for col in 0..qr_size {
                let is_finder_region =
                    (row < 7 && (col < 7 || col >= qr_size - 7)) || (row >= qr_size - 7 && col < 7);

                let is_dark = if is_finder_region {
                    let local_row = if row >= qr_size - 7 {
                        row - (qr_size - 7)
                    } else {
                        row
                    };
                    let local_col = if col >= qr_size - 7 {
                        col - (qr_size - 7)
                    } else {
                        col
                    };
                    local_row == 0
                        || local_row == 6
                        || local_col == 0
                        || local_col == 6
                        || ((2..=4).contains(&local_row) && (2..=4).contains(&local_col))
                } else {
                    (row + col) % 2 == 0
                };
                if !is_dark {
                    continue;
                }

                let start_x = (col + quiet_zone) * module_size;
                let start_y = (row + quiet_zone) * module_size;
                for y in start_y..start_y + module_size {
                    for x in start_x..start_x + module_size {
                        pixels[(y * image_size + x) as usize] = 0;
                    }
                }
            }
        }

        encode_grayscale_png(image_size, image_size, &pixels)
    }

    /// Create a minimal valid JPEG from a grayscale pixel grid.
    /// Uses the `image` crate to produce a real JPEG.
    fn encode_grayscale_jpeg(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
        use image::{GrayImage, ImageFormat};
        let img = GrayImage::from_raw(width, height, pixels.to_vec())
            .expect("valid dimensions for GrayImage");
        let mut buf = std::io::Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Jpeg)
            .expect("JPEG encode");
        buf.into_inner()
    }

    /// Create a minimal valid GIF from a grayscale pixel grid.
    ///
    /// GIF format requires indexed/palette color — the `image` crate's GIF encoder
    /// does not support direct L8 (grayscale). We convert to RGB first.
    fn encode_grayscale_gif(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
        use image::{GrayImage, ImageFormat};
        let gray = GrayImage::from_raw(width, height, pixels.to_vec())
            .expect("valid dimensions for GrayImage");
        let rgb = image::DynamicImage::ImageLuma8(gray).into_rgb8();
        let mut buf = std::io::Cursor::new(Vec::new());
        rgb.write_to(&mut buf, ImageFormat::Gif)
            .expect("GIF encode");
        buf.into_inner()
    }

    fn build_zip_with_files(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip_w = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        for (name, content) in files {
            zip_w.start_file(*name, options).expect("start zip entry");
            zip_w.write_all(content).expect("write zip entry");
        }

        zip_w.finish().expect("finish zip").into_inner()
    }

    fn build_pdf_with_embedded_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Length ");
        pdf.extend_from_slice(bytes.len().to_string().as_bytes());
        pdf.extend_from_slice(b" >>\nstream\n");
        pdf.extend_from_slice(bytes);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    // -----------------------------------------------------------------------
    // Existing tests (preserved from original)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_qr_like_attachment_with_lure_is_flagged() {
        let png = build_qr_like_png(8);
        let attachment = EmailAttachment {
            filename: "secure-voicemail.png".to_string(),
            content_type: "image/png".to_string(),
            size: png.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(png)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Secure voice message"),
            Some("Scan the QR code to review your Microsoft 365 voicemail"),
        );

        let result = make_module_with_keywords(&["scan the qr code", "secure voicemail"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR-bearing attachment should be detected: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"attachment_qr_lure".to_string()),
            "QR login lure should be detected: {:?}",
            result.categories
        );
        assert!(result.threat_level >= ThreatLevel::Low);
    }

    #[tokio::test]
    async fn test_plain_image_attachment_is_safe() {
        let pixels = vec![255u8; 256 * 256];
        let encoded = encode_grayscale_png(256, 256, &pixels);
        let attachment = EmailAttachment {
            filename: "logo.png".to_string(),
            content_type: "image/png".to_string(),
            size: encoded.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(encoded)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Monthly update"),
            Some("Normal business email"),
        );

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    // -----------------------------------------------------------------------
    // New tests for enhanced QR decoding
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_jpeg_qr_attachment_detected() {
        // Build a QR-like image as PNG pixels, then encode as JPEG.
        let qr_png = build_qr_like_png(8);
        let grayscale = decode_png_grayscale(&qr_png).expect("manual PNG decode");
        let jpeg_bytes = encode_grayscale_jpeg(
            grayscale.width as u32,
            grayscale.height as u32,
            &grayscale.pixels,
        );

        let attachment = EmailAttachment {
            filename: "qr-code.jpg".to_string(),
            content_type: "image/jpeg".to_string(),
            size: jpeg_bytes.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(&jpeg_bytes)),
        };
        let ctx = make_ctx(vec![attachment], Some("Scan this"), None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "JPEG QR should be detected: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_gif_qr_attachment_detected() {
        let qr_png = build_qr_like_png(8);
        let grayscale = decode_png_grayscale(&qr_png).expect("manual PNG decode");
        let gif_bytes = encode_grayscale_gif(
            grayscale.width as u32,
            grayscale.height as u32,
            &grayscale.pixels,
        );

        let attachment = EmailAttachment {
            filename: "scan-me.gif".to_string(),
            content_type: "image/gif".to_string(),
            size: gif_bytes.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(&gif_bytes)),
        };
        let ctx = make_ctx(vec![attachment], Some("Important"), None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "GIF QR should be detected: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_docx_embedded_qr_image_detected() {
        let png = build_qr_like_png(8);
        let docx = build_zip_with_files(&[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>"#.to_vec(),
            ),
            (
                "word/document.xml",
                br#"<w:document><w:body><w:t>Scan the QR code</w:t></w:body></w:document>"#
                    .to_vec(),
            ),
            ("word/media/image1.png", png),
        ]);
        let attachment = EmailAttachment {
            filename: "secure-voicemail.docx".to_string(),
            content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            size: docx.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(docx)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Secure voice message"),
            Some("Scan the QR code to review your Microsoft 365 voicemail"),
        );

        let result = make_module_with_keywords(&["scan the qr code", "secure voicemail"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR embedded in DOCX media should be detected: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"document_embedded_qr".to_string()),
            "DOCX media QR should carry document_embedded_qr: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"attachment_qr_lure".to_string()),
            "DOCX QR with lure context should be scored as a lure: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_pdf_embedded_png_qr_detected() {
        let png = build_qr_like_png(8);
        let pdf = build_pdf_with_embedded_bytes(&png);
        let attachment = EmailAttachment {
            filename: "secure-message.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: pdf.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(pdf)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Secure message"),
            Some("Scan QR to review the protected document"),
        );

        let result = make_module_with_keywords(&["scan qr", "protected document"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR embedded in PDF image stream should be detected: {:?}",
            result.categories
        );
        assert!(
            result.categories.contains(&"pdf_embedded_qr".to_string()),
            "PDF image stream QR should carry pdf_embedded_qr: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_svg_data_uri_embedded_qr_detected() {
        let png = build_qr_like_png(8);
        let png_b64 = base64::engine::general_purpose::STANDARD.encode(png);
        let svg = format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300"><image href="data:image/png;base64,{png_b64}" width="300" height="300"/></svg>"#
        );
        let attachment = EmailAttachment {
            filename: "qr-invoice.svg".to_string(),
            content_type: "image/svg+xml".to_string(),
            size: svg.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(svg.as_bytes())),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Invoice shared"),
            Some("Scan QR to access the invoice portal"),
        );

        let result = make_module_with_keywords(&["scan qr", "invoice portal"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR embedded as SVG data URI should be detected: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"embedded_data_uri_qr".to_string()),
            "SVG data URI QR should carry embedded_data_uri_qr: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_html_data_uri_embedded_qr_detected() {
        let png = build_qr_like_png(8);
        let png_b64 = base64::engine::general_purpose::STANDARD.encode(png);
        let html = format!(
            r#"<!doctype html><html><body><img alt="review" src="data:image/png;base64,{png_b64}"></body></html>"#
        );
        let attachment = EmailAttachment {
            filename: "secure-review.html".to_string(),
            content_type: "text/html".to_string(),
            size: html.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(html.as_bytes())),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Secure review"),
            Some("Scan QR to open the secure message"),
        );

        let result = make_module_with_keywords(&["scan qr", "secure message"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR embedded as HTML data URI should be detected: {:?}",
            result.categories
        );
        assert!(
            result
                .categories
                .contains(&"embedded_data_uri_qr".to_string()),
            "HTML data URI QR should carry embedded_data_uri_qr: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_docx_without_media_qr_is_not_flagged() {
        let docx = build_zip_with_files(&[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>"#.to_vec(),
            ),
            (
                "word/document.xml",
                br#"<w:document><w:body><w:t>Quarterly business report</w:t></w:body></w:document>"#
                    .to_vec(),
            ),
        ]);
        let attachment = EmailAttachment {
            filename: "report.docx".to_string(),
            content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            size: docx.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(docx)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Quarterly report"),
            Some("Please review the attached report."),
        );

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert!(
            !result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "DOCX without QR media should not be flagged: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_docx_clean_embedded_image_is_safe() {
        let pixels = vec![255u8; 128 * 128];
        let clean_png = encode_grayscale_png(128, 128, &pixels);
        let docx = build_zip_with_files(&[
            (
                "[Content_Types].xml",
                br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>"#.to_vec(),
            ),
            (
                "word/document.xml",
                br#"<w:document><w:body><w:t>Quarterly business report</w:t></w:body></w:document>"#
                    .to_vec(),
            ),
            ("word/media/image1.png", clean_png),
        ]);
        let attachment = EmailAttachment {
            filename: "report.docx".to_string(),
            content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            size: docx.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(docx)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Quarterly report"),
            Some("Please review the attached report."),
        );

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "clean embedded DOCX image should remain safe: {:?}",
            result
        );
        assert!(
            !result
                .categories
                .contains(&"document_embedded_qr".to_string()),
            "clean embedded DOCX image should not carry document_embedded_qr: {:?}",
            result.categories
        );
    }

    #[tokio::test]
    async fn test_pdf_clean_embedded_image_is_safe() {
        let pixels = vec![255u8; 128 * 128];
        let clean_png = encode_grayscale_png(128, 128, &pixels);
        let pdf = build_pdf_with_embedded_bytes(&clean_png);
        let attachment = EmailAttachment {
            filename: "statement.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size: pdf.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(pdf)),
        };
        let ctx = make_ctx(
            vec![attachment],
            Some("Statement"),
            Some("Please review the attached statement."),
        );

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "clean embedded PDF image should remain safe: {:?}",
            result
        );
        assert!(
            !result.categories.contains(&"pdf_embedded_qr".to_string()),
            "clean embedded PDF image should not carry pdf_embedded_qr: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_binarization_pipeline() {
        // Create a low-contrast grayscale image (values between 100 and 160).
        let width = 64;
        let height = 64;
        let pixels: Vec<u8> = (0..width * height)
            .map(|i| {
                if (i / width + i % width) % 2 == 0 {
                    100
                } else {
                    160
                }
            })
            .collect();
        let img = GrayscaleImage {
            width,
            height,
            pixels,
        };

        // Binarize at 128 — should produce clean black/white.
        let binary = binarize_at_threshold(&img, 128);
        assert_eq!(binary.pixels.len(), width * height);
        for (i, &p) in binary.pixels.iter().enumerate() {
            let row = i / width;
            let col = i % width;
            let expected = if (row + col) % 2 == 0 { 0 } else { 255 };
            assert_eq!(p, expected, "pixel ({},{}) mismatch", col, row);
        }
    }

    #[test]
    fn test_rqrr_panic_is_contained() {
        let image = GrayscaleImage {
            width: 64,
            height: 64,
            pixels: vec![255; 64 * 64],
        };

        let result = run_rqrr_guarded(&image, || panic!("assertion failed: scan >= 1"));

        assert_eq!(result, (0, Vec::new()));
    }

    #[test]
    fn test_ascii_qr_block_extraction() {
        // Build a fake ASCII QR block: 15 rows of 15 block characters each.
        let dark = '\u{2588}'; // █
        let light = ' ';
        let mut body = String::new();
        body.push_str("Hello, please scan this code:\n\n");
        for row in 0..15 {
            for col in 0..15 {
                if (row + col) % 2 == 0 {
                    body.push(dark);
                } else {
                    body.push(light);
                }
            }
            body.push('\n');
        }
        body.push_str("\nThank you.\n");

        let blocks = extract_ascii_qr_blocks(&body);
        assert_eq!(blocks.len(), 1, "should extract one block region");
        assert_eq!(blocks[0].len(), 15, "block region should have 15 rows");
    }

    #[test]
    fn test_ascii_qr_rendering() {
        // Build a simple 3x3 grid: dark corners, light center.
        let dark = '\u{2588}';
        let grid = vec![
            vec![dark, ' ', dark],
            vec![' ', dark, ' '],
            vec![dark, ' ', dark],
        ];
        let rendered = render_ascii_qr_to_image(&grid, 4).expect("should render");
        // 3 cols + 8 quiet zone = 11 * 4 = 44 pixels wide, same for height.
        assert_eq!(rendered.width, (3 + 8) * 4);
        assert_eq!(rendered.height, (3 + 8) * 4);

        // Check that the center quiet zone pixel is white.
        let center_quiet = rendered.pixels[0]; // top-left corner is quiet zone.
        assert_eq!(center_quiet, 255, "quiet zone should be white");

        // Check a known dark pixel (first dark block at grid position 0,0).
        let dark_x = 4 * 4; // quiet=4 modules, scale=4 pixels each.
        let dark_y = 4 * 4;
        let dark_pixel = rendered.pixels[dark_y * rendered.width + dark_x];
        assert_eq!(dark_pixel, 0, "dark block character should render as black");
    }

    #[tokio::test]
    async fn test_malformed_image_handled_gracefully() {
        // Random garbage bytes with image content type — should not panic.
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        let attachment = EmailAttachment {
            filename: "broken.jpg".to_string(),
            content_type: "image/jpeg".to_string(),
            size: garbage.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(&garbage)),
        };
        let ctx = make_ctx(vec![attachment], Some("Test"), None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        // Should complete without error — either Safe or NotApplicable.
        assert!(
            result.threat_level == ThreatLevel::Safe
                || result.summary.contains("no QR phishing signals found"),
            "malformed image should be handled gracefully: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_empty_tiny_image_handled() {
        // 1x1 white pixel PNG — no QR code possible.
        let pixels = vec![255u8; 1];
        let tiny_png = encode_grayscale_png(1, 1, &pixels);
        let attachment = EmailAttachment {
            filename: "dot.png".to_string(),
            content_type: "image/png".to_string(),
            size: tiny_png.len(),
            hash: "hash".to_string(),
            content_base64: Some(base64::engine::general_purpose::STANDARD.encode(&tiny_png)),
        };
        let ctx = make_ctx(vec![attachment], None, None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(
            result.threat_level,
            ThreatLevel::Safe,
            "tiny image should not trigger QR detection"
        );
    }

    #[test]
    fn test_is_raster_candidate_multi_format() {
        // PNG by magic bytes.
        assert!(is_raster_qr_candidate(
            "application/octet-stream",
            Some(DetectedFileType::Png)
        ));
        // JPEG by magic bytes.
        assert!(is_raster_qr_candidate(
            "application/octet-stream",
            Some(DetectedFileType::Jpeg)
        ));
        // GIF by magic bytes.
        assert!(is_raster_qr_candidate(
            "application/octet-stream",
            Some(DetectedFileType::Gif)
        ));
        // BMP by magic bytes.
        assert!(is_raster_qr_candidate(
            "application/octet-stream",
            Some(DetectedFileType::Bmp)
        ));
        // TIFF by magic bytes.
        assert!(is_raster_qr_candidate(
            "application/octet-stream",
            Some(DetectedFileType::Tiff)
        ));
        // WebP by content-type (no magic bytes variant in DetectedFileType).
        assert!(is_raster_qr_candidate("image/webp", None));
        // Non-image should not match.
        assert!(!is_raster_qr_candidate(
            "application/pdf",
            Some(DetectedFileType::Pdf)
        ));
        assert!(!is_raster_qr_candidate("text/plain", None));
    }

    #[test]
    fn test_url_extraction_from_decoded_qr() {
        // Verify that analyze_url is callable with typical QR payloads.
        let (score, cats) = analyze_url(
            "https://evil-phish.example.com/login?token=abc123&redirect=http://bank.com",
        );
        // We expect some score from suspicious URL patterns.
        // The exact score depends on link_content heuristics — just ensure no panic.
        assert!(score >= 0.0, "analyze_url should return non-negative score");
        let _ = cats; // Suppress unused warning.
    }

    #[test]
    fn routine_decoded_qr_is_observable_but_not_threat_evidence() {
        let finding = QrImageFinding {
            width: 285,
            height: 285,
            grid_count: 1,
            decoded_payloads: vec![
                "https://gjb.yungujia.com/vr2/xaty/87F49F27-AB8D-440B-B39F-5496B61804B6"
                    .to_string(),
            ],
        };

        let (score, categories, evidence) =
            score_qr_payloads(&finding, "attachment:property.pdf", false, &[], &[]);

        assert_eq!(score, 0.0);
        assert!(categories.contains(&"attachment_qr_code".to_string()));
        assert!(categories.contains(&"attachment_qr_decoded".to_string()));
        assert_eq!(evidence.len(), 2);
    }

    #[test]
    fn generic_notice_text_does_not_create_qr_lure_context() {
        assert!(!has_explicit_qr_lure_context(
            "请查收，若对邮件内容有异议，请在三个工作日内及时回复。"
        ));
    }

    #[test]
    fn explicit_qr_instruction_creates_qr_lure_context() {
        assert!(has_explicit_qr_lure_context("请扫描二维码登录系统"));
    }

    #[test]
    fn qr_credential_lure_remains_actionable() {
        let finding = QrImageFinding {
            width: 300,
            height: 300,
            grid_count: 1,
            decoded_payloads: vec![
                "https://login-example.evil/login?token=0123456789abcdef"
                    .to_string(),
            ],
        };

        let (score, categories, _) = score_qr_payloads(
            &finding,
            "attachment:secure-message.png",
            true,
            &["victim@example.com".to_string()],
            &["scan the qr code".to_string()],
        );

        assert!(score >= 0.30, "credential QR score={score}");
        assert!(categories.contains(&"attachment_qr_lure".to_string()));
        assert!(categories.contains(&"attachment_qr_login_lure".to_string()));
    }

    #[test]
    fn test_ascii_qr_too_few_rows_rejected() {
        // Only 5 rows of block characters — below the minimum threshold.
        let dark = '\u{2588}';
        let mut body = String::new();
        for _ in 0..5 {
            for _ in 0..20 {
                body.push(dark);
            }
            body.push('\n');
        }

        let blocks = extract_ascii_qr_blocks(&body);
        assert!(
            blocks.is_empty(),
            "too few rows should not be extracted as QR block"
        );
    }

    #[test]
    fn test_ascii_qr_block_extraction_has_a_per_message_cap() {
        let mut body = String::new();
        for _ in 0..(MAX_ASCII_QR_BLOCKS + 2) {
            for _ in 0..ASCII_QR_MIN_ROWS {
                body.push_str("██████████\n");
            }
            body.push_str("separator\n");
        }

        assert_eq!(extract_ascii_qr_blocks(&body).len(), MAX_ASCII_QR_BLOCKS);
    }

    #[test]
    fn test_ascii_qr_after_scan_prefix_is_not_copied_or_processed() {
        let mut body = "x".repeat(MAX_ASCII_QR_SCAN_BYTES + 1);
        body.push('\n');
        for _ in 0..ASCII_QR_MIN_ROWS {
            body.push_str("██████████\n");
        }

        assert!(extract_ascii_qr_blocks(&body).is_empty());
    }

    #[test]
    fn perf_ascii_qr_scan_cost_is_independent_of_trailing_body_size() {
        let body = "ordinary body text\n".repeat(MAX_ASCII_QR_SCAN_BYTES / 2);
        let started = Instant::now();

        assert!(extract_ascii_qr_blocks(&body).is_empty());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "bounded ASCII QR scan exceeded the generous performance ceiling"
        );
    }

    #[test]
    fn test_render_ascii_qr_oversized_rejected() {
        // A grid that would exceed the max render dimension.
        let dark = '\u{2588}';
        let row: Vec<char> = vec![dark; 200];
        let grid: Vec<Vec<char>> = vec![row; 200];
        // scale=4 → (200 + 8) * 4 = 832 > 512 max.
        let result = render_ascii_qr_to_image(&grid, 4);
        assert!(result.is_none(), "oversized render should be rejected");
    }

    #[test]
    fn test_decode_image_crate_grayscale_rejects_oversize() {
        // 11 MB of zeros — should be rejected before attempting decode.
        let data = vec![0u8; 11 * 1024 * 1024];
        let result = decode_image_crate_grayscale(&data);
        assert!(result.is_none(), "oversized input should be rejected");
    }

    #[test]
    fn test_decode_rejects_huge_declared_dimensions_before_allocation() {
        // Minimal BMP metadata declaring a 50,000 x 50,000 canvas. Header inspection
        // must reject it without allocating the declared pixel buffer.
        let mut bmp = vec![0u8; 54];
        bmp[0..2].copy_from_slice(b"BM");
        bmp[2..6].copy_from_slice(&(54u32).to_le_bytes());
        bmp[10..14].copy_from_slice(&(54u32).to_le_bytes());
        bmp[14..18].copy_from_slice(&(40u32).to_le_bytes());
        bmp[18..22].copy_from_slice(&(50_000i32).to_le_bytes());
        bmp[22..26].copy_from_slice(&(50_000i32).to_le_bytes());
        bmp[26..28].copy_from_slice(&(1u16).to_le_bytes());
        bmp[28..30].copy_from_slice(&(24u16).to_le_bytes());

        assert!(decode_image_crate_grayscale(&bmp).is_none());
    }

    #[tokio::test]
    async fn test_oversized_qr_candidate_surfaces_incomplete_coverage() {
        let attachment = EmailAttachment {
            filename: "oversized.png".to_string(),
            content_type: "image/png".to_string(),
            size: MAX_QR_ATTACHMENT_DECODE_BYTES + 1,
            hash: "hash".to_string(),
            content_base64: Some("iVBORw0KGgo=".to_string()),
        };
        let ctx = make_ctx(vec![attachment], None, None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert!(
            result.details["inspection_budget_exhausted"] == serde_json::json!(true)
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert_eq!(result.details["inspection_budget_exhausted"], true);
    }

    #[tokio::test]
    async fn test_oversized_known_non_qr_attachment_does_not_create_coverage_alert() {
        let attachment = EmailAttachment {
            filename: "training.mp4".to_string(),
            content_type: "video/mp4".to_string(),
            size: MAX_QR_ATTACHMENT_DECODE_BYTES + 1,
            hash: "hash".to_string(),
            content_base64: Some("AAAA".to_string()),
        };
        let ctx = make_ctx(vec![attachment], None, None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(result.summary.starts_with("No image"));
    }

    #[tokio::test]
    async fn test_per_message_image_budget_stops_additional_decoders() {
        // 64x64 white images are plausible QR carriers, so each one charges
        // the per-message budget (placeholder-sized decoys no longer do).
        let png = encode_grayscale_png(64, 64, &vec![255u8; 64 * 64]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&png);
        let attachments = (0..MAX_QR_IMAGES_PER_MESSAGE + 3)
            .map(|index| EmailAttachment {
                filename: format!("image_{index}.png"),
                content_type: "image/png".to_string(),
                size: png.len(),
                hash: format!("hash_{index}"),
                content_base64: Some(encoded.clone()),
            })
            .collect();
        let ctx = make_ctx(attachments, None, None);

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(
            result.details["scanned_images"],
            serde_json::json!(MAX_QR_IMAGES_PER_MESSAGE)
        );
        assert_eq!(result.details["inspection_budget_exhausted"], true);
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[tokio::test]
    async fn test_placeholder_decoys_do_not_exhaust_qr_budget() {
        // PoC bypass: MAX_QR_IMAGES_PER_MESSAGE 1x1 placeholder images used to
        // consume the entire per-message budget, so the real QR image appended
        // after them was never scanned. Tiny images must be skipped for free.
        let placeholder = encode_grayscale_png(1, 1, &[255u8]);
        let placeholder_b64 = base64::engine::general_purpose::STANDARD.encode(&placeholder);
        let qr_png = build_qr_like_png(8);
        let qr_b64 = base64::engine::general_purpose::STANDARD.encode(&qr_png);

        let mut attachments: Vec<EmailAttachment> = (0..MAX_QR_IMAGES_PER_MESSAGE)
            .map(|index| EmailAttachment {
                filename: format!("pixel_{index}.png"),
                content_type: "image/png".to_string(),
                size: placeholder.len(),
                hash: format!("hash_{index}"),
                content_base64: Some(placeholder_b64.clone()),
            })
            .collect();
        attachments.push(EmailAttachment {
            filename: "secure-voicemail.png".to_string(),
            content_type: "image/png".to_string(),
            size: qr_png.len(),
            hash: "hash_qr".to_string(),
            content_base64: Some(qr_b64),
        });
        let ctx = make_ctx(
            attachments,
            Some("Secure voice message"),
            Some("Scan the QR code to review your Microsoft 365 voicemail"),
        );

        let result = make_module_with_keywords(&["scan the qr code", "secure voicemail"])
            .analyze(&ctx)
            .await
            .unwrap();

        assert!(
            result
                .categories
                .contains(&"attachment_qr_code".to_string()),
            "QR image behind placeholder decoys must still be scanned: {:?}",
            result.categories
        );
        assert_eq!(
            result.details["inspection_budget_exhausted"],
            serde_json::json!(false),
            "placeholder decoys must not exhaust the budget"
        );
        assert_eq!(result.details["scanned_images"], serde_json::json!(1));
    }
}
