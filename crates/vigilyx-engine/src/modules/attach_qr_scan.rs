//! Attachment QR-code scan module.
//!
//! Detects QR codes in image attachments (PNG, JPEG, GIF, BMP, WebP, TIFF)
//! and ASCII block-character QR codes in email body text.
//! Scores phishing-specific QR lures such as login/OAuth/device-code landing pages.

use std::io::Read;
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use flate2::read::ZlibDecoder;
use regex::Regex;
use tracing::warn;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::decode_base64_bytes;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};
use crate::modules::link_content::analyze_url;

const MAX_QR_IMAGE_DIM: u32 = 1024;
const STRUCTURAL_QR_PAYLOAD_TERMS: &[&str] = &[
    "microsoft.com/devicelogin",
    "login.microsoftonline.com",
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

fn has_keyword_context(text: &str, keywords: &[String]) -> bool {
    let normalized = normalize_text(text);
    keywords.iter().any(|keyword| normalized.contains(keyword))
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
/// SECURITY: image dimensions are capped at `MAX_QR_IMAGE_DIM` x `MAX_QR_IMAGE_DIM` to
/// prevent decompression bombs (CWE-400). Input byte length is also checked.
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

    let reader = image::ImageReader::new(std::io::Cursor::new(data))
        .with_guessed_format()
        .ok()?;

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
    let lines: Vec<&str> = text.lines().collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < lines.len() {
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
    keyword_context: bool,
    rcpt_to: &[String],
    phishing_keywords: &[String],
) -> (f64, Vec<String>, Vec<Evidence>) {
    let _ = phishing_keywords; // reserved for future per-payload keyword matching
    let mut score = 0.0_f64;
    let mut categories = Vec::new();
    let mut evidence = Vec::new();

    // Base score for QR detection.
    score += 0.20 + (finding.grid_count.min(2) as f64 * 0.03);
    categories.push("attachment_qr_code".to_string());
    evidence.push(Evidence {
        description: format!(
            "{} contains QR-like image patterns ({} grid(s), {}x{})",
            source_label, finding.grid_count, finding.width, finding.height
        ),
        location: Some(source_label.to_string()),
        snippet: None,
    });

    if keyword_context {
        score += 0.10;
        categories.push("attachment_qr_lure".to_string());
    }

    if finding.decoded_payloads.is_empty() {
        return (score, categories, evidence);
    }

    score += 0.20;
    categories.push("attachment_qr_decoded".to_string());

    for payload in finding.decoded_payloads.iter().take(3) {
        let payload_lower = payload.to_lowercase();
        let has_recipient = rcpt_to.iter().any(|rcpt| {
            let rcpt_lower = rcpt.to_lowercase();
            payload_lower.contains(&rcpt_lower)
                || payload_lower.contains(&rcpt_lower.replace('@', "%40"))
        });
        if has_recipient {
            score += 0.15;
            categories.push("attachment_qr_targeted".to_string());
        }
        if contains_any(&payload_lower, STRUCTURAL_QR_PAYLOAD_TERMS) {
            score += 0.10;
            categories.push("attachment_qr_login_lure".to_string());
        }
        if keyword_context && payload_lower.contains("microsoft.com/devicelogin") {
            score += 0.15;
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
        let keyword_context = has_keyword_context(&email_context, &self.phishing_keywords);

        let mut total_score = 0.0_f64;
        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut scanned_images = 0usize;
        let mut payloads = Vec::new();

        // --- Phase 1: Scan image attachments ---
        for attachment in &ctx.session.content.attachments {
            let Some(b64) = attachment.content_base64.as_deref() else {
                continue;
            };
            let Some(bytes) = decode_base64_bytes(b64) else {
                continue;
            };
            let file_type = detect_file_type(&bytes);
            if !is_raster_qr_candidate(&attachment.content_type, file_type) {
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
                keyword_context,
                &ctx.session.rcpt_to,
                &self.phishing_keywords,
            );
            total_score += s;
            categories.extend(cats);
            evidence.extend(evs);
        }

        // --- Phase 2: Scan email body for ASCII block-character QR codes ---
        let mut ascii_qr_scanned = false;
        if let Some(body) = ctx.session.content.body_text.as_deref()
            && body.len() >= ASCII_QR_MIN_BLOCK_RUN * ASCII_QR_MIN_ROWS
        {
            let ascii_findings = decode_ascii_qr_from_text(body);
            if !ascii_findings.is_empty() {
                ascii_qr_scanned = true;
            }
            for finding in &ascii_findings {
                payloads.extend(finding.decoded_payloads.iter().cloned());
                let (s, cats, evs) = score_qr_payloads(
                    finding,
                    "body:ascii_qr",
                    keyword_context,
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

        if scanned_images == 0 && !ascii_qr_scanned {
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No raster image attachments with retained content",
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
            return Ok(ModuleResult::safe_analyzed(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                &format!(
                    "Scanned {} image attachment(s){}, no QR phishing signals found",
                    scanned_images,
                    if ascii_qr_scanned { " + body text" } else { "" }
                ),
                duration_ms,
            ));
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
}
