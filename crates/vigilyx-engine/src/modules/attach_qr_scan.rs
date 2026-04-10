//! Attachment QR-code scan module.
//!
//! Detects QR-bearing PNG attachments and scores phishing-specific QR lures
//! such as login/OAuth/device-code landing pages.

use std::io::Read;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use flate2::read::ZlibDecoder;
use vigilyx_core::magic_bytes::{DetectedFileType, detect_file_type};
use vigilyx_core::models::decode_base64_bytes;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel};
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};

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
                description: "Detect QR-bearing image attachments and score phishing QR lures"
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

fn is_raster_qr_candidate(content_type: &str, file_type: Option<DetectedFileType>) -> bool {
    matches!(file_type, Some(DetectedFileType::Png))
        || content_type
            .to_ascii_lowercase()
            .starts_with("image/png")
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

fn decode_qr_from_image_bytes(data: &[u8]) -> Option<QrImageFinding> {
    let grayscale = downscale_grayscale_nearest(decode_png_grayscale(data)?, MAX_QR_IMAGE_DIM);
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
        grayscale.width,
        grayscale.height,
        |x, y| grayscale.pixels[y * grayscale.width + x],
    );
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

    let grid_count = if grids.is_empty() && has_qr_finder_patterns(&grayscale) {
        1
    } else {
        grids.len()
    };
    if grid_count == 0 {
        return None;
    }

    Some(QrImageFinding {
        width: grayscale.width as u32,
        height: grayscale.height as u32,
        grid_count,
        decoded_payloads,
    })
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

            total_score += 0.20 + (qr.grid_count.min(2) as f64 * 0.03);
            categories.push("attachment_qr_code".to_string());
            evidence.push(Evidence {
                description: format!(
                    "Attachment {} contains QR-like image patterns ({} grid(s), {}x{})",
                    attachment.filename, qr.grid_count, qr.width, qr.height
                ),
                location: Some(format!("attachment:{}", attachment.filename)),
                snippet: None,
            });

            if keyword_context {
                total_score += 0.10;
                categories.push("attachment_qr_lure".to_string());
            }

            if qr.decoded_payloads.is_empty() {
                continue;
            }

            total_score += 0.20;
            categories.push("attachment_qr_decoded".to_string());
            payloads.extend(qr.decoded_payloads.iter().cloned());

            for payload in qr.decoded_payloads.iter().take(3) {
                let payload_lower = payload.to_lowercase();
                let has_recipient = ctx.session.rcpt_to.iter().any(|rcpt| {
                    let rcpt_lower = rcpt.to_lowercase();
                    payload_lower.contains(&rcpt_lower)
                        || payload_lower.contains(&rcpt_lower.replace('@', "%40"))
                });
                if has_recipient {
                    total_score += 0.15;
                    categories.push("attachment_qr_targeted".to_string());
                }
                if contains_any(&payload_lower, STRUCTURAL_QR_PAYLOAD_TERMS) {
                    total_score += 0.10;
                    categories.push("attachment_qr_login_lure".to_string());
                }
                if keyword_context && payload_lower.contains("microsoft.com/devicelogin") {
                    total_score += 0.15;
                    categories.push("device_code_phishing".to_string());
                }

                evidence.push(Evidence {
                    description: format!(
                        "Attachment {} QR decoded payload: {}{}",
                        attachment.filename,
                        payload,
                        if has_recipient {
                            " (contains recipient address)"
                        } else {
                            ""
                        }
                    ),
                    location: Some(format!("attachment:{}", attachment.filename)),
                    snippet: Some(payload.clone()),
                });
            }
        }

        if scanned_images == 0 {
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
                &format!("Scanned {} image attachments, no QR phishing signals found", scanned_images),
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
                "Attachment QR analysis found {} findings across {} image attachment(s)",
                evidence.len(),
                scanned_images
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "scanned_images": scanned_images,
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

    fn make_ctx(attachments: Vec<EmailAttachment>, subject: Option<&str>, body: Option<&str>) -> SecurityContext {
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
                    let local_row = if row >= qr_size - 7 { row - (qr_size - 7) } else { row };
                    let local_col = if col >= qr_size - 7 { col - (qr_size - 7) } else { col };
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
            result.categories.contains(&"attachment_qr_code".to_string()),
            "QR-bearing attachment should be detected: {:?}",
            result.categories
        );
        assert!(
            result.categories.contains(&"attachment_qr_lure".to_string()),
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
        let ctx = make_ctx(vec![attachment], Some("Monthly update"), Some("Normal business email"));

        let result = AttachmentQrScanModule::new().analyze(&ctx).await.unwrap();

        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }
}
