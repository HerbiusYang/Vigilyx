//! Build a bounded OCR request from visual assets already contained in HTML.
//!
//! This module resolves only `data:image/...` and `cid:` references.  It never
//! fetches an external URL and never sends an unrelated image attachment to
//! the AI service.  The returned request is advisory; OCR text remains a
//! separate semantic source.

use base64::Engine as _;
use regex::Regex;
use std::sync::LazyLock;

use vigilyx_core::models::{EmailAttachment, EmailSession, decode_base64_bytes_limited};

use crate::external::remote::{VisualOcrImageRequest, VisualOcrRequest};

pub(crate) const MAX_VISUAL_OCR_IMAGES: usize = 3;
const MAX_VISUAL_OCR_IMAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_VISUAL_OCR_TOTAL_BYTES: usize = 4 * 1024 * 1024;

static RE_VISUAL_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(?:\b(?:src|href)\s*=\s*["']|url\(\s*["']?)(data:image/[^"')\s]+|cid:[^"')\s]+)"#,
    )
    .expect("valid visual reference regex")
});

fn supported_image_type(media_type: &str) -> bool {
    matches!(
        media_type.trim().to_ascii_lowercase().as_str(),
        "image/png"
            | "image/jpeg"
            | "image/jpg"
            | "image/gif"
            | "image/bmp"
            | "image/webp"
            | "image/tiff"
    )
}

fn normalize_asset_key(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .strip_prefix("cid:")
        .unwrap_or(value)
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

fn attachment_matches_cid(attachment: &EmailAttachment, cid: &str) -> bool {
    let cid_key = normalize_asset_key(cid);
    if cid_key.is_empty() {
        return false;
    }
    let filename_stem = attachment
        .filename
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(&attachment.filename);
    let filename_key = normalize_asset_key(filename_stem)
        .strip_prefix("cid")
        .unwrap_or_default()
        .to_string();
    filename_key == cid_key
}

fn data_uri_image(value: &str) -> Option<(String, String)> {
    let (metadata, payload) = value.strip_prefix("data:")?.split_once(',')?;
    let media_type = metadata
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !supported_image_type(&media_type)
        || !metadata
            .split(';')
            .any(|part| part.eq_ignore_ascii_case("base64"))
    {
        return None;
    }
    let bytes = decode_base64_bytes_limited(payload, MAX_VISUAL_OCR_IMAGE_BYTES)?;
    if bytes.is_empty() {
        return None;
    }
    Some((
        media_type,
        base64::engine::general_purpose::STANDARD.encode(bytes),
    ))
}

fn append_image(
    images: &mut Vec<VisualOcrImageRequest>,
    total_bytes: &mut usize,
    source_id: String,
    media_type: String,
    content_base64: String,
) {
    if images.len() >= MAX_VISUAL_OCR_IMAGES
        || images
            .iter()
            .any(|image| image.content_base64 == content_base64)
    {
        return;
    }
    let Some(decoded) = decode_base64_bytes_limited(&content_base64, MAX_VISUAL_OCR_IMAGE_BYTES)
    else {
        return;
    };
    if *total_bytes + decoded.len() > MAX_VISUAL_OCR_TOTAL_BYTES {
        return;
    }
    *total_bytes += decoded.len();
    images.push(VisualOcrImageRequest {
        source_id,
        media_type,
        content_base64,
    });
}

/// Resolve inline and CID image bytes into a bounded OCR request.
pub(crate) fn build_visual_ocr_request(session: &EmailSession) -> Option<VisualOcrRequest> {
    let html = session.content.body_html.as_deref()?;
    let mut images = Vec::new();
    let mut total_bytes = 0usize;

    for (index, capture) in RE_VISUAL_REFERENCE.captures_iter(html).enumerate() {
        let Some(reference) = capture.get(1).map(|value| value.as_str()) else {
            continue;
        };
        if let Some((media_type, content_base64)) = data_uri_image(reference) {
            append_image(
                &mut images,
                &mut total_bytes,
                format!("html_data_image_{}", index + 1),
                media_type,
                content_base64,
            );
            continue;
        }

        let Some(cid) = reference.strip_prefix("cid:") else {
            // External HTTP(S) resources are metadata-only at this stage.
            continue;
        };
        for attachment in &session.content.attachments {
            if !supported_image_type(&attachment.content_type)
                || !attachment_matches_cid(attachment, cid)
            {
                continue;
            }
            let Some(content_base64) = attachment.content_base64.as_deref() else {
                continue;
            };
            append_image(
                &mut images,
                &mut total_bytes,
                format!("html_cid_image_{}", index + 1),
                attachment
                    .content_type
                    .split(';')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                content_base64.to_string(),
            );
            break;
        }
    }

    (!images.is_empty()).then(|| VisualOcrRequest {
        session_id: session.id.to_string(),
        images,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::models::{EmailContent, Protocol, SessionStatus};

    fn session(html: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.status = SessionStatus::Completed;
        session.content = EmailContent {
            body_html: Some(html.to_string()),
            is_complete: true,
            ..EmailContent::default()
        };
        session
    }

    #[test]
    fn resolves_bounded_data_uri_without_external_fetch() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"image-bytes");
        let request = build_visual_ocr_request(&session(&format!(
            r#"<img src="data:image/png;base64,{encoded}">"#
        )))
        .expect("data URI should be resolvable");
        assert_eq!(request.images.len(), 1);
        assert_eq!(request.images[0].media_type, "image/png");
    }

    #[test]
    fn external_image_is_not_sent_to_ocr() {
        assert!(
            build_visual_ocr_request(&session(
                r#"<img src="https://example.invalid/banner.png">"#
            ))
            .is_none()
        );
    }

    #[test]
    fn resolves_parser_synthesized_cid_filename() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"image-bytes");
        let mut email = session(r#"<img src="cid:banner-1">"#);
        email.content.attachments.push(EmailAttachment {
            filename: "cid_banner-1.png".to_string(),
            content_type: "image/png".to_string(),
            size: 11,
            hash: String::new(),
            content_base64: Some(encoded),
        });
        let request = build_visual_ocr_request(&email).expect("CID should resolve");
        assert_eq!(request.images.len(), 1);
        assert_eq!(request.images[0].source_id, "html_cid_image_1");
    }
}
