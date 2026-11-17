use super::{
    AttachmentExtractionBudget, MAX_NESTED_TEXT_CHARS, append_nested_text,
    extract_attachment_text_for_policy,
};
use base64::Engine as _;
use std::io::{Cursor, Write};
use vigilyx_core::models::EmailAttachment;

fn attachment(filename: &str, content_type: &str, bytes: &[u8]) -> EmailAttachment {
    EmailAttachment {
        filename: filename.to_string(),
        content_type: content_type.to_string(),
        size: bytes.len(),
        hash: "synthetic-budget-regression".to_string(),
        content_base64: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
    }
}

fn archive(first: &str, last: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, text) in [("first.txt", first), ("last.txt", last)] {
        writer.start_file(name, options).unwrap();
        writer.write_all(text.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn single_attachment_cap_marks_policy_incomplete_and_preserves_exact_limit() {
    let prefix = "a".repeat(MAX_NESTED_TEXT_CHARS);
    let complete = extract_attachment_text_for_policy(&[attachment(
        "notice.txt",
        "text/plain",
        prefix.as_bytes(),
    )]);
    assert!(
        complete.complete,
        "an exact-fit attachment remains complete"
    );
    assert_eq!(complete.scanned_count, 1);
    assert!(complete.text.ends_with(&prefix));

    let oversized = prefix + "UNSCANNED_TAIL";
    let partial = extract_attachment_text_for_policy(&[attachment(
        "notice.txt",
        "text/plain",
        oversized.as_bytes(),
    )]);
    assert!(!partial.complete, "a dropped tail must reach the DLP gate");
    assert_eq!(partial.scanned_count, 1);
    assert!(!partial.text.contains("UNSCANNED_TAIL"));
}

#[test]
fn single_attachment_cap_preserves_utf8_and_reports_incomplete_policy_text() {
    let prefix = "a".repeat(MAX_NESTED_TEXT_CHARS - 1);
    let input = prefix.clone() + "测UNSCANNED_TAIL";
    let partial = extract_attachment_text_for_policy(&[attachment(
        "notice.txt",
        "text/plain; charset=utf-8",
        input.as_bytes(),
    )]);
    assert!(!partial.complete);
    assert_eq!(partial.scanned_count, 1);
    assert!(partial.text.ends_with(&prefix));
    assert!(!partial.text.contains('测'));
    assert!(!partial.text.contains('\u{fffd}'));
    assert!(!partial.text.contains("UNSCANNED_TAIL"));
}

#[test]
fn last_nested_append_without_capacity_records_dropped_content() {
    for length in [MAX_NESTED_TEXT_CHARS - 1, MAX_NESTED_TEXT_CHARS] {
        let mut text = "a".repeat(length);
        let mut budget = AttachmentExtractionBudget::default();
        append_nested_text(&mut text, "UNSCANNED_LAST_MEMBER", &mut budget);
        assert!(
            budget.exhausted,
            "the final dropped append is a coverage gap"
        );
        assert_eq!(text.len(), length);
        assert!(!text.contains("UNSCANNED_LAST_MEMBER"));
    }
}

#[test]
fn last_zip_member_truncation_propagates_policy_coverage() {
    let small = archive("ordinary notice", "ordinary appendix");
    let complete =
        extract_attachment_text_for_policy(&[attachment("notice.zip", "application/zip", &small)]);
    assert!(complete.complete);
    assert!(complete.text.contains("ordinary appendix"));

    // Leave two bytes after the first member. The last member then loses its
    // content during append, with no later iteration to discover the gap.
    let first = "a".repeat(MAX_NESTED_TEXT_CHARS - "[first.txt]\n".len() - 2);
    let zip = archive(&first, "UNSCANNED_LAST_MEMBER");
    let partial =
        extract_attachment_text_for_policy(&[attachment("notice.zip", "application/zip", &zip)]);
    assert!(
        !partial.complete,
        "the nested gap must reach the policy caller"
    );
    assert_eq!(partial.scanned_count, 1);
    assert!(!partial.text.contains("UNSCANNED_LAST_MEMBER"));
}
