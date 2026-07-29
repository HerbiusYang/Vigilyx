use vigilyx_parser::MimeParser;

const MULTIPART_WITH_ATTACHMENT: &[u8] = include_bytes!("fixtures/multipart_with_attachment.eml");

#[test]
fn multipart_eml_golden_preserves_body_links_and_attachment_metadata() {
    let content = MimeParser::new()
        .parse(MULTIPART_WITH_ATTACHMENT)
        .expect("golden EML must remain parseable");

    assert!(content.is_complete);
    assert_eq!(content.raw_size, MULTIPART_WITH_ATTACHMENT.len());
    assert_eq!(
        content.get_header("message-id"),
        Some("<golden-001@example.test>")
    );

    let body_text = content.body_text.as_deref().expect("plain text body");
    assert!(body_text.contains("Hello, analyst."));
    assert!(body_text.contains("https://example.test/login"));

    let body_html = content.body_html.as_deref().expect("HTML body");
    assert!(body_html.contains("<p>Hello, analyst.</p>"));
    assert!(
        content
            .links
            .iter()
            .any(|link| link.url == "https://example.test/login")
    );

    assert_eq!(content.attachments.len(), 1);
    let attachment = &content.attachments[0];
    assert_eq!(attachment.filename, "report.txt");
    assert_eq!(attachment.content_type, "text/plain");
    assert_eq!(attachment.size, 14);
    assert_eq!(attachment.hash.len(), 64);
    assert!(attachment.content_base64.is_some());
}
