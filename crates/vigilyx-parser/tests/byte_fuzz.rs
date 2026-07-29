use proptest::prelude::*;
use vigilyx_parser::MimeParser;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 2_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn arbitrary_mime_bytes_never_panic(data in prop::collection::vec(any::<u8>(), 0..32 * 1024)) {
        let outcome = std::panic::catch_unwind(|| MimeParser::new().parse(&data));
        prop_assert!(outcome.is_ok(), "MIME parser panicked for {} input bytes", data.len());
    }

    #[test]
    fn arbitrary_header_and_boundary_bytes_never_panic(
        header in prop::collection::vec(any::<u8>(), 0..2 * 1024),
        body in prop::collection::vec(any::<u8>(), 0..16 * 1024),
    ) {
        let mut message = b"Content-Type: multipart/mixed; boundary=fuzz-boundary\r\nX-Fuzz: ".to_vec();
        message.extend_from_slice(&header);
        message.extend_from_slice(b"\r\n\r\n--fuzz-boundary\r\nContent-Type: text/plain\r\n\r\n");
        message.extend_from_slice(&body);
        message.extend_from_slice(b"\r\n--fuzz-boundary--\r\n");

        let outcome = std::panic::catch_unwind(|| MimeParser::new().parse(&message));
        prop_assert!(outcome.is_ok(), "MIME multipart parser panicked");
    }
}
