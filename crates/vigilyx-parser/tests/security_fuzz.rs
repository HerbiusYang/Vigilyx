//! Security-oriented property tests for the protocol and MIME boundary.
//!
//! These are intentionally bounded and deterministic so they run in normal CI.
//! They complement the longer red-team mutation harness instead of replacing
//! it. The oracle is fail-closed: no panic, no unbounded retained buffer, and
//! every reconstructed message remains safe to hand to the MIME parser.

use std::panic::{AssertUnwindSafe, catch_unwind};

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use vigilyx_core::MAX_EMAIL_LINKS;
use vigilyx_parser::{MimeParser, SmtpStateMachine};

const MAX_RETAINED_SMTP_BYTES: usize = 26 * 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 1_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn hostile_smtp_chunks_never_panic_or_exceed_capture_budget(
        client_chunks in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..2 * 1024),
            0..32,
        ),
        server_chunks in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..512),
            0..16,
        ),
    ) {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let mut smtp = SmtpStateMachine::new();

            for (index, chunk) in client_chunks.iter().enumerate() {
                smtp.process_client_data(chunk);
                prop_assert!(
                    smtp.buffered_email_bytes() <= MAX_RETAINED_SMTP_BYTES,
                    "SMTP capture retained more than its hard byte budget"
                );

                // Draining completed messages is part of the real consumer
                // contract and exercises the truncation metadata path.
                if index % 4 == 0 {
                    for message in smtp.take_completed_messages() {
                        let parsed = MimeParser::new().parse(&message.data);
                        prop_assert!(
                            parsed.is_ok() || !message.is_complete,
                            "a complete reconstructed message must be MIME-parseable"
                        );
                    }
                }
            }

            for chunk in &server_chunks {
                smtp.process_server_response(chunk);
                prop_assert!(
                    smtp.buffered_email_bytes() <= MAX_RETAINED_SMTP_BYTES,
                    "server responses must not grow the SMTP DATA buffer"
                );
            }

            for message in smtp.take_completed_messages() {
                let parsed = MimeParser::new().parse(&message.data);
                prop_assert!(
                    parsed.is_ok() || !message.is_complete,
                    "a complete reconstructed message must be MIME-parseable"
                );
            }

            Ok::<(), TestCaseError>(())
        }));

        prop_assert!(outcome.is_ok(), "hostile SMTP input caused a panic");
        prop_assert!(
            outcome.unwrap().is_ok(),
            "the SMTP security oracle rejected a bounded input"
        );
    }

    #[test]
    fn hostile_mime_bytes_never_panic(
        data in prop::collection::vec(any::<u8>(), 0..48 * 1024),
    ) {
        let outcome = catch_unwind(AssertUnwindSafe(|| MimeParser::new().parse(&data)));
        prop_assert!(outcome.is_ok(), "MIME parser panicked for arbitrary bytes");
    }

    #[test]
    fn structured_mime_variants_never_panic(
        boundary in prop::string::string_regex(r"[A-Za-z0-9._-]{1,32}").unwrap(),
        filename in prop::string::string_regex(r"[A-Za-z0-9._/]{0,64}").unwrap(),
        transfer_encoding in prop_oneof![
            Just("base64".to_string()),
            Just("quoted-printable".to_string()),
            Just("8bit".to_string()),
            Just("binary".to_string()),
        ],
        body in prop::collection::vec(any::<u8>(), 0..8 * 1024),
    ) {
        // Generate a syntactically shaped multipart message while varying the
        // fields attackers actually control. The body is intentionally not
        // made valid for the declared transfer encoding: decoder error paths
        // are part of the parser boundary we want to exercise.
        let mut raw = format!(
            "From: alice@example.com\r\n\
             To: recipient@example.net\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\
             \r\n\
             --{boundary}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"{filename}\"\r\n\
             Content-Transfer-Encoding: {transfer_encoding}\r\n\
             \r\n"
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        raw.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        let outcome = catch_unwind(AssertUnwindSafe(|| MimeParser::new().parse(&raw)));
        prop_assert!(outcome.is_ok(), "structured MIME input caused a panic");
        if let Ok(Ok(content)) = outcome {
            prop_assert!(
                content.attachments.len() <= 1,
                "one generated MIME part must not fabricate many attachments"
            );
        }
    }

    #[test]
    fn smtp_data_chunk_boundaries_preserve_one_complete_message(
        chunk_size in 1usize..128,
    ) {
        let message = concat!(
            "From: alice@example.com\r\n",
            "To: recipient@example.net\r\n",
            "Subject: chunk boundary\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "synthetic body with a phone-shaped DLP vector: 13800138000",
        );
        let mut wire = message.as_bytes().to_vec();
        wire.extend_from_slice(b"\r\n.\r\n");

        let mut smtp = SmtpStateMachine::new();
        smtp.process_client_data(b"EHLO client.example\r\n");
        smtp.process_server_response(b"250 OK\r\n");
        smtp.process_client_data(b"MAIL FROM:<alice@example.com>\r\n");
        smtp.process_client_data(b"RCPT TO:<recipient@example.net>\r\n");
        smtp.process_client_data(b"DATA\r\n");
        smtp.process_server_response(b"354 Start mail input\r\n");

        for chunk in wire.chunks(chunk_size) {
            smtp.process_client_data(chunk);
            prop_assert!(
                smtp.buffered_email_bytes() <= MAX_RETAINED_SMTP_BYTES,
                "chunked SMTP DATA exceeded the retained buffer budget"
            );
        }

        let messages = smtp.take_completed_messages();
        prop_assert_eq!(messages.len(), 1);
        prop_assert!(messages[0].is_complete);
        prop_assert_eq!(&messages[0].data[..], message.as_bytes());
        prop_assert!(MimeParser::new().parse(&messages[0].data).is_ok());
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        max_shrink_iters: 512,
        rng_seed: RngSeed::Fixed(0x5649_4749_4c59_5801),
        ..ProptestConfig::default()
    })]

    #[test]
    fn mixed_script_bare_domain_reaches_idn_analysis_without_resource_growth(
        label in prop::string::string_regex(r"[a-z]{1,16}").unwrap(),
        confusable in prop_oneof![
            Just('\u{03BF}'), // Greek omicron
            Just('\u{043E}'), // Cyrillic o
            Just('\u{03C1}'), // Greek rho
        ],
    ) {
        let host = format!("{label}-security.c{confusable}m");
        let raw = format!(
            "Content-Type: text/plain; charset=utf-8\r\n\r\n确认入口：{host}"
        );
        let outcome = catch_unwind(AssertUnwindSafe(|| MimeParser::new().parse(raw.as_bytes())));
        prop_assert!(outcome.is_ok(), "mixed-script bare-domain parsing panicked");
        let content = outcome.unwrap().expect("bounded synthetic MIME must parse");
        prop_assert!(content.links.len() <= MAX_EMAIL_LINKS);
        prop_assert!(
            content.links.iter().any(|link| link.url == format!("https://{host}")),
            "client-linkified IDN candidate was lost: {:?}",
            content.links
        );
    }

    #[test]
    fn dbf_interface_tokens_never_become_synthetic_hosts(
        stem in prop::string::string_regex(r"[A-Za-z][A-Za-z0-9_-]{0,31}").unwrap(),
        suffix in prop_oneof![Just("dbf"), Just("DBF"), Just("DbF")],
        wrapper in prop_oneof![Just(("", "")), Just(("(", ")")), Just(("（", "）"))],
    ) {
        let token = format!("{}.{suffix}", stem);
        let raw = format!(
            "Content-Type: text/plain; charset=utf-8\r\n\r\n结算接口：{}{}{} 将于月底下线。",
            wrapper.0, token, wrapper.1
        );
        let outcome = catch_unwind(AssertUnwindSafe(|| MimeParser::new().parse(raw.as_bytes())));
        prop_assert!(outcome.is_ok(), "DBF filename parsing panicked");
        let content = outcome.unwrap().expect("bounded synthetic MIME must parse");
        prop_assert!(
            content.links.is_empty(),
            "DBF filename was linkified as a host: token={token} links={:?}",
            content.links
        );
    }
}

#[test]
fn oversized_mime_input_is_rejected_without_parsing() {
    let oversized = vec![b'x'; 100 * 1024 * 1024 + 1];
    let outcome = catch_unwind(AssertUnwindSafe(|| MimeParser::new().parse(&oversized)));
    assert!(outcome.is_ok(), "oversize MIME input panicked");
    assert!(
        outcome.unwrap().is_err(),
        "oversize MIME input must be rejected instead of parsed"
    );
}

#[test]
fn smtp_bare_lf_terminator_does_not_hide_a_second_message() {
    let mut smtp = SmtpStateMachine::new();
    smtp.process_client_data(b"EHLO client.example\r\n");
    smtp.process_server_response(b"250 OK\r\n");
    smtp.process_client_data(b"MAIL FROM:<alice@example.com>\r\n");
    smtp.process_client_data(b"RCPT TO:<bob@example.net>\r\n");
    smtp.process_client_data(b"DATA\r\n");
    smtp.process_server_response(b"354 Start mail input\r\n");
    smtp.process_client_data(b"Subject: boundary\r\n\r\nbody\n.\nhidden\r\n.\r\n");

    let messages = smtp.take_completed_messages();
    assert_eq!(
        messages.len(),
        2,
        "smuggling variant must remain observable"
    );
    assert!(messages.iter().all(|message| message.is_complete));
}
