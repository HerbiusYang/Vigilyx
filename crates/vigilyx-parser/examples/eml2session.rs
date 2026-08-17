//! Red-team helper: convert a raw .eml into the exact EmailSession JSON the
//! sniffer publishes to the `vigilyx:stream:sessions` Redis Stream.
//!
//! Usage: cargo run --release -p vigilyx-parser --example eml2session -- <file.eml> [mail_from] [rcpt_to]
//! Prints one JSON document per invocation.

use vigilyx_core::models::{EmailSession, Protocol, SessionSource, SessionStatus};
use vigilyx_parser::mime::decode_rfc2047;
use vigilyx_parser::MimeParser;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: eml2session <file.eml> [mail_from] [rcpt_to]");
    let mail_from = args
        .next()
        .unwrap_or_else(|| "sender@partner-external.com".to_string());
    let rcpt = args
        .next()
        .unwrap_or_else(|| "employee@ccabchina.com".to_string());

    let raw = std::fs::read(&path).expect("read eml");
    let mut content = MimeParser::new().parse(&raw).expect("parse eml");
    content.is_complete = true;

    let mut session = EmailSession::new(
        Protocol::Smtp,
        "198.51.100.77".to_string(),
        40000,
        "10.7.126.68".to_string(),
        25,
    );
    session.source = SessionSource::Sniffer;
    session.status = SessionStatus::Completed;
    session.mail_from = Some(mail_from);
    session.rcpt_to.push(rcpt);
    session.total_bytes = raw.len();
    session.email_count = 1;
    for (key, value) in &content.headers {
        if key.eq_ignore_ascii_case("subject") && session.subject.is_none() {
            let decoded = decode_rfc2047(value);
            let trimmed = decoded.trim();
            if !trimmed.is_empty() {
                session.subject = Some(trimmed.to_string());
            }
        }
        if key.eq_ignore_ascii_case("message-id") && session.message_id.is_none() {
            session.message_id = Some(value.trim().to_string());
        }
    }
    session.content = content;

    println!("{}", serde_json::to_string(&session).expect("serialize"));
}
