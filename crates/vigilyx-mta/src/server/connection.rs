//! SMTP

//! SMTP:
//! 1. banner -> EHLO -> STARTTLS
//! 2. MAIL FROM -> RCPT TO -> DATA
//! 3. DATA -> MIME -> EmailSession -> inline


use std::io::{self, ErrorKind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, error, warn};

use vigilyx_core::models::{EmailSession, Protocol, SessionSource, SessionStatus};
use vigilyx_parser::mime::MimeParser;

use crate::config::MtaConfig;
use crate::envelope::{extract_domain, is_valid_envelope_address};

/// SMTP. RFC 5321,.
const MAX_COMMAND_LEN: usize = 1024;
/// DATA;,.
const MAX_DATA_LINE_LEN: usize = 16 * 1024;

/// SEC: Maximum total session lifetime (CWE-400).
/// Prevents NOOP-keepalive attacks from holding connection slots indefinitely.
const MAX_SESSION_SECS: u64 = 600; // 10 minutes

/// SEC: Maximum total time for a single DATA transaction (CWE-400).
/// Prevents slow-data attacks where one tiny line per ~300s holds the DATA phase open.
const MAX_DATA_TRANSACTION_SECS: u64 = 300; // 5 minutes

/// SMTP
pub struct SmtpConnection {
   /// IP
    client_ip: String,

    client_port: u16,
    server_ip: String,
    server_port: u16,
   /// SMTP
    state: SmtpState,
   /// MAIL FROM
    mail_from: Option<String>,
   /// RCPT TO
    rcpt_to: Vec<String>,
   /// DATA
    data_buffer: Vec<u8>,
    
    config: Arc<MtaConfig>,
   /// TLS
    tls_active: bool,
   /// SEC: connection start time for session lifetime enforcement
    session_started: Instant,
   /// SEC: DATA phase start time for transaction timeout enforcement
    data_phase_started: Option<Instant>,
}

/// SMTP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmtpState {
   /// EHLO/HELO
    Connected,
   /// EHLO, MAIL FROM (STARTTLS)
    Ready,
   /// MAIL FROM, RCPT TO
    MailFrom,
   /// RCPT TO, DATA RCPT TO
    RcptTo,
   /// DATA
    Data,
}

/// SMTP
pub enum HandleResult {
   /// : EmailSession,
    Email(Box<EmailSession>, Vec<u8>),
   /// QUIT
    Closed,
    
    Error(String),
   /// TLS
    StartTls,
}

enum DataLineResult {
    Continue,
    Complete(Vec<u8>),
    TooLarge,
}

impl SmtpConnection {
    pub fn new(client_ip: String, client_port: u16, server_ip: String, server_port: u16, config: Arc<MtaConfig>, tls_active: bool) -> Self {
        Self {
            client_ip,
            client_port,
            server_ip,
            server_port,
            state: SmtpState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::new(),
            config,
            tls_active,
            session_started: Instant::now(),
            data_phase_started: None,
        }
    }

    fn reset_transaction(&mut self) {
        self.state = SmtpState::Ready;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.data_phase_started = None;
    }

    fn append_data_line(&mut self, line: &[u8]) -> DataLineResult {
        if line == b".\r\n" || line == b".\n" {
            let raw_email = std::mem::take(&mut self.data_buffer);
            // Do not reset here - build_email_session still needs mail_from and rcpt_to
            // Reset after the Complete branch in handle()
            return DataLineResult::Complete(raw_email);
        }

       // RFC 5321 dot-stuffing: ".." on the wire means a single leading dot in message data.
        let payload = if line.starts_with(b"..") { &line[1..] } else { line };
        if self.data_buffer.len() + payload.len() > self.config.max_message_size {
            return DataLineResult::TooLarge;
        }

        self.data_buffer.extend_from_slice(payload);
        DataLineResult::Continue
    }

    fn is_local_recipient(&self, addr: &str) -> bool {
        let Some(domain) = extract_domain(addr) else {
            return false;
        };
        self.config
            .local_domains
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(domain))
    }

   /// SMTP (-> ->)
    
    
   /// generic AsyncRead+AsyncWrite plain TCP TLS.
    pub async fn handle<S>(
        &mut self,
        stream: &mut S,
        skip_banner: bool,
    ) -> Vec<HandleResult>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut results = Vec::new();
        let mut reader = BufReader::new(stream);

        // SMTP banner (skip on TLS-upgraded connections to avoid double greeting)
        if !skip_banner {
            let banner = format!("220 {} ESMTP Vigilyx MTA\r\n", self.config.hostname);
            if let Err(e) = reader.get_mut().write_all(banner.as_bytes()).await {
                error!(client_ip = %self.client_ip, "Failed to send banner: {e}");
                return results;
            }
            if let Err(e) = reader.get_mut().flush().await {
                error!(client_ip = %self.client_ip, "Failed to flush banner: {e}");
                return results;
            }
        }

        loop {
            // SEC: enforce total session lifetime to prevent NOOP-keepalive attacks (CWE-400)
            if self.session_started.elapsed() > Duration::from_secs(MAX_SESSION_SECS) {
                warn!(client_ip = %self.client_ip, elapsed_secs = MAX_SESSION_SECS, "Session lifetime exceeded");
                let _ = reader.get_mut().write_all(b"421 4.4.2 Session lifetime exceeded\r\n").await;
                let _ = reader.get_mut().flush().await;
                break;
            }

            // SEC: enforce total DATA transaction timeout to prevent slow-data attacks
            if let Some(data_start) = self.data_phase_started
                && data_start.elapsed() > Duration::from_secs(MAX_DATA_TRANSACTION_SECS)
            {
                warn!(client_ip = %self.client_ip, elapsed_secs = MAX_DATA_TRANSACTION_SECS, "DATA transaction timeout");
                let _ = reader.get_mut().write_all(b"451 4.4.2 DATA transaction timeout\r\n").await;
                let _ = reader.get_mut().flush().await;
                self.reset_transaction();
                break;
            }

            let line_limit = if self.state == SmtpState::Data {
                MAX_DATA_LINE_LEN
            } else {
                MAX_COMMAND_LEN
            };
            // SEC: 60s idle timeout during the command phase (prevents slowloris from exhausting connection slots)
            // 300s during the DATA phase (RFC 5321 allows large messages to take longer)
            let idle_timeout = if self.state == SmtpState::Data {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(60)
            };
            let read_result = tokio::time::timeout(
                idle_timeout,
                read_smtp_line(&mut reader, line_limit),
            )
            .await;

            let line_buf = match read_result {
                Ok(Ok(None)) => {
                    debug!(client_ip = %self.client_ip, "Client disconnected");
                    break;
                }
                Ok(Ok(Some(line))) => line,
                Ok(Err(e)) if e.kind() == ErrorKind::InvalidData => {
                    let reply = if self.state == SmtpState::Data {
                        b"554 5.6.0 DATA line too long\r\n".as_slice()
                    } else {
                        b"500 5.5.1 Line too long\r\n".as_slice()
                    };
                    let _ = reader.get_mut().write_all(reply).await;
                    let _ = reader.get_mut().flush().await;
                    break;
                }
                Ok(Err(e)) => {
                    warn!(client_ip = %self.client_ip, "Read error: {e}");
                    break;
                }
                Err(_) => {
                    warn!(client_ip = %self.client_ip, "Client timeout (300s)");
                    let _ = reader
                        .get_mut()
                        .write_all(b"421 4.4.2 Connection timeout\r\n")
                        .await;
                    break;
                }
            };

           // DATA,
            if self.state == SmtpState::Data {
                match self.append_data_line(&line_buf) {
                    DataLineResult::Continue => {}
                    DataLineResult::Complete(raw_email) => {
                        let session = self.build_email_session(&raw_email);
                        let from_domain = session.mail_from.as_deref()
                            .and_then(|a| a.rsplit('@').next())
                            .unwrap_or("<>");
                        tracing::info!(
                            client_ip = %self.client_ip,
                            from_domain = %from_domain,
                            rcpt_count = session.rcpt_to.len(),
                            data_size = raw_email.len(),
                            "DATA complete"
                        );
                        self.reset_transaction();
                        results.push(HandleResult::Email(Box::new(session), raw_email));
                        // Continue loop — RFC 5321 allows multiple transactions per connection
                    }
                    DataLineResult::TooLarge => {
                        let _ = reader
                            .get_mut()
                            .write_all(b"552 5.3.4 Message too large\r\n")
                            .await;
                        let _ = reader.get_mut().flush().await;
                        self.reset_transaction();
                    }
                }
                continue;
            }

            let cmd = trim_line_end(&line_buf);
            if cmd.is_empty() {
                continue;
            }
            let cmd = match std::str::from_utf8(cmd) {
                Ok(cmd) => cmd,
                Err(_) => {
                    let _ = reader
                        .get_mut()
                        .write_all(b"500 5.5.2 Invalid command encoding\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;
                    continue;
                }
            };

            // SEC: full command at debug only to avoid leaking envelope addresses in production logs (CWE-532)
            tracing::debug!(client_ip = %self.client_ip, state = ?self.state, cmd = %cmd.trim(), "SMTP cmd");
           // SMTP
            let upper = cmd.to_ascii_uppercase();
            let response = self.process_command(&upper, cmd);

            
            match response {
                CmdResponse::Reply(code, msg) => {
                    let reply = format!("{code} {msg}\r\n");
                    if let Err(e) = reader.get_mut().write_all(reply.as_bytes()).await {
                        error!("Write error: {e}");
                        break;
                    }
                    let _ = reader.get_mut().flush().await;
                }
                CmdResponse::MultiLine(lines) => {
                    let mut buf = String::new();
                    for line in &lines {
                        buf.push_str(line);
                        buf.push_str("\r\n");
                    }
                    if let Err(e) = reader.get_mut().write_all(buf.as_bytes()).await {
                        error!("Write error: {e}");
                        break;
                    }
                    let _ = reader.get_mut().flush().await;
                }
                CmdResponse::Quit => {
                    let _ = reader.get_mut().write_all(b"221 2.0.0 Bye\r\n").await;
                    let _ = reader.get_mut().flush().await;
                    results.push(HandleResult::Closed);
                    break;
                }
                CmdResponse::StartTls => {
                    let _ = reader
                        .get_mut()
                        .write_all(b"220 2.0.0 Ready to start TLS\r\n")
                        .await;
                    let _ = reader.get_mut().flush().await;
                    results.push(HandleResult::StartTls);
                    return results;
                }
            }
        }

        results
    }

   /// SMTP,
    fn process_command(&mut self, upper: &str, original: &str) -> CmdResponse {
        if upper.starts_with("QUIT") {
            return CmdResponse::Quit;
        }

        if upper.starts_with("RSET") {
            self.reset_transaction();
            return CmdResponse::Reply(250, "2.1.5 OK".into());
        }

        if upper.starts_with("NOOP") {
            return CmdResponse::Reply(250, "2.0.0 OK".into());
        }

        match self.state {
            SmtpState::Connected => {
                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                    self.state = SmtpState::Ready;
                    let mut lines = vec![
                        format!("250-{} Hello", self.config.hostname),
                        "250-PIPELINING".into(),
                        format!("250-SIZE {}", self.config.max_message_size),
                        "250-8BITMIME".into(),
                    ];
                    if self.config.tls.is_some() && !self.tls_active {
                        lines.push("250-STARTTLS".into());
                    }
                    lines.push("250 OK".into());
                    CmdResponse::MultiLine(lines)
                } else {
                    CmdResponse::Reply(503, "5.5.1 Send EHLO/HELO first".into())
                }
            }
            SmtpState::Ready | SmtpState::MailFrom | SmtpState::RcptTo => {
                if upper.starts_with("STARTTLS") && self.state == SmtpState::Ready {
                    if self.tls_active {
                        return CmdResponse::Reply(503, "5.5.1 TLS already active".into());
                    }
                    if self.config.tls.is_none() {
                        return CmdResponse::Reply(502, "5.5.1 TLS not available".into());
                    }
                    return CmdResponse::StartTls;
                }

                if upper.starts_with("EHLO") || upper.starts_with("HELO") {
                   // EHLO (TLS)
                    self.reset_transaction();
                    let mut lines = vec![
                        format!("250-{} Hello", self.config.hostname),
                        "250-PIPELINING".into(),
                        format!("250-SIZE {}", self.config.max_message_size),
                        "250-8BITMIME".into(),
                    ];
                    if self.config.tls.is_some() && !self.tls_active {
                        lines.push("250-STARTTLS".into());
                    }
                    lines.push("250 OK".into());
                    return CmdResponse::MultiLine(lines);
                }

                if upper.starts_with("MAIL FROM:") || upper.starts_with("MAIL FROM :") {
                    if self.state != SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Nested MAIL command".into());
                    }
                    let addr = match extract_envelope_address(original, true) {
                        Ok(addr) => addr,
                        Err(_) => {
                            return CmdResponse::Reply(501, "5.1.7 Bad sender address syntax".into());
                        }
                    };
                    let from_domain = addr.as_deref().and_then(|a| a.rsplit('@').next()).unwrap_or("<>");
                    tracing::info!(from_domain = %from_domain, "MAIL FROM accepted");
                    self.mail_from = addr;
                    self.state = SmtpState::MailFrom;
                    return CmdResponse::Reply(250, "2.1.0 OK".into());
                }

                if upper.starts_with("RCPT TO:") || upper.starts_with("RCPT TO :") {
                    if self.state == SmtpState::Ready {
                        return CmdResponse::Reply(503, "5.5.1 Need MAIL command first".into());
                    }
                    if self.rcpt_to.len() >= self.config.max_recipients {
                        return CmdResponse::Reply(452, "4.5.3 Too many recipients".into());
                    }
                    let addr = match extract_envelope_address(original, false) {
                        Ok(Some(addr)) => addr,
                        Ok(None) | Err(_) => {
                            return CmdResponse::Reply(501, "5.1.3 Bad recipient address syntax".into());
                        }
                    };
                    if !self.is_local_recipient(&addr) {
                        return CmdResponse::Reply(554, "5.7.1 Relay access denied".into());
                    }
                    let rcpt_domain = addr.rsplit('@').next().unwrap_or("<>");
                    tracing::info!(rcpt_domain = %rcpt_domain, rcpt_count = self.rcpt_to.len() + 1, "RCPT TO accepted");
                    self.rcpt_to.push(addr);
                    self.state = SmtpState::RcptTo;
                    return CmdResponse::Reply(250, "2.1.5 OK".into());
                }

                if upper.starts_with("DATA") {
                    if self.rcpt_to.is_empty() {
                        return CmdResponse::Reply(503, "5.5.1 Need RCPT command first".into());
                    }
                    self.state = SmtpState::Data;
                    self.data_phase_started = Some(Instant::now());
                    self.data_buffer.clear();
                    return CmdResponse::Reply(354, "Start mail input; end with <CRLF>.<CRLF>".into());
                }

                CmdResponse::Reply(502, "5.5.1 Command not recognized".into())
            }
            SmtpState::Data => {
               // (DATA handle)
                CmdResponse::Reply(503, "5.5.1 Unexpected command during DATA".into())
            }
        }
    }

   /// EmailSession
    fn build_email_session(&self, raw_email: &[u8]) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            self.client_ip.clone(),
            self.client_port,
            self.server_ip.clone(),
            self.server_port,
        );

        session.source = SessionSource::MtaProxy;
        session.status = SessionStatus::Completed;
        session.ended_at = Some(Utc::now());
        session.mail_from = self.mail_from.clone();
        session.rcpt_to = self.rcpt_to.clone();
        session.total_bytes = raw_email.len();
        session.email_count = 1;

       // MIME
        let parser = MimeParser::new();
        session.content = match parser.parse(raw_email) {
            Ok(content) => content,
            Err(e) => {
                warn!(client_ip = %self.client_ip, "MIME parse error: {e:?}");
                vigilyx_core::EmailContent::default()
            }
        };
        session.content.is_complete = true;

       // headers subject message_id
        for (key, value) in &session.content.headers {
            match key.to_ascii_lowercase().as_str() {
                "subject" => {
                    if session.subject.is_none() {
                        session.subject = Some(value.clone());
                    }
                }
                "message-id" => {
                    if session.message_id.is_none() {
                        session.message_id = Some(value.clone());
                    }
                }
                _ => {}
            }
        }

        session
    }
}

/// SMTP
enum CmdResponse {
    Reply(u16, String),
    MultiLine(Vec<String>),
    Quit,
    StartTls,
}

async fn read_smtp_line<R>(reader: &mut R, max_len: usize) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::with_capacity(max_len.min(4096));

    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Ok(Some(line));
        }

        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if line.len() + take > max_len {
                return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
            }
            line.extend_from_slice(&buf[..take]);
            reader.consume(take);
            return Ok(Some(line));
        }

        if line.len() + buf.len() > max_len {
            return Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"));
        }

        let take = buf.len();
        line.extend_from_slice(&buf[..take]);
        reader.consume(take);
    }
}

fn trim_line_end(line: &[u8]) -> &[u8] {
    if let Some(stripped) = line.strip_suffix(b"\r\n") {
        stripped
    } else if let Some(stripped) = line.strip_suffix(b"\n") {
        stripped
    } else if let Some(stripped) = line.strip_suffix(b"\r") {
        stripped
    } else {
        line
    }
}

fn extract_envelope_address(cmd: &str, allow_empty: bool) -> Result<Option<String>, &'static str> {
    let (_, rest) = cmd.split_once(':').ok_or("missing colon")?;
    let rest = rest.trim();
    let addr = if let Some(stripped) = rest.strip_prefix('<') {
        let (addr, suffix) = stripped
            .split_once('>')
            .ok_or("missing closing angle bracket")?;
        if !suffix.is_empty() && !suffix.chars().next().is_some_and(char::is_whitespace) {
            return Err("invalid address parameters");
        }
        addr.trim()
    } else {
        rest.split_whitespace().next().ok_or("missing address")?
    };

    if addr.is_empty() {
        return if allow_empty {
            Ok(None)
        } else {
            Err("empty address")
        };
    }

    if !is_valid_envelope_address(addr) {
        return Err("invalid address");
    }

    Ok(Some(addr.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_address_with_brackets() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<user@example.com>", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_without_brackets() {
        assert_eq!(
            extract_envelope_address("MAIL FROM: user@example.com", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_with_params() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<user@example.com> SIZE=1024", true),
            Ok(Some("user@example.com".into()))
        );
    }

    #[test]
    fn test_extract_address_empty_mail_from() {
        assert_eq!(
            extract_envelope_address("MAIL FROM:<>", true),
            Ok(None)
        );
    }

    #[test]
    fn test_extract_rcpt_to() {
        assert_eq!(
            extract_envelope_address("RCPT TO:<admin@corp.com>", false),
            Ok(Some("admin@corp.com".into()))
        );
    }

    #[test]
    fn test_extract_invalid_sender_domain_rejected() {
        assert!(
            extract_envelope_address("MAIL FROM:<user@bad_domain>", true).is_err(),
            "Underscore domain should be rejected"
        );
    }

    #[test]
    fn test_extract_invalid_sender_local_part_rejected() {
        assert!(
            extract_envelope_address("MAIL FROM:<a..b@example.com>", true).is_err(),
            "Invalid local-part should be rejected"
        );
    }

    #[test]
    fn test_extract_address_rejects_garbage_after_brackets() {
        assert!(
            extract_envelope_address("MAIL FROM:<user@example.com>X", true).is_err(),
            "Address parameters must be separated from the mailbox"
        );
    }

   /// MtaConfig
    fn test_config() -> Arc<MtaConfig> {
        Arc::new(MtaConfig {
            listen_smtp: "127.0.0.1:2525".parse().unwrap(),
            listen_submission: None,
            listen_smtps: None,
            max_connections: 10,
            tls: None,
            downstream: crate::config::DownstreamConfig {
                host: "127.0.0.1".into(),
                port: 25,
                starttls: false,
                timeout_secs: 5,
            },
            outbound: None,
            local_domains: vec!["test.com".into(), "corp.com".into()],
            inline_timeout_secs: 8,
            fail_open: true,
            quarantine_threshold: vigilyx_core::security::ThreatLevel::Medium,
            reject_threshold: vigilyx_core::security::ThreatLevel::Critical,
            max_message_size: 1024 * 1024,
            max_recipients: 10,
            database_url: String::new(),
            redis_url: None,
            hostname: "test-mta".into(),
            dlp: crate::dlp::DlpConfig::default(),
        })
    }

   /// : process_command (I/O,)
    fn cmd(conn: &mut SmtpConnection, cmd: &str) -> String {
        let upper = cmd.to_ascii_uppercase();
        match conn.process_command(&upper, cmd) {
            CmdResponse::Reply(code, msg) => format!("{code} {msg}"),
            CmdResponse::MultiLine(lines) => lines.join("\n"),
            CmdResponse::Quit => "QUIT".into(),
            CmdResponse::StartTls => "STARTTLS".into(),
        }
    }

    #[test]
    fn test_smtp_ehlo_returns_capabilities() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let resp = cmd(&mut conn, "EHLO client.test");
        assert!(resp.contains("250"), "Should get 250: {resp}");
        assert!(resp.contains("PIPELINING"));
        assert!(resp.contains("8BITMIME"));
        assert_eq!(conn.state, SmtpState::Ready);
    }

    #[test]
    fn test_smtp_mail_from_before_ehlo_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let resp = cmd(&mut conn, "MAIL FROM:<test@example.com>");
        assert!(resp.contains("503"), "Should fail: {resp}");
    }

    #[test]
    fn test_smtp_full_command_sequence() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);

        let r = cmd(&mut conn, "EHLO client.test");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::Ready);

        let r = cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::MailFrom);
        assert_eq!(conn.mail_from, Some("sender@test.com".into()));

        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::RcptTo);
        assert_eq!(conn.rcpt_to, vec!["rcpt@test.com"]);

        let r = cmd(&mut conn, "DATA");
        assert!(r.contains("354"));
        assert_eq!(conn.state, SmtpState::Data);
    }

    #[test]
    fn test_smtp_rcpt_to_before_mail_from_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("503"), "Should fail: {r}");
    }

    #[test]
    fn test_smtp_data_before_rcpt_to_fails() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "DATA");
        assert!(r.contains("503"), "DATA without RCPT should fail: {r}");
    }

    #[test]
    fn test_smtp_rset_resets_state() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        assert_eq!(conn.state, SmtpState::MailFrom);

        let r = cmd(&mut conn, "RSET");
        assert!(r.contains("250"));
        assert_eq!(conn.state, SmtpState::Ready);
        assert!(conn.mail_from.is_none());
        assert!(conn.rcpt_to.is_empty());

       // After RSET, RCPT should fail (no MAIL FROM)
        let r = cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(r.contains("503"));
    }

    #[test]
    fn test_smtp_noop() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO client.test");
        let r = cmd(&mut conn, "NOOP");
        assert!(r.contains("250"));
    }

    #[test]
    fn test_smtp_quit() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        let r = cmd(&mut conn, "QUIT");
        assert_eq!(r, "QUIT");
    }

    #[test]
    fn test_smtp_multiple_rcpt_to() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<a@test.com>");
        cmd(&mut conn, "RCPT TO:<b@test.com>");
        cmd(&mut conn, "RCPT TO:<c@test.com>");
        assert_eq!(conn.rcpt_to.len(), 3);
    }

    #[test]
    fn test_smtp_too_many_recipients() {
        let config = test_config(); // max_recipients = 10
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        for i in 0..10 {
            cmd(&mut conn, &format!("RCPT TO:<user{i}@test.com>"));
        }
        let r = cmd(&mut conn, "RCPT TO:<overflow@test.com>");
        assert!(r.contains("452"), "Should reject excess recipients: {r}");
    }

    #[test]
    fn test_smtp_starttls_without_tls_config() {
        let config = test_config(); // tls = None
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "STARTTLS");
        assert!(r.contains("502"), "No TLS config should return 502: {r}");
    }

    #[test]
    fn test_smtp_rejects_non_local_recipient_domain() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@external.net>");
        assert!(r.contains("554"), "Non-local relay should be denied: {r}");
    }

    #[test]
    fn test_smtp_accepts_empty_bounce_sender() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        let r = cmd(&mut conn, "MAIL FROM:<>");
        assert!(r.contains("250"), "Bounce sender should be allowed: {r}");
        assert!(conn.mail_from.is_none());
    }

    #[test]
    fn test_smtp_local_domain_match_is_case_insensitive() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        let r = cmd(&mut conn, "RCPT TO:<user@Corp.Com>");
        assert!(r.contains("250"), "Local domains should match case-insensitively: {r}");
    }

    #[test]
    fn test_data_line_unstuffs_leading_dot() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        conn.state = SmtpState::Data;

        assert!(matches!(
            conn.append_data_line(b"..leading dot\r\n"),
            DataLineResult::Continue
        ));
        assert_eq!(conn.data_buffer, b".leading dot\r\n");
    }

    #[test]
    fn test_session_started_is_set_on_construction() {
        let config = test_config();
        let before = Instant::now();
        let conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        assert!(conn.session_started >= before);
        assert!(conn.session_started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn test_data_phase_started_set_on_data_command() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        assert!(conn.data_phase_started.is_none());
        cmd(&mut conn, "DATA");
        assert!(conn.data_phase_started.is_some());
    }

    #[test]
    fn test_data_phase_started_cleared_on_reset() {
        let config = test_config();
        let mut conn = SmtpConnection::new("127.0.0.1".into(), 9999, "0.0.0.0".into(), 25, config, false);
        cmd(&mut conn, "EHLO test");
        cmd(&mut conn, "MAIL FROM:<sender@test.com>");
        cmd(&mut conn, "RCPT TO:<rcpt@test.com>");
        cmd(&mut conn, "DATA");
        assert!(conn.data_phase_started.is_some());
        conn.reset_transaction();
        assert!(conn.data_phase_started.is_none());
    }

    #[tokio::test]
    async fn test_build_email_session_from_raw() {
        let config = test_config();
        let mut conn = SmtpConnection::new("10.0.0.1".into(), 4321, "0.0.0.0".into(), 25, config, false);
        conn.mail_from = Some("test@example.com".into());
        conn.rcpt_to = vec!["admin@corp.com".into()];

        let raw = b"From: test@example.com\r\nTo: admin@corp.com\r\nSubject: Hello\r\n\r\nBody text";
        let session = conn.build_email_session(raw);

        assert_eq!(session.client_ip, "10.0.0.1");
        assert_eq!(session.mail_from, Some("test@example.com".into()));
        assert_eq!(session.rcpt_to, vec!["admin@corp.com"]);
        assert_eq!(session.subject, Some("Hello".into()));
        assert!(session.content.body_text.is_some());
        assert_eq!(session.source, SessionSource::MtaProxy);
        assert_eq!(session.status, SessionStatus::Completed);
    }
}
