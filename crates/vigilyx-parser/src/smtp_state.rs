//! SMTP ProtocolState machine

//! tracing SMTP SessionStatus, emailContent.

//! SMTP SessionStream:
//! ```text
//! C: (connect)
//! S: 220 Service
//! C: EHLO client.example.com
//! S: 250-server.example.com
//! S: 250 OK
//! C: MAIL FROM:<sender@example.com>
//! S: 250 OK
//! C: RCPT TO:<recipient@example.com>
//! S: 250 OK
//! C: DATA
//! S: 354 StartemailInput
//! C: From: sender@example.com
//! C: To: recipient@example.com
//! C: Subject: Test
//! C: (line)
//! C: emailbody...
//! C:.
//! S: 250 OK
//! C: QUIT
//! S: 221

use bytes::Bytes;
use memchr::memmem;
use smallvec::SmallVec;
use tracing::{debug, info, trace, warn};
use vigilyx_core::SmtpState;

/// Full-audit mode: no practical email body size limit.
/// Hard upper bound for the SMTP DATA buffer (prevents OOM).
/// Aligned with MTA max_message_size (25MB), plus 1MB of headroom for SMTP line terminator overhead.
const MAX_DATA_BUFFER_SIZE: usize = 26 * 1024 * 1024; // 26 MB

/// SMTP AUTH Authentication Segment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPhase {
    /// AuthenticationStream Medium
    None,
    /// AUTH PLAIN alreadySend (credentials),Waiting for server 334 Sendcredentials
    PlainWaiting,
    /// AUTH LOGIN: waitWaitclientSenduserName (Servicehandleralready 334)
    LoginWaitingUsername,
    /// AUTH LOGIN: waitWaitclientSendPassword (Servicehandleralready 334)
    LoginWaitingPassword,
}

/// SMTP CommandType
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    /// EHLO/HELO
    Greeting(String),
    /// AUTH
    Auth(String),
    /// STARTTLS
    StartTls,
    /// MAIL FROM
    MailFrom(String),
    /// RCPT TO
    RcptTo(String),
    /// DATA
    Data,
    /// emailContentEnd (of.)
    DataEnd,
    /// RFC 3030: `BDAT <size> [LAST]`
    Bdat { size: usize, is_last: bool },
    /// RSET
    Reset,
    /// QUIT
    Quit,
    /// Authenticationcredentialsalready
    AuthCredential {
        method: String,
        username: String,
        password: String,
    },
    /// AuthenticationResult (Success/Failed)
    AuthResult(bool),
    /// /Unknown
    Other(String),
}

/// SMTP Response (store code,Messagealready trace! downgradelevellogProcess)
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    /// ResponseCode/Digit (if 250, 354)
    pub code: u16,
    /// whether lineResponseoflast1line
    #[allow(dead_code)]
    pub is_final: bool,
}

/// One SMTP message reconstructed from the transport stream.
///
/// `is_complete` is false when the capture exceeded a parser byte budget. The
/// retained bytes may still be useful for detection, but callers must not
/// represent the resulting verdict as a fully inspected message.
#[derive(Debug, Clone)]
pub struct CompletedSmtpMessage {
    pub data: Bytes,
    pub is_complete: bool,
}

/// Hard cap on retained envelope recipients per message in passive capture
/// mode (SEC M-5, amended 2026-08-16). A mirrored client can otherwise push
/// millions of RCPT TO lines and grow session memory without a live MTA being
/// able to reject the transaction. Inline MTA policy is independently
/// configurable up to this same 10,000-recipient safety ceiling.
const MAX_RCPT_TO: usize = 10_000;

/// Hard cap on replayable AUTH commands (SEC M-5): pending_commands grew once
/// per multiline AUTH response with no bound; legitimate flows hold 1-2.
const MAX_PENDING_COMMANDS: usize = 64;

/// SMTP State machine
pub struct SmtpStateMachine {
    /// WhenfirstStatus
    state: SmtpState,
    /// Sender
    mail_from: Option<String>,
    /// recipientList
    rcpt_to: Vec<String>,
    /// Recipients dropped after `MAX_RCPT_TO` was reached (SEC M-5); surfaced
    /// for diagnostics so the truncation stays observable.
    dropped_rcpt_to: usize,
    overflow_warned: bool,
    /// emaildatabufferDistrict
    data_buffer: Vec<u8>,
    /// emaildatawhether Receive
    in_data_mode: bool,
    /// alreadycompleteofemaildataList (1ConnectionpossiblySend email)
    completed_emails: Vec<CompletedSmtpMessage>,
    /// Whether bytes from the message currently being reconstructed were
    /// discarded because the bounded DATA buffer was full.
    current_message_truncated: bool,
    /// whetherUse STARTTLS (ofdataall Encryptof)
    is_starttls_active: bool,
    /// STARTTLS CommandalreadySend,Waiting for server 220
    starttls_pending: bool,
    /// DATA command sent, waiting for server 354 response.
    /// While true, all client data is buffered in pipelined_data instead of being
    /// parsed as commands. This prevents email body from being silently discarded
    /// when it arrives in a separate TCP packet before the 354 response.
    data_cmd_pending: bool,
    /// AUTH Authentication Segment
    auth_phase: AuthPhase,
    /// AUTH AuthenticationMethod
    auth_method: Option<String>,
    /// AUTH alreadyDecodeofuserName
    auth_username: Option<String>,
    /// AUTH alreadyDecodeofPassword
    auth_password: Option<String>,
    /// ByServicehandlerResponse ofWaitGetCommand (if AuthResult, AuthCredential)
    pending_commands: SmallVec<[SmtpCommand; 2]>,
    /// Pipelinecache: DATA Command, 354 Response first emaildata
    /// SMTP Pipeline (RFC 2920) client wait 354 SendemailContent
    /// Segment stored data,354 Auto data_buffer
    pipelined_data: Option<Vec<u8>>,
    /// FIX #3: Partial command line buffer (client) - lines split across TCP segments
    cmd_line_buf: Vec<u8>,
    /// FIX #3: Partial response line buffer (server) - lines split across TCP segments
    resp_line_buf: Vec<u8>,
    /// RFC 3030 BDAT: whether we are in BDAT data collection mode.
    #[allow(dead_code)]
    in_bdat_mode: bool,
    /// RFC 3030 BDAT: remaining bytes to read for the current chunk.
    #[allow(dead_code)]
    bdat_remaining: usize,
    /// RFC 3030 BDAT: whether the current/last chunk had the LAST flag.
    #[allow(dead_code)]
    bdat_is_last: bool,
    /// Offset where the current BDAT chunk begins in the accumulated message.
    /// Late TCP prepend recovery must insert bytes here, not before prior chunks.
    bdat_chunk_start: usize,
    /// Protocol anomalies observed (e.g. a 354 response with no pending DATA).
    /// An injected server response must not be able to silently discard the
    /// buffered message body, so anomalies are counted instead of applied.
    anomaly_count: u32,
    /// Capture started mid-connection (no SYN observed). In that mode a 354
    /// without a seen DATA command is still honored once, otherwise mid-stream
    /// restore would lose the whole message body.
    midstream_capture: bool,
    /// Structured SMTP commands / valid response codes observed so far.
    /// Used by the capture layer to distinguish real SMTP dialog from TLS
    /// garbage before trusting the TLS-record magic heuristic.
    dialog_lines_observed: u32,
}

impl SmtpStateMachine {
    pub fn new() -> Self {
        Self {
            state: SmtpState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            dropped_rcpt_to: 0,
            overflow_warned: false,
            data_buffer: Vec::with_capacity(64 * 1024), // 64KB Capacity
            in_data_mode: false,
            completed_emails: Vec::new(),
            current_message_truncated: false,
            cmd_line_buf: Vec::new(),
            resp_line_buf: Vec::new(),
            is_starttls_active: false,
            starttls_pending: false,
            data_cmd_pending: false,
            auth_phase: AuthPhase::None,
            auth_method: None,
            auth_username: None,
            auth_password: None,
            pending_commands: SmallVec::new(),
            pipelined_data: None,
            in_bdat_mode: false,
            bdat_remaining: 0,
            bdat_is_last: false,
            bdat_chunk_start: 0,
            anomaly_count: 0,
            midstream_capture: false,
            dialog_lines_observed: 0,
        }
    }

    /// GetWhenfirstStatus
    pub fn state(&self) -> SmtpState {
        self.state
    }

    /// GetSender
    #[allow(dead_code)]
    pub fn mail_from(&self) -> Option<&str> {
        self.mail_from.as_deref()
    }

    /// GetrecipientList
    #[allow(dead_code)]
    pub fn rcpt_to(&self) -> &[String] {
        &self.rcpt_to
    }

    /// Recipients dropped after the cap was reached (SEC M-5).
    pub fn dropped_rcpt_to(&self) -> usize {
        self.dropped_rcpt_to
    }

    /// Retain a parsed recipient under the passive-parser hard ceiling.
    /// Every command ingestion path must use this helper so packet framing or
    /// pipelining cannot bypass the resource bound.
    fn retain_recipient(&mut self, email: &str) {
        if self.rcpt_to.len() >= MAX_RCPT_TO {
            self.dropped_rcpt_to = self.dropped_rcpt_to.saturating_add(1);
            if !self.overflow_warned {
                self.overflow_warned = true;
                warn!(
                    limit = MAX_RCPT_TO,
                    "SMTP session exceeded the passive recipient cap — further RCPT TO entries are dropped"
                );
            }
        } else {
            self.rcpt_to.push(email.to_owned());
        }
    }

    /// Whether in data collection mode
    pub fn is_in_data_mode(&self) -> bool {
        self.in_data_mode || self.in_bdat_mode
    }

    /// FIX #4: Release data_buffer memory after email extraction (avoid redundant copy)
    pub fn clear_data_buffer(&mut self) {
        self.data_buffer = Vec::new(); // Deallocate, not just clear
    }

    /// whetherUse STARTTLS (Stream alreadyEncrypt)
    pub fn is_encrypted(&self) -> bool {
        self.is_starttls_active
    }

    /// Whether the parser is still waiting for DATA payload to finish.
    pub fn has_pending_data(&self) -> bool {
        self.in_data_mode || self.data_cmd_pending || self.in_bdat_mode
    }

    /// Best-effort buffered email bytes not yet turned into a completed MIME message.
    pub fn buffered_email_bytes(&self) -> usize {
        self.data_buffer.len() + self.pipelined_data.as_ref().map_or(0, Vec::len)
    }

    /// Number of protocol anomalies observed (e.g. forged/duplicate 354).
    pub fn anomaly_count(&self) -> u32 {
        self.anomaly_count
    }

    /// Whether any structured SMTP command or valid server response line has
    /// been observed on this connection.
    pub fn has_observed_dialog(&self) -> bool {
        self.dialog_lines_observed > 0
    }

    /// Mark this connection as captured mid-stream (no SYN seen). A lone 354
    /// is then still honored once so the in-flight message body is collected.
    pub fn set_midstream_capture(&mut self, midstream: bool) {
        self.midstream_capture = midstream;
    }

    fn data_terminator(buffer: &[u8]) -> Option<(usize, usize)> {
        memmem::find(buffer, b"\r\n.\r\n").map(|pos| (pos, 5usize))
    }

    /// Find a suspicious bare-LF dot line in `buffer[from..]`: `\n.` where the
    /// `\n` is NOT preceded by `\r` (a genuine CRLF message never contains
    /// one), followed by `\r\n` or `\n`. Legacy MTAs (old Postfix, unpatched
    /// Exchange) accept this variant as the end of DATA, so the bytes between
    /// it and the real `\r\n.\r\n` terminator become a hidden second message
    /// that structured analysis never sees.
    ///
    /// Returns `(line_start, next_segment_start)`. Only applied when a real
    /// CRLF terminator exists later in the buffer, so bare-LF-only mail
    /// remains untouched (still recovered on close, not terminated early).
    fn bare_lf_dot_line(buffer: &[u8], from: usize) -> Option<(usize, usize)> {
        let mut i = from.max(1);
        while i + 2 < buffer.len() {
            if buffer[i] == b'\n' && buffer[i - 1] != b'\r' && buffer[i + 1] == b'.' {
                if buffer[i + 2..].starts_with(b"\r\n") {
                    return Some((i, i + 4));
                }
                if buffer[i + 2] == b'\n' {
                    return Some((i, i + 3));
                }
            }
            i += 1;
        }
        None
    }

    fn append_message_bytes(&mut self, data: &[u8]) {
        let remaining = MAX_DATA_BUFFER_SIZE.saturating_sub(self.data_buffer.len());
        let retained = remaining.min(data.len());
        if retained < data.len() {
            let first_truncation = !self.current_message_truncated;
            self.current_message_truncated = true;
            if first_truncation {
                warn!(
                    limit_bytes = MAX_DATA_BUFFER_SIZE,
                    dropped_bytes = data.len() - retained,
                    "SMTP message exceeded capture budget; verdict must remain inspection-incomplete"
                );
            }
        }
        if retained > 0 {
            self.data_buffer.extend_from_slice(&data[..retained]);
        }
    }

    fn append_pipelined_bytes(&mut self, data: &[u8]) {
        let buffer = self.pipelined_data.get_or_insert_with(Vec::new);
        let remaining = MAX_DATA_BUFFER_SIZE.saturating_sub(buffer.len());
        let retained = remaining.min(data.len());
        if retained < data.len() {
            let first_truncation = !self.current_message_truncated;
            self.current_message_truncated = true;
            if first_truncation {
                warn!(
                    limit_bytes = MAX_DATA_BUFFER_SIZE,
                    dropped_bytes = data.len() - retained,
                    "SMTP pipelined message exceeded capture budget; verdict must remain inspection-incomplete"
                );
            }
        }
        if retained > 0 {
            buffer.extend_from_slice(&data[..retained]);
        }
    }

    fn prepend_pipelined_bytes(&mut self, data: &[u8]) {
        let existing = self.pipelined_data.take().unwrap_or_default();
        let total_len = data.len().saturating_add(existing.len());
        if total_len > MAX_DATA_BUFFER_SIZE {
            self.current_message_truncated = true;
            warn!(
                limit_bytes = MAX_DATA_BUFFER_SIZE,
                total_len,
                "SMTP late-prepend pipelined message exceeded capture budget; verdict must remain inspection-incomplete"
            );
        }

        let retained_prefix = data.len().min(MAX_DATA_BUFFER_SIZE);
        let retained_existing = MAX_DATA_BUFFER_SIZE
            .saturating_sub(retained_prefix)
            .min(existing.len());
        let mut merged = Vec::with_capacity(retained_prefix + retained_existing);
        merged.extend_from_slice(&data[..retained_prefix]);
        merged.extend_from_slice(&existing[..retained_existing]);
        self.pipelined_data = Some(merged);
    }

    fn complete_message(&mut self, data: Bytes) {
        let is_complete = !std::mem::take(&mut self.current_message_truncated);
        self.completed_emails
            .push(CompletedSmtpMessage { data, is_complete });
    }

    fn prepend_bounded_message_bytes(&mut self, data: &[u8]) {
        let total_len = data.len().saturating_add(self.data_buffer.len());
        if total_len > MAX_DATA_BUFFER_SIZE {
            self.current_message_truncated = true;
            warn!(
                limit_bytes = MAX_DATA_BUFFER_SIZE,
                total_len,
                "SMTP late-prepend message exceeded capture budget; verdict must remain inspection-incomplete"
            );
        }

        let retained_prefix = data.len().min(MAX_DATA_BUFFER_SIZE);
        let retained_existing = MAX_DATA_BUFFER_SIZE
            .saturating_sub(retained_prefix)
            .min(self.data_buffer.len());
        let mut new_buffer = Vec::with_capacity(retained_prefix + retained_existing);
        new_buffer.extend_from_slice(&data[..retained_prefix]);
        new_buffer.extend_from_slice(&self.data_buffer[..retained_existing]);
        self.data_buffer = new_buffer;
    }

    fn begin_bdat_chunk(&mut self, size: usize, is_last: bool) {
        if self.data_buffer.is_empty() {
            self.current_message_truncated = false;
        }
        self.in_bdat_mode = true;
        self.bdat_remaining = size;
        self.bdat_is_last = is_last;
        self.bdat_chunk_start = self.data_buffer.len();
        self.state = SmtpState::Data;
    }

    fn process_bdat_payload(&mut self, data: &[u8]) -> SmallVec<[SmtpCommand; 4]> {
        let mut commands = SmallVec::new();
        let mut pos = 0usize;

        while self.in_bdat_mode {
            let available = data.len().saturating_sub(pos);
            let take = self.bdat_remaining.min(available);
            if take > 0 {
                self.append_message_bytes(&data[pos..pos + take]);
                self.bdat_remaining -= take;
                pos += take;
            }

            if self.bdat_remaining > 0 {
                break;
            }

            let is_last = self.bdat_is_last;
            self.in_bdat_mode = false;
            self.bdat_is_last = false;
            self.bdat_chunk_start = 0;

            if is_last {
                let raw = std::mem::take(&mut self.data_buffer);
                info!(
                    "📧📧📧 SMTP BDAT: emaildataReceivecomplete! largesmall: {} Byte, mail_from={:?}, rcpt_to={:?}",
                    raw.len(),
                    self.mail_from,
                    self.rcpt_to
                );
                self.complete_message(Bytes::from(raw));
                self.state = SmtpState::DataDone;
                commands.push(SmtpCommand::DataEnd);
            } else {
                self.state = SmtpState::RcptTo;
            }

            if pos < data.len() {
                commands.extend(self.parse_commands(&data[pos..]));
                break;
            }
        }

        commands
    }

    fn update_state_for_parsed_command(&mut self, cmd: &SmtpCommand) {
        match cmd {
            SmtpCommand::MailFrom(email) => {
                self.mail_from = Some(email.clone());
                self.rcpt_to.clear();
                self.state = SmtpState::MailFrom;
            }
            SmtpCommand::RcptTo(email) => {
                self.retain_recipient(email);
                self.state = SmtpState::RcptTo;
            }
            SmtpCommand::Reset => {
                self.mail_from = None;
                self.rcpt_to.clear();
                self.state = SmtpState::Greeted;
            }
            SmtpCommand::Quit => {
                self.state = SmtpState::Quit;
            }
            _ => {}
        }
    }

    fn flush_completed_data_buffer(&mut self) -> SmallVec<[SmtpCommand; 4]> {
        let mut commands = SmallVec::new();

        // Empty DATA: the client sent the dot terminator immediately after 354,
        // so the buffer starts with ".\r\n" and no preceding CRLF exists for the
        // regular terminator search. Treat a leading bare dot-line as the
        // terminator of an empty message, otherwise the connection would be
        // stuck in DATA mode forever.
        let terminator = Self::data_terminator(&self.data_buffer).or_else(|| {
            self.data_buffer
                .starts_with(b".\r\n")
                .then_some((0usize, 3usize))
        });
        let Some((pos, term_len)) = terminator else {
            return commands;
        };
        let is_empty_message = pos == 0 && term_len == 3;

        let raw = &self.data_buffer[..pos];

        if is_empty_message {
            debug!("📧 SMTP: 空 DATA 消息（354 后直接终结符），正常完结不产生邮件");
        } else {
            // SMTP smuggling split: surface every segment delimited by a bare-LF
            // dot-line variant as its own message so a hidden second email cannot
            // be silently absorbed into the first message's body.
            let mut segments: SmallVec<[(usize, usize); 2]> = SmallVec::new();
            let mut segment_start = 0usize;
            while let Some((variant_line, next_segment)) =
                Self::bare_lf_dot_line(raw, segment_start)
            {
                segments.push((segment_start, variant_line));
                segment_start = next_segment;
            }
            segments.push((segment_start, raw.len()));

            if segments.len() > 1 {
                warn!(
                    segments = segments.len(),
                    "⚠️ SMTP: 检测到裸 LF 走私变体（<LF>.<CR><LF>）— 额外切分出多段邮件分别解析"
                );
            }

            let messages: SmallVec<[Bytes; 2]> = segments
                .iter()
                // Adjacent variants can yield empty segments; skip them, but keep
                // the single-segment path byte-identical to the pre-split behavior.
                .filter(|&&(start, end)| end > start || segments.len() == 1)
                .map(|&(start, end)| Bytes::from(Self::dot_unstuff(&raw[start..end])))
                .collect();

            for email_data in messages {
                info!(
                    "📧📧📧 SMTP: emaildataReceivecomplete! largesmall: {} Byte, mail_from={:?}, rcpt_to={:?}",
                    email_data.len(),
                    self.mail_from,
                    self.rcpt_to
                );
                self.complete_message(email_data);
            }
        }

        let after_terminator = pos + term_len;
        let remaining = if after_terminator < self.data_buffer.len() {
            self.data_buffer[after_terminator..].to_vec()
        } else {
            Vec::new()
        };
        self.data_buffer.clear();
        self.in_data_mode = false;
        self.state = SmtpState::DataDone;
        commands.push(SmtpCommand::DataEnd);

        if !remaining.is_empty() {
            debug!(
                "📧 SMTP: 终止Mark后有 {} Byteremainingdata (Pipeline), 继续ParseCommand",
                remaining.len()
            );
            let pipelined = self.parse_commands(&remaining);
            for cmd in pipelined {
                self.update_state_for_parsed_command(&cmd);
                commands.push(cmd);
            }
        }

        commands
    }

    pub fn prepend_pending_client_data(&mut self, data: &[u8]) -> SmallVec<[SmtpCommand; 4]> {
        let mut commands = SmallVec::new();
        if data.is_empty() {
            return commands;
        }

        if self.in_bdat_mode {
            // Only the bytes still missing from this exact-size BDAT chunk belong to
            // the message. Any overflow is the next SMTP command (often another
            // BDAT or QUIT) and must be parsed after the chunk completes.
            let payload_len = data.len().min(self.bdat_remaining);
            let insert_at = self.bdat_chunk_start.min(self.data_buffer.len());
            let retained_payload_len =
                payload_len.min(MAX_DATA_BUFFER_SIZE.saturating_sub(self.data_buffer.len()));
            if retained_payload_len < payload_len {
                self.current_message_truncated = true;
            }
            let mut new_buffer = Vec::with_capacity(self.data_buffer.len() + retained_payload_len);
            new_buffer.extend_from_slice(&self.data_buffer[..insert_at]);
            new_buffer.extend_from_slice(&data[..retained_payload_len]);
            new_buffer.extend_from_slice(&self.data_buffer[insert_at..]);
            self.data_buffer = new_buffer;
            self.bdat_remaining -= payload_len;
            commands.extend(self.process_bdat_payload(&data[payload_len..]));
        } else if self.in_data_mode {
            self.prepend_bounded_message_bytes(data);
            commands.extend(self.flush_completed_data_buffer());
        } else if self.data_cmd_pending {
            self.prepend_pipelined_bytes(data);
        }

        commands
    }

    pub fn process_late_client_prepend(
        &mut self,
        prepend: &[u8],
        already_processed_suffix: &[u8],
    ) -> SmallVec<[SmtpCommand; 4]> {
        let saved_cmd_line_buf = std::mem::take(&mut self.cmd_line_buf);
        let was_pending = self.has_pending_data();
        let mut commands = if was_pending {
            self.prepend_pending_client_data(prepend)
        } else {
            self.process_client_data(prepend)
        };

        if !was_pending && self.has_pending_data() && !already_processed_suffix.is_empty() {
            self.cmd_line_buf.clear();
            commands.extend(self.process_client_data(already_processed_suffix));
        } else if !was_pending && !saved_cmd_line_buf.is_empty() {
            if self.cmd_line_buf.len() + saved_cmd_line_buf.len() <= 4096 {
                self.cmd_line_buf.extend_from_slice(&saved_cmd_line_buf);
            } else if self.cmd_line_buf.is_empty() {
                self.cmd_line_buf = saved_cmd_line_buf;
            }
        }

        commands
    }

    /// Extract any still-buffered email payload when the SMTP session closes before the
    /// normal DATA-end path fires. This recovers sessions where the message bytes are
    /// already present in memory, but the parser never observed a clean terminator or 354.
    pub fn take_pending_email_for_close(&mut self) -> Option<(Bytes, bool, bool)> {
        let pending = if !self.data_buffer.is_empty() {
            std::mem::take(&mut self.data_buffer)
        } else {
            self.pipelined_data.take()?
        };

        let terminator = memmem::find(&pending, b"\r\n.\r\n").map(|pos| (pos, 5usize));

        let raw = match terminator {
            Some((pos, _)) => &pending[..pos],
            None => pending.as_slice(),
        };

        self.in_data_mode = false;
        self.in_bdat_mode = false;
        self.bdat_remaining = 0;
        self.bdat_is_last = false;
        self.bdat_chunk_start = 0;
        self.data_cmd_pending = false;
        self.state = SmtpState::DataDone;
        self.pipelined_data = None;

        if raw.is_empty() {
            self.current_message_truncated = false;
            return None;
        }

        let is_complete =
            terminator.is_some() && !std::mem::take(&mut self.current_message_truncated);
        Some((
            Bytes::from(Self::dot_unstuff(raw)),
            terminator.is_some(),
            is_complete,
        ))
    }

    /// Processclientdata (Command emailContent)
    pub fn process_client_data(&mut self, data: &[u8]) -> SmallVec<[SmtpCommand; 4]> {
        let mut commands = SmallVec::new();

        // if STARTTLS already,data Encryptof, Parse
        if self.is_starttls_active {
            debug!("SMTP: STARTTLS already激活，hopsdataProcess");
            return commands;
        }

        trace!(
            "📤 SMTP process_client_data: in_data_mode={} | state={:?} | dataLength={}",
            self.in_data_mode,
            self.state,
            data.len(),
        );

        if self.in_bdat_mode {
            commands.extend(self.process_bdat_payload(data));
        } else if self.in_data_mode {
            // data mode: collect email content
            self.append_message_bytes(data);

            trace!(
                "📧 SMTP DATA mode: 收集data {} Byte, bufferDistrict总计: {} Byte",
                data.len(),
                self.data_buffer.len()
            );

            commands.extend(self.flush_completed_data_buffer());
        } else if self.data_cmd_pending {
            // DATA sent but 354 not yet received - buffer all client data as email body.
            // This handles the case where DATA and email body arrive in separate TCP packets.
            self.append_pipelined_bytes(data);
            debug!(
                "SMTP Pipeline: buffered {} bytes while waiting for 354 (total {})",
                data.len(),
                self.pipelined_data.as_ref().map_or(0, |b| b.len()),
            );
        } else {
            // Commandmode: Parse SMTP Command (Pipeline)
            commands = self.parse_commands(data);

            // CheckwhetherSend STARTTLS Command (Mark pending,waitServicehandler 220)
            for cmd in &commands {
                if matches!(cmd, SmtpCommand::StartTls) {
                    warn!("SMTP: Detected STARTTLS Command，Waiting for server确认...");
                    self.starttls_pending = true;
                }
            }
        }

        commands
    }

    /// Process server response data
    pub fn process_server_response(&mut self, data: &[u8]) -> SmallVec<[SmtpResponse; 4]> {
        let mut responses = SmallVec::new();

        trace!("SMTP process_server_response: {} bytes", data.len());

        // FIX #3: Prepend partial line from previous call
        let work_data: Vec<u8>;
        let effective_data = if !self.resp_line_buf.is_empty() {
            self.resp_line_buf.extend_from_slice(data);
            work_data = std::mem::take(&mut self.resp_line_buf);
            &work_data[..]
        } else {
            data
        };

        let has_trailing_newline = effective_data.last() == Some(&b'\n');
        let lines: Vec<&[u8]> = effective_data.split(|&b| b == b'\n').collect();
        let last_idx = lines.len().saturating_sub(1);

        for (idx, line) in lines.iter().enumerate() {
            let line = line.strip_suffix(b"\r").unwrap_or(line);

            // Last chunk without trailing \n - partial line, save for next call.
            // Cap at 4KB to prevent unbounded growth from TLS garbage.
            if idx == last_idx && !has_trailing_newline && !line.is_empty() {
                if line.len() <= 4096 {
                    self.resp_line_buf = line.to_vec();
                } else {
                    self.resp_line_buf.clear();
                }
                break;
            }

            if line.len() < 3 {
                continue;
            }

            // ParseResponseCode/Digit
            // Parse 3 bit ASCII ResponseCode/Digit (Avoid str Convert + parse)
            if line.len() >= 3
                && line[0].is_ascii_digit()
                && line[1].is_ascii_digit()
                && line[2].is_ascii_digit()
            {
                self.dialog_lines_observed = self.dialog_lines_observed.saturating_add(1);
                let code = (line[0] - b'0') as u16 * 100
                    + (line[1] - b'0') as u16 * 10
                    + (line[2] - b'0') as u16;
                let is_final = line.get(3) != Some(&b'-');

                trace!(
                    "📩 SMTP Response: code={} is_final={} current_state={:?}",
                    code, is_final, self.state
                );

                // UpdateStatus (possibly Authentication Command)
                if let Some(cmd) = self.handle_response_code(code) {
                    if self.pending_commands.len() < MAX_PENDING_COMMANDS {
                        self.pending_commands.push(cmd);
                    } else if !self.overflow_warned {
                        // Reuse the one-shot warn flag: both caps signal the
                        // same abusive-client condition for this session.
                        self.overflow_warned = true;
                        warn!(
                            limit = MAX_PENDING_COMMANDS,
                            "SMTP session exceeded the pending-command cap — further replayable commands are dropped"
                        );
                    }
                }

                responses.push(SmtpResponse { code, is_final });
            }
        }

        responses
    }

    /// according toResponseCode/DigitUpdateStatus,Returnpossibly ofCommand (ifAuthenticationResult)
    fn handle_response_code(&mut self, code: u16) -> Option<SmtpCommand> {
        match code {
            220 => {
                // Service (Used for STARTTLS)
                if self.starttls_pending {
                    // Servicehandler STARTTLS,found EncryptMark
                    warn!(
                        "⚠️ SMTP: ServiceDevice/Handler确认 STARTTLS (220)，后续Stream量将被Encrypt，无法 原emailContent"
                    );
                    self.is_starttls_active = true;
                    self.starttls_pending = false;
                } else {
                    self.state = SmtpState::Connected;
                }
                None
            }
            250 => {
                // OperationsSuccess
                match self.state {
                    SmtpState::Connected => self.state = SmtpState::Greeted,
                    SmtpState::MailFrom => self.state = SmtpState::RcptTo,
                    SmtpState::DataDone => {
                        // emailSendSuccess, 1
                        self.state = SmtpState::Greeted;
                    }
                    _ => {}
                }
                None
            }
            235 => {
                // AuthenticationSuccess
                self.state = SmtpState::Authenticated;
                self.auth_phase = AuthPhase::None;
                info!(
                    "🔑 SMTP AUTH AuthenticationSuccess: method={:?} username={:?}",
                    self.auth_method, self.auth_username
                );
                Some(SmtpCommand::AuthResult(true))
            }
            334 => {
                // ServicehandlerRequestAuthenticationdata
                match self.auth_phase {
                    AuthPhase::None => {
                        // AUTH Command,Servicehandler 334 Requestcredentials
                        if self.auth_method.as_deref() == Some("LOGIN") {
                            if self.auth_username.is_some() {
                                // userNamealready Method For (AUTH LOGIN <base64_username>)
                                self.auth_phase = AuthPhase::LoginWaitingPassword;
                                debug!(
                                    "🔑 SMTP AUTH LOGIN: userNamealready内联，waitWaitclientSendPassword"
                                );
                            } else {
                                self.auth_phase = AuthPhase::LoginWaitingUsername;
                                debug!("🔑 SMTP AUTH LOGIN: waitWaitclientSenduserName");
                            }
                        } else if self.auth_method.as_deref() == Some("PLAIN") {
                            self.auth_phase = AuthPhase::PlainWaiting;
                            debug!("🔑 SMTP AUTH PLAIN: waitWaitclientSendcredentials");
                        }
                    }
                    AuthPhase::LoginWaitingUsername => {
                        // userNamealreadySend,Servicehandler Time/Count 334 RequestPassword
                        self.auth_phase = AuthPhase::LoginWaitingPassword;
                        debug!(
                            "🔑 SMTP AUTH LOGIN: userNamealreadyReceived，waitWaitclientSendPassword"
                        );
                    }
                    AuthPhase::LoginWaitingPassword => {
                        // Occur
                    }
                    AuthPhase::PlainWaiting => {
                        // already waitWaitMedium
                    }
                }
                None
            }
            354 => {
                // StartemailInput - StatusConvert!
                if self.is_starttls_active {
                    warn!("📨 SMTP: Received 354 But STARTTLS already激活，hopsdata收集");
                // A 354 is only meaningful as the answer to a DATA command. A
                // forged/duplicate 354 must not enter DATA mode or clear the
                // buffered message body (response-injection wipe). Mid-stream
                // captures are the one exception: the DATA command was missed
                // together with the SYN, so the first lone 354 is still honored.
                } else if !self.data_cmd_pending
                    && !(self.midstream_capture && !self.in_data_mode)
                {
                    self.anomaly_count = self.anomaly_count.saturating_add(1);
                    warn!(
                        in_data_mode = self.in_data_mode,
                        buffered_bytes = self.data_buffer.len(),
                        anomaly_count = self.anomaly_count,
                        "⚠️ SMTP: Received 354 without pending DATA command; ignoring (possible response injection)"
                    );
                } else {
                    self.state = SmtpState::Data;
                    self.in_data_mode = true;
                    self.data_cmd_pending = false;
                    self.data_buffer.clear();

                    // Pipelinecache: DATA Command, 354 firstalready ofemaildata
                    if let Some(pipelined) = self.pipelined_data.take() {
                        info!(
                            "📨📨📨 SMTP: 354 Response! entering DATA mode + 重放 {} Byte���水线data | mail_from={:?} rcpt_to={:?}",
                            pipelined.len(),
                            self.mail_from,
                            self.rcpt_to
                        );
                        self.append_message_bytes(&pipelined);
                        let completed_cmds = self.flush_completed_data_buffer();
                        if !completed_cmds.is_empty() {
                            self.pending_commands.extend(completed_cmds);
                        }
                    } else {
                        info!(
                            "📨📨📨 SMTP: 354 Response! entering DATA mode | mail_from={:?} rcpt_to={:?}",
                            self.mail_from, self.rcpt_to
                        );
                    }
                }
                None
            }
            221 => {
                // ServiceClose
                self.state = SmtpState::Quit;
                None
            }
            535 => {
                // AuthenticationFailed
                self.auth_phase = AuthPhase::None;
                info!(
                    "🔑 SMTP AUTH AuthenticationFailed: method={:?} username={:?}",
                    self.auth_method, self.auth_username
                );
                Some(SmtpCommand::AuthResult(false))
            }
            _ => {
                if code >= 400 {
                    // 4xx/5xx: server rejected something - reset all pending states
                    if self.starttls_pending {
                        warn!(
                            "SMTP: server rejected STARTTLS ({}), continuing plaintext",
                            code
                        );
                        self.starttls_pending = false;
                    }
                    // DATA rejected (e.g. 503/550) - must clear data_cmd_pending
                    // otherwise all subsequent client data gets buffered as email body
                    if self.data_cmd_pending {
                        self.data_cmd_pending = false;
                        self.pipelined_data = None;
                    }
                    if self.in_bdat_mode {
                        self.in_bdat_mode = false;
                        self.bdat_remaining = 0;
                        self.bdat_is_last = false;
                        self.bdat_chunk_start = 0;
                        self.data_buffer.clear();
                    }
                    if self.auth_phase != AuthPhase::None {
                        self.auth_phase = AuthPhase::None;
                    }
                }
                None
            }
        }
    }

    /// Parse SMTP Command
    fn parse_commands(&mut self, data: &[u8]) -> SmallVec<[SmtpCommand; 4]> {
        let mut commands = SmallVec::new();

        // FIX #3: Prepend partial line from previous call
        let work_data: Vec<u8>;
        let effective_data = if !self.cmd_line_buf.is_empty() {
            self.cmd_line_buf.extend_from_slice(data);
            work_data = std::mem::take(&mut self.cmd_line_buf);
            &work_data[..]
        } else {
            data
        };

        // Tracking consumed byte offset for DATA command pipelining
        let mut offset = 0;
        let mut data_cmd_seen = false;
        let mut bdat_cmd_seen = false;

        // FIX #3: Check if data ends with incomplete line (no trailing \n)
        let has_trailing_newline = effective_data.last() == Some(&b'\n');

        for line in effective_data.split(|&b| b == b'\n') {
            offset += line.len() + 1;

            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }

            // Partial line (no trailing \n) - save for next call.
            // Cap at 4KB to prevent unbounded growth from TLS garbage or missing newlines.
            // An oversized line must NOT be dropped wholesale: the server is still
            // buffering the same logical line, so the bytes that follow belong to it.
            // Clearing the buffer let an attacker place a forged command exactly
            // where parsing resumed (envelope sender forgery). Keep the last 4KB so
            // the continuation stays glued to the junk tail and can never parse as
            // a fresh command, and count the anomaly instead.
            if !has_trailing_newline && offset > effective_data.len() {
                if line.len() <= 4096 {
                    self.cmd_line_buf = line.to_vec();
                } else {
                    self.anomaly_count = self.anomaly_count.saturating_add(1);
                    warn!(
                        anomaly_count = self.anomaly_count,
                        line_len = line.len(),
                        "⚠️ SMTP: 命令行超过 4KB 无换行，保留尾部 4KB 继续对齐（防信封归属伪造）"
                    );
                    self.cmd_line_buf = line[line.len() - 4096..].to_vec();
                }
                break;
            }

            // if AuthenticationStream Medium,priorityWhen AuthenticationdataProcess
            if self.auth_phase != AuthPhase::None
                && let Some(auth_cmd) = self.process_auth_data(line)
            {
                commands.push(auth_cmd);
                continue;
            }

            if let Some(cmd) = self.parse_single_command(line) {
                // Structured commands (not unrecognized "Other" lines) count as
                // legitimate SMTP dialog for the mid-stream TLS heuristic gate.
                if !matches!(cmd, SmtpCommand::Other(_)) {
                    self.dialog_lines_observed = self.dialog_lines_observed.saturating_add(1);
                }
                // UpdateInternalStatus
                match &cmd {
                    SmtpCommand::Auth(arg) => {
                        self.handle_auth_command(arg);
                        // if AUTH PLAIN credentials, immediately AuthCredential
                        if let Some(cred_cmd) = self.try_emit_credential() {
                            commands.push(cmd);
                            commands.push(cred_cmd);
                            continue;
                        }
                    }
                    SmtpCommand::MailFrom(email) => {
                        self.mail_from = Some(email.clone());
                        self.rcpt_to.clear();
                        self.data_buffer.clear();
                        self.pipelined_data = None;
                        self.current_message_truncated = false;
                        self.state = SmtpState::MailFrom;
                    }
                    SmtpCommand::RcptTo(email) => {
                        self.retain_recipient(email);
                        self.state = SmtpState::RcptTo;
                    }
                    SmtpCommand::Data => {
                        // SMTP Pipeline: DATA ofdata emailContent, Command
                        // cacheremainingdata,wait 354 Response
                        self.data_cmd_pending = true;
                        self.current_message_truncated = false;
                        commands.push(cmd);
                        data_cmd_seen = true;
                        break; // Parse line
                    }
                    SmtpCommand::Bdat { size, is_last } => {
                        self.begin_bdat_chunk(*size, *is_last);
                        commands.push(cmd);
                        bdat_cmd_seen = true;
                        break;
                    }
                    SmtpCommand::Reset => {
                        self.mail_from = None;
                        self.rcpt_to.clear();
                        self.state = SmtpState::Greeted;
                        self.auth_phase = AuthPhase::None;
                        self.pipelined_data = None;
                        self.data_cmd_pending = false;
                        self.in_bdat_mode = false;
                        self.bdat_remaining = 0;
                        self.bdat_is_last = false;
                        self.bdat_chunk_start = 0;
                        self.data_buffer.clear();
                        self.current_message_truncated = false;
                    }
                    SmtpCommand::Quit => {
                        self.state = SmtpState::Quit;
                    }
                    _ => {}
                }
                commands.push(cmd);
            }
        }

        // DATA command: cache remaining data as pipelined email body.
        // Use effective_data (which includes cmd_line_buf prefix) not original data.
        if data_cmd_seen && offset < effective_data.len() {
            let remaining = &effective_data[offset..];
            if !remaining.is_empty() {
                info!(
                    "📧 SMTP Pipeline: DATA 后cache {} Byteemaildata (waitWait 354)",
                    remaining.len()
                );
                self.pipelined_data = None;
                self.append_pipelined_bytes(remaining);
            }
        }

        if bdat_cmd_seen {
            let remaining = if offset < effective_data.len() {
                &effective_data[offset..]
            } else {
                &[]
            };
            commands.extend(self.process_bdat_payload(remaining));
        }

        commands
    }

    /// Process AUTH CommandParameter,SetAuthenticationStatus
    fn handle_auth_command(&mut self, arg: &str) {
        let parts: Vec<&str> = arg.splitn(2, ' ').collect();
        let method = parts[0].to_uppercase();
        // Clear ALL auth state before starting new attempt - prevents credential leakage
        // from a previous failed AUTH into the current one
        self.auth_method = Some(method.clone());
        self.auth_username = None;
        self.auth_password = None;
        self.auth_phase = AuthPhase::None;

        match method.as_str() {
            "PLAIN" => {
                if parts.len() > 1 && !parts[1].is_empty() {
                    // AUTH PLAIN <base64> - credentials
                    self.decode_auth_plain(parts[1]);
                } else {
                    // AUTH PLAIN (credentials,Waiting for server 334 Send)
                    self.auth_phase = AuthPhase::PlainWaiting;
                }
                debug!("🔑 SMTP AUTH PLAIN Command: inline={}", parts.len() > 1);
            }
            "LOGIN" => {
                if parts.len() > 1 && !parts[1].is_empty() {
                    // AUTH LOGIN <base64_username> - client userName
                    if let Some(username) = Self::decode_base64_string(parts[1]) {
                        self.auth_username = Some(username);
                        // userNamealready,Waiting for server 334 Password
                        // auth_phase Keep None,ByServicehandler 334 Response LoginWaitingPassword
                    }
                }
                // auth_phase Keep None,Waiting for server 334 Status
                debug!("🔑 SMTP AUTH LOGIN Command");
            }
            _ => {
                // CRAM-MD5, XOAUTH2 wait Method,
                debug!("🔑 SMTP AUTH {} Command (不支持credentials 原)", method);
            }
        }
    }

    /// ProcessAuthentication Segmentofclientdata (base64 EncodeofuserName/Password)
    fn process_auth_data(&mut self, line: &[u8]) -> Option<SmtpCommand> {
        let line_str = std::str::from_utf8(line).ok()?.trim();
        if line_str.is_empty() || line_str == "*" {
            // clientCancelAuthentication
            self.auth_phase = AuthPhase::None;
            return None;
        }

        match self.auth_phase {
            AuthPhase::PlainWaiting => {
                // Received AUTH PLAIN ofcredentialsdata
                self.decode_auth_plain(line_str);
                self.auth_phase = AuthPhase::None;
                self.try_emit_credential()
            }
            AuthPhase::LoginWaitingUsername => {
                // Received AUTH LOGIN ofuserName (base64)
                if let Some(username) = Self::decode_base64_string(line_str) {
                    debug!("🔑 SMTP AUTH LOGIN userNamealreadyDecode: {}", username);
                    self.auth_username = Some(username);
                    // Keep LoginWaitingUsername Status,waitServicehandler 1 334 LoginWaitingPassword
                } else {
                    self.auth_phase = AuthPhase::None;
                }
                None
            }
            AuthPhase::LoginWaitingPassword => {
                // Received AUTH LOGIN ofPassword (base64)
                if let Some(password) = Self::decode_base64_string(line_str) {
                    debug!("🔑 SMTP AUTH LOGIN PasswordalreadyDecode");
                    self.auth_password = Some(password);
                    self.auth_phase = AuthPhase::None;
                    return self.try_emit_credential();
                } else {
                    self.auth_phase = AuthPhase::None;
                }
                None
            }
            AuthPhase::None => None,
        }
    }

    /// Decode AUTH PLAIN credentials: base64(\0username\0password)
    fn decode_auth_plain(&mut self, encoded: &str) {
        if let Some(decoded) = Self::decode_base64_bytes(encoded) {
            // AUTH PLAIN: \0username\0password authzid\0username\0password
            let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
            match parts.len() {
                3 => {
                    // authzid\0username\0password
                    self.auth_username = std::str::from_utf8(parts[1]).ok().map(|s| s.to_string());
                    self.auth_password = std::str::from_utf8(parts[2]).ok().map(|s| s.to_string());
                }
                2 => {
                    // username\0password (Standardimplementation)
                    self.auth_username = std::str::from_utf8(parts[0]).ok().map(|s| s.to_string());
                    self.auth_password = std::str::from_utf8(parts[1]).ok().map(|s| s.to_string());
                }
                _ => {}
            }
        }
    }

    /// AuthCredential Command (WhenuserNameAndPasswordallalreadyDecode)
    fn try_emit_credential(&self) -> Option<SmtpCommand> {
        let method = self.auth_method.as_ref()?;
        let username = self.auth_username.as_ref()?;
        // Passwordpossibly Butstored
        let password = self.auth_password.clone().unwrap_or_default();
        Some(SmtpCommand::AuthCredential {
            method: method.clone(),
            username: username.clone(),
            password,
        })
    }

    /// Base64 Decode Byte
    fn decode_base64_bytes(encoded: &str) -> Option<Vec<u8>> {
        const DECODE_TABLE: [i8; 256] = {
            let mut table = [-1i8; 256];
            let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut i = 0;
            while i < 64 {
                table[chars[i] as usize] = i as i8;
                i += 1;
            }
            table[b'=' as usize] = 0;
            table
        };

        let data = encoded.as_bytes();
        let mut output = Vec::with_capacity(data.len() * 3 / 4);
        let mut buffer = 0u32;
        let mut bits = 0u8;

        for &byte in data {
            if byte == b'=' {
                break;
            }
            if byte.is_ascii_whitespace() {
                continue;
            }
            let value = DECODE_TABLE[byte as usize];
            if value < 0 {
                return None; // Invalidcharacters
            }
            buffer = (buffer << 6) | (value as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                output.push((buffer >> bits) as u8);
                buffer &= (1 << bits) - 1;
            }
        }

        Some(output)
    }

    /// Base64 Decode UTF-8 String
    fn decode_base64_string(encoded: &str) -> Option<String> {
        let bytes = Self::decode_base64_bytes(encoded)?;
        String::from_utf8(bytes).ok()
    }

    /// Parse Command (Allocate: Use case-insensitive Vec largewrite)
    fn parse_single_command(&mut self, line: &[u8]) -> Option<SmtpCommand> {
        // EHLO / HELO (5+ bytes)
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"EHLO ") {
            let arg = std::str::from_utf8(&line[5..]).ok()?.trim().to_string();
            return Some(SmtpCommand::Greeting(arg));
        }
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"HELO ") {
            let arg = std::str::from_utf8(&line[5..]).ok()?.trim().to_string();
            return Some(SmtpCommand::Greeting(arg));
        }

        // AUTH (5+ bytes)
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"AUTH ") {
            let arg = std::str::from_utf8(&line[5..]).ok()?.trim().to_string();
            return Some(SmtpCommand::Auth(arg));
        }

        // STARTTLS (8 bytes, no argument). Do not accept prefix-smuggled
        // variants such as STARTTLSNOW.
        if line.len() >= 8
            && line[..8].eq_ignore_ascii_case(b"STARTTLS")
            && (line.len() == 8 || line[8..].iter().all(|b| b.is_ascii_whitespace()))
        {
            return Some(SmtpCommand::StartTls);
        }

        // MAIL FROM: (10 bytes prefix) - Use bufferDistrict largewritefirst 10 Byte
        if line.len() >= 10 {
            let mut prefix = [0u8; 10];
            prefix.copy_from_slice(&line[..10]);
            prefix.make_ascii_uppercase();
            if &prefix == b"MAIL FROM:" {
                let rest = &line[10..];
                if let Some(email) = Self::extract_email(rest) {
                    return Some(SmtpCommand::MailFrom(email));
                }
            }
        }

        // RCPT TO: (8 bytes prefix) - Use bufferDistrict largewritefirst 8 Byte
        if line.len() >= 8 {
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&line[..8]);
            prefix.make_ascii_uppercase();
            if &prefix == b"RCPT TO:" {
                let rest = &line[8..];
                if let Some(email) = Self::extract_email(rest) {
                    return Some(SmtpCommand::RcptTo(email));
                }
            }
        }

        if let Some((size, is_last)) = Self::parse_bdat_args(line) {
            return Some(SmtpCommand::Bdat { size, is_last });
        }

        // matchshortCommand (4 bytes,)
        if line.len() >= 4 {
            let cmd_part = &line[..4];
            let trailing_ok = line.len() == 4 || line[4..].iter().all(|b| b.is_ascii_whitespace());
            if trailing_ok {
                if cmd_part.eq_ignore_ascii_case(b"DATA") {
                    return Some(SmtpCommand::Data);
                }
                if cmd_part.eq_ignore_ascii_case(b"RSET") {
                    return Some(SmtpCommand::Reset);
                }
                if cmd_part.eq_ignore_ascii_case(b"QUIT") {
                    return Some(SmtpCommand::Quit);
                }
            } else {
                // Lenient-MTA tolerance: some servers accept junk arguments or
                // padding after DATA / RSET / QUIT and still answer 354 / 221.
                // Rejecting such a line desyncs us from the server: the 354 is
                // then refused (no pending DATA) and the whole message body is
                // parsed as unknown commands — a fully delivered email with
                // zero detection. Recognize the verb when the tail starts with
                // whitespace and stays printable ASCII, and count the anomaly.
                // Binary tails (TLS garbage) and glued verbs (DATAX) stay
                // `Other`. STARTTLS intentionally remains strict: falsely
                // marking the stream encrypted blinds capture, which is worse
                // than mis-parsing a rejected command.
                let printable_tail = line[4].is_ascii_whitespace()
                    && line[4..]
                        .iter()
                        .all(|b| b.is_ascii_whitespace() || b.is_ascii_graphic());
                if printable_tail {
                    let recognized = if cmd_part.eq_ignore_ascii_case(b"DATA") {
                        Some(SmtpCommand::Data)
                    } else if cmd_part.eq_ignore_ascii_case(b"RSET") {
                        Some(SmtpCommand::Reset)
                    } else if cmd_part.eq_ignore_ascii_case(b"QUIT") {
                        Some(SmtpCommand::Quit)
                    } else {
                        None
                    };
                    if let Some(cmd) = recognized {
                        self.anomaly_count = self.anomaly_count.saturating_add(1);
                        warn!(
                            anomaly_count = self.anomaly_count,
                            "⚠️ SMTP: 短命令携带非法参数（宽容 MTA 仍可能受理），按命令识别并计 anomaly"
                        );
                        return Some(cmd);
                    }
                }
            }
        }

        // Command
        let cmd_str = std::str::from_utf8(line).ok()?.trim().to_string();
        if !cmd_str.is_empty() {
            Some(SmtpCommand::Other(cmd_str))
        } else {
            None
        }
    }

    fn parse_bdat_args(line: &[u8]) -> Option<(usize, bool)> {
        let line = std::str::from_utf8(line).ok()?.trim();
        let mut parts = line.split_ascii_whitespace();
        let cmd = parts.next()?;
        if !cmd.eq_ignore_ascii_case("BDAT") {
            return None;
        }

        let size_str = parts.next()?;
        if !size_str.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let size: usize = size_str.parse().ok()?;

        let mut is_last = false;
        for part in parts {
            if part.eq_ignore_ascii_case("LAST") && !is_last {
                is_last = true;
            } else {
                return None;
            }
        }
        if size == 0 && !is_last {
            return None;
        }

        Some((size, is_last))
    }

    /// FromStringMediumExtractemailAddress
    fn extract_email(data: &[u8]) -> Option<String> {
        // lookup <email>
        let start = memchr::memchr(b'<', data)?;
        let end = memchr::memchr(b'>', &data[start + 1..])?;
        let email_bytes = &data[start + 1..start + 1 + end];

        // MAIL FROM:<> (null sender / bounce) -> Return None
        // session.mail_from Keep None, From emailHeader
        if email_bytes.is_empty() {
            return None;
        }

        // VerifyemailAddress
        if email_bytes.len() > 256 {
            return None;
        }

        if email_bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"@.-_+".contains(&b))
        {
            std::str::from_utf8(email_bytes).ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// SMTP: dot-stuffing (RFC 5321 4.5.2)
    ///
    /// SIMD Add: Use memchr bit line,Batch extend_from_slice,
    /// "\n.." hops of '.'. ByteIterate 20-30x.
    fn dot_unstuff(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut copy_start = 0;

        // Processdata Header (line_start=true): if ".." Header hopsAfter1 '.'
        if data.len() >= 2 && data[0] == b'.' && data[1] == b'.' {
            result.push(b'.');
            copy_start = 2;
        }

        // SIMD line bit
        for pos in memchr::memchr_iter(b'\n', data) {
            // Batch line (Contains line)
            result.extend_from_slice(&data[copy_start..=pos]);
            let after = pos + 1;
            // Check line whether ".." (dot-stuffed line)
            if after + 1 < data.len() && data[after] == b'.' && data[after + 1] == b'.' {
                result.push(b'.');
                copy_start = after + 2;
            } else {
                copy_start = after;
            }
        }

        // remainingdata
        if copy_start < data.len() {
            result.extend_from_slice(&data[copy_start..]);
        }

        result
    }

    /// Getalreadycompleteofemaildata
    pub fn take_completed_emails(&mut self) -> Vec<Bytes> {
        self.take_completed_messages()
            .into_iter()
            .map(|message| message.data)
            .collect()
    }

    /// Return completed messages together with their inspection-completeness
    /// state. Production consumers should use this method instead of dropping
    /// the truncation signal.
    pub fn take_completed_messages(&mut self) -> Vec<CompletedSmtpMessage> {
        std::mem::take(&mut self.completed_emails)
    }

    /// GetWhenfirst Receiveofemaildata (Used forDebug)
    #[allow(dead_code)]
    pub fn current_data_buffer(&self) -> &[u8] {
        &self.data_buffer
    }

    /// Status (Used forNewConnection)
    #[allow(dead_code)]
    pub fn reset(&mut self) {
        self.state = SmtpState::Connected;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.in_data_mode = false;
        self.data_cmd_pending = false;
        self.completed_emails.clear();
        self.current_message_truncated = false;
        self.is_starttls_active = false;
        self.starttls_pending = false;
        self.auth_phase = AuthPhase::None;
        self.auth_method = None;
        self.auth_username = None;
        self.auth_password = None;
        self.pending_commands.clear();
        self.cmd_line_buf.clear();
        self.resp_line_buf.clear();
    }

    /// Get ByServicehandlerResponse ofWaitProcessCommand (if AuthResult, AuthCredential)
    pub fn take_pending_commands(&mut self) -> SmallVec<[SmtpCommand; 2]> {
        std::mem::take(&mut self.pending_commands)
    }
}

impl Default for SmtpStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m5_rcpt_to_is_capped_at_ten_thousand_and_counted() {
        // PoC (M-5): a mirrored client floods RCPT TO to grow retained
        // session memory unboundedly (≈280MB from ≈30MB on the wire).
        let mut sm = SmtpStateMachine::new();
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"MAIL FROM:<a@example.com>\r\n");
        for i in 0..(MAX_RCPT_TO + 25) {
            sm.process_client_data(format!("RCPT TO:<u{i}@example.com>\r\n").as_bytes());
        }
        assert_eq!(sm.rcpt_to().len(), MAX_RCPT_TO, "cap must hold");
        assert_eq!(sm.dropped_rcpt_to(), 25, "dropped entries must be counted");
    }

    #[test]
    fn m5_direct_state_update_uses_the_same_recipient_cap() {
        let mut sm = SmtpStateMachine::new();
        for i in 0..(MAX_RCPT_TO + 1) {
            sm.update_state_for_parsed_command(&SmtpCommand::RcptTo(format!(
                "u{i}@example.com"
            )));
        }
        assert_eq!(sm.rcpt_to().len(), MAX_RCPT_TO);
        assert_eq!(sm.dropped_rcpt_to(), 1);
    }

    #[test]
    fn test_smtp_flow() {
        let mut sm = SmtpStateMachine::new();

        // EHLO
        let cmds = sm.process_client_data(b"EHLO client.example.com\r\n");
        assert_eq!(cmds.len(), 1);
        assert!(matches!(&cmds[0], SmtpCommand::Greeting(s) if s == "client.example.com"));

        // ServicehandlerResponse
        sm.process_server_response(b"250 OK\r\n");
        assert_eq!(sm.state(), SmtpState::Greeted);

        // MAIL FROM
        let cmds = sm.process_client_data(b"MAIL FROM:<sender@example.com>\r\n");
        assert_eq!(cmds.len(), 1);
        assert!(matches!(&cmds[0], SmtpCommand::MailFrom(s) if s == "sender@example.com"));
        assert_eq!(sm.mail_from(), Some("sender@example.com"));

        // RCPT TO
        let cmds = sm.process_client_data(b"RCPT TO:<recipient@example.com>\r\n");
        assert_eq!(cmds.len(), 1);
        assert_eq!(sm.rcpt_to(), &["recipient@example.com"]);

        // DATA
        let cmds = sm.process_client_data(b"DATA\r\n");
        assert!(matches!(&cmds[0], SmtpCommand::Data));

        // Servicehandler 354
        sm.process_server_response(b"354 Start mail input\r\n");
        assert!(sm.is_in_data_mode());

        // emailContent
        sm.process_client_data(b"From: sender@example.com\r\n");
        sm.process_client_data(b"To: recipient@example.com\r\n");
        sm.process_client_data(b"Subject: Test\r\n");
        sm.process_client_data(b"\r\n");
        sm.process_client_data(b"Hello World!\r\n");

        // emailEnd
        let cmds = sm.process_client_data(b".\r\n");
        assert!(cmds.iter().any(|c| matches!(c, SmtpCommand::DataEnd)));
        assert!(!sm.is_in_data_mode());

        // CheckemailContent
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        let email_str = std::str::from_utf8(&emails[0]).unwrap();
        assert!(email_str.contains("Subject: Test"));
        assert!(email_str.contains("Hello World!"));
    }

    #[test]
    fn test_auth_plain_inline() {
        let mut sm = SmtpStateMachine::new();

        sm.process_server_response(b"220 smtp.example.com ESMTP\r\n");
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250-smtp.example.com\r\n250 AUTH PLAIN LOGIN\r\n");

        // AUTH PLAIN with inline base64: \0user@example.com\0mypassword
        // base64("\0user@example.com\0mypassword") = "AHVzZXJAZXhhbXBsZS5jb20AbXlwYXNzd29yZA=="
        let cmds =
            sm.process_client_data(b"AUTH PLAIN AHVzZXJAZXhhbXBsZS5jb20AbXlwYXNzd29yZA==\r\n");

        // Should have Auth + AuthCredential
        let cred = cmds
            .iter()
            .find(|c| matches!(c, SmtpCommand::AuthCredential { .. }));
        assert!(cred.is_some(), "Should have AuthCredential command");
        if let Some(SmtpCommand::AuthCredential {
            method,
            username,
            password,
        }) = cred
        {
            assert_eq!(method, "PLAIN");
            assert_eq!(username, "user@example.com");
            assert_eq!(password, "mypassword");
        }
    }

    #[test]
    fn test_auth_login_flow() {
        let mut sm = SmtpStateMachine::new();

        sm.process_server_response(b"220 smtp.example.com ESMTP\r\n");
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250 AUTH LOGIN PLAIN\r\n");

        // AUTH LOGIN
        let cmds = sm.process_client_data(b"AUTH LOGIN\r\n");
        assert!(cmds.iter().any(|c| matches!(c, SmtpCommand::Auth(..))));

        // Server requests username (334 VXNlcm5hbWU6 = "Username:")
        sm.process_server_response(b"334 VXNlcm5hbWU6\r\n");

        // Client sends base64 username: "user@example.com" = "dXNlckBleGFtcGxlLmNvbQ=="
        let cmds = sm.process_client_data(b"dXNlckBleGFtcGxlLmNvbQ==\r\n");
        assert!(
            cmds.is_empty()
                || !cmds
                    .iter()
                    .any(|c| matches!(c, SmtpCommand::AuthCredential { .. })),
            "Should not have credential yet (waiting for password)"
        );

        // Server requests password (334 UGFzc3dvcmQ6 = "Password:")
        sm.process_server_response(b"334 UGFzc3dvcmQ6\r\n");

        // Client sends base64 password: "mypassword" = "bXlwYXNzd29yZA=="
        let cmds = sm.process_client_data(b"bXlwYXNzd29yZA==\r\n");
        let cred = cmds
            .iter()
            .find(|c| matches!(c, SmtpCommand::AuthCredential { .. }));
        assert!(
            cred.is_some(),
            "Should have AuthCredential command after password"
        );
        if let Some(SmtpCommand::AuthCredential {
            method,
            username,
            password,
        }) = cred
        {
            assert_eq!(method, "LOGIN");
            assert_eq!(username, "user@example.com");
            assert_eq!(password, "mypassword");
        }

        // Server confirms authentication
        sm.process_server_response(b"235 2.7.0 Authentication successful\r\n");
        let pending = sm.take_pending_commands();
        assert!(
            pending
                .iter()
                .any(|c| matches!(c, SmtpCommand::AuthResult(true)))
        );
        assert_eq!(sm.state(), SmtpState::Authenticated);
    }

    #[test]
    fn test_auth_plain_split() {
        let mut sm = SmtpStateMachine::new();

        sm.process_server_response(b"220 smtp.example.com ESMTP\r\n");
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250 AUTH PLAIN\r\n");

        // AUTH PLAIN without inline credentials
        sm.process_client_data(b"AUTH PLAIN\r\n");

        // Server asks for credentials
        sm.process_server_response(b"334\r\n");

        // Client sends base64 credentials
        let cmds = sm.process_client_data(b"AHVzZXJAZXhhbXBsZS5jb20AbXlwYXNzd29yZA==\r\n");
        let cred = cmds
            .iter()
            .find(|c| matches!(c, SmtpCommand::AuthCredential { .. }));
        assert!(
            cred.is_some(),
            "Should have AuthCredential after split PLAIN"
        );
        if let Some(SmtpCommand::AuthCredential {
            method,
            username,
            password,
        }) = cred
        {
            assert_eq!(method, "PLAIN");
            assert_eq!(username, "user@example.com");
            assert_eq!(password, "mypassword");
        }
    }

    #[test]
    fn test_base64_decode() {
        // "Hello" = "SGVsbG8="
        assert_eq!(
            SmtpStateMachine::decode_base64_string("SGVsbG8="),
            Some("Hello".to_string())
        );
        // Empty string
        assert_eq!(
            SmtpStateMachine::decode_base64_string(""),
            Some(String::new())
        );
        // AUTH PLAIN format: \0user\0pass
        let decoded = SmtpStateMachine::decode_base64_bytes("AHVzZXIAcGFzcw==");
        assert!(decoded.is_some());
        let bytes = decoded.unwrap();
        assert_eq!(bytes, b"\0user\0pass");
    }

    #[test]
    fn test_command_line_split_across_packets() {
        let mut sm = SmtpStateMachine::new();

        let first = sm.process_client_data(b"MAIL FROM:<sender");
        assert!(first.is_empty());

        let second = sm.process_client_data(b"@example.com>\r\nRCPT TO:<rcpt@example.com>\r\n");

        assert_eq!(second.len(), 2);
        assert!(matches!(&second[0], SmtpCommand::MailFrom(addr) if addr == "sender@example.com"));
        assert!(matches!(&second[1], SmtpCommand::RcptTo(addr) if addr == "rcpt@example.com"));
        assert_eq!(sm.mail_from(), Some("sender@example.com"));
        assert_eq!(sm.rcpt_to(), &["rcpt@example.com"]);
    }

    #[test]
    fn test_response_line_split_across_packets() {
        let mut sm = SmtpStateMachine::new();

        let first = sm.process_server_response(b"250-smtp.example.com");
        assert!(first.is_empty());

        let second = sm.process_server_response(b"\r\n250 OK\r\n");

        assert_eq!(second.len(), 2);
        assert_eq!(second[0].code, 250);
        assert!(!second[0].is_final);
        assert_eq!(second[1].code, 250);
        assert!(second[1].is_final);
    }

    #[test]
    fn test_data_rejection_clears_pending_pipelined_body() {
        let mut sm = SmtpStateMachine::new();

        let cmds =
            sm.process_client_data(b"DATA\r\nSubject: should-not-be-buffered\r\n\r\nbody\r\n.\r\n");
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Data)));
        assert!(sm.has_pending_data());
        assert!(sm.buffered_email_bytes() > 0);

        sm.process_server_response(b"503 5.5.1 Need RCPT command first\r\n");

        assert!(!sm.has_pending_data());
        assert_eq!(sm.buffered_email_bytes(), 0);

        let next = sm.process_client_data(b"MAIL FROM:<fresh@example.com>\r\n");
        assert!(matches!(&next[0], SmtpCommand::MailFrom(addr) if addr == "fresh@example.com"));
    }

    #[test]
    fn test_starttls_prefix_smuggling_is_not_accepted() {
        let mut sm = SmtpStateMachine::new();

        let cmds = sm.process_client_data(b"STARTTLSNOW\r\nSTARTTLS \t\r\n");

        assert!(matches!(&cmds[0], SmtpCommand::Other(cmd) if cmd == "STARTTLSNOW"));
        assert!(matches!(&cmds[1], SmtpCommand::StartTls));
    }

    #[test]
    fn test_starttls_acceptance_suppresses_plaintext_after_upgrade() {
        let mut sm = SmtpStateMachine::new();

        let cmds = sm.process_client_data(b"STARTTLS\r\n");
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::StartTls)));
        sm.process_server_response(b"220 2.0.0 Ready to start TLS\r\n");

        assert!(sm.is_encrypted());
        let plaintext_after_tls = sm.process_client_data(b"MAIL FROM:<hidden@example.com>\r\n");
        assert!(plaintext_after_tls.is_empty());
    }

    #[test]
    fn test_bdat_last_restores_email() {
        let mut sm = SmtpStateMachine::new();
        let body = b"Subject: BDAT\r\n\r\nhello via chunking";
        let mut input = format!(
            "MAIL FROM:<sender@example.com>\r\nRCPT TO:<rcpt@example.com>\r\nBDAT {} LAST\r\n",
            body.len()
        )
        .into_bytes();
        input.extend_from_slice(body);
        input.extend_from_slice(b"QUIT\r\n");

        let cmds = sm.process_client_data(&input);

        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Bdat { size, is_last } if *size == body.len() && *is_last)));
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::DataEnd)));
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Quit)));
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        assert_eq!(&emails[0][..], body);
    }

    #[test]
    fn test_bdat_multi_chunk_restores_email() {
        let mut sm = SmtpStateMachine::new();
        let first = b"Subject: Multi\r\n\r\n";
        let second = b"chunk body";
        let mut input = format!("BDAT {}\r\n", first.len()).into_bytes();
        input.extend_from_slice(first);

        let cmds = sm.process_client_data(&input);
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Bdat { size, is_last } if *size == first.len() && !*is_last)));
        assert!(sm.take_completed_emails().is_empty());
        assert!(!sm.has_pending_data());

        let mut last = format!("BDAT {} LAST\r\n", second.len()).into_bytes();
        last.extend_from_slice(second);
        let cmds = sm.process_client_data(&last);

        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::DataEnd)));
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        let mut expected = first.to_vec();
        expected.extend_from_slice(second);
        assert_eq!(&emails[0][..], expected.as_slice());
    }

    #[test]
    fn test_bdat_command_split_from_payload() {
        let mut sm = SmtpStateMachine::new();
        let body = b"Subject: Split\r\n\r\npayload";

        let cmds = sm.process_client_data(format!("BDAT {} LAST\r\n", body.len()).as_bytes());
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Bdat { size, is_last } if *size == body.len() && *is_last)));
        assert!(sm.is_in_data_mode());
        assert!(sm.has_pending_data());

        let cmds = sm.process_client_data(body);
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::DataEnd)));
        let emails = sm.take_completed_emails();
        assert_eq!(&emails[0][..], body);
    }

    #[test]
    fn test_bdat_late_prepend_keeps_prior_chunks_and_parses_overflow_command() {
        let mut sm = SmtpStateMachine::new();

        let cmds = sm.process_client_data(b"BDAT 5\r\nprior");
        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            SmtpCommand::Bdat {
                size: 5,
                is_last: false
            }
        )));

        let cmds = sm.process_client_data(b"BDAT 3 LAST\r\nBC");
        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            SmtpCommand::Bdat {
                size: 3,
                is_last: true
            }
        )));
        assert!(sm.has_pending_data());

        // `A` precedes the already processed `BC`; QUIT follows the exact three-byte
        // BDAT payload and must not be absorbed into the message.
        let cmds = sm.prepend_pending_client_data(b"AQUIT\r\n");

        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::DataEnd)));
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Quit)));
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        assert_eq!(&emails[0][..], b"priorABC");
    }

    #[test]
    fn test_bdat_zero_last_completes_empty_message() {
        let mut sm = SmtpStateMachine::new();

        let cmds = sm.process_client_data(b"BDAT 0 LAST\r\nQUIT\r\n");

        assert!(cmds.iter().any(|cmd| matches!(
            cmd,
            SmtpCommand::Bdat {
                size: 0,
                is_last: true
            }
        )));
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::DataEnd)));
        assert!(cmds.iter().any(|cmd| matches!(cmd, SmtpCommand::Quit)));
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        assert!(emails[0].is_empty());
    }

    #[test]
    fn test_data_bare_lf_dot_lf_is_not_accepted_as_terminator() {
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\nSubject: LF only\n\nbody\n.\nQUIT\n");
        sm.process_server_response(b"354 Start mail input\r\n");

        assert!(sm.take_completed_emails().is_empty());
        assert!(sm.has_pending_data());
        let (raw, had_terminator, complete) = sm
            .take_pending_email_for_close()
            .expect("pending DATA should be recoverable on close");
        assert!(!had_terminator);
        assert!(!complete);
        assert!(std::str::from_utf8(&raw).unwrap().contains("\n.\nQUIT\n"));
    }

    #[test]
    fn test_data_bare_lf_smuggling_variant_splits_hidden_second_message() {
        // PoC bypass (R3A): legacy MTAs (old Postfix, unpatched Exchange)
        // accept `<LF>.<CR><LF>` as the end of DATA. The bytes between that
        // variant and the real `\r\n.\r\n` terminator form a hidden second
        // message that used to be silently absorbed into the first message's
        // body, losing all structured analysis. Both segments must surface.
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 Start mail input\r\n");

        sm.process_client_data(
            b"Subject: first\r\n\r\nfirst body\n.\r\nSubject: hidden\r\n\r\nhidden payload\r\n.\r\n",
        );

        let emails = sm.take_completed_emails();
        assert_eq!(
            emails.len(),
            2,
            "smuggling variant must split the hidden message out"
        );
        let first = std::str::from_utf8(&emails[0]).unwrap();
        let second = std::str::from_utf8(&emails[1]).unwrap();
        assert!(first.contains("Subject: first"));
        assert!(first.contains("first body"));
        assert!(!first.contains("hidden payload"));
        assert!(second.contains("Subject: hidden"));
        assert!(second.contains("hidden payload"));
        assert!(!sm.has_pending_data());
    }

    #[test]
    fn test_data_bare_lf_dot_lf_variant_before_real_terminator_also_splits() {
        // `<LF>.<LF>` variant followed later by the real CRLF terminator:
        // still a parser differential against lenient downstreams, so split.
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 Start mail input\r\n");
        sm.process_client_data(b"body one\n.\nsecond segment\r\n.\r\n");

        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 2);
        assert_eq!(std::str::from_utf8(&emails[0]).unwrap(), "body one");
        assert_eq!(std::str::from_utf8(&emails[1]).unwrap(), "second segment");
    }

    #[test]
    fn test_normal_crlf_message_is_not_split() {
        // Guard: an ordinary CRLF-only message must still produce exactly one
        // completed email (no false-positive smuggling split).
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 Start mail input\r\n");
        sm.process_client_data(b"Subject: normal\r\n\r\nline1\r\nline2\r\n.\r\n");

        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        let text = std::str::from_utf8(&emails[0]).unwrap();
        assert!(text.contains("line1\r\nline2"));
    }

    #[test]
    fn test_data_buffer_is_bounded_and_marked_incomplete() {
        let mut sm = SmtpStateMachine::new();
        sm.in_data_mode = true;
        sm.append_message_bytes(&vec![b'a'; MAX_DATA_BUFFER_SIZE + 1]);

        assert_eq!(sm.buffered_email_bytes(), MAX_DATA_BUFFER_SIZE);
        let (raw, had_terminator, complete) = sm
            .take_pending_email_for_close()
            .expect("bounded prefix should remain available for analysis");

        assert_eq!(raw.len(), MAX_DATA_BUFFER_SIZE);
        assert!(!had_terminator);
        assert!(!complete);
    }

    #[test]
    fn test_take_pending_email_for_close_unstuffs_and_marks_complete() {
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\nSubject: Close Recovery\r\n\r\n..leading dot\r\n.\r\n");

        let (raw, had_terminator, complete) = sm
            .take_pending_email_for_close()
            .expect("pending DATA should be recoverable on close");

        assert!(had_terminator);
        assert!(complete);
        assert_eq!(
            std::str::from_utf8(&raw).unwrap(),
            "Subject: Close Recovery\r\n\r\n.leading dot"
        );
        assert!(!sm.has_pending_data());
    }

    #[test]
    fn test_take_pending_email_for_close_recovers_incomplete_pipelined_body() {
        let mut sm = SmtpStateMachine::new();

        sm.process_client_data(b"DATA\r\nSubject: Incomplete\r\n\r\npartial body");

        let (raw, had_terminator, complete) = sm
            .take_pending_email_for_close()
            .expect("pipelined DATA should be recoverable on close");

        assert!(!had_terminator);
        assert!(!complete);
        assert_eq!(
            std::str::from_utf8(&raw).unwrap(),
            "Subject: Incomplete\r\n\r\npartial body"
        );
        assert!(!sm.has_pending_data());
    }

    /// Build a session that completed DATA handshake and entered DATA mode.
    fn smtp_machine_in_data_mode() -> SmtpStateMachine {
        let mut sm = SmtpStateMachine::new();
        sm.process_server_response(b"220 smtp.example.com ESMTP\r\n");
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"MAIL FROM:<sender@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"RCPT TO:<recipient@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        assert!(sm.is_in_data_mode());
        sm
    }

    #[test]
    fn test_forged_second_354_does_not_wipe_buffered_body() {
        let mut sm = smtp_machine_in_data_mode();

        // 4 KB of message prefix already buffered when the forged 354 arrives.
        let prefix = vec![b'X'; 4096];
        let mut body = prefix.clone();
        body.extend_from_slice(b"\r\nSubject: payment instruction\r\n\r\nfirst half\r\n");
        sm.process_client_data(&body);

        // Injected server response: previously this cleared data_buffer.
        sm.process_server_response(b"354 injected by on-path attacker\r\n");
        assert_eq!(sm.anomaly_count(), 1, "forged 354 must be counted");
        assert!(sm.is_in_data_mode(), "forged 354 must not leave DATA mode");

        sm.process_client_data(b"second half\r\n.\r\n");
        let messages = sm.take_completed_messages();
        assert_eq!(messages.len(), 1);
        let data = &messages[0].data;
        assert!(
            data.len() >= 4096,
            "buffered prefix must survive the forged 354"
        );
        assert_eq!(&data[..4096], &prefix[..]);
        let text = std::str::from_utf8(data).unwrap();
        assert!(text.contains("Subject: payment instruction"));
        assert!(text.contains("first half"));
        assert!(text.contains("second half"));
    }

    #[test]
    fn test_unsolicited_354_without_data_command_is_ignored() {
        let mut sm = SmtpStateMachine::new();
        sm.process_server_response(b"220 smtp.example.com ESMTP\r\n");
        sm.process_client_data(b"EHLO client.example.com\r\n");
        sm.process_server_response(b"250 OK\r\n");

        // 354 without any DATA command: must not enter DATA mode.
        sm.process_server_response(b"354 Go ahead\r\n");
        assert!(!sm.is_in_data_mode());
        assert_eq!(sm.anomaly_count(), 1);

        // A subsequent real DATA flow still works.
        sm.process_client_data(b"MAIL FROM:<sender@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"RCPT TO:<recipient@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        assert!(sm.is_in_data_mode());
        sm.process_client_data(b"Subject: legit\r\n\r\nbody\r\n.\r\n");
        let messages = sm.take_completed_messages();
        assert_eq!(messages.len(), 1);
        assert!(String::from_utf8_lossy(&messages[0].data).contains("Subject: legit"));
    }

    #[test]
    fn test_midstream_capture_honors_first_lone_354_but_not_second() {
        let mut sm = SmtpStateMachine::new();
        sm.set_midstream_capture(true);

        // Capture started after DATA was sent: the lone 354 is honored once.
        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        assert!(sm.is_in_data_mode());
        assert_eq!(sm.anomaly_count(), 0);

        // A second 354 mid-DATA is still an anomaly and keeps the buffer.
        sm.process_client_data(b"Subject: midstream\r\n\r\npartial");
        sm.process_server_response(b"354 forged\r\n");
        assert_eq!(sm.anomaly_count(), 1);
        assert!(sm.is_in_data_mode());

        sm.process_client_data(b" rest\r\n.\r\n");
        let messages = sm.take_completed_messages();
        assert_eq!(messages.len(), 1);
        let text = String::from_utf8_lossy(&messages[0].data).into_owned();
        assert!(text.contains("Subject: midstream"));
        assert!(text.contains("partial"));
    }

    #[test]
    fn test_empty_data_terminator_at_buffer_start_completes() {
        let mut sm = smtp_machine_in_data_mode();

        // Client immediately terminates DATA with an empty message: the buffer
        // starts with ".\r\n" and the regular "\r\n.\r\n" search never matches.
        let cmds = sm.process_client_data(b".\r\n");
        assert!(
            !sm.is_in_data_mode(),
            "empty DATA must not stick the session in data mode"
        );
        assert!(cmds.iter().any(|c| matches!(c, SmtpCommand::DataEnd)));
        assert!(
            sm.take_completed_messages().is_empty(),
            "empty DATA must not fabricate an empty email"
        );

        // The connection stays usable: a following message parses normally.
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"MAIL FROM:<second@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"RCPT TO:<recipient@example.com>\r\n");
        sm.process_server_response(b"250 OK\r\n");
        sm.process_client_data(b"DATA\r\n");
        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        sm.process_client_data(b"Subject: second message\r\n\r\nreal body\r\n.\r\n");
        let messages = sm.take_completed_messages();
        assert_eq!(messages.len(), 1);
        assert!(String::from_utf8_lossy(&messages[0].data).contains("Subject: second message"));
    }

    #[test]
    fn test_normal_data_terminator_after_empty_line_still_works() {
        // Regression guard: a message ending with an empty line then "." must
        // still complete via the regular "\r\n.\r\n" path.
        let mut sm = smtp_machine_in_data_mode();
        sm.process_client_data(b"Subject: normal\r\n\r\nbody line\r\n.\r\n");
        let messages = sm.take_completed_messages();
        assert_eq!(messages.len(), 1);
        assert!(String::from_utf8_lossy(&messages[0].data).contains("body line"));
    }

    #[test]
    fn test_data_with_trailing_whitespace_enters_data_mode() {
        // Guard: `DATA` followed by whitespace-only padding was already
        // accepted; keep it that way and make sure the message flows.
        let mut sm = SmtpStateMachine::new();
        sm.process_client_data(b"MAIL FROM:<sender@example.com>\r\n");
        sm.process_client_data(b"RCPT TO:<rcpt@example.com>\r\n");
        let cmds = sm.process_client_data(b"DATA \t\r\n");
        assert!(cmds.iter().any(|c| matches!(c, SmtpCommand::Data)));
        assert_eq!(sm.anomaly_count(), 0, "whitespace padding is not an anomaly");
        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        assert!(sm.is_in_data_mode());
        sm.process_client_data(b"Subject: padded\r\n\r\nbody\r\n.\r\n");
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1);
        assert!(String::from_utf8_lossy(&emails[0]).contains("Subject: padded"));
    }

    #[test]
    fn test_data_with_lenient_arguments_still_enters_data_mode_with_anomaly() {
        // PoC bypass (R5-F1): lenient MTAs accept `DATA x` and answer 354, but
        // the sniffer used to classify the line as `Other`, so the 354 was
        // refused (no pending DATA) and the entire message body was parsed as
        // unknown commands — a fully delivered phishing email with zero
        // engine contact. The verb must be recognized and the anomaly counted.
        let mut sm = SmtpStateMachine::new();
        sm.process_client_data(b"MAIL FROM:<phish@evil.example>\r\n");
        sm.process_client_data(b"RCPT TO:<victim@corp.example>\r\n");
        let cmds = sm.process_client_data(b"DATA 1\r\n");
        assert!(
            cmds.iter().any(|c| matches!(c, SmtpCommand::Data)),
            "lenient `DATA <arg>` must be recognized as DATA"
        );
        assert!(
            sm.anomaly_count() >= 1,
            "argument-bearing DATA must be counted as anomaly"
        );

        sm.process_server_response(b"354 End data with <CR><LF>.<CR><LF>\r\n");
        assert!(sm.is_in_data_mode(), "354 after lenient DATA must be honored");
        sm.process_client_data(
            b"Subject: your account will be suspended\r\n\r\nverify now\r\n.\r\n",
        );
        let emails = sm.take_completed_emails();
        assert_eq!(emails.len(), 1, "message must reach the engine");
        let text = String::from_utf8_lossy(&emails[0]);
        assert!(text.contains("your account will be suspended"));
        assert!(text.contains("verify now"));
    }

    #[test]
    fn test_short_command_with_binary_tail_is_not_recognized() {
        // Guard: the lenient tail must stay printable — TLS-record bytes after
        // a DATA-looking prefix must keep falling into `Other`.
        let mut sm = SmtpStateMachine::new();
        let cmds = sm.process_client_data(b"DATA \x16\x03\x01\r\nDATAX\r\n");
        assert!(cmds.iter().all(|c| matches!(c, SmtpCommand::Other(_))));
        assert!(!sm.has_pending_data());
    }

    #[test]
    fn test_oversized_command_line_keeps_tail_alignment_and_blocks_forged_envelope() {
        // PoC bypass (R5-F1): a >4KB partial command line used to be dropped
        // wholesale while the server kept buffering the same logical line. The
        // attacker placed a forged `MAIL FROM` exactly where the sniffer
        // resumed, so the sniffer attributed the session to a sender the
        // server never saw as a command. The tail must now stay glued.
        let mut sm = SmtpStateMachine::new();

        let mut junk = b"MAIL FROM:<real-sender@attacker.example> ".to_vec();
        junk.extend_from_slice(&[b'A'; 4080]); // one logical line, >4KB, no newline yet
        let first = sm.process_client_data(&junk);
        assert!(first.is_empty(), "incomplete line must not emit commands");
        assert!(
            sm.anomaly_count() >= 1,
            "oversized line retention must be counted as anomaly"
        );

        // Same logical line continues; the forged command must merge with the
        // retained junk tail and never parse as a standalone envelope command.
        let second = sm.process_client_data(b"MAIL FROM:<forged@attacker.example>\r\nQUIT\r\n");
        assert!(
            !second.iter().any(|c| matches!(c, SmtpCommand::MailFrom(_))),
            "forged MAIL FROM inside the oversized line must not be parsed"
        );
        assert!(
            sm.mail_from().is_none(),
            "no envelope sender may be fabricated from mid-line bytes"
        );
        // The session realigns once the logical line finally terminates.
        assert!(second.iter().any(|c| matches!(c, SmtpCommand::Quit)));
    }
}
