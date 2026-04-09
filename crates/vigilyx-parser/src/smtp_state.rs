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

/// SMTP State machine
pub struct SmtpStateMachine {
   /// WhenfirstStatus
    state: SmtpState,
   /// Sender
    mail_from: Option<String>,
   /// recipientList
    rcpt_to: Vec<String>,
   /// emaildatabufferDistrict
    data_buffer: Vec<u8>,
   /// emaildatawhether Receive
    in_data_mode: bool,
   /// alreadycompleteofemaildataList (1ConnectionpossiblySend email)
    completed_emails: Vec<Bytes>,
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
}

impl SmtpStateMachine {
    pub fn new() -> Self {
        Self {
            state: SmtpState::Connected,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::with_capacity(64 * 1024), // 64KB Capacity
            in_data_mode: false,
            completed_emails: Vec::new(),
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

   /// Whether in data collection mode
    pub fn is_in_data_mode(&self) -> bool {
        self.in_data_mode
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
        self.in_data_mode || self.data_cmd_pending
    }

   /// Best-effort buffered email bytes not yet turned into a completed MIME message.
    pub fn buffered_email_bytes(&self) -> usize {
        self.data_buffer.len() + self.pipelined_data.as_ref().map_or(0, Vec::len)
    }

    fn data_terminator(buffer: &[u8]) -> Option<(usize, usize)> {
        memmem::find(buffer, b"\r\n.\r\n")
            .map(|pos| (pos, 5usize))
            .or_else(|| memmem::find(buffer, b"\n.\n").map(|pos| (pos, 3usize)))
    }

    fn update_state_for_parsed_command(&mut self, cmd: &SmtpCommand) {
        match cmd {
            SmtpCommand::MailFrom(email) => {
                self.mail_from = Some(email.clone());
                self.rcpt_to.clear();
                self.state = SmtpState::MailFrom;
            }
            SmtpCommand::RcptTo(email) => {
                self.rcpt_to.push(email.clone());
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

        let Some((pos, term_len)) = Self::data_terminator(&self.data_buffer) else {
            return commands;
        };

        let raw = &self.data_buffer[..pos];
        let unstuffed = Self::dot_unstuff(raw);
        let email_data = Bytes::from(unstuffed);
        info!(
            "📧📧📧 SMTP: emaildataReceivecomplete! largesmall: {} Byte, mail_from={:?}, rcpt_to={:?}",
            email_data.len(),
            self.mail_from,
            self.rcpt_to
        );
        self.completed_emails.push(email_data);

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

        if self.in_data_mode {
            let mut new_buffer = Vec::with_capacity(data.len() + self.data_buffer.len());
            new_buffer.extend_from_slice(data);
            new_buffer.extend_from_slice(&self.data_buffer);
            self.data_buffer = new_buffer;
            commands.extend(self.flush_completed_data_buffer());
        } else if self.data_cmd_pending {
            let mut new_buffer =
                Vec::with_capacity(data.len() + self.pipelined_data.as_ref().map_or(0, Vec::len));
            new_buffer.extend_from_slice(data);
            if let Some(existing) = self.pipelined_data.take() {
                new_buffer.extend_from_slice(&existing);
            }
            self.pipelined_data = Some(new_buffer);
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
    pub fn take_pending_email_for_close(&mut self) -> Option<(Bytes, bool)> {
        let pending = if !self.data_buffer.is_empty() {
            std::mem::take(&mut self.data_buffer)
        } else {
            self.pipelined_data.take()?
        };

        let terminator = memmem::find(&pending, b"\r\n.\r\n")
            .map(|pos| (pos, 5usize))
            .or_else(|| memmem::find(&pending, b"\n.\n").map(|pos| (pos, 3usize)));

        let raw = match terminator {
            Some((pos, _)) => &pending[..pos],
            None => pending.as_slice(),
        };

        self.in_data_mode = false;
        self.data_cmd_pending = false;
        self.state = SmtpState::DataDone;
        self.pipelined_data = None;

        if raw.is_empty() {
            return None;
        }

        Some((Bytes::from(Self::dot_unstuff(raw)), terminator.is_some()))
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

        if self.in_data_mode {
           // data mode: collect email content
            if self.data_buffer.len() + data.len() > MAX_DATA_BUFFER_SIZE {
                warn!(
                    "SMTP: emaildata超 {}MB limit，截Break/JudgeProcess",
                    MAX_DATA_BUFFER_SIZE / 1024 / 1024
                );
                let remaining = MAX_DATA_BUFFER_SIZE.saturating_sub(self.data_buffer.len());
                if remaining > 0 {
                    self.data_buffer.extend_from_slice(&data[..remaining]);
                }
            } else {
                self.data_buffer.extend_from_slice(data);
            }

            trace!(
                "📧 SMTP DATA mode: 收集data {} Byte, bufferDistrict总计: {} Byte",
                data.len(),
                self.data_buffer.len()
            );

            commands.extend(self.flush_completed_data_buffer());
        } else if self.data_cmd_pending {
           // DATA sent but 354 not yet received - buffer all client data as email body.
           // This handles the case where DATA and email body arrive in separate TCP packets.
            match self.pipelined_data {
                Some(ref mut buf) => {
                    buf.extend_from_slice(data);
                }
                None => {
                    self.pipelined_data = Some(data.to_vec());
                }
            }
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
                    self.pending_commands.push(cmd);
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
                if !self.is_starttls_active {
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
                        self.data_buffer.extend_from_slice(&pipelined);
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
                } else {
                    warn!("📨 SMTP: Received 354 But STARTTLS already激活，hopsdata收集");
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
            if !has_trailing_newline && offset > effective_data.len() {
                if line.len() <= 4096 {
                    self.cmd_line_buf = line.to_vec();
                } else {
                    self.cmd_line_buf.clear(); // oversized - likely TLS garbage, discard
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
                        self.state = SmtpState::MailFrom;
                    }
                    SmtpCommand::RcptTo(email) => {
                        self.rcpt_to.push(email.clone());
                        self.state = SmtpState::RcptTo;
                    }
                    SmtpCommand::Data => {
                       // SMTP Pipeline: DATA ofdata emailContent, Command
                       // cacheremainingdata,wait 354 Response
                        self.data_cmd_pending = true;
                        commands.push(cmd);
                        data_cmd_seen = true;
                        break; // Parse line
                    }
                    SmtpCommand::Reset => {
                        self.mail_from = None;
                        self.rcpt_to.clear();
                        self.state = SmtpState::Greeted;
                        self.auth_phase = AuthPhase::None;
                        self.pipelined_data = None;
                        self.data_cmd_pending = false;
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
                self.pipelined_data = Some(remaining.to_vec());
            }
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
    fn parse_single_command(&self, line: &[u8]) -> Option<SmtpCommand> {
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

       // STARTTLS (8 bytes)
        if line.len() >= 8 && line[..8].eq_ignore_ascii_case(b"STARTTLS") {
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
}
