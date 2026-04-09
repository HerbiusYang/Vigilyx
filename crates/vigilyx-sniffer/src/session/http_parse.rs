//! HTTP data security (DLP) and login credential extraction.

use super::*;
use super::http_helpers::{
    extract_coremail_account_from_body, extract_form_credentials, extract_sid_from_uri,
    extract_socketio_auth_user, extract_user_from_cookie, write_body_temp_file,
};
use crate::capture::RawpacketInfo;
use crate::stream::TcpSegment;
use std::sync::atomic::Ordering;
use std::time::Instant;
use tracing::{debug, info, warn};
use vigilyx_core::{Direction, HttpSession, SessionStatus, SmtpAuthInfo};

impl ShardedSessionManager {
   /// Extract WaitPublishof HTTP Session (dataSecuritydetect)
    pub fn take_http_sessions(&self) -> Vec<HttpSession> {
        let mut sessions = Vec::new();
        while let Some(session) = self.http_session_queue.pop() {
            sessions.push(session);
        }
       // BatchUpdatecounter (Time/Count CAS N Time/Count fetch_sub)
        let drained = sessions.len() as u64;
        if drained > 0 {
            let _ = self
                .http_queue_len
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(drained))
                });
        }
        sessions
    }

   /// Comment retained in English.
   /// Processoutbound POST/PUT Request, construct `HttpSession` ObjectFor DataSecurityEngine Analyze.
   /// detectRange: Save, FileUpload, emailSendwait webmail Operations.
   /// Use TCP stream reassemblyParse HTTP Request (dataSecuritydetect)
   /// Comment retained in English.
   /// TCP SegmentaddStreambuffer -> State machinesplitcomplete requests -> construct HttpSession
   /// of traffic, HTTP keep-alive Request
    pub(super) fn parse_http_data_security(&self, session_data: &mut Sessiondata, packet: &RawpacketInfo) {
       // ProcessoutboundRequest (client -> Servicehandler ofdatapacket)
        if packet.direction != Direction::Outbound {
           // packet dataSecuritydetect (Normalline, drop)
            return;
        }

       // packethops (TCP ACK wait packet)
        if packet.payload.is_empty() {
            return;
        }

       // HTTP pipeline: Validoutboundpacketcount
        self.stats
            .http_pipeline
            .http_packets_outbound
            .fetch_add(1, Ordering::Relaxed);

       // TCP Constant
        const TCP_FIN: u8 = 0x01;
        const TCP_RST: u8 = 0x04;

       // 1. TCP SegmentaddStreambuffer (Reuse SMTP Same1 TcpHalfStream)
        let segment = TcpSegment {
            seq: packet.tcp_seq,
            data: packet.payload.clone(),
            is_fin: (packet.tcp_flags & TCP_FIN) != 0,
            is_rst: (packet.tcp_flags & TCP_RST) != 0,
            timestamp: Instant::now(),
        };

        if session_data.client_stream.add_segment(segment).is_err() {
           // HTTP pipeline: Stream buffer overflow - data loss!
            self.stats
                .http_pipeline
                .http_stream_overflow
                .fetch_add(1, Ordering::Relaxed);
            warn!(
                session_id = %session_data.session.id,
                client_ip = %session_data.session.client_ip,
                server_ip = %session_data.session.server_ip,
                server_port = session_data.session.server_port,
                payload_len = packet.payload.len(),
                "HTTP dataSecurity\u{4e22}packet: TCP Streambuffer\u{6ea2}\u{51fa} (65MB \u{4e0a}\u{9650})"
            );
            return;
        }

       // 2. GetalreadyreassembleofcontiguousStreamdata
        let stream_has_gaps = session_data.client_stream.gap_bytes_skipped > 0;
        let reassembled = session_data.client_stream.get_data();
        if reassembled.is_empty() {
            return;
        }

       // 3. Use HTTP State machineFromStreamMediumsplitcomplete requests
        let http_state = match &mut session_data.http_state {
            Some(state) => state,
            None => return,
        };

        let requests = http_state.process_stream(reassembled);
        if requests.is_empty() {
            return;
        }

       // HTTP pipeline: RecordingParse ofRequest
        self.stats
            .http_pipeline
            .http_requests_parsed
            .fetch_add(requests.len() as u64, Ordering::Relaxed);

       // 4. Eachcomplete requestsconstruct HttpSession
        for req in &requests {
           // dataSecurityonlyfocus onwriteOperations (POST/PUT)
            if req.method != vigilyx_core::HttpMethod::Post
                && req.method != vigilyx_core::HttpMethod::Put
            {
                self.stats
                    .http_pipeline
                    .http_requests_skipped_method
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let mut http_session = HttpSession::new(
                session_data.session.client_ip.clone(),
                session_data.session.client_port,
                session_data.session.server_ip.clone(),
                session_data.session.server_port,
                req.method,
                req.uri.clone(),
            );

            http_session.host = req.host.clone();
            http_session.content_type = req.content_type.clone();
            http_session.network_session_id = Some(session_data.session.id);
            http_session.has_gaps = stream_has_gaps;

           // ExtractRequest (Fromreassemble ofStreamMediumAccording to)
            if req.body_length > 0 {
                let body_end = req.body_offset + req.body_length;
                if body_end <= reassembled.len() {
                    let body = &reassembled[req.body_offset..body_end];
                    http_session.request_body_size = body.len();

                   // Body storage strategy:
                   // <= 256KB -> Memory (request_body)
                   // > 256KB -> writedisktempFile (body_temp_file)
                    const BODY_MEMORY_THRESHOLD: usize = 256 * 1024;

                    if body.len() > BODY_MEMORY_THRESHOLD {
                       // large body -> writetempFile
                        match write_body_temp_file(&http_session.id, body) {
                            Ok(path) => {
                                http_session.body_temp_file = Some(path);
                                debug!(body_size = body.len(), "HTTP body write\u{5165}tempFile");
                            }
                            Err(e) => {
                                warn!("HTTP body writetempFile\u{5931}\u{8d25}: {}", e);
                               // Downgrade: truncate stored in memory
                                let cap = body.len().min(16384);
                                http_session.request_body =
                                    String::from_utf8_lossy(&body[..cap]).into_owned().into();
                            }
                        }
                    }

                   // 1) Magic byte detect (only needs first few hundred bytes)
                    let detected = vigilyx_core::magic_bytes::detect_file_type(body);
                    http_session.detected_file_type = detected;

                   // 2) determinewhether2Base/Radix
                   // Content-Type TextType,override magic bytes misclassified
                   // (Coremail of text/x-json Contains GBK Chinese characters may be misclassified as UnknownBinary)
                    let ct_is_text = req
                        .content_type
                        .as_ref()
                        .map(|ct| {
                            let ct = ct.to_ascii_lowercase();
                            ct.starts_with("text/")
                                || ct.contains("json")
                                || ct.contains("xml")
                                || ct.contains("javascript")
                                || ct.contains("x-www-form-urlencoded")
                        })
                        .unwrap_or(false);
                    let is_binary = if ct_is_text {
                        false
                    } else {
                        detected.map(|ft| !ft.is_text_scannable()).unwrap_or(false)
                    };
                    http_session.body_is_binary = is_binary;

                   // 3) Small body -> store in request_body (if notwritetempFile)
                   // immediately 2Base/Radix lossy Convertstore, SecurityAnalyze
                    if http_session.body_temp_file.is_none() {
                        let cap = body.len().min(16384);
                        http_session.request_body =
                            String::from_utf8_lossy(&body[..cap]).into_owned().into();
                    }

                   // ExtractUploadFileInfo (multipart/form-data)
                    if let Some(ref ct) = req.content_type
                        && ct.contains("multipart/form-data")
                        && let Some((filename, size)) =
                            crate::parser::http::extract_multipart_file_info(ct, body)
                    {
                        http_session.uploaded_filename = Some(filename);
                        http_session.uploaded_file_size = Some(size);
                    }

                   // CheckFileType extensionwhethermatch
                    if let (Some(ft), Some(filename)) = (
                        http_session.detected_file_type,
                        &http_session.uploaded_filename,
                    ) {
                        http_session.file_type_mismatch =
                            vigilyx_core::magic_bytes::check_extension_mismatch(ft, filename);
                    }

                   // Extract sender/recipient (Used forself-senddetect)
                    let (sender, recipients) = crate::parser::http::extract_email_fields(body);
                    http_session.detected_sender = sender;
                    http_session.detected_recipients = recipients;
                }
            }

           // Extract user identifier - multi-source priority:
           // 1. Cookie Segmentmatch (uid, username, coremail_uid wait)
           // 2. socket.io auth message learns sid -> user mapping
           // 3. Coremail body Mediumof account Segment (compose)
            if let Some(ref cookie) = req.cookie {
                http_session.detected_user = extract_user_from_cookie(cookie);
            }

           // Learn sid -> user mapping from body
            if let Some(ref body) = http_session.request_body {
               // Method 1: socket.io auth Message
                if let Some(user) = extract_socketio_auth_user(body)
                    && let Some(sid) = extract_sid_from_uri(&req.uri)
                {
                    self.sid_user_insert(sid, user.clone());
                    if http_session.detected_user.is_none() {
                        http_session.detected_user = Some(user);
                    }
                }
               // Method 2: Coremail compose body Mediumof attrs.account
                if http_session.detected_user.is_none()
                    && let Some(user) = extract_coremail_account_from_body(body)
                {
                    if let Some(sid) = extract_sid_from_uri(&req.uri) {
                        self.sid_user_insert(sid, user.clone());
                    }
                    http_session.detected_user = Some(user);
                }
            }

           // Cookie did not extract user -> sid -> user Mappingtable (LRU Updateaccesstimestamp)
            if http_session.detected_user.is_none()
                && let Some(sid) = extract_sid_from_uri(&req.uri)
                && let Some(user) = self.sid_user_get(&sid)
            {
                http_session.detected_user = Some(user);
            }

           // LRU eviction (keep recent 40K items, delete oldest)
            self.sid_user_evict_lru();

            info!(
                session_id = %http_session.id,
                network_session_id = ?http_session.network_session_id,
                uri = %req.uri,
                method = ?req.method,
                host = ?req.host,
                body_size = req.body_length,
                client_ip = %session_data.session.client_ip,
                server_ip = %session_data.session.server_ip,
                "HTTP dataSecurity: Capturecomplete POST/PUT Request (stream reassembly)"
            );

           // Capacity limit: prevent infinite queue growth when consumer is slower than producer
            let queue_depth = self.http_queue_len.load(Ordering::Relaxed);
            if queue_depth >= HTTP_SESSION_QUEUE_CAPACITY as u64 {
               // HTTP pipeline: Queuefulldrop - dataSecurity !
                self.stats
                    .http_pipeline
                    .http_sessions_dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                warn!(
                    queue_depth = queue_depth,
                    capacity = HTTP_SESSION_QUEUE_CAPACITY,
                    session_id = %http_session.id,
                    uri = %req.uri,
                    client_ip = %session_data.session.client_ip,
                    body_size = req.body_length,
                    "HTTP dataSecurity\u{4f1a}\u{8bdd}drop! Queue\u{5df2}full (Engine\u{8f7d})"
                );
            } else {
               // HTTP pipeline: successfully queued
                self.stats
                    .http_pipeline
                    .http_sessions_queued
                    .fetch_add(1, Ordering::Relaxed);
                self.http_queue_len.fetch_add(1, Ordering::Relaxed);
                self.http_session_queue.push(http_session);
            }
        }
    }

   // ============================================
   // HTTP Login detection
   // ============================================

   /// Parse HTTP datapacket, detect webmail Loginline
    pub(super) fn parse_http_login(&self, session_data: &mut Sessiondata, packet: &RawpacketInfo) {
        let payload = &packet.payload;
        if payload.len() < 16 {
            return;
        }

        match packet.direction {
            Direction::Outbound => {
               // Client request: detect POST login form
                if session_data.session.auth_info.is_some() {
                    return; // already extracted credentials
                }
                if !payload.starts_with(b"POST ") {
                    return;
                }
               // find HTTP body (CRLF delimited)
                if let Some(body_start) = memchr::memmem::find(payload, b"\r\n\r\n") {
                    let body = &payload[body_start + 4..];
                    if let Some((username, password)) = extract_form_credentials(body) {
                        info!(
                            "\u{1f511} HTTP Login detection: {} -> {}:{} | user={}",
                            session_data.session.client_ip,
                            session_data.session.server_ip,
                            session_data.session.server_port,
                            username
                        );
                        session_data.session.auth_info = Some(SmtpAuthInfo {
                            auth_method: "HTTP_FORM".to_string(),
                            username: Some(username),
                            password: Some(password),
                            auth_success: None, // waitResponsedetermine
                        });
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                    }
                }
            }
            Direction::Inbound => {
               // ServicehandlerResponse: determineLoginSuccess/failed
                if let Some(ref mut auth) = session_data.session.auth_info {
                    if auth.auth_success.is_some() {
                        return; // alreadydetermine
                    }
                    if payload.starts_with(b"HTTP/1.1 302")
                        || payload.starts_with(b"HTTP/1.0 302")
                        || payload.starts_with(b"HTTP/1.1 303")
                        || payload.starts_with(b"HTTP/1.0 303")
                    {
                        auth.auth_success = Some(true); // = LoginSuccess
                    } else if payload.starts_with(b"HTTP/1.1 401")
                        || payload.starts_with(b"HTTP/1.0 401")
                        || payload.starts_with(b"HTTP/1.1 403")
                        || payload.starts_with(b"HTTP/1.0 403")
                    {
                        auth.auth_success = Some(false); // Authenticationfailed
                    } else if payload.starts_with(b"HTTP/1.1 200")
                        || payload.starts_with(b"HTTP/1.0 200")
                    {
                        auth.auth_success = Some(true); // 200 OK = possiblySuccess
                    }

                   // HTTP Session WeekdayPeriodshort, ReceivedResponseimmediatelycomplete
                    if auth.auth_success.is_some() {
                        session_data.session.status = SessionStatus::Completed;
                        session_data.session.ended_at = Some(chrono::Utc::now());
                        self.decrement_active_session_if_needed(
                            &mut session_data.active_counter_open,
                        );
                        if !session_data.dirty {
                            session_data.dirty = true;
                            self.dirty_queue.push(session_data.key.clone());
                        }
                    }
                }
            }
        }
    }
}
