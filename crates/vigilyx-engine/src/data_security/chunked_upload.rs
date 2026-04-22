//! Coremail chunked upload reassembly module.
//!
//! Coremail attachment uploads are sent as chunked HTTP requests:
//! ```text
//! POST /coremail/XT/jsp/upload.jsp?sid=...&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=0
//! POST /coremail/XT/jsp/upload.jsp?sid=...&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=2097152
//! POST /coremail/XT/jsp/upload.jsp?sid=...&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=4194304

//! Request with1 chunk,`offset` Parameter chunk FileMediumof bit.
//! Module Same1Fileof chunk According to offset Domain squatingConnect completeFile.

//! : (client_ip, composeId, attachmentId)

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use tracing::{debug, warn};
use vigilyx_core::HttpSession;

/// ChunkedUploadTimeout - timestamp New chunk complete
const CHUNK_TIMEOUT: Duration = Duration::from_secs(120);

/// Timeout - prevent Attack
const ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(600);

/// largeConcurrenttracing
const MAX_PENDING_UPLOADS: usize = 200;

/// File largereassemblesize (50 MB)
const MAX_REASSEMBLED_SIZE: usize = 50 * 1024 * 1024;

/// Coremail ChunkedUpload URL mode
const UPLOAD_JSP_PATTERNS: &[&str] = &["upload.jsp", "/upload?"];

/// From URL Extractof Coremail ChunkedParameter
#[derive(Debug, Clone)]
pub struct ChunkParams {
    pub compose_id: String,
    pub attachment_id: String,
    pub offset: u64,
}

/// Chunked
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct ChunkKey {
    client_ip: String,
    compose_id: String,
    attachment_id: String,
}

/// FileofWaitreassembleStatus
struct PendingUpload {
    /// Chunked: BTreeMap<offset, body_data> - According to offset,Process
    chunks: BTreeMap<u64, Vec<u8>>,
    total_size: u64,
    chunk_count: u32,
    last_chunk_at: Instant,
    created_at: Instant,
    /// keepAfter1ChunkedofYuandata (Used forconstructCompositionof HttpSession)
    first_session: HttpSession,
}

/// completeofFilereassembleResult
pub struct CompletedUpload {
    /// According to offset Domain squatingConnectofcompleteFile
    pub reassembled_data: Vec<u8>,
    pub total_size: u64,
    pub chunk_count: u32,
    /// After1ChunkedofYuandata
    pub base_session: HttpSession,
}

/// Coremail ChunkedUploadtracinghandler
pub struct ChunkedUploadTracker {
    pending: HashMap<ChunkKey, PendingUpload>,
}

impl ChunkedUploadTracker {
    pub fn new() -> Self {
        Self {
            pending: HashMap::with_capacity(64),
        }
    }

    /// Check URL whether Coremail ChunkedUpload
    pub fn is_chunk_upload_url(uri: &str) -> bool {
        let uri_lower = uri.to_lowercase();
        uri_lower.contains("func=directdata")
            && UPLOAD_JSP_PATTERNS.iter().any(|p| uri_lower.contains(p))
    }

    /// From URL MediumExtractChunkedParameter
    pub fn parse_chunk_params(uri: &str) -> Option<ChunkParams> {
        // From query string MediumExtractParameter
        let query = uri.split('?').nth(1)?;

        let mut compose_id = None;
        let mut attachment_id = None;
        let mut offset = None;

        for pair in query.split('&') {
            let mut kv = pair.splitn(2, '=');
            let key = kv.next()?.to_lowercase();
            let value = kv.next().unwrap_or("");

            match key.as_str() {
                "composeid" => compose_id = Some(urldecode(value)),
                "attachmentid" => attachment_id = Some(value.to_string()),
                "offset" => offset = value.parse::<u64>().ok(),
                _ => {}
            }
        }

        Some(ChunkParams {
            compose_id: compose_id?,
            attachment_id: attachment_id?,
            offset: offset.unwrap_or(0),
        })
    }

    /// Receive1Chunked (SynchronousreadGet body)

    /// if body_temp_file value,FromFilereadGet body; request_body.
    /// Note: MethodUse I/O, async ContextMedium.
    /// async ContextMedium Use `ingest_with_data()` Asynchronous read.
    pub fn ingest(&mut self, session: &HttpSession, params: &ChunkParams) {
        let body_data = self.read_body(session);
        self.ingest_with_data(session, params, body_data);
    }

    /// Receive1Chunked (Use readof body data)

    /// Used for async Context: AsynchronousreadGet body data, Method.
    /// Avoid tokio RuntimeMediumExecuteline File I/O.
    pub fn ingest_with_data(
        &mut self,
        session: &HttpSession,
        params: &ChunkParams,
        body_data: Vec<u8>,
    ) {
        let key = ChunkKey {
            client_ip: session.client_ip.clone(),
            compose_id: params.compose_id.clone(),
            attachment_id: params.attachment_id.clone(),
        };

        // Capacitylimit
        if !self.pending.contains_key(&key) && self.pending.len() >= MAX_PENDING_UPLOADS {
            warn!(
                "ChunkedtracingDevice/Handleralreadyfull ({}/{}), dropNewUpload",
                self.pending.len(),
                MAX_PENDING_UPLOADS
            );
            return;
        }

        if body_data.is_empty() {
            return;
        }

        let now = Instant::now();

        let entry = self.pending.entry(key).or_insert_with(|| PendingUpload {
            chunks: BTreeMap::new(),
            total_size: 0,
            chunk_count: 0,
            last_chunk_at: now,
            created_at: now,
            first_session: session.clone(),
        });

        // sizelimit
        if entry.total_size + body_data.len() as u64 > MAX_REASSEMBLED_SIZE as u64 {
            warn!(
                "Chunked upload exceeds {} MB limit, dropping subsequent chunks",
                MAX_REASSEMBLED_SIZE / 1024 / 1024
            );
            return;
        }

        entry.total_size += body_data.len() as u64;
        entry.chunk_count += 1;
        entry.last_chunk_at = now;
        entry.chunks.insert(params.offset, body_data);

        debug!(
            compose_id = %params.compose_id,
            attachment_id = %params.attachment_id,
            offset = params.offset,
            chunk_count = entry.chunk_count,
            total_size = entry.total_size,
            "Coremail ChunkedReceive"
        );
    }

    /// when checking,Returnalreadycomplete/TimeoutofFile
    pub fn tick(&mut self) -> Vec<CompletedUpload> {
        let now = Instant::now();
        let mut completed = Vec::new();
        let mut to_remove = Vec::new();

        for (key, upload) in &self.pending {
            let idle = now.duration_since(upload.last_chunk_at);
            let age = now.duration_since(upload.created_at);

            if idle >= CHUNK_TIMEOUT || age >= ABSOLUTE_TIMEOUT {
                to_remove.push(key.clone());
            }
        }

        for key in to_remove {
            if let Some(upload) = self.pending.remove(&key) {
                if upload.chunk_count == 0 {
                    continue;
                }

                // According to offset Domain squatingConnect
                let mut data = Vec::with_capacity(upload.total_size as usize);
                for chunk in upload.chunks.values() {
                    data.extend_from_slice(chunk);
                }

                debug!(
                    compose_id = %key.compose_id,
                    attachment_id = %key.attachment_id,
                    chunk_count = upload.chunk_count,
                    total_size = data.len(),
                    "Coremail Chunkedreassemblecomplete"
                );

                completed.push(CompletedUpload {
                    reassembled_data: data,
                    total_size: upload.total_size,
                    chunk_count: upload.chunk_count,
                    base_session: upload.first_session,
                });
            }
        }

        completed
    }

    /// Read body data from HttpSession — SEC: path validation (CWE-22)
    fn read_body(&self, session: &HttpSession) -> Vec<u8> {
        // priorityFromtempFilereadGet
        if let Some(ref path) = session.body_temp_file
            && let Some(validated) = super::validate_temp_path(path)
        {
            match std::fs::read(&validated) {
                Ok(data) => return data,
                Err(e) => {
                    warn!("readGet body tempFileFailed {}: {}", path, e);
                }
            }
        }

        // downgradelevel: FromMemoryMediumof request_body readGet
        if let Some(ref body) = session.request_body {
            return body.as_bytes().to_vec();
        }

        Vec::new()
    }
}

impl Default for ChunkedUploadTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// URL Decode
fn urldecode(s: &str) -> String {
    let mut result = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            result.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&result).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(uri: &str, body: Option<&str>) -> HttpSession {
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "192.168.1.200".to_string(),
            80,
            vigilyx_core::HttpMethod::Post,
            uri.to_string(),
        );
        s.request_body = body.map(|b| b.to_string());
        s.request_body_size = body.map(|b| b.len()).unwrap_or(0);
        s
    }

    #[test]
    fn test_is_chunk_upload_url_positive() {
        assert!(ChunkedUploadTracker::is_chunk_upload_url(
            "/coremail/XT/jsp/upload.jsp?sid=abc&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=0"
        ));
    }

    #[test]
    fn test_is_chunk_upload_url_negative() {
        assert!(!ChunkedUploadTracker::is_chunk_upload_url("/compose/send"));
        assert!(!ChunkedUploadTracker::is_chunk_upload_url(
            "/coremail/XT/jsp/upload.jsp?sid=abc"
        ));
    }

    #[test]
    fn test_parse_chunk_params_full_url() {
        let uri = "/coremail/XT/jsp/upload.jsp?sid=abc&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=2097152";
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();
        assert_eq!(params.compose_id, "c:nf:9");
        assert_eq!(params.attachment_id, "1");
        assert_eq!(params.offset, 2097152);
    }

    #[test]
    fn test_parse_chunk_params_missing_offset_defaults_to_zero() {
        let uri = "/upload.jsp?func=directdata&composeId=test&attachmentId=1";
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_parse_chunk_params_no_query_returns_none() {
        assert!(ChunkedUploadTracker::parse_chunk_params("/upload.jsp").is_none());
    }

    #[test]
    fn test_parse_chunk_params_missing_compose_id_returns_none() {
        let uri = "/upload.jsp?func=directdata&attachmentId=1&offset=0";
        assert!(ChunkedUploadTracker::parse_chunk_params(uri).is_none());
    }

    #[test]
    fn test_ingest_and_tick_single_chunk() {
        let mut tracker = ChunkedUploadTracker::new();
        let uri = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=0";
        let session = make_session(uri, Some("chunk data here"));
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();

        tracker.ingest(&session, &params);

        // immediately (Timeout)
        let completed = tracker.tick();
        assert!(completed.is_empty());
    }

    #[test]
    fn test_ingest_multiple_chunks_reassemble_order() {
        let mut tracker = ChunkedUploadTracker::new();

        // Send chunk: offset=100, offset=0
        let uri1 = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=5";
        let s1 = make_session(uri1, Some("BBBBB"));
        let p1 = ChunkedUploadTracker::parse_chunk_params(uri1).unwrap();
        tracker.ingest(&s1, &p1);

        let uri0 = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=0";
        let s0 = make_session(uri0, Some("AAAAA"));
        let p0 = ChunkedUploadTracker::parse_chunk_params(uri0).unwrap();
        tracker.ingest(&s0, &p0);

        // SetTimeout
        for (_, upload) in tracker.pending.iter_mut() {
            upload.last_chunk_at = Instant::now() - CHUNK_TIMEOUT - Duration::from_secs(1);
        }

        let completed = tracker.tick();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].chunk_count, 2);
        // BTreeMap According to offset: offset=0 -> "AAAAA", offset=5 -> "BBBBB"
        assert_eq!(
            String::from_utf8_lossy(&completed[0].reassembled_data),
            "AAAAABBBBB"
        );
    }

    #[test]
    fn test_different_attachments_tracked_separately() {
        let mut tracker = ChunkedUploadTracker::new();

        let uri_a = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=0";
        let uri_b = "/upload.jsp?func=directdata&composeId=test&attachmentId=2&offset=0";

        let sa = make_session(uri_a, Some("file A"));
        let sb = make_session(uri_b, Some("file B"));

        let pa = ChunkedUploadTracker::parse_chunk_params(uri_a).unwrap();
        let pb = ChunkedUploadTracker::parse_chunk_params(uri_b).unwrap();

        tracker.ingest(&sa, &pa);
        tracker.ingest(&sb, &pb);

        assert_eq!(tracker.pending.len(), 2);
    }

    #[test]
    fn test_capacity_limit_rejects_excess() {
        let mut tracker = ChunkedUploadTracker::new();

        // fulltracinghandler
        for i in 0..MAX_PENDING_UPLOADS {
            let uri = format!(
                "/upload.jsp?func=directdata&composeId=compose{}&attachmentId=1&offset=0",
                i
            );
            let session = make_session(&uri, Some("data"));
            let params = ChunkedUploadTracker::parse_chunk_params(&uri).unwrap();
            tracker.ingest(&session, &params);
        }

        assert_eq!(tracker.pending.len(), MAX_PENDING_UPLOADS);

        // Add1 Rejected
        let uri = "/upload.jsp?func=directdata&composeId=overflow&attachmentId=1&offset=0";
        let session = make_session(uri, Some("data"));
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();
        tracker.ingest(&session, &params);

        // MAX_PENDING_UPLOADS
        assert_eq!(tracker.pending.len(), MAX_PENDING_UPLOADS);
    }

    #[test]
    fn test_urldecode_coremail_compose_id() {
        assert_eq!(urldecode("c%3Anf%3A9"), "c:nf:9");
        assert_eq!(urldecode("plain_text"), "plain_text");
        assert_eq!(urldecode("a%20b"), "a b");
    }

    #[test]
    fn test_ingest_with_data_pre_read_body() {
        let mut tracker = ChunkedUploadTracker::new();
        let uri = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=0";
        let session = make_session(uri, None); // Memory body
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();

        // Asynchronous readofdata
        let pre_read_data = b"pre-read chunk data".to_vec();
        tracker.ingest_with_data(&session, &params, pre_read_data);

        assert_eq!(tracker.pending.len(), 1);
    }

    #[test]
    fn test_ingest_with_data_empty_body_skipped() {
        let mut tracker = ChunkedUploadTracker::new();
        let uri = "/upload.jsp?func=directdata&composeId=test&attachmentId=1&offset=0";
        let session = make_session(uri, None);
        let params = ChunkedUploadTracker::parse_chunk_params(uri).unwrap();

        // data hops
        tracker.ingest_with_data(&session, &params, Vec::new());
        assert_eq!(tracker.pending.len(), 0);
    }
}
