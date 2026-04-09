//! dataSecuritydetectEngine

//! Receive HTTP Session, line detecthandler, store indata.
//! Session Deduplicate,prevent TCP reassemble of HTTP Session.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};
use vigilyx_core::{DataSecurityIncident, HttpSession, WsMessage};
use vigilyx_db::VigilDb;

use super::DataSecurityDetector;
use super::chunked_upload::ChunkedUploadTracker;
use super::dlp::DlpScanResult;
use super::draft_detect::DraftBoxDetector;
use super::file_transit_detect::FileTransitDetector;
use super::jrt_compliance::JrtComplianceTracker;
use super::self_send_detect::SelfSendDetector;
use super::time_policy;
use super::volume_anomaly::VolumeAnomalyTracker;
use crate::syslog::{SyslogForwardConfig, SyslogForwarder};

/// SessionlevelDeduplicate () - Same1 timestamp onlyProcess1Time/Count
/// 300 override Coremail largeFileChunkedUpload minuteofScenario
const DEDUP_WINDOW_SECS: i64 = 300;
/// levelDeduplicate () - Same1 (user, FileName, DLPmatch) timestamp only 1Time/Count
/// SessionlevelDeduplicate,prevent SameSessionID(ifChunkedUploadreassemble, NewLogin) Same
const INCIDENT_DEDUP_WINDOW_SECS: i64 = 300;
/// Deduplicatetable largeCapacity, CleanupExpiredentry
const DEDUP_MAX_ENTRIES: usize = 50_000;

/// data security engineStatistics
pub struct DataSecurityEngineStats {
    pub http_sessions_processed: u64,
    pub incidents_detected: u64,
}

/// dataSecuritydetectEngine
pub struct DataSecurityEngine {
    tx: mpsc::Sender<HttpSession>,
    sessions_processed: Arc<AtomicU64>,
    incidents_detected: Arc<AtomicU64>,
}

impl DataSecurityEngine {
   /// Create Startdata security engine
    
   /// ReturnEnginehandle, `submit()` HTTP Session lineAnalyze.
    pub fn start(db: VigilDb, ws_tx: broadcast::Sender<WsMessage>) -> Self {
        let (tx, rx) = mpsc::channel::<HttpSession>(5_000);
        let sessions_processed = Arc::new(AtomicU64::new(0));
        let incidents_detected = Arc::new(AtomicU64::new(0));

        let sessions_counter = Arc::clone(&sessions_processed);
        let incidents_counter = Arc::clone(&incidents_detected);

        tokio::spawn(async move {
            Self::process_loop(rx, db, ws_tx, sessions_counter, incidents_counter).await;
        });

        info!("DataSecurityEngine started");

        Self {
            tx,
            sessions_processed,
            incidents_detected,
        }
    }

   /// HTTP Session lineAnalyze
    pub async fn submit(&self, session: HttpSession) -> Result<(), String> {
        self.tx
            .send(session)
            .await
            .map_err(|_| "DataSecurityEngine channel closed".to_string())
    }

   /// non-blocking (channelfull immediatelyReturnError)
    pub fn try_submit(&self, session: HttpSession) -> Result<(), String> {
        self.tx.try_send(session).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => "DataSecurityEngine channel full".to_string(),
            mpsc::error::TrySendError::Closed(_) => "DataSecurityEngine channel closed".to_string(),
        })
    }

   /// GetEngineStatistics
    pub fn stats(&self) -> DataSecurityEngineStats {
        DataSecurityEngineStats {
            http_sessions_processed: self.sessions_processed.load(Ordering::Relaxed),
            incidents_detected: self.incidents_detected.load(Ordering::Relaxed),
        }
    }

   /// HTTP SessionofDeduplicate
    
   /// client_ip + method + NormalizeURI + filename generateHash.
   /// Coremail ChunkedUploadof Same chunk(offset Same) Merge Same1,
   /// due to URI Mediumof offset/attachmentId Parameter.
    fn session_fingerprint(session: &HttpSession) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.client_ip.hash(&mut hasher);
        session.method.hash(&mut hasher);

       // Normalize URI: offset/attachmentId Parameter(Coremail ChunkedUploadDeduplicate)
        let normalized_uri = Self::normalize_uri_for_dedup(&session.uri);
        normalized_uri.hash(&mut hasher);

        if let Some(ref filename) = session.uploaded_filename {
            filename.hash(&mut hasher);
        }
        hasher.finish()
    }

   /// URI MediumofChunkedUploadParameter (offset, attachmentId),keep composeId/sid/func
    fn normalize_uri_for_dedup(uri: &str) -> String {
        if let Some(query_start) = uri.find('?') {
            let path = &uri[..query_start];
            let query = &uri[query_start + 1..];
            let filtered: Vec<&str> = query
                .split('&')
                .filter(|param| {
                    let key = param.split('=').next().unwrap_or("");
                   // keep "Same1UploadOperations"ofParameter, Chunked Parameter
                    key != "offset" && key != "attachmentId"
                })
                .collect();
            if filtered.is_empty() {
                path.to_string()
            } else {
                format!("{}?{}", path, filtered.join("&"))
            }
        } else {
            uri.to_string()
        }
    }

   /// CleanupDeduplicatetableMediumExpiredentry
    fn cleanup_dedup_table(table: &mut HashMap<u64, DateTime<Utc>>, now: DateTime<Utc>) {
        table.retain(|_, ts| (now - *ts).num_seconds() < DEDUP_WINDOW_SECS);
    }

   /// URI Coremail composeId
    
   /// URL: `composeId=c%3Anf%3A8628193` -> `c:nf:8628193`
   /// : `composeId=1775031606750` -> `1775031606750`
    fn extract_compose_id_from_uri(uri: &str) -> Option<String> {
        let query = uri.split('?').nth(1)?;
        for param in query.split('&') {
            let key_value: Vec<&str> = param.splitn(2, '=').collect();
            if key_value.len() == 2 && key_value[0].eq_ignore_ascii_case("composeId") {
               // URL (%3A ->:)
                let decoded = key_value[1]
                    .replace("%3A", ":")
                    .replace("%3a", ":")
                    .replace("%2F", "/")
                    .replace("%2f", "/");
                return Some(decoded);
            }
        }
        None
    }

   /// levelDeduplicate
    
   /// (user IP, FileName, ofDLPmatchType) generateHash.
   /// overrideSessionlevelDeduplicate CaptureofScenario(ifChunkedreassemble ofCompositionSession, SID of Upload).
    fn incident_fingerprint(
        user_or_ip: &str,
        filename: Option<&str>,
        dlp_matches: &[String],
    ) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        user_or_ip.hash(&mut hasher);
        filename.unwrap_or("").hash(&mut hasher);
        let mut sorted = dlp_matches.to_vec();
        sorted.sort();
        sorted.hash(&mut hasher);
        hasher.finish()
    }

   /// ProcessLoop
    
   /// Use tokio::select! Same:
   /// 1. Receive HTTP Session Analyze
   /// 2. when checking Coremail ChunkedUploadwhethercomplete
   /// 3. Output HTTP pipeline ReceiveStatistics
    async fn process_loop(
        mut rx: mpsc::Receiver<HttpSession>,
        db: VigilDb,
        ws_tx: broadcast::Sender<WsMessage>,
        sessions_counter: Arc<AtomicU64>,
        incidents_counter: Arc<AtomicU64>,
    ) {
       // initializedetecthandler (Arc packet,For spawn_blocking Shared)
        let detectors: Arc<Vec<Box<dyn DataSecurityDetector>>> = Arc::new(vec![
            Box::new(DraftBoxDetector::new()),
            Box::new(FileTransitDetector::new()),
            Box::new(SelfSendDetector::new()),
        ]);

       // LoadtimestampstrategyConfiguration (From DB, Failed Defaultvalue)
        let time_policy_config = match db.get_time_policy_config().await {
            Ok(Some(json)) => serde_json::from_str::<time_policy::TimePolicyConfig>(&json)
                .unwrap_or_else(|e| {
                    warn!("Failed to parse time_policy config, using defaults: {}", e);
                    time_policy::TimePolicyConfig::default()
                }),
            Ok(None) => {
                info!("No time_policy config in DB, using defaults (08:00-18:00 UTC+8)");
                time_policy::TimePolicyConfig::default()
            }
            Err(e) => {
                warn!("Failed to load time_policy config: {}, using defaults", e);
                time_policy::TimePolicyConfig::default()
            }
        };
        info!(
            "Time policy: enabled={}, hours={:02}:00-{:02}:00, UTC{:+}, weekend={}",
            time_policy_config.enabled,
            time_policy_config.work_hour_start,
            time_policy_config.work_hour_end,
            time_policy_config.utc_offset_hours,
            time_policy_config.weekend_is_off_hours,
        );

       // Load Syslog Configuration (From DB)
        let syslog_forwarder = match db.get_syslog_config().await {
            Ok(Some(json)) => match serde_json::from_str::<SyslogForwardConfig>(&json) {
                Ok(cfg) if cfg.enabled && !cfg.server_address.is_empty() => {
                    match SyslogForwarder::start(cfg.clone()) {
                        Ok(forwarder) => {
                            info!(
                                "Syslog forwarding enabled: {}:{} ({})",
                                cfg.server_address, cfg.port, cfg.protocol
                            );
                            Some(forwarder)
                        }
                        Err(reason) => {
                            warn!(
                                target = %cfg.server_address,
                                "Syslog forwarding blocked at runtime: {}",
                                reason
                            );
                            None
                        }
                    }
                }
                Ok(_) => {
                    info!("Syslog forwarding disabled in config");
                    None
                }
                Err(e) => {
                    warn!("Failed to parse syslog config: {}, forwarding disabled", e);
                    None
                }
            },
            Ok(None) => {
                info!("No syslog config in DB, forwarding disabled");
                None
            }
            Err(e) => {
                warn!("Failed to load syslog config: {}, forwarding disabled", e);
                None
            }
        };

       // Coremail ChunkedUploadtracinghandler
        let mut chunk_tracker = ChunkedUploadTracker::new();

       // Coremail upload:prepare
       // (client_ip, composeId) -> (fileName, timestamp)
       // upload:prepare JSON body fileName, upload.jsp?func=directData
        let mut prepare_filename_tracker: HashMap<(String, String), (String, DateTime<Utc>)> =
            HashMap::with_capacity(128);

       // Stream Abnormaltracinghandler
        let mut volume_tracker = VolumeAnomalyTracker::new();

       // JR/T 0197-2020 Compliancetracinghandler
        let mut jrt_tracker = JrtComplianceTracker::new();

       // ChunkedCheck handler (5 Check1Time/Count)
        let mut tick_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

       // HTTP pipeline ReceiveStatistics handler (3 minute)
       // Used for 100% Stream of packet/ Session
        let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(180));

       // SessionlevelDeduplicatetable: fingerprint -> First foundtimestamp
        let mut dedup_table: HashMap<u64, DateTime<Utc>> = HashMap::with_capacity(1024);
       // levelDeduplicatetable: incident_fingerprint -> First foundtimestamp
        let mut incident_dedup_table: HashMap<u64, DateTime<Utc>> = HashMap::with_capacity(256);
        let mut cleanup_counter: u64 = 0;

       // Engine Statisticscounter
        let mut engine_dedup_skipped: u64 = 0;
        let mut engine_db_store_failed: u64 = 0;
        let mut engine_analyzed: u64 = 0;

        loop {
            tokio::select! {
                session_opt = rx.recv() => {
                    let mut session = match session_opt {
                        Some(s) => s,
                        None => {
                            warn!("DataSecurityEngine process loop ended (channel closed)");
                            break;
                        }
                    };

                    sessions_counter.fetch_add(1, Ordering::Relaxed);
                    let received_total = sessions_counter.load(Ordering::Relaxed);

                    info!(
                        session_id = %session.id,
                        uri = %session.uri,
                        method = ?session.method,
                        host = ?session.host,
                        client_ip = %session.client_ip,
                        body_size = session.request_body_size,
                        network_session_id = ?session.network_session_id,
                        received_total = received_total,
                        channel_remaining = rx.len(),
                        "DataSecurityEngine: Receive HTTP Session"
                    );

                    let now = Utc::now();
                    let fingerprint = Self::session_fingerprint(&session);

                   // DeduplicateCheck
                    if let Some(first_seen) = dedup_table.get(&fingerprint)
                        && (now - *first_seen).num_seconds() < DEDUP_WINDOW_SECS {
                            engine_dedup_skipped += 1;
                            debug!(
                                fingerprint = fingerprint,
                                uri = %session.uri,
                                ip = %session.client_ip,
                                dedup_skipped_total = engine_dedup_skipped,
                                "Duplicate HTTP session skipped (dedup)"
                            );
                            continue;
                        }
                    dedup_table.insert(fingerprint, now);

                   // PeriodicCleanupExpiredentry
                    cleanup_counter += 1;
                    if cleanup_counter.is_multiple_of(500) || dedup_table.len() > DEDUP_MAX_ENTRIES {
                        Self::cleanup_dedup_table(&mut dedup_table, now);
                       // 1 Cleanup levelDeduplicatetable
                        incident_dedup_table.retain(|_, ts| (now - *ts).num_seconds() < INCIDENT_DEDUP_WINDOW_SECS);
                    }

                   // store HTTP Session
                    if let Err(e) = db.insert_http_session(&session).await {
                        engine_db_store_failed += 1;
                        error!(
                            session_id = %session.id,
                            db_store_failed_total = engine_db_store_failed,
                            "Failed to store HTTP session: {}", e
                        );
                    }

                    
                   // Coremail upload:prepare
                   // prepare body: {"composeId":"xxx","attachmentId":-1,"fileName":"test.txt","size":1234}
                   // tracker, upload.jsp?func=directData composeId
                    
                    let uri_lower = session.uri.to_lowercase();
                    if uri_lower.contains("func=upload") && uri_lower.contains("prepare")
                        && let Some(ref body) = session.request_body
                        && let Ok(json) = serde_json::from_str::<serde_json::Value>(body)
                        && let (Some(filename), Some(compose_id)) = (
                            json.get("fileName").or_else(|| json.get("name")).and_then(|v| v.as_str()),
                            json.get("composeId").and_then(|v| v.as_str().map(|s| s.to_string()).or_else(|| v.as_i64().map(|n| n.to_string()))),
                        )
                    {
                        let key = (session.client_ip.clone(), compose_id.clone());
                        debug!(
                            client_ip = %session.client_ip,
                            compose_id = %compose_id,
                            filename = %filename,
                            "upload:prepare 文件名已记录"
                        );
                        prepare_filename_tracker.insert(key, (filename.to_string(), now));

                        
                        if prepare_filename_tracker.len() > 200 {
                            prepare_filename_tracker.retain(|_, (_, ts)| {
                                (now - *ts).num_seconds() < 600
                            });
                        }
                    }

                    
                   // Coremail directData: prepare tracker uploaded_filename
                    
                    if session.uploaded_filename.is_none()
                        && uri_lower.contains("func=directdata")
                        && let Some(compose_id) = Self::extract_compose_id_from_uri(&session.uri)
                    {
                        let key = (session.client_ip.clone(), compose_id.clone());
                        if let Some((filename, _)) = prepare_filename_tracker.get(&key) {
                            debug!(
                                client_ip = %session.client_ip,
                                compose_id = %compose_id,
                                filename = %filename,
                                "directData 上传关联到 prepare 文件名"
                            );
                            session.uploaded_filename = Some(filename.clone());
                        }
                    }

                   // Checkwhether Coremail ChunkedUpload - Recording chunked tracker,But hopsdetecthandler
                   // ChunkedallSame givingdetecthandler DLP,EnsuresmallFile1Time/Count Upload
                    if ChunkedUploadTracker::is_chunk_upload_url(&session.uri)
                        && let Some(params) = ChunkedUploadTracker::parse_chunk_params(&session.uri) {
                            let body_data = Self::async_read_body(&session).await;
                            chunk_tracker.ingest_with_data(&session, &params, body_data);
                           // continue - detecthandler
                        }

                   // line detecthandler (spawn_blocking MediumExecuteline,Avoid DLP async Loop)
                    engine_analyzed += 1;
                    let session = Arc::new(session);
                    Self::run_detectors(&detectors, &session, &db, &ws_tx, &incidents_counter, &mut volume_tracker, &mut jrt_tracker, &time_policy_config, &syslog_forwarder, &mut incident_dedup_table).await;
                }
                _ = tick_interval.tick() => {
                   // CheckChunkedUploadwhethercomplete
                    let completed_uploads = chunk_tracker.tick();
                    for completed in completed_uploads {
                       // completeFileconstructComposition HttpSession linedetect
                        let mut synthetic = Self::build_synthetic_session(&completed);

                       // prepare tracker
                        if synthetic.uploaded_filename.is_none()
                            && let Some(compose_id) = Self::extract_compose_id_from_uri(&synthetic.uri)
                            && let Some((filename, _)) = prepare_filename_tracker.get(&(synthetic.client_ip.clone(), compose_id))
                        {
                            synthetic.uploaded_filename = Some(filename.clone());
                        }

                        info!(
                            "Coremail chunked upload reassembled: {} bytes, {} chunks, ip={}, filename={:?}",
                            completed.total_size,
                            completed.chunk_count,
                            synthetic.client_ip,
                            synthetic.uploaded_filename,
                        );

                       // storeCompositionSession
                        if let Err(e) = db.insert_http_session(&synthetic).await {
                            engine_db_store_failed += 1;
                            error!("Failed to store synthetic HTTP session: {}", e);
                        }

                       // linedetecthandler
                        engine_analyzed += 1;
                        let synthetic = Arc::new(synthetic);
                        Self::run_detectors(&detectors, &synthetic, &db, &ws_tx, &incidents_counter, &mut volume_tracker, &mut jrt_tracker, &time_policy_config, &syslog_forwarder, &mut incident_dedup_table).await;
                    }
                }
                _ = stats_interval.tick() => {
                   // HTTP data security engineReceive Statistics
                    let received = sessions_counter.load(Ordering::Relaxed);
                    let incidents = incidents_counter.load(Ordering::Relaxed);
                    info!(
                        received_total = received,
                        analyzed = engine_analyzed,
                        dedup_skipped = engine_dedup_skipped,
                        db_store_failed = engine_db_store_failed,
                        incidents_detected = incidents,
                        dedup_table_size = dedup_table.len(),
                        channel_remaining = rx.len(),
                        "DataSecurityEngine Statistics | \
                         Receive={} Analyze={} Deduplicatehops={} DBwrite入Failed={} | \
                         事件={} | Deduplicatetable={} channel积压={}",
                        received, engine_analyzed, engine_dedup_skipped, engine_db_store_failed,
                        incidents, dedup_table.len(), rx.len(),
                    );

                   // channel Alert
                    let remaining = rx.len();
                    if remaining > 1000 {
                        warn!(
                            channel_remaining = remaining,
                            channel_capacity = 5000,
                            "DataSecurityEngine channel积压Critical! EngineProcess速度不足"
                        );
                    }
                }
            }
        }
    }

   /// Asynchronous read body tempFile (Used forChunkedUpload)
    
   /// Avoid async ContextMediumUse std::fs::read tokio Runtime.
   /// priorityUseMemoryMediumof request_body, tempFilestored AsynchronousreadGet.
    async fn async_read_body(session: &HttpSession) -> Vec<u8> {
       // priorityFromtempFileAsynchronousreadGet — SEC: path validation (CWE-22)
        if let Some(ref path) = session.body_temp_file
            && let Some(validated) = super::validate_temp_path(path)
        {
            match tokio::fs::read(&validated).await {
                Ok(data) => return data,
                Err(e) => {
                    warn!("AsynchronousreadGet body tempFileFailed {}: {}", path, e);
                }
            }
        }

       // downgradelevel: FromMemoryMediumof request_body readGet
        if let Some(ref body) = session.request_body {
            return body.as_bytes().to_vec();
        }

        Vec::new()
    }

   /// 1 HTTP Session line detecthandler
    
   /// detecthandler (Contains DLP) spawn_blocking MediumExecuteline,
   /// Avoid CPU of match tokio AsynchronousRuntime.
   /// Use `Arc<HttpSession>` Avoid HttpSession (Contains String Segment) Thread.
    
   /// Process:
   /// 1. timestampstrategy (Non-workingtimestampCritical +1)
   /// 2. Stream Abnormaltracing (user/IP)
    #[allow(clippy::too_many_arguments)] // InternalMethod, Parameterall independentfocus on
    #[allow(clippy::too_many_arguments)]
    async fn run_detectors(
        detectors: &Arc<Vec<Box<dyn DataSecurityDetector>>>,
        session: &Arc<HttpSession>,
        db: &VigilDb,
        ws_tx: &broadcast::Sender<WsMessage>,
        incidents_counter: &Arc<AtomicU64>,
        volume_tracker: &mut VolumeAnomalyTracker,
        jrt_tracker: &mut JrtComplianceTracker,
        tp_config: &time_policy::TimePolicyConfig,
        syslog_forwarder: &Option<SyslogForwarder>,
        incident_dedup: &mut HashMap<u64, DateTime<Utc>>,
    ) {
        let detectors = Arc::clone(detectors);
        let session_arc = Arc::clone(session); // Arc reference counting +1,

       // Return (incident, dlp_result) Yuan
        let results: Vec<(DataSecurityIncident, Option<DlpScanResult>)> =
            tokio::task::spawn_blocking(move || {
                let mut results = Vec::new();
                for detector in detectors.iter() {
                    if let Some(result) = detector.analyze(&session_arc) {
                        results.push(result);
                    }
                }
                results
            })
            .await
            .unwrap_or_else(|e| {
                error!("spawn_blocking panic in run_detectors: {}", e);
                Vec::new()
            });

       // DLP Result Used for JR/T Compliancetracing
        let mut all_dlp_results: Vec<DlpScanResult> = Vec::new();
        let mut incidents: Vec<DataSecurityIncident> = Vec::new();
        for (incident, dlp_result) in results {
            if let Some(dlp) = dlp_result {
                all_dlp_results.push(dlp);
            }
            incidents.push(incident);
        }

        for mut incident in incidents {
           // P0: user - When Cookie/body Extract user, Same IP of Session
            if incident.detected_user.is_none() {
                match db.lookup_user_by_client_ip(&incident.client_ip).await {
                    Ok(Some(user)) => {
                       // Update incident of detected_user And summary
                        let old_summary = incident.summary.replace("Unknownuser", &user);
                        incident.summary = old_summary;
                        incident.detected_user = Some(user);
                    }
                    Ok(None) => {} // not userRecording
                    Err(e) => {
                        debug!("user身份回查Failed (ip={}): {}", incident.client_ip, e);
                    }
                }
            }

           // levelDeduplicate(level):
           // L1: MemoryDeduplicate - Same1 (user/IP, FileName, DLPmatch) 300s only 1Time/Count
            let user_or_ip = incident
                .detected_user
                .as_deref()
                .unwrap_or(&incident.client_ip);
            let inc_fp = Self::incident_fingerprint(
                user_or_ip,
                session.uploaded_filename.as_deref(),
                &incident.dlp_matches,
            );
            let now_inc = Utc::now();
            if let Some(first_seen) = incident_dedup.get(&inc_fp)
                && (now_inc - *first_seen).num_seconds() < INCIDENT_DEDUP_WINDOW_SECS
            {
                debug!(
                    user = user_or_ip,
                    filename = ?session.uploaded_filename,
                    incident_type = %incident.incident_type,
                    "Duplicate incident suppressed (memory dedup)"
                );
                continue;
            }
            incident_dedup.insert(inc_fp, now_inc);

           // L2: DB Deduplicate - preventEngine Memory (1 small)
           // Same1user + Same1 Type + Same1 DLP match -> 1 small
            {
                let since = (now_inc - chrono::Duration::hours(1)).to_rfc3339();
                let mut sorted_dlp = incident.dlp_matches.clone();
                sorted_dlp.sort();
                let dlp_json = serde_json::to_string(&sorted_dlp).unwrap_or_default();
                if db
                    .has_recent_incident(
                        user_or_ip,
                        &incident.incident_type.to_string(),
                        &dlp_json,
                        &since,
                    )
                    .await
                    .unwrap_or(false)
                {
                    debug!(
                        user = user_or_ip,
                        incident_type = %incident.incident_type,
                        "Duplicate incident suppressed (DB dedup, 1h window)"
                    );
                    continue;
                }
            }

           // P2.1: Non-workingtimestampCritical (Configuration)
            incident.severity = time_policy::apply_time_policy_with_config(
                incident.severity,
                incident.created_at,
                tp_config,
            );

            info!(
                "data security incident detected: type={}, severity={}, user={:?}, ip={}",
                incident.incident_type,
                incident.severity,
                incident.detected_user,
                incident.client_ip
            );

            incidents_counter.fetch_add(1, Ordering::Relaxed);

           // P2.2: Stream Abnormaltracing - user IP key
            let volume_key = incident
                .detected_user
                .as_deref()
                .unwrap_or(&incident.client_ip);
            if let Some(volume_incident) = volume_tracker.record_incident(
                volume_key,
                &incident.client_ip,
                incident.detected_user.as_deref(),
                incident.http_session_id,
                &incident.request_url,
                incident.host.as_deref(),
            ) {
               // Stream Abnormal timestampstrategy
                let mut vi = volume_incident;
                vi.severity = time_policy::apply_time_policy_with_config(
                    vi.severity,
                    vi.created_at,
                    tp_config,
                );

                info!(
                    "Volume anomaly detected: user={:?}, ip={}, severity={}",
                    vi.detected_user, vi.client_ip, vi.severity
                );
                incidents_counter.fetch_add(1, Ordering::Relaxed);

                if let Err(e) = db.insert_data_security_incident(&vi).await {
                    error!("Failed to store volume anomaly incident: {}", e);
                }
                if let Some(fwd) = syslog_forwarder.as_ref() {
                    fwd.try_forward(&vi);
                }
                Self::broadcast_incident(ws_tx, vi);
            }

            if let Err(e) = db.insert_data_security_incident(&incident).await {
                error!("Failed to store data security incident: {}", e);
            }
            if let Some(fwd) = syslog_forwarder.as_ref() {
                fwd.try_forward(&incident);
            }
            Self::broadcast_incident(ws_tx, incident);
        }

       // P3: JR/T 0197-2020 Compliancetracing - DLP Result According tolevel Cumulative
        if !all_dlp_results.is_empty() {
            let jrt_key = session
                .detected_user
                .as_deref()
                .unwrap_or(&session.client_ip);
            for dlp in &all_dlp_results {
                let jrt_incidents = jrt_tracker.record_dlp_result(
                    jrt_key,
                    dlp,
                    &session.client_ip,
                    session.detected_user.as_deref(),
                    session.id,
                    &session.uri,
                    session.host.as_deref(),
                );
                for mut ji in jrt_incidents {
                    ji.severity = time_policy::apply_time_policy_with_config(
                        ji.severity,
                        ji.created_at,
                        tp_config,
                    );
                    incidents_counter.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = db.insert_data_security_incident(&ji).await {
                        error!("Failed to store JR/T compliance incident: {}", e);
                    }
                    if let Some(fwd) = syslog_forwarder.as_ref() {
                        fwd.try_forward(&ji);
                    }
                    Self::broadcast_incident(ws_tx, ji);
                }
            }
        }
    }

   /// FromChunkedreassembleResult constructComposition HttpSession
    fn build_synthetic_session(completed: &super::chunked_upload::CompletedUpload) -> HttpSession {
        let mut session = completed.base_session.clone();
        session.id = vigilyx_core::fast_uuid();
        session.request_body_size = completed.reassembled_data.len();

       // Magic byte detect
        let detected = vigilyx_core::magic_bytes::detect_file_type(&completed.reassembled_data);
        session.detected_file_type = detected;

        let is_binary = detected.map(|ft| !ft.is_text_scannable()).unwrap_or(false);
        session.body_is_binary = is_binary;

       // Full-audit mode: store entire text body for DLP - no truncation
        if !is_binary {
            session.request_body = String::from_utf8_lossy(&completed.reassembled_data)
                .into_owned()
                .into();
        }

        session
    }

   /// dataSecurity WebSocket
    fn broadcast_incident(ws_tx: &broadcast::Sender<WsMessage>, incident: DataSecurityIncident) {
        let msg = WsMessage::DataSecurityAlert(incident);
       // send Return Err, Normal
        let _ = ws_tx.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_http_session() -> HttpSession {
        HttpSession {
            id: uuid::Uuid::new_v4(),
            client_ip: "192.168.1.100".to_string(),
            client_port: 54321,
            server_ip: "10.0.0.1".to_string(),
            server_port: 443,
            method: vigilyx_core::HttpMethod::Post,
            uri: "/save".to_string(),
            host: Some("mail.example.com".to_string()),
            content_type: None,
            request_body_size: 0,
            request_body: None,
            response_status: None,
            uploaded_filename: None,
            uploaded_file_size: None,
            detected_user: None,
            detected_sender: None,
            detected_file_type: None,
            body_is_binary: false,
            file_type_mismatch: None,
            body_temp_file: None,
            has_gaps: false,
            detected_recipients: vec![],
            timestamp: chrono::Utc::now(),
            network_session_id: None,
        }
    }

    #[tokio::test]
    async fn test_data_security_channel_capacity_5000() {
       // Verify the increased channel capacity
        let (tx, _rx) = mpsc::channel::<HttpSession>(5_000);
        let mut count = 0;
        for _ in 0..3_000 {
            if tx.try_send(make_http_session()).is_ok() {
                count += 1;
            }
        }
        assert_eq!(
            count, 3_000,
            "Should accept 3000 HTTP sessions without blocking"
        );
    }

    #[tokio::test]
    async fn test_try_submit_returns_error_when_full() {
        let (tx, _rx) = mpsc::channel::<HttpSession>(1);
        tx.try_send(make_http_session()).unwrap();

        let result = tx.try_send(make_http_session());
        assert!(
            result.is_err(),
            "try_submit should fail when channel is full"
        );
    }

    #[tokio::test]
    async fn test_try_submit_succeeds_when_capacity_available() {
        let (tx, _rx) = mpsc::channel::<HttpSession>(10);
        let result = tx.try_send(make_http_session());
        assert!(
            result.is_ok(),
            "try_submit should succeed with available capacity"
        );
    }

    #[test]
    fn test_session_fingerprint_same_content_same_hash() {
        let mut s1 = make_http_session();
        s1.client_ip = "10.0.0.1".to_string();
        s1.uri = "/compose/send".to_string();
        s1.request_body = Some("hello world".to_string());

        let mut s2 = make_http_session();
        s2.client_ip = "10.0.0.1".to_string();
        s2.uri = "/compose/send".to_string();
        s2.request_body = Some("hello world".to_string());

        assert_eq!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Same content should produce same fingerprint"
        );
    }

    #[test]
    fn test_session_fingerprint_different_uri_different_hash() {
        let mut s1 = make_http_session();
        s1.uri = "/compose/send".to_string();

        let mut s2 = make_http_session();
        s2.uri = "/draft/save".to_string();

        assert_ne!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Different URIs should produce different fingerprints"
        );
    }

    #[test]
    fn test_session_fingerprint_different_ip_different_hash() {
        let mut s1 = make_http_session();
        s1.client_ip = "10.0.0.1".to_string();
        s1.uri = "/compose/send".to_string();

        let mut s2 = make_http_session();
        s2.client_ip = "10.0.0.2".to_string();
        s2.uri = "/compose/send".to_string();

        assert_ne!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Different IPs should produce different fingerprints"
        );
    }

    #[test]
    fn test_dedup_table_cleanup_removes_old_entries() {
        let mut table = HashMap::new();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(DEDUP_WINDOW_SECS + 10);
        let recent = now - chrono::Duration::seconds(5);

        table.insert(111, old);
        table.insert(222, recent);
        table.insert(333, now);

        DataSecurityEngine::cleanup_dedup_table(&mut table, now);

        assert!(!table.contains_key(&111), "Old entry should be removed");
        assert!(table.contains_key(&222), "Recent entry should remain");
        assert!(table.contains_key(&333), "Current entry should remain");
    }

    
   // Test: URI NormalizeDeduplicate
    

    #[test]
    fn test_normalize_uri_strips_offset() {
        let uri = "/upload.jsp?sid=abc&func=directdata&composeId=c%3Anf%3A9&attachmentId=1&offset=2097152";
        let normalized = DataSecurityEngine::normalize_uri_for_dedup(uri);
        assert!(!normalized.contains("offset"), "offset should be stripped");
        assert!(
            !normalized.contains("attachmentId"),
            "attachmentId should be stripped"
        );
        assert!(normalized.contains("sid=abc"), "sid should be kept");
        assert!(normalized.contains("composeId"), "composeId should be kept");
    }

    #[test]
    fn test_normalize_uri_no_query() {
        let uri = "/compose/send";
        let normalized = DataSecurityEngine::normalize_uri_for_dedup(uri);
        assert_eq!(normalized, "/compose/send");
    }

    #[test]
    fn test_normalize_uri_all_params_stripped() {
        let uri = "/upload?offset=0&attachmentId=1";
        let normalized = DataSecurityEngine::normalize_uri_for_dedup(uri);
        assert_eq!(
            normalized, "/upload",
            "Should return path only when all params stripped"
        );
    }

    #[test]
    fn test_normalize_uri_keeps_non_chunk_params() {
        let uri = "/api?func=directdata&sid=xyz&offset=0";
        let normalized = DataSecurityEngine::normalize_uri_for_dedup(uri);
        assert!(normalized.contains("func=directdata"));
        assert!(normalized.contains("sid=xyz"));
        assert!(!normalized.contains("offset"));
    }

    #[test]
    fn test_fingerprint_coremail_chunks_same_file_same_hash() {
       // Same1Fileof SameChunked (only offset/attachmentId Same) -> Same
        let mut s1 = make_http_session();
        s1.client_ip = "10.0.0.1".to_string();
        s1.uri = "/upload.jsp?func=directdata&composeId=c1&attachmentId=1&offset=0".to_string();

        let mut s2 = make_http_session();
        s2.client_ip = "10.0.0.1".to_string();
        s2.uri =
            "/upload.jsp?func=directdata&composeId=c1&attachmentId=1&offset=2097152".to_string();

        assert_eq!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Same file different offsets should produce same fingerprint"
        );
    }

    #[test]
    fn test_fingerprint_different_compose_different_hash() {
       // Same composeId -> Same
        let mut s1 = make_http_session();
        s1.client_ip = "10.0.0.1".to_string();
        s1.uri = "/upload.jsp?func=directdata&composeId=compose1&offset=0".to_string();

        let mut s2 = make_http_session();
        s2.client_ip = "10.0.0.1".to_string();
        s2.uri = "/upload.jsp?func=directdata&composeId=compose2&offset=0".to_string();

        assert_ne!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Different composeId should produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_includes_filename() {
        let mut s1 = make_http_session();
        s1.uri = "/upload".to_string();
        s1.uploaded_filename = Some("file_a.xlsx".to_string());

        let mut s2 = make_http_session();
        s2.uri = "/upload".to_string();
        s2.uploaded_filename = Some("file_b.xlsx".to_string());

        assert_ne!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Different filenames should produce different fingerprints"
        );
    }

    #[test]
    fn test_fingerprint_none_filename_consistent() {
        let mut s1 = make_http_session();
        s1.uri = "/compose/send".to_string();
        s1.uploaded_filename = None;

        let mut s2 = make_http_session();
        s2.uri = "/compose/send".to_string();
        s2.uploaded_filename = None;

        assert_eq!(
            DataSecurityEngine::session_fingerprint(&s1),
            DataSecurityEngine::session_fingerprint(&s2),
            "Both None filenames should produce same fingerprint"
        );
    }

    #[test]
    fn test_dedup_table_cleanup_empty_table() {
        let mut table: HashMap<u64, DateTime<Utc>> = HashMap::new();
        DataSecurityEngine::cleanup_dedup_table(&mut table, Utc::now());
        assert!(table.is_empty());
    }

    #[test]
    fn test_dedup_table_cleanup_all_expired() {
        let mut table = HashMap::new();
        let now = Utc::now();
        let old = now - chrono::Duration::seconds(DEDUP_WINDOW_SECS + 100);
        table.insert(1, old);
        table.insert(2, old);
        table.insert(3, old);

        DataSecurityEngine::cleanup_dedup_table(&mut table, now);
        assert!(table.is_empty(), "All expired entries should be removed");
    }

   // levelDeduplicate Test

    #[test]
    fn test_incident_fingerprint_deterministic() {
        let fp1 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["credit_card".to_string()],
        );
        let fp2 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["credit_card".to_string()],
        );
        assert_eq!(fp1, fp2, "Same inputs should produce same fingerprint");
    }

    #[test]
    fn test_incident_fingerprint_different_user() {
        let fp1 = DataSecurityEngine::incident_fingerprint(
            "user_a@test.com",
            Some("file.txt"),
            &["credit_card".to_string()],
        );
        let fp2 = DataSecurityEngine::incident_fingerprint(
            "user_b@test.com",
            Some("file.txt"),
            &["credit_card".to_string()],
        );
        assert_ne!(
            fp1, fp2,
            "Different users should produce different fingerprints"
        );
    }

    #[test]
    fn test_incident_fingerprint_different_dlp() {
        let fp1 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["credit_card".to_string()],
        );
        let fp2 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["phone_number".to_string()],
        );
        assert_ne!(
            fp1, fp2,
            "Different DLP matches should produce different fingerprints"
        );
    }

    #[test]
    fn test_incident_fingerprint_order_independent() {
        let fp1 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["credit_card".to_string(), "phone_number".to_string()],
        );
        let fp2 = DataSecurityEngine::incident_fingerprint(
            "user@test.com",
            Some("file.txt"),
            &["phone_number".to_string(), "credit_card".to_string()],
        );
        assert_eq!(fp1, fp2, "DLP match order should not affect fingerprint");
    }

    
   // extract_compose_id_from_uri
    

    #[test]
    fn test_extract_compose_id_numeric() {
        let uri =
            "/upload.jsp?sid=abc&func=directData&composeId=1775031606750&attachmentId=1&offset=0";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
        assert_eq!(result, Some("1775031606750".to_string()));
    }

    #[test]
    fn test_extract_compose_id_url_encoded() {
       // c%3Anf%3A8628193 -> c:nf:8628193
        let uri = "/upload.jsp?sid=BAQk&func=directData&attachmentId=1&composeId=c%3Anf%3A8628193&offset=0";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
        assert_eq!(result, Some("c:nf:8628193".to_string()));
    }

    #[test]
    fn test_extract_compose_id_missing() {
        let uri = "/upload.jsp?sid=abc&func=directData&attachmentId=1&offset=0";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_compose_id_no_query() {
        let uri = "/upload.jsp";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_compose_id_case_insensitive() {
        let uri = "/upload.jsp?COMPOSEID=test123&func=directData";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
       // eq_ignore_ascii_case
        assert_eq!(result, Some("test123".to_string()));
    }

    #[test]
    fn test_extract_compose_id_first_param() {
        let uri = "/upload.jsp?composeId=first_val&sid=abc";
        let result = DataSecurityEngine::extract_compose_id_from_uri(uri);
        assert_eq!(result, Some("first_val".to_string()));
    }
}
