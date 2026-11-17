//! dataSecuritydetectEngine

//! Receive HTTP Session, line detecthandler, store indata.
//! Session Deduplicate,prevent TCP reassemble of HTTP Session.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, warn};
use vigilyx_core::{DataSecurityIncident, HttpSession, WsMessage};
use vigilyx_db::VigilDb;

use super::DataSecurityDetector;
use super::bulk_transfer::BulkTransferTracker;
use super::chunked_upload::ChunkedUploadTracker;
use super::dlp::DlpScanResult;
use super::draft_detect::DraftBoxDetector;
use super::file_transit_detect::FileTransitDetector;
use super::mail_transfer_detect::MailTransferDetector;
use super::time_policy;
use super::volume_anomaly::VolumeAnomalyTracker;
use crate::syslog::{SyslogForwardConfig, SyslogForwarder};

/// SessionlevelDeduplicate () - Same1 timestamp onlyProcess1Time/Count
/// 300 override Coremail largeFileChunkedUpload minuteofScenario
const DEDUP_WINDOW_SECS: i64 = 300;
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
    time_policy_tx: watch::Sender<time_policy::TimePolicyConfig>,
    sessions_processed: Arc<AtomicU64>,
    incidents_detected: Arc<AtomicU64>,
}

impl DataSecurityEngine {
    /// Create Startdata security engine

    /// ReturnEnginehandle, `submit()` HTTP Session lineAnalyze.
    pub fn start(db: VigilDb, ws_tx: broadcast::Sender<WsMessage>) -> Self {
        let (tx, rx) = mpsc::channel::<HttpSession>(5_000);
        let (time_policy_tx, time_policy_rx) =
            watch::channel(time_policy::TimePolicyConfig::default());
        let sessions_processed = Arc::new(AtomicU64::new(0));
        let incidents_detected = Arc::new(AtomicU64::new(0));

        let sessions_counter = Arc::clone(&sessions_processed);
        let incidents_counter = Arc::clone(&incidents_detected);

        tokio::spawn(async move {
            Self::process_loop(
                rx,
                db,
                ws_tx,
                sessions_counter,
                incidents_counter,
                time_policy_rx,
            )
            .await;
        });

        info!("DataSecurityEngine started");

        Self {
            tx,
            time_policy_tx,
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

    /// Reload the time policy from persistent configuration without restarting the engine.
    pub async fn reload_time_policy(
        &self,
        db: &VigilDb,
    ) -> Result<time_policy::TimePolicyConfig, String> {
        let config = Self::read_time_policy_config(db).await?;
        self.time_policy_tx.send_replace(config.clone());
        Ok(config)
    }

    async fn read_time_policy_config(
        db: &VigilDb,
    ) -> Result<time_policy::TimePolicyConfig, String> {
        let config = match db.get_time_policy_config().await {
            Ok(Some(json)) => serde_json::from_str::<time_policy::TimePolicyConfig>(&json)
                .map_err(|e| format!("Failed to parse time_policy config: {e}"))?,
            Ok(None) => time_policy::TimePolicyConfig::default(),
            Err(e) => return Err(format!("Failed to load time_policy config: {e}")),
        };
        config.validate()?;
        Ok(config)
    }

    /// HTTP SessionofDeduplicate

    /// Deduplicate only retries of the same captured session. Identical data in
    /// a new session is a new transfer and must remain observable.
    fn session_fingerprint(session: &HttpSession) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session.id.hash(&mut hasher);
        hasher.finish()
    }

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
        mut time_policy_rx: watch::Receiver<time_policy::TimePolicyConfig>,
    ) {
        // initializedetecthandler (Arc packet,For spawn_blocking Shared)
        let detectors: Arc<Vec<Box<dyn DataSecurityDetector>>> = Arc::new(vec![
            Box::new(DraftBoxDetector::new()),
            Box::new(FileTransitDetector::new()),
            Box::new(MailTransferDetector::new()),
        ]);

        // LoadtimestampstrategyConfiguration (From DB, Failed Defaultvalue)
        let mut time_policy_config = match Self::read_time_policy_config(&db).await {
            Ok(config) => config,
            Err(e) => {
                warn!("{}, using defaults", e);
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

        // Product bulk-transfer escalation (not a statutory allowance).
        let mut bulk_tracker = BulkTransferTracker::new();

        // ChunkedCheck handler (5 Check1Time/Count)
        let mut tick_interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

        // HTTP pipeline ReceiveStatistics handler (3 minute)
        // Used for 100% Stream of packet/ Session
        let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(180));

        // SessionlevelDeduplicatetable: fingerprint -> First foundtimestamp
        let mut dedup_table: HashMap<u64, DateTime<Utc>> = HashMap::with_capacity(1024);
        let mut cleanup_counter: u64 = 0;

        // Engine Statisticscounter
        let mut engine_dedup_skipped: u64 = 0;
        let mut engine_db_store_failed: u64 = 0;
        let mut engine_analyzed: u64 = 0;

        loop {
            tokio::select! {
                changed = time_policy_rx.changed() => {
                    if changed.is_err() {
                        warn!("Time policy update channel closed; stopping data security engine");
                        break;
                    }
                    time_policy_config = time_policy_rx.borrow_and_update().clone();
                    info!(
                        "Time policy reloaded: enabled={}, hours={:02}:00-{:02}:00, UTC{:+}, weekend={}",
                        time_policy_config.enabled,
                        time_policy_config.work_hour_start,
                        time_policy_config.work_hour_end,
                        time_policy_config.utc_offset_hours,
                        time_policy_config.weekend_is_off_hours,
                    );
                }
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
                        uri = %vigilyx_core::redact_http_uri(&session.uri),
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
                                uri = %vigilyx_core::redact_http_uri(&session.uri),
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
                    }

                   // store HTTP Session (F4: 含敏感键的 request_body 落库前脱敏)
                    let stored = Self::redacted_session_for_storage(&session);
                    if let Err(e) = db
                        .insert_http_session(stored.as_ref().unwrap_or(&session))
                        .await
                    {
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
                    Self::run_detectors(&detectors, &session, &db, &ws_tx, &incidents_counter, &mut volume_tracker, &mut bulk_tracker, &time_policy_config, &syslog_forwarder).await;
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

                       // storeCompositionSession (F4: 落库副本同样脱敏)
                        let stored_synthetic = Self::redacted_session_for_storage(&synthetic);
                        if let Err(e) = db
                            .insert_http_session(stored_synthetic.as_ref().unwrap_or(&synthetic))
                            .await
                        {
                            engine_db_store_failed += 1;
                            error!("Failed to store synthetic HTTP session: {}", e);
                        }

                       // linedetecthandler
                        engine_analyzed += 1;
                        let synthetic = Arc::new(synthetic);
                        Self::run_detectors(&detectors, &synthetic, &db, &ws_tx, &incidents_counter, &mut volume_tracker, &mut bulk_tracker, &time_policy_config, &syslog_forwarder).await;
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

    /// F4: 落库副本脱敏 —— request_body 含登录凭据 (如 `password=明文`) 时,
    /// 写入 http_sessions 表的副本按 redact 键表脱敏; 内存中的 session
    /// 保持原样, 供后续检测器 (DLP credential_leak 等) 分析原文。
    /// 返回 None 表示无敏感键, 调用方直接用原 session 落库 (零拷贝)。
    fn redacted_session_for_storage(session: &HttpSession) -> Option<HttpSession> {
        let body = session.request_body.as_deref()?;
        let redacted = super::redact::redact_request_body(body, session.content_type.as_deref());
        if redacted == body {
            return None;
        }
        let mut stored = session.clone();
        stored.request_body = Some(redacted);
        Some(stored)
    }

    /// Asynchronous read body tempFile (Used forChunkedUpload)

    /// Avoid async ContextMediumUse std::fs::read tokio Runtime.
    /// priorityUseMemoryMediumof request_body, tempFilestored AsynchronousreadGet.
    async fn async_read_body(session: &HttpSession) -> Vec<u8> {
        // priorityFromtempFileAsynchronousreadGet — SEC: path validation (CWE-22)
        if let Some(ref path) = session.body_temp_file {
            if let Some(data) =
                super::read_temp_path_limited_async(path, super::MAX_TEMP_BODY_READ_BYTES).await
            {
                return data;
            }
            warn!(
                "AsynchronousreadGet body tempFileFailed or blocked {}",
                path
            );
        }

        // downgradelevel: FromMemoryMediumof request_body readGet
        if let Some(ref body) = session.request_body {
            let bytes = body.as_bytes();
            let cap = bytes.len().min(super::MAX_TEMP_BODY_READ_BYTES);
            return bytes[..cap].to_vec();
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
    #[allow(clippy::too_many_arguments)]
    async fn run_detectors(
        detectors: &Arc<Vec<Box<dyn DataSecurityDetector>>>,
        session: &Arc<HttpSession>,
        db: &VigilDb,
        ws_tx: &broadcast::Sender<WsMessage>,
        incidents_counter: &Arc<AtomicU64>,
        volume_tracker: &mut VolumeAnomalyTracker,
        bulk_tracker: &mut BulkTransferTracker,
        tp_config: &time_policy::TimePolicyConfig,
        syslog_forwarder: &Option<SyslogForwarder>,
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

        // Merge field counts once per newly persisted transfer.
        let mut transfer_dlp = DlpScanResult::default();
        let mut incidents: Vec<DataSecurityIncident> = Vec::new();
        for (incident, dlp_result) in results {
            if let Some(dlp) = dlp_result
                && incident.incident_type != vigilyx_core::DataSecurityIncidentType::DraftBoxAbuse
            {
                transfer_dlp.merge(dlp);
            }
            incidents.push(incident);
        }

        let mut new_transfer_observed = false;
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

            super::financial_policy::assign_incident_id(&mut incident);
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

            match db.insert_data_security_incident(&incident).await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => {
                    error!(%error, "Failed to store data security incident");
                    continue;
                }
            }

            if incident.incident_type != vigilyx_core::DataSecurityIncidentType::DraftBoxAbuse {
                new_transfer_observed = true;
            }
            incidents_counter.fetch_add(1, Ordering::Relaxed);

            // P2.2: Stream Abnormaltracing - user IP key
            let volume_key = incident
                .detected_user
                .as_deref()
                .unwrap_or(&incident.client_ip);
            if incident.incident_type != vigilyx_core::DataSecurityIncidentType::DraftBoxAbuse
                && let Some(volume_incident) = volume_tracker.record_incident(
                    volume_key,
                    &incident.client_ip,
                    incident.detected_user.as_deref(),
                    incident.http_session_id,
                    &incident.request_url,
                    incident.host.as_deref(),
                )
            {
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

            if let Some(fwd) = syslog_forwarder.as_ref() {
                fwd.try_forward(&incident);
            }
            Self::broadcast_incident(ws_tx, incident);
        }

        // Additional bulk escalation: merged once per observed transfer, excluding drafts.
        if new_transfer_observed && !transfer_dlp.is_empty() {
            let jrt_key = session
                .detected_user
                .as_deref()
                .unwrap_or(&session.client_ip);
            {
                let bulk_incidents = bulk_tracker.record_dlp_result(
                    jrt_key,
                    &transfer_dlp,
                    &session.client_ip,
                    session.detected_user.as_deref(),
                    session.id,
                    &session.uri,
                    session.host.as_deref(),
                );
                for mut ji in bulk_incidents {
                    ji.severity = time_policy::apply_time_policy_with_config(
                        ji.severity,
                        ji.created_at,
                        tp_config,
                    );
                    incidents_counter.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = db.insert_data_security_incident(&ji).await {
                        error!("Failed to store bulk transfer incident: {}", e);
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

    #[test]
    fn retries_keep_identity_but_separate_sends_do_not_merge() {
        let first = make_http_session();
        let retry = first.clone();
        let mut second = first.clone();
        second.id = uuid::Uuid::new_v4();
        assert_eq!(
            DataSecurityEngine::session_fingerprint(&first),
            DataSecurityEngine::session_fingerprint(&retry)
        );
        assert_ne!(
            DataSecurityEngine::session_fingerprint(&first),
            DataSecurityEngine::session_fingerprint(&second)
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
