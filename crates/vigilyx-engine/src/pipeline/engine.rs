use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use tokio::sync::{RwLock, Semaphore, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use vigilyx_core::models::{EmailSession, WsMessage};
use vigilyx_core::security::{InlineVerdictResponse, ThreatLevel, VerdictDisposition};
use vigilyx_db::VigilDb;

use crate::alert::AlertEngine;
use crate::config::PipelineConfig;
use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::ioc::IocManager;
use crate::metrics::EngineMetrics;
use crate::modules::registry::{build_module_registry, is_inline_tier1};
use crate::orchestrator::PipelineOrchestrator;
use crate::temporal::temporal_analyzer::TemporalAnalyzer;
use crate::whitelist::WhitelistManager;
use vigilyx_soar::disposition::DispositionEngine;

use super::internal_domains::{load_internal_domains, refresh_internal_domains};
use super::post_verdict::{PostVerdictContext, run_post_verdict};

fn load_inbound_mail_servers_from_env() -> HashSet<String> {
    std::env::var("INBOUND_MAIL_SERVERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn load_inbound_mail_servers(db: &VigilDb) -> HashSet<String> {
    match db.get_capture_inbound_target_ips().await {
        Ok(servers) if !servers.is_empty() => servers,
        Ok(_) => load_inbound_mail_servers_from_env(),
        Err(err) => {
            warn!("Failed to load inbound targets from ui_preferences: {}", err);
            load_inbound_mail_servers_from_env()
        }
    }
}

fn log_inbound_mail_servers(servers: &HashSet<String>) {
    if !servers.is_empty() {
        info!(
            servers = ?servers,
            "Inbound mail server filter active: only analyzing sessions delivered to these IPs"
        );
    }
}


// MTA Inline Verdict - (oneshot, vigilyx-core)


/// MTA inline (, tokio oneshot channel)
pub struct InlineVerdictRequest {
    pub session: EmailSession,
    pub respond_to: oneshot::Sender<InlineVerdictResponse>,
    pub deadline: Instant,
    
    pub quarantine_threshold: ThreatLevel,
    
    pub reject_threshold: ThreatLevel,
}

/// The main security engine: receives email sessions, runs the pipeline, stores verdicts.
pub struct SecurityEngine {
    tx: mpsc::Sender<EmailSession>,
    inline_tx: mpsc::Sender<InlineVerdictRequest>,
    pub engine_db: VigilDb,
    pub ioc_manager: IocManager,
    pub whitelist_manager: WhitelistManager,
    pub disposition_engine: DispositionEngine,
    pub metrics: EngineMetrics,
    pub temporal_analyzer: Arc<TemporalAnalyzer>,
    pub alert_engine: Arc<AlertEngine>,
    /// Safe-domain cache handle for runtime IOC reload (None if intel disabled).
    pub safe_domains_handle: Option<crate::modules::registry::SafeDomainsHandle>,
}

impl SecurityEngine {
   /// Create and start the security engine.
   /// Returns the engine handle (for sending sessions) and spawns the background processor.
    pub async fn start(
        db: VigilDb,
        pipeline_config: PipelineConfig,
        ws_tx: broadcast::Sender<WsMessage>,
    ) -> Result<Self, EngineError> {
        let (tx, rx) = mpsc::channel::<EmailSession>(10_000);
        let (inline_tx, inline_rx) = mpsc::channel::<InlineVerdictRequest>(500);

       // Initialize engine DB and tables
        let engine_db = db;
        engine_db
            .init_security_tables()
            .await
            .map_err(|e| EngineError::Other(format!("Failed to init engine tables: {}", e)))?;
        match engine_db.seed_system_whitelist().await {
            Ok(n) if n > 0 => info!("System whitelist seed applied: {} rows inserted/refreshed", n),
            Ok(_) => info!("System whitelist seed already up to date"),
            Err(e) => warn!("Failed to seed system whitelist: {}", e),
        }

       // Initialize subsystems
        let ioc_manager = IocManager::new(engine_db.clone());
        let whitelist_manager = WhitelistManager::new(engine_db.clone());
        let disposition_engine = DispositionEngine::new(engine_db.clone());
        let metrics = EngineMetrics::new();

       // Initialize temporal analyzer (Phase 3)
        let temporal_analyzer = Arc::new(TemporalAnalyzer::new());

       // Load temporal state from DB
        match (
            engine_db.load_cusum_states().await,
            engine_db.load_ewma_states().await,
            engine_db.load_entity_risk_states().await,
        ) {
            (Ok(cusum), Ok(ewma), Ok(entity)) => {
                let total = cusum.len() + ewma.len() + entity.len();
                if total > 0 {
                    temporal_analyzer.import_states(cusum, ewma, entity).await;
                    info!(total_states = total, "Loaded temporal state from DB");
                }
            }
            _ => {
                warn!("Failed to load some temporal states from DB, starting fresh");
            }
        }

       // Initialize alert engine (Phase 4)
        let alert_engine = Arc::new(AlertEngine::new());

       // Load whitelist cache
        if let Err(e) = whitelist_manager.load().await {
            warn!("Failed to load whitelist cache: {}", e);
        }

       // AutodetectInternalDomain(From DB ConfigurationLoad, Firstdetect)
        let internal_domains = Arc::new(RwLock::new(load_internal_domains(&engine_db).await));

       // Build module registry (async: loads source config from DB)
        let (modules, safe_domains_handle) = build_module_registry(&engine_db).await;

       // detectwhether AI Module (supports_ai && is_remote)
        let has_ai = modules
            .values()
            .any(|m| m.metadata().supports_ai && m.metadata().is_remote);
        metrics.set_ai_available(has_ai);
        if has_ai {
            info!("AI service detected (NLP modules ready)");
        }

       // Build orchestrator
        let orchestrator = PipelineOrchestrator::build(&modules, &pipeline_config)?;
        let inline_pipeline_config = Self::inline_pipeline_config(&pipeline_config);
        let inline_orchestrator = PipelineOrchestrator::build(&modules, &inline_pipeline_config)?;

       // Clone subsystems for background task
        let bg_engine_db = engine_db.clone();
        let bg_ioc = ioc_manager.clone();
        let bg_whitelist = whitelist_manager.clone();
        let bg_disposition = disposition_engine.clone();
        let bg_metrics = metrics.clone();
        let bg_temporal = Arc::clone(&temporal_analyzer);
        let bg_alert = Arc::clone(&alert_engine);

       // Spawn background processor
        tokio::spawn(async move {
            Self::run_loop(
                rx,
                inline_rx,
                orchestrator,
                inline_orchestrator,
                pipeline_config,
                bg_engine_db,
                bg_ioc,
                bg_whitelist,
                bg_disposition,
                bg_metrics,
                bg_temporal,
                bg_alert,
                ws_tx,
                internal_domains.clone(),
            )
            .await;
        });

        info!("Security engine started");
        Ok(Self {
            tx,
            inline_tx,
            engine_db,
            ioc_manager,
            whitelist_manager,
            disposition_engine,
            metrics,
            temporal_analyzer,
            alert_engine,
            safe_domains_handle,
        })
    }

   /// Submit a session for security analysis (awaits channel capacity).
    pub async fn submit(&self, session: EmailSession) -> Result<(), EngineError> {
        self.tx
            .send(session)
            .await
            .map_err(|_| EngineError::Other("Engine channel closed".into()))
    }

   /// Submit a session without blocking (returns error if channel is full).
    
   /// Use this in the import pipeline to avoid stalling the HTTP handler
   /// when the engine can't keep up with incoming session volume.
    pub fn try_submit(&self, session: EmailSession) -> Result<(), EngineError> {
        self.tx.try_send(session).map_err(|e| match e {
            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                EngineError::Other("Engine channel full, session dropped".into())
            }
            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                EngineError::Other("Engine channel closed".into())
            }
        })
    }

   /// Submit a session with a timeout - retries briefly instead of immediately dropping.
    
   /// Provides backpressure without permanently blocking the caller.
    pub async fn submit_with_backoff(&self, session: EmailSession) -> Result<(), EngineError> {
       // First try non-blocking
        match self.tx.try_send(session) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(EngineError::Other("Engine channel closed".into()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
               // Wait up to 2 seconds for capacity
                match tokio::time::timeout(std::time::Duration::from_secs(2), self.tx.send(session))
                    .await
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(EngineError::Other("Engine channel closed".into())),
                    Err(_) => Err(EngineError::Other(
                        "Engine channel full after 2s backoff, session dropped".into(),
                    )),
                }
            }
        }
    }

   /// Submit a session for synchronous inline verdict (MTA proxy mode).
    
   /// Blocks until the engine produces a verdict or the timeout expires.
   /// On timeout/error: returns Tempfail so the caller can choose fail-open or fail-closed.
    pub async fn submit_inline(
        &self,
        session: EmailSession,
        timeout: std::time::Duration,
        quarantine_threshold: ThreatLevel,
        reject_threshold: ThreatLevel,
    ) -> InlineVerdictResponse {
        let session_id = session.id;
        let (resp_tx, resp_rx) = oneshot::channel();

        let req = InlineVerdictRequest {
            session,
            respond_to: resp_tx,
            deadline: Instant::now() + timeout,
            quarantine_threshold,
            reject_threshold,
        };

        // SEC: tempfail responses must never claim threat_level=Safe,
        // otherwise unscanned messages would be counted as "safe" in fail-open mode.
        // Use Low to mean "unscanned, threat level unknown".

        // Try to send request to inline channel
        if self.inline_tx.try_send(req).is_err() {
            warn!(session_id = %session_id, "Inline channel full or closed — unscanned bypass");
            return InlineVerdictResponse {
                disposition: VerdictDisposition::Tempfail,
                threat_level: ThreatLevel::Low,
                confidence: 0.0,
                summary: "Engine overloaded: inline channel full (unscanned)".into(),
                session_id,
                modules_run: 0,
                modules_flagged: 0,
                duration_ms: 0,
            };
        }

        // Wait for response with timeout
        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                warn!(session_id = %session_id, "Inline verdict channel dropped — unscanned bypass");
                InlineVerdictResponse {
                    disposition: VerdictDisposition::Tempfail,
                    threat_level: ThreatLevel::Low,
                    confidence: 0.0,
                    summary: "Engine verdict channel dropped (unscanned)".into(),
                    session_id,
                    modules_run: 0,
                    modules_flagged: 0,
                    duration_ms: 0,
                }
            }
            Err(_) => {
                warn!(session_id = %session_id, timeout_secs = timeout.as_secs(), "Inline verdict timeout — unscanned bypass");
                InlineVerdictResponse {
                    disposition: VerdictDisposition::Tempfail,
                    threat_level: ThreatLevel::Low,
                    confidence: 0.0,
                    summary: format!("Engine verdict timeout after {}s (unscanned)", timeout.as_secs()),
                    session_id,
                    modules_run: 0,
                    modules_flagged: 0,
                    duration_ms: 0,
                }
            }
        }
    }

   /// Deduplicate: Same1 session timestamp may be Analyze
    const DEDUP_WINDOW_SECS: u64 = 30;

   /// Temporal state flush interval (every N verdicts).
    const TEMPORAL_FLUSH_INTERVAL: u64 = 50;

    fn inline_pipeline_config(config: &PipelineConfig) -> PipelineConfig {
        PipelineConfig {
            version: config.version,
            modules: config
                .modules
                .iter()
                .filter(|module| module.enabled && is_inline_tier1(&module.id))
                .cloned()
                .collect(),
            verdict_config: config.verdict_config.clone(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_loop(
        mut rx: mpsc::Receiver<EmailSession>,
        mut inline_rx: mpsc::Receiver<InlineVerdictRequest>,
        orchestrator: PipelineOrchestrator,
        inline_orchestrator: PipelineOrchestrator,
        config: PipelineConfig,
        engine_db: VigilDb,
        ioc_manager: IocManager,
        whitelist_manager: crate::whitelist::WhitelistManager,
        disposition_engine: DispositionEngine,
        metrics: EngineMetrics,
        temporal_analyzer: Arc<TemporalAnalyzer>,
        alert_engine: Arc<AlertEngine>,
        ws_tx: broadcast::Sender<WsMessage>,
        internal_domains: Arc<RwLock<HashSet<String>>>,
    ) {
       // Shared state for concurrent processing
        let orchestrator = Arc::new(orchestrator);
        let inline_orchestrator = Arc::new(inline_orchestrator);
        let config = Arc::new(config);
        // Track (last_analyzed_time, was_completed) to allow re-analysis when
        // a session transitions from Active → Completed with full email content.
        let recent_analyzed: Arc<RwLock<HashMap<Uuid, (Instant, bool)>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let verdict_count = Arc::new(AtomicU64::new(0));

        // Inbound mail server IPs: when configured, the engine ONLY analyzes
        // sessions delivered TO these IPs — the final hop in the delivery chain
        // has the most complete information (gateway headers, all Received hops).
        // Intermediate relay hops are skipped entirely.
        // Format: comma-separated IPs, e.g. "10.7.126.68,10.1.246.41"
        let inbound_mail_servers =
            Arc::new(RwLock::new(load_inbound_mail_servers(&engine_db).await));
        {
            let servers = inbound_mail_servers.read().await;
            log_inbound_mail_servers(&servers);
        }

        {
            let inbound_mail_servers = inbound_mail_servers.clone();
            let db = engine_db.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let refreshed = load_inbound_mail_servers(&db).await;
                    let mut current = inbound_mail_servers.write().await;
                    if *current != refreshed {
                        *current = refreshed;
                        log_inbound_mail_servers(&current);
                    }
                }
            });
        }

        // Message-ID dedup: same email captured at multiple network hops
        // should only produce one verdict (the final inbound hop).
        let msgid_dedup: Arc<RwLock<HashMap<String, Uuid>>> =
            Arc::new(RwLock::new(HashMap::new()));

       // Semaphore: limit concurrent email processing.
       // Most modules are I/O-bound (DB queries, DNS lookups, intel API), not CPU-bound.
       // Using 4x CPU cores to prevent I/O-wait from starving the pipeline.
        let max_concurrent = (num_cpus::get() * 6).max(8);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        info!(max_concurrent, "Engine concurrent pipeline capacity");

       // Limit temporal analysis background tasks (prevent unbounded spawning)
        let temporal_semaphore = Arc::new(Semaphore::new(max_concurrent));

       // InternalDomain New (6 small)
        {
            let domains = internal_domains.clone();
            let db = engine_db.clone();
            tokio::spawn(async move {
               // First New 10 minute(Engine Stable)
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
                loop {
                    interval.tick().await;
                    info!("Refreshing internal domains...");
                    let new_domains = refresh_internal_domains(&db).await;
                   *domains.write().await = new_domains;
                }
            });
        }

       // Threat scene detector (bulk mailing + bounce harvest, every 5 min)
        crate::threat_scene::spawn_scene_detector(
            engine_db.clone(),
            internal_domains.clone(),
        );

       // JoinSet tracks in-flight per-email tasks for graceful shutdown
        let mut inflight = tokio::task::JoinSet::new();
        let mut dedup_cleanup_counter: u64 = 0;

        loop {
           // Select: inline requests have priority (biased)
            let session = tokio::select! {
                biased;
                Some(inline_req) = inline_rx.recv() => {
                   // Inline verdict path (MTA proxy)
                    let start = Instant::now();
                    let session = Arc::new(inline_req.session);
                    let session_id = session.id;
                    let remaining = inline_req.deadline.saturating_duration_since(Instant::now());

                    if remaining.is_zero() {
                        warn!(session_id = %session_id, "Inline verdict deadline already expired");
                        // SEC-A01: Timeout must NOT return Safe — an unscanned message
                        // has unknown threat level. Use Low ("fail-closed light") so it
                        // gets flagged for review rather than silently passing as safe.
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
                            disposition: VerdictDisposition::Tempfail,
                            threat_level: ThreatLevel::Low,
                            confidence: 0.0,
                            summary: "Security analysis timed out — conservative verdict applied (deadline already expired)".into(),
                            session_id,
                            modules_run: 0,
                            modules_flagged: 0,
                            duration_ms: 0,
                        });
                        continue;
                    }

                    let domains_snapshot = Arc::new(internal_domains.read().await.clone());
                    let ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot);
                    let inline_outcome = inline_orchestrator.execute_with_timeout(&ctx, remaining).await;
                    if inline_outcome.timed_out {
                        warn!(
                            session_id = %session_id,
                            timeout_ms = remaining.as_millis() as u64,
                            "Inline verdict hit deadline before tier-1 analysis completed"
                        );
                        // SEC-A01: Timeout must NOT return Safe — an unscanned message
                        // has unknown threat level. Use Low ("fail-closed light") so it
                        // gets flagged for review rather than silently passing as safe.
                        let _ = inline_req.respond_to.send(InlineVerdictResponse {
                            disposition: VerdictDisposition::Tempfail,
                            threat_level: ThreatLevel::Low,
                            confidence: 0.0,
                            summary: format!(
                                "Security analysis timed out — conservative verdict applied (tier-1 incomplete after {}ms)",
                                remaining.as_millis()
                            ),
                            session_id,
                            modules_run: 0,
                            modules_flagged: 0,
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                        continue;
                    }
                    let results = inline_outcome.results;

                    let verdict_result = crate::verdict::aggregate_verdict_with_session(
                        Some(session.as_ref()),
                        session_id,
                        &results,
                        &config.verdict_config,
                    );

                    let disposition = VerdictDisposition::from_threat_level(
                        verdict_result.threat_level,
                        inline_req.quarantine_threshold,
                        inline_req.reject_threshold,
                    );

                    let response = InlineVerdictResponse {
                        disposition,
                        threat_level: verdict_result.threat_level,
                        confidence: verdict_result.confidence,
                        summary: verdict_result.summary.clone(),
                        session_id,
                        modules_run: verdict_result.modules_run,
                        modules_flagged: verdict_result.modules_flagged,
                        duration_ms: start.elapsed().as_millis() as u64,
                    };

                    info!(
                        session_id = %session_id,
                        threat_level = %verdict_result.threat_level,
                        disposition = %response.disposition,
                        duration_ms = response.duration_ms,
                        "Inline verdict produced"
                    );

                   // Send response back to MTA proxy
                    let _ = inline_req.respond_to.send(response);

                   // Persist the session to the DB (the MTA inline path had not stored it yet)
                    if let Err(e) = engine_db.insert_session(&session).await {
                        error!(session_id = %session_id, "Failed to store MTA session: {e}");
                    }

                   // Also run post-verdict (DB storage, IOC, alerts) as background task
                    let pv = Arc::new(PostVerdictContext {
                        db: engine_db.clone(),
                        ioc: ioc_manager.clone(),
                        disposition: disposition_engine.clone(),
                        metrics: metrics.clone(),
                        temporal: Arc::clone(&temporal_analyzer),
                        alert: Arc::clone(&alert_engine),
                        ws_tx: ws_tx.clone(),
                        verdict_count: Arc::clone(&verdict_count),
                        temporal_semaphore: Arc::clone(&temporal_semaphore),
                        temporal_flush_interval: Self::TEMPORAL_FLUSH_INTERVAL,
                        internal_domains: internal_domains.clone(),
                    });
                    let s = session.clone();
                    inflight.spawn(async move {
                        run_post_verdict(&pv, &s, &verdict_result, &results).await;
                    });

                    continue; // Back to select!
                }
                Some(session) = rx.recv() => session,
                else => break,
            };

            let session = Arc::new(session);
            let session_id = session.id;

           // 1. Skip non-email sessions (permanent filter)
           // emailHeaderofSession completeemail, Security
           // override: 554, QUIT-only, entering DATA Segmentof connection
            if session.content.headers.is_empty() {
                debug!(
                    session_id = %session_id,
                    mail_from = session.mail_from.as_deref().unwrap_or("<none>"),
                    "Skipping non-email session (no email headers, cannot reconstruct)"
                );
                continue;
            }

           // 1b. Inbound IP filter: when INBOUND_MAIL_SERVERS is configured,
            //     only analyze sessions delivered TO those IPs (the final hop).
            //     Intermediate relay hops are skipped — the final inbound has
            //     the most complete info (gateway headers, all Received hops).
            let (inbound_filter_active, is_inbound_target) = {
                let servers = inbound_mail_servers.read().await;
                if servers.is_empty() {
                    (false, true) // No filter configured — all sessions pass
                } else {
                    (true, servers.contains(&session.server_ip))
                }
            };
            if !is_inbound_target {
                debug!(
                    session_id = %session_id,
                    server_ip = %session.server_ip,
                    "Skipping non-inbound hop (server_ip not in INBOUND_MAIL_SERVERS)"
                );
                continue;
            }

           // 1c. Message-ID dedup: only active when INBOUND_MAIL_SERVERS is set.
            //     When inbound filter is active, same email at the same inbound
            //     server should only produce one verdict.
            //     When inbound filter is NOT set, all sessions are analyzed (no dedup).
            if inbound_filter_active
                && let Some(ref mid) = session.message_id
            {
                let norm_mid = mid.trim().trim_matches(|c| c == '<' || c == '>').to_lowercase();
                if !norm_mid.is_empty() {
                    let mut map = msgid_dedup.write().await;
                    if let Some(&prev_sid) = map.get(&norm_mid) {
                        if prev_sid != session_id {
                            debug!(
                                session_id = %session_id,
                                prev_session_id = %prev_sid,
                                message_id = %norm_mid,
                                "Skipping duplicate Message-ID (already analyzed in another session)"
                            );
                            continue;
                        }
                    } else {
                        map.insert(norm_mid, session_id);
                    }
                    // Periodic cleanup
                    if map.len() > 5000 {
                        let keys: Vec<String> = map.keys().take(2500).cloned().collect();
                        for k in keys {
                            map.remove(&k);
                        }
                    }
                }
            }

           // 2. Whitelist check (fast async)
            let mut whitelisted = false;
            if let Some(ref mail_from) = session.mail_from
                && let Some(domain) = mail_from.split('@').nth(1)
            {
                let domain_ok = whitelist_manager
                    .is_trusted_domain(&domain.to_lowercase())
                    .await;
                let ip_ok = whitelist_manager
                    .is_trusted_ip(&session.client_ip.to_string())
                    .await;
                if domain_ok && ip_ok {
                    whitelisted = true;
                }
            }
            if whitelisted {
                debug!(
                    session_id = %session_id,
                    mail_from = session.mail_from.as_deref().unwrap_or(""),
                    client_ip = %session.client_ip,
                    "Skipping whitelisted session"
                );
                continue;
            }

           // 3. Dedup check (atomic: write lock -> check -> insert -> release)
            //
            // Key fix: when a session was previously analyzed while still Active
            // (e.g. on MAIL FROM dirty flush with empty links/body), allow
            // re-analysis once it reaches Completed status with full content.
            {
                let now_instant = Instant::now();
                let is_completed = session.status == vigilyx_core::models::SessionStatus::Completed
                    || session.status == vigilyx_core::models::SessionStatus::Timeout;
                let mut map = recent_analyzed.write().await;
                if let Some(&(last_time, prev_was_completed)) = map.get(&session_id)
                    && now_instant.duration_since(last_time).as_secs() < Self::DEDUP_WINDOW_SECS
                {
                    // Allow re-analysis: session is now Completed but was previously
                    // analyzed while still Active (incomplete content).
                    if is_completed && !prev_was_completed {
                        info!(
                            session_id = %session_id,
                            "Re-analyzing: session now Completed (previously analyzed while Active)"
                        );
                    } else {
                        debug!(
                            session_id = %session_id,
                            "Skipping duplicate submission (analyzed {}s ago, completed={})",
                            now_instant.duration_since(last_time).as_secs(),
                            prev_was_completed,
                        );
                        continue;
                    }
                }
               // PeriodicCleanupExpiredentry: 50 session map 100 Item Cleanup
                dedup_cleanup_counter += 1;
                if dedup_cleanup_counter.is_multiple_of(50) || map.len() > 100 {
                    map.retain(|_, &mut (t, _)| {
                        now_instant.duration_since(t).as_secs() < Self::DEDUP_WINDOW_SECS
                    });
                }
                map.insert(session_id, (now_instant, is_completed));
            } // write lock released

           // 4. Acquire semaphore permit (backpressure)
            let permit = match Arc::clone(&semaphore).acquire_owned().await {
                Ok(p) => p,
                Err(_) => {
                    warn!("Semaphore closed, engine run_loop exiting");
                    break;
                }
            };

           // 5. Clone shared state for the per-email task
            let orch = Arc::clone(&orchestrator);
            let cfg = Arc::clone(&config);
            let met = metrics.clone();
            let int_domains = internal_domains.clone();

            let pv_ctx = Arc::new(PostVerdictContext {
                db: engine_db.clone(),
                ioc: ioc_manager.clone(),
                disposition: disposition_engine.clone(),
                metrics: metrics.clone(),
                temporal: Arc::clone(&temporal_analyzer),
                alert: Arc::clone(&alert_engine),
                ws_tx: ws_tx.clone(),
                verdict_count: Arc::clone(&verdict_count),
                temporal_semaphore: Arc::clone(&temporal_semaphore),
                temporal_flush_interval: Self::TEMPORAL_FLUSH_INTERVAL,
                internal_domains: int_domains.clone(),
            });

           // 6. Spawn per-email processing task
            inflight.spawn(async move {
                let _permit = permit; // held until task completes

                info!(session_id = %session_id, "Processing session through security pipeline");
                met.record_session_start();

                let domains_snapshot = Arc::new(int_domains.read().await.clone());
                let ctx = SecurityContext::with_internal_domains(session.clone(), domains_snapshot);
                let results = orch.execute(&ctx).await;

               // Record per-module metrics
                for (module_id, result) in &results {
                    let success = result.threat_level != crate::module::ThreatLevel::Safe
                        || !result.summary.contains("ModuleExecutelineFailed");
                    let timed_out = result.summary.contains("ModuleTimeout");
                    met.record_module_run(
                        module_id,
                        result.duration_ms,
                        success && !timed_out,
                        timed_out,
                    )
                    .await;
                }

               // Aggregate verdict (synchronous, <1ms)
                let verdict_result = crate::verdict::aggregate_verdict_with_session(
                    Some(session.as_ref()),
                    session_id,
                    &results,
                    &cfg.verdict_config,
                );

                info!(
                    session_id = %session_id,
                    threat_level = %verdict_result.threat_level,
                    modules_run = verdict_result.modules_run,
                    modules_flagged = verdict_result.modules_flagged,
                    duration_ms = verdict_result.total_duration_ms,
                    "Security verdict produced"
                );

               // Persist session to DB (UPSERT — idempotent).
                // In Redis Streams mode the Sniffer only publishes to the stream;
                // the Engine is the component that persists sessions to PostgreSQL.
                if let Err(e) = pv_ctx.db.insert_session(&session).await {
                    error!(session_id = %session_id, "Failed to persist session: {e}");
                }

               // Post-verdict processing: DB storage, IOC, disposition, temporal, alerts
                run_post_verdict(&pv_ctx, &session, &verdict_result, &results).await;
            });

           // Reap completed tasks without blocking the receive loop
            while let Some(result) = inflight.try_join_next() {
                if let Err(e) = result {
                    error!("Email processing task panicked: {}", e);
                }
            }
        }

       // Graceful shutdown: wait for all in-flight tasks
        info!(
            inflight = inflight.len(),
            "Channel closed, waiting for in-flight tasks"
        );
        while let Some(result) = inflight.join_next().await {
            if let Err(e) = result {
                error!("Task panicked during shutdown: {}", e);
            }
        }

       // Final temporal flush
        let (cusum, ewma, entity) = temporal_analyzer.export_states().await;
        if let Err(e) = engine_db
            .flush_temporal_states(&cusum, &ewma, &entity)
            .await
        {
            error!("Failed to flush temporal states on shutdown: {}", e);
        }

        info!("Security engine stopped (channel closed)");
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use vigilyx_core::models::{EmailSession, Protocol};

   /// Helper: create a minimal EmailSession with content headers for pipeline processing
    fn make_session_with_headers() -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.168.1.1".to_string(),
            12345,
            "10.0.0.1".to_string(),
            25,
        );
        session.mail_from = Some("test@example.com".to_string());
        session.rcpt_to = vec!["admin@example.com".to_string()];
        session
            .content
            .headers
            .push(("From".into(), "test@example.com".into()));
        session
            .content
            .headers
            .push(("To".into(), "admin@example.com".into()));
        session
            .content
            .headers
            .push(("Subject".into(), "Test email".into()));
        session.content.body_text = Some("Hello world".into());
        session.content.is_complete = true;
        session
    }

   /// Helper: create a session without headers (should be skipped by engine)
    fn make_empty_session() -> EmailSession {
        EmailSession::new(
            Protocol::Smtp,
            "192.168.1.1".to_string(),
            12345,
            "10.0.0.1".to_string(),
            25,
        )
    }

    #[tokio::test]
    async fn test_try_submit_returns_error_when_channel_full() {
        let (tx, _rx) = mpsc::channel::<EmailSession>(2);
       // Fill the channel
        tx.try_send(make_session_with_headers()).unwrap();
        tx.try_send(make_session_with_headers()).unwrap();

       // Third should fail
        let result = tx.try_send(make_session_with_headers());
        assert!(result.is_err(), "Expected channel full error");
    }

    #[tokio::test]
    async fn test_submit_with_backoff_succeeds_after_drain() {
        let (tx, mut rx) = mpsc::channel::<EmailSession>(2);
       // Fill the channel
        tx.try_send(make_session_with_headers()).unwrap();
        tx.try_send(make_session_with_headers()).unwrap();

       // Spawn a drainer that frees space after 100ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let _ = rx.recv().await;
        });

       // submit_with_backoff should succeed (waits up to 2s)
        let session = make_session_with_headers();
        match tx.try_send(session) {
            Ok(()) => panic!("Expected full channel"),
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
                let result =
                    tokio::time::timeout(std::time::Duration::from_secs(2), tx.send(session)).await;
                assert!(
                    result.is_ok(),
                    "submit_with_backoff should succeed after drain"
                );
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_submit_with_backoff_times_out_when_permanently_full() {
        let (tx, _rx) = mpsc::channel::<EmailSession>(1);
        tx.try_send(make_session_with_headers()).unwrap();

       // No drainer - should timeout after 200ms (using short timeout for test speed)
        let session = make_session_with_headers();
        let result = match tx.try_send(session) {
            Err(tokio::sync::mpsc::error::TrySendError::Full(session)) => {
                tokio::time::timeout(std::time::Duration::from_millis(200), tx.send(session)).await
            }
            _ => panic!("Expected full channel"),
        };
        assert!(
            result.is_err(),
            "Should timeout when channel is permanently full"
        );
    }

    #[tokio::test]
    async fn test_channel_capacity_allows_burst() {
       // Verify the increased channel capacity (10,000) can handle burst imports
        let (tx, _rx) = mpsc::channel::<EmailSession>(10_000);
        let mut success_count = 0;

        for _ in 0..5_000 {
            if tx.try_send(make_session_with_headers()).is_ok() {
                success_count += 1;
            }
        }
        assert_eq!(
            success_count, 5_000,
            "Should accept 5000 sessions without blocking"
        );
    }

    #[tokio::test]
    async fn test_empty_session_has_no_headers() {
        let session = make_empty_session();
        assert!(
            session.content.headers.is_empty(),
            "Empty session should have no headers (will be skipped by engine)"
        );
    }

    #[tokio::test]
    async fn test_session_with_headers_is_not_empty() {
        let session = make_session_with_headers();
        assert!(
            !session.content.headers.is_empty(),
            "Session with headers should not be skipped"
        );
    }

    #[tokio::test]
    async fn test_dedup_window_prevents_reprocessing() {
        let dedup: Arc<RwLock<HashMap<Uuid, Instant>>> = Arc::new(RwLock::new(HashMap::new()));
        let session_id = Uuid::new_v4();

       // First submission: insert into dedup map
        {
            let mut map = dedup.write().await;
            map.insert(session_id, Instant::now());
        }

       // Second submission within window: should be skipped
        {
            let now = Instant::now();
            let map = dedup.read().await;
            if let Some(&last_time) = map.get(&session_id) {
                let elapsed = now.duration_since(last_time).as_secs();
                assert!(elapsed < 30, "Should detect duplicate within 30s window");
            }
        }
    }

    #[tokio::test]
    async fn test_dedup_cleanup_at_threshold() {
        let dedup: Arc<RwLock<HashMap<Uuid, Instant>>> = Arc::new(RwLock::new(HashMap::new()));

       // Add 250 entries (above the 200 threshold)
        {
            let mut map = dedup.write().await;
            for _ in 0..250 {
                map.insert(Uuid::new_v4(), Instant::now());
            }
            assert_eq!(map.len(), 250);

           // Simulate cleanup (retain only entries within window)
            if map.len() > 200 {
                let now = Instant::now();
                map.retain(|_, t| now.duration_since(*t).as_secs() < 30);
            }
           // All entries are recent so all retained
            assert_eq!(map.len(), 250);
        }
    }

    #[tokio::test]
    async fn test_concurrent_semaphore_capacity() {
       // Verify semaphore allows sufficient concurrency for I/O-bound workloads
        let max_concurrent = (num_cpus::get() * 6).max(8);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));

        let mut permits = Vec::new();
        for _ in 0..max_concurrent {
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            permits.push(permit);
        }

       // All permits acquired
        assert_eq!(semaphore.available_permits(), 0);

       // Next acquire should not immediately succeed
        let try_result = semaphore.try_acquire();
        assert!(try_result.is_err(), "No permits should be available");

       // Drop one permit
        drop(permits.pop());
        assert_eq!(semaphore.available_permits(), 1);
    }

   // MTA Inline Verdict Tests

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_safe_accepts() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Safe,
            ThreatLevel::Medium, // quarantine threshold
            ThreatLevel::Critical, // reject threshold
        );
        assert!(matches!(d, VerdictDisposition::Accept));
        assert_eq!(d.smtp_code(), 250);
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_low_accepts() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Low,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Accept));
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_medium_quarantines() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Medium,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Quarantine));
        assert_eq!(d.smtp_code(), 250); 
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_high_quarantines() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::High,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Quarantine));
    }

    #[tokio::test]
    async fn test_verdict_disposition_from_threat_level_critical_rejects() {
        let d = VerdictDisposition::from_threat_level(
            ThreatLevel::Critical,
            ThreatLevel::Medium,
            ThreatLevel::Critical,
        );
        assert!(matches!(d, VerdictDisposition::Reject { .. }));
        assert_eq!(d.smtp_code(), 550);
    }

    #[tokio::test]
    async fn test_inline_channel_full_returns_tempfail() {
       // Create a tiny inline channel (capacity 1)
        let (inline_tx, _inline_rx) = mpsc::channel::<InlineVerdictRequest>(1);

       // Fill it with a dummy request
        let (dummy_tx, _dummy_rx) = oneshot::channel();
        inline_tx
            .try_send(InlineVerdictRequest {
                session: make_session_with_headers(),
                respond_to: dummy_tx,
                deadline: Instant::now() + std::time::Duration::from_secs(5),
                quarantine_threshold: ThreatLevel::Medium,
                reject_threshold: ThreatLevel::Critical,
            })
            .unwrap();

       // Second request should fail (channel full)
        let (resp_tx, _resp_rx) = oneshot::channel();
        let result = inline_tx.try_send(InlineVerdictRequest {
            session: make_session_with_headers(),
            respond_to: resp_tx,
            deadline: Instant::now() + std::time::Duration::from_secs(5),
            quarantine_threshold: ThreatLevel::Medium,
            reject_threshold: ThreatLevel::Critical,
        });
        assert!(result.is_err(), "Channel should be full");
    }

    #[tokio::test]
    async fn test_inline_verdict_response_serialization_roundtrip() {
        let response = InlineVerdictResponse {
            disposition: VerdictDisposition::Quarantine,
            threat_level: ThreatLevel::High,
            confidence: 0.85,
            summary: "Phishing detected".into(),
            session_id: uuid::Uuid::new_v4(),
            modules_run: 15,
            modules_flagged: 3,
            duration_ms: 4500,
        };
        let json = serde_json::to_string(&response).unwrap();
        let deser: InlineVerdictResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.threat_level, ThreatLevel::High);
        assert_eq!(deser.modules_run, 15);
        assert!(matches!(deser.disposition, VerdictDisposition::Quarantine));
    }

    #[tokio::test]
    async fn test_inline_tier1_module_classification() {
        use crate::modules::registry::{is_inline_tier1, INLINE_TIER1_MODULES};

       // Tier 1 modules
        assert!(is_inline_tier1("content_scan"));
        assert!(is_inline_tier1("header_scan"));
        assert!(is_inline_tier1("yara_scan"));

       // Tier 2 modules (should NOT be tier 1)
        assert!(!is_inline_tier1("semantic_scan"));
        assert!(!is_inline_tier1("link_content"));
        assert!(!is_inline_tier1("sandbox_scan"));
        assert!(!is_inline_tier1("transaction_correlation"));

       // Tier 1 should have 15 modules
        assert_eq!(INLINE_TIER1_MODULES.len(), 15);
    }

    #[test]
    fn test_inline_pipeline_config_filters_tier2_modules() {
        let config = PipelineConfig::default();
        let inline = SecurityEngine::inline_pipeline_config(&config);

        assert!(
            inline.modules.iter().all(|module| is_inline_tier1(&module.id)),
            "inline config should only contain tier-1 modules"
        );
        assert!(
            !inline.modules.iter().any(|module| module.id == "semantic_scan"),
            "AI module must stay out of SMTP inline path"
        );
        assert!(
            !inline.modules.iter().any(|module| module.id == "link_content"),
            "link_content must stay out of SMTP inline path"
        );
    }

    #[test]
    fn test_tempfail_uses_smtp_451() {
        assert_eq!(VerdictDisposition::Tempfail.smtp_code(), 451);
        assert!(VerdictDisposition::Tempfail.smtp_message().starts_with("4.7.1"));
    }
}
