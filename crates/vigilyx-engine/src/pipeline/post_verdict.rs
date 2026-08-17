//! Post-verdict processing: IOC recording, disposition, temporal analysis, and alerting.

//! After a security verdict is produced, this module handles all the downstream
//! side effects: storing results, recording IOCs, evaluating disposition rules,
//! running temporal analysis, and generating alerts.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::sync::{RwLock, Semaphore, broadcast};
use tracing::{debug, error};
use uuid::Uuid;
use vigilyx_core::models::{EmailSession, SecurityVerdictSummary, WsMessage};
use vigilyx_core::security::{AlertLevel, AlertRecord};
use vigilyx_db::VigilDb;

use crate::alert::AlertEngine;
use crate::ioc::IocManager;
use crate::metrics::EngineMetrics;
use crate::temporal::temporal_analyzer::TemporalAnalyzer;
use vigilyx_core::security::SecurityVerdict;
use vigilyx_soar::alert::AlertSignals;
use vigilyx_soar::disposition::DispositionEngine;

/// All the shared state needed by post-verdict processing.

/// Bundled into a struct to avoid passing 10+ arguments through the task boundary.
pub(crate) struct PostVerdictContext {
    pub db: VigilDb,
    pub ioc: IocManager,
    pub disposition: DispositionEngine,
    pub metrics: EngineMetrics,
    pub temporal: Arc<TemporalAnalyzer>,
    pub alert: Arc<AlertEngine>,
    pub ws_tx: broadcast::Sender<WsMessage>,
    pub verdict_count: Arc<AtomicU64>,
    pub temporal_semaphore: Arc<Semaphore>,
    pub temporal_flush_interval: u64,
    pub internal_domains: Arc<RwLock<HashSet<String>>>,
}

/// Process-wide rate limit for P3 (lowest-severity) alert inserts/broadcasts.
///
/// Every email scoring ≥ 0.15 (Low) used to produce one P3 row plus one WS
/// broadcast; the per-(session, level) 10-minute dedup does nothing across
/// sessions, so an attacker spraying N borderline emails flooded the alert
/// center with N junk P3 rows. A sliding one-minute window caps P3 alerts
/// process-wide; overflow is counted and surfaced as ONE aggregate summary
/// alert when the next window opens, so the flood stays visible without
/// burying the console.
const P3_ALERTS_PER_MINUTE: u32 = 30;

#[derive(Debug, Default)]
struct P3RateWindow {
    window_start: Option<Instant>,
    admitted: u32,
    suppressed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum P3RateDecision {
    /// Under the limit: proceed with the alert.
    Allow,
    /// First alert of a fresh window after suppression: proceed, and also
    /// emit one aggregate summary for the `u64` suppressed alerts.
    AllowWithSummary(u64),
    /// Over the limit: drop the alert, only count it.
    Suppress,
}

fn admit_p3_alert(window: &mut P3RateWindow, now: Instant) -> P3RateDecision {
    let window_expired = window
        .window_start
        .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(60));
    if window_expired {
        let suppressed = std::mem::take(&mut window.suppressed);
        window.window_start = Some(now);
        window.admitted = 1;
        return if suppressed > 0 {
            P3RateDecision::AllowWithSummary(suppressed)
        } else {
            P3RateDecision::Allow
        };
    }
    if window.admitted < P3_ALERTS_PER_MINUTE {
        window.admitted += 1;
        P3RateDecision::Allow
    } else {
        window.suppressed += 1;
        P3RateDecision::Suppress
    }
}

static P3_RATE_WINDOW: Mutex<P3RateWindow> = Mutex::new(P3RateWindow {
    window_start: None,
    admitted: 0,
    suppressed: 0,
});

/// Gate a P3 alert insert/broadcast through the process-wide rate limiter.
/// Returns `false` when the alert must be dropped as flood overflow.
async fn p3_alert_admitted(db: &VigilDb, ws_tx: &broadcast::Sender<WsMessage>) -> bool {
    let decision = {
        let mut window = P3_RATE_WINDOW.lock().unwrap_or_else(|p| p.into_inner());
        admit_p3_alert(&mut window, Instant::now())
    };
    match decision {
        P3RateDecision::Allow => true,
        P3RateDecision::Suppress => {
            debug!("P3 alert dropped by global rate limit (flood protection)");
            false
        }
        P3RateDecision::AllowWithSummary(suppressed) => {
            // Aggregate marker uses the nil UUID as session/verdict so it
            // never collides with a real session's dedup key.
            let rationale = format!(
                "P3 alert flood rate-limited: {suppressed} low-severity alerts suppressed \
                 in the last minute (global cap {P3_ALERTS_PER_MINUTE}/min)"
            );
            let record = AlertRecord {
                id: Uuid::new_v4(),
                verdict_id: Uuid::nil(),
                session_id: Uuid::nil(),
                alert_level: AlertLevel::P3,
                expected_loss: 0.0,
                return_period: 0.0,
                cvar: 0.0,
                risk_final: 0.0,
                k_conflict: 0.0,
                cusum_alarm: false,
                rationale: rationale.clone(),
                acknowledged: false,
                acknowledged_by: None,
                acknowledged_at: None,
                created_at: Utc::now(),
            };
            match db.insert_alert(&record).await {
                Ok(true) => {
                    let _ = ws_tx.send(WsMessage::Alert(format!("[P3] {rationale}")));
                }
                Ok(false) => debug!("P3 flood summary alert deduplicated"),
                Err(e) => error!("Failed to store P3 flood summary alert: {}", e),
            }
            true
        }
    }
}

/// Run all post-verdict processing for a single email session.

/// This includes:
/// 1. Storing verdict and module results to DB
/// 2. Auto-recording IOCs from verdict
/// 3. Broadcasting verdict via WebSocket
/// 4. Evaluating disposition rules
/// 5. Temporal analysis + alert evaluation (spawned as background sub-task)
/// 6. Periodic temporal state flush
pub(crate) async fn run_post_verdict(
    ctx: &PostVerdictContext,
    session: &Arc<EmailSession>,
    verdict_result: &SecurityVerdict,
    results: &std::collections::HashMap<String, crate::module::ModuleResult>,
) {
    let session_id = session.id;

    // 1. Store verdict and module results to DB atomically (single
    // transaction): concurrent analyses of the same session must never leave
    // a verdict from analysis A next to module rows from analysis B.
    let results_refs: Vec<&_> = results.values().collect();
    if let Err(e) = ctx
        .db
        .insert_verdict_with_module_results(verdict_result, &results_refs)
        .await
    {
        error!(
            session_id = %session_id,
            "Failed to store verdict and module results: {}", e
        );
    }

    // 2. Auto-record IOC if threat_level>= High
    // Security: UPSERT Use Connect (MAX),confidence downgrade;
    // auto IOC 30 DayExpired;admin_clean Name override.
    ctx.ioc
        .auto_record_from_verdict(session, verdict_result)
        .await;
    {
        let domains = ctx.internal_domains.read().await;
        ctx.ioc
            .auto_record_internal_spoofing(session, verdict_result, &domains)
            .await;
    }

    // Auto-record domain impersonation IOC (self-learning loop):
    // When header_scan detects a domain impersonation hit and the overall
    // verdict is >= High, record the spoofing domain as a malicious IOC so
    // future emails from the same domain get an automatic score boost in
    // Step 5c of header_scan.
    if let Some(hs_result) = results.get("header_scan")
        && let Some(imp_hit) = hs_result.details.get("impersonation_hit")
        && let (Some(sender), Some(target), Some(sim_type), Some(score)) = (
            imp_hit.get("sender_domain").and_then(|v| v.as_str()),
            imp_hit.get("target_domain").and_then(|v| v.as_str()),
            imp_hit.get("similarity_type").and_then(|v| v.as_str()),
            imp_hit.get("score").and_then(|v| v.as_f64()),
        )
    {
        ctx.ioc
            .auto_record_impersonation_domain(
                session,
                verdict_result,
                sender,
                target,
                sim_type,
                score,
            )
            .await;
    }

    if let Some(sem_result) = results.get("semantic_scan")
        && sem_result.threat_level >= crate::module::ThreatLevel::Medium
    {
        ctx.ioc.auto_record_nonsensical(session, sem_result).await;
    }

    // 3. Broadcast verdict via WebSocket
    let summary = SecurityVerdictSummary {
        verdict_id: verdict_result.id,
        session_id: verdict_result.session_id,
        threat_level: verdict_result.threat_level.to_string(),
        confidence: verdict_result.confidence,
        categories: verdict_result.categories.clone(),
        summary: verdict_result.summary.clone(),
        modules_run: verdict_result.modules_run,
        modules_flagged: verdict_result.modules_flagged,
        total_duration_ms: verdict_result.total_duration_ms,
    };
    let _ = ctx.ws_tx.send(WsMessage::SecurityVerdict(summary));

    // 3b. Surface incomplete-inspection coverage gaps (parser Err, truncated
    // capture, scan budget exhausted) as a P3 alert — otherwise a Safe verdict
    // caused by missing evidence is invisible to operators. The alert insert
    // is deduplicated per (session, level) so concurrent rescan paths do not
    // double-report the same gap.
    maybe_alert_incomplete_inspection(ctx, session, verdict_result).await;

    // 4. Evaluate disposition rules + email alerts
    ctx.disposition.evaluate(verdict_result, session).await;

    // 5. Temporal analysis (spawned as background sub-task)
    spawn_temporal_analysis(ctx, session, verdict_result);

    // 6. Periodic temporal state flush
    let count = ctx.verdict_count.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_multiple_of(ctx.temporal_flush_interval) {
        let temporal = Arc::clone(&ctx.temporal);
        let db = ctx.db.clone();
        tokio::spawn(async move {
            let (cusum, ewma, entity) = temporal.export_states().await;
            if let Err(e) = db.flush_temporal_states(&cusum, &ewma, &entity).await {
                error!("Failed to flush temporal states: {}", e);
            } else {
                debug!(
                    cusum = cusum.len(),
                    ewma = ewma.len(),
                    entity = entity.len(),
                    "Flushed temporal states to DB"
                );
            }
        });
    }

    ctx.metrics.record_verdict();
}

/// Spawn temporal analysis and alert evaluation as a background sub-task.
fn spawn_temporal_analysis(
    ctx: &PostVerdictContext,
    session: &Arc<EmailSession>,
    verdict_result: &SecurityVerdict,
) {
    let sender = session.mail_from.as_deref().unwrap_or("").to_string();
    let risk_single = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.risk_single)
        .unwrap_or_else(|| verdict_result.threat_level.as_numeric());

    if sender.is_empty() {
        return;
    }

    let temporal = Arc::clone(&ctx.temporal);
    let alert = Arc::clone(&ctx.alert);
    let db = ctx.db.clone();
    let verdict_id = verdict_result.id;
    let v_session_id = verdict_result.session_id;
    let session_for_temporal = Arc::clone(session);
    let ws = ctx.ws_tx.clone();
    let temporal_sem = Arc::clone(&ctx.temporal_semaphore);

    let u_final = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.fused_bpa.u)
        .unwrap_or(0.3);
    let k_conflict = verdict_result
        .fusion_details
        .as_ref()
        .map(|fd| fd.k_conflict)
        .unwrap_or(0.0);
    let novelty = verdict_result
        .fusion_details
        .as_ref()
        .and_then(|fd| fd.novelty);
    let k_cross = verdict_result
        .fusion_details
        .as_ref()
        .and_then(|fd| fd.k_cross);

    tokio::spawn(async move {
        // Limit concurrent temporal tasks to prevent resource exhaustion
        let _temporal_permit = match temporal_sem.acquire().await {
            Ok(p) => p,
            Err(_) => return, // semaphore closed
        };
        let obs = crate::temporal::temporal_analyzer::TemporalObservation {
            sender: &sender,
            recipients: &session_for_temporal.rcpt_to,
            risk_single,
            u_final,
            k_conflict,
            content_similarity_delta: 0.0,
        };
        let temporal_result = temporal.analyze_full(&obs).await;

        let risk_final = if temporal_result.risk_upgraded {
            risk_single.max(temporal_result.temporal_risk)
        } else {
            risk_single
        };
        alert.observe(risk_final).await;

        let signals = temporal_to_signals(&temporal_result);
        if let Some(decision) = alert
            .evaluate(
                risk_final,
                k_conflict,
                u_final,
                novelty,
                k_cross,
                Some(&signals),
                &session_for_temporal.rcpt_to,
            )
            .await
        {
            // Flood protection: P3 is the default level for every email
            // scoring >= 0.15, so cap it process-wide; higher severities are
            // never rate-limited.
            let admitted =
                decision.level != AlertLevel::P3 || p3_alert_admitted(&db, &ws).await;
            if admitted {
                let record = AlertEngine::to_record(&decision, verdict_id, v_session_id);
                match db.insert_alert(&record).await {
                    Ok(true) => {
                        let _ = ws.send(WsMessage::Alert(format!(
                            "[{}] session={} EL={:.2} — {}",
                            decision.level.as_str(),
                            v_session_id,
                            decision.expected_loss,
                            decision.rationale.join("; ")
                        )));
                    }
                    Ok(false) => {
                        debug!(
                            verdict_id = %verdict_id,
                            "Suppressed duplicate alert for session within dedup window"
                        );
                    }
                    Err(e) => {
                        error!(verdict_id = %verdict_id, "Failed to store alert: {}", e);
                    }
                }
            }
        }

        if temporal_result.risk_upgraded {
            debug!(
                sender = sender.as_str(),
                temporal_risk = temporal_result.temporal_risk,
                "Temporal analysis upgraded risk"
            );
        }
    });
}

/// Write a P3 alert when the verdict carries incomplete-inspection metadata
/// or the session failed with an `inspection:` capture/parse error. A Safe
/// verdict that exists only because evidence was missing must not be silent.
async fn maybe_alert_incomplete_inspection(
    ctx: &PostVerdictContext,
    session: &EmailSession,
    verdict: &SecurityVerdict,
) {
    let Some(reason) = incomplete_inspection_alert_reason(session, verdict) else {
        return;
    };

    // Flood protection: `.rar` attachments etc. flag `inspection_limited`
    // unconditionally, so an attacker can mint unlimited P3 rows; cap them
    // process-wide (higher severities are never rate-limited).
    if !p3_alert_admitted(&ctx.db, &ctx.ws_tx).await {
        return;
    }

    let record = AlertRecord {
        id: Uuid::new_v4(),
        verdict_id: verdict.id,
        session_id: verdict.session_id,
        alert_level: AlertLevel::P3,
        expected_loss: 0.0,
        return_period: 0.0,
        cvar: 0.0,
        risk_final: verdict.confidence,
        k_conflict: 0.0,
        cusum_alarm: false,
        rationale: format!(
            "Inspection incomplete — threat level reflects captured evidence only: {reason}"
        ),
        acknowledged: false,
        acknowledged_by: None,
        acknowledged_at: None,
        created_at: Utc::now(),
    };
    match ctx.db.insert_alert(&record).await {
        Ok(true) => {
            let _ = ctx.ws_tx.send(WsMessage::Alert(format!(
                "[P3] session={} — {}",
                verdict.session_id, record.rationale
            )));
        }
        Ok(false) => {
            debug!(
                session_id = %verdict.session_id,
                "Suppressed duplicate inspection-incomplete alert"
            );
        }
        Err(e) => {
            error!(
                session_id = %verdict.session_id,
                "Failed to store inspection-incomplete alert: {}", e
            );
        }
    }
}

/// Decide whether a verdict/session pair describes an incomplete inspection
/// and, if so, produce a human-readable reason for the P3 alert rationale.
fn incomplete_inspection_alert_reason(
    session: &EmailSession,
    verdict: &SecurityVerdict,
) -> Option<String> {
    let inspection_error = session
        .error_reason
        .as_deref()
        .filter(|reason| reason.starts_with("inspection:"));
    let coverage_flag = crate::pipeline::verdict::has_incomplete_inspection(verdict);
    match (coverage_flag, inspection_error) {
        (false, None) => None,
        (true, Some(error)) => Some(format!("inspection coverage incomplete; capture error: {error}")),
        (true, None) => Some("inspection coverage incomplete".to_string()),
        (false, Some(error)) => Some(format!("capture error: {error}")),
    }
}

/// Convert engine-internal `TemporalResult` to the decoupled `AlertSignals` for vigilyx-soar.
fn temporal_to_signals(t: &crate::temporal::temporal_analyzer::TemporalResult) -> AlertSignals {
    AlertSignals {
        cusum_alarm: t.cusum_alarm,
        hmm_trust_building: t
            .hmm_phase
            .as_ref()
            .map(|h| h.trust_building)
            .unwrap_or(0.0),
        hmm_attack_execution: t
            .hmm_phase
            .as_ref()
            .map(|h| h.attack_execution)
            .unwrap_or(0.0),
        sender_watchlisted: t.sender_watchlisted,
        sender_risk: t.sender_risk,
        ewma_drifting: t.ewma_drifting,
        ewma_drift_score: t.ewma_drift_score,
        graph_anomalous: t
            .graph_anomaly
            .as_ref()
            .map(|g| g.is_anomalous)
            .unwrap_or(false),
        graph_pattern_label: t
            .graph_anomaly
            .as_ref()
            .map(|g| g.pattern_label.clone())
            .unwrap_or_default(),
        hawkes_intensity_ratio: t.hawkes.as_ref().map(|h| h.intensity_ratio).unwrap_or(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        P3_ALERTS_PER_MINUTE, P3RateDecision, P3RateWindow, admit_p3_alert,
        incomplete_inspection_alert_reason,
    };
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use uuid::Uuid;
    use vigilyx_core::models::{EmailSession, Protocol};
    use vigilyx_core::security::{SecurityVerdict, ThreatLevel};

    fn make_session() -> EmailSession {
        EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        )
    }

    fn make_verdict(categories: &[&str]) -> SecurityVerdict {
        SecurityVerdict {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            threat_level: ThreatLevel::Safe,
            confidence: 0.5,
            categories: categories.iter().map(|c| (*c).to_string()).collect(),
            summary: "test verdict".to_string(),
            pillar_scores: HashMap::new(),
            modules_run: 15,
            modules_flagged: 0,
            total_duration_ms: 10,
            created_at: Utc::now(),
            fusion_details: None,
        }
    }

    #[test]
    fn inspection_error_reason_alone_triggers_p3_alert_reason() {
        // Attack surface (round 4): a MIME parser Err leaves a Safe verdict
        // whose only trace is session.error_reason — before the fix nobody
        // ever surfaced it.
        let mut session = make_session();
        session.error_reason = Some("inspection:mime_parse_failed:NoBoundary".to_string());
        let verdict = make_verdict(&[]);

        let reason = incomplete_inspection_alert_reason(&session, &verdict)
            .expect("inspection: error_reason must produce a P3 alert reason");
        assert!(reason.contains("inspection:mime_parse_failed"));
    }

    #[test]
    fn incomplete_coverage_category_alone_triggers_p3_alert_reason() {
        let session = make_session();
        let verdict = make_verdict(&["inspection_coverage_incomplete"]);

        let reason = incomplete_inspection_alert_reason(&session, &verdict)
            .expect("inspection coverage category must produce a P3 alert reason");
        assert!(reason.contains("inspection coverage incomplete"));
    }

    #[test]
    fn clean_verdict_without_inspection_metadata_stays_silent() {
        // Regression protection: a normal fully-analyzed Safe verdict must not
        // generate any alert.
        let session = make_session();
        let verdict = make_verdict(&[]);
        assert!(incomplete_inspection_alert_reason(&session, &verdict).is_none());

        // An unrelated session error (not an inspection gap) must not alert.
        let mut session = make_session();
        session.error_reason = Some("connection reset by peer".to_string());
        assert!(incomplete_inspection_alert_reason(&session, &verdict).is_none());
    }

    #[test]
    fn p3_rate_limiter_admits_up_to_cap_then_suppresses() {
        // PoC (D1): before the fix, every Low+ email produced one P3 alert
        // row + WS broadcast, so an attacker spraying N borderline emails
        // (e.g. unconditional `inspection_limited` from .rar attachments)
        // flooded the alert center with N rows. The limiter must bound P3
        // inserts per minute process-wide.
        let mut window = P3RateWindow::default();
        let t0 = Instant::now();
        for i in 0..P3_ALERTS_PER_MINUTE {
            assert_eq!(
                admit_p3_alert(&mut window, t0 + Duration::from_secs(1)),
                P3RateDecision::Allow,
                "alert #{i} within the cap must be admitted"
            );
        }
        assert_eq!(
            admit_p3_alert(&mut window, t0 + Duration::from_secs(2)),
            P3RateDecision::Suppress,
            "alert beyond the cap must be suppressed"
        );
        assert_eq!(
            admit_p3_alert(&mut window, t0 + Duration::from_secs(59)),
            P3RateDecision::Suppress
        );
    }

    #[test]
    fn p3_rate_limiter_aggregates_suppressed_count_into_next_window() {
        // Suppressed alerts must not vanish silently: the first alert of the
        // next window carries the aggregate count as ONE summary alert.
        let mut window = P3RateWindow::default();
        let t0 = Instant::now();
        for _ in 0..P3_ALERTS_PER_MINUTE {
            let _ = admit_p3_alert(&mut window, t0);
        }
        for _ in 0..2 {
            assert_eq!(admit_p3_alert(&mut window, t0), P3RateDecision::Suppress);
        }

        assert_eq!(
            admit_p3_alert(&mut window, t0 + Duration::from_secs(61)),
            P3RateDecision::AllowWithSummary(2)
        );
        // The summary is emitted once; the window then behaves normally.
        assert_eq!(
            admit_p3_alert(&mut window, t0 + Duration::from_secs(62)),
            P3RateDecision::Allow
        );
    }

    #[test]
    fn p3_rate_limiter_fresh_window_without_suppression_is_plain_allow() {
        let mut window = P3RateWindow::default();
        let t0 = Instant::now();
        assert_eq!(admit_p3_alert(&mut window, t0), P3RateDecision::Allow);
        assert_eq!(
            admit_p3_alert(&mut window, t0 + Duration::from_secs(120)),
            P3RateDecision::Allow
        );
    }
}
