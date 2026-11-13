//! Periodic threat scene detection: bulk mailing + bounce/NDR harvest + internal domain impersonation.
//!
//! Runs as a background tokio task, scanning the DB every 5 minutes for
//! cross-session behavioral patterns that indicate email threat scenarios.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use vigilyx_core::security::{
    BounceHarvestConfig, BulkMailingConfig, InternalDomainImpersonationConfig, IocEntry,
    ThreatLevel, ThreatScene, ThreatSceneStatus, ThreatSceneType,
};
use vigilyx_db::VigilDb;
use vigilyx_db::security::threat_scene::BounceHarvestRow;
use vigilyx_soar::disposition::DispositionEngine;

/// Scan interval: 5 minutes.
const SCAN_INTERVAL_SECS: u64 = 300;

/// Initial delay before first scan (let engine stabilize).
const INITIAL_DELAY_SECS: u64 = 120;

async fn persist_scene(
    db: &VigilDb,
    disposition: &DispositionEngine,
    scene: &ThreatScene,
) -> anyhow::Result<()> {
    db.upsert_threat_scene(scene).await?;
    disposition.evaluate_scene(scene).await;
    Ok(())
}

/// Spawn the background threat scene detector.
pub fn spawn_scene_detector(
    db: VigilDb,
    internal_domains: Arc<RwLock<HashSet<String>>>,
    disposition: DispositionEngine,
) {
    tokio::spawn(async move {
        // Wait for engine to stabilize
        tokio::time::sleep(std::time::Duration::from_secs(INITIAL_DELAY_SECS)).await;
        info!(
            "Threat scene detector started, scan interval {}s",
            SCAN_INTERVAL_SECS
        );

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(SCAN_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let domains = internal_domains.read().await.clone();
            if domains.is_empty() {
                continue;
            }
            if let Err(e) = run_detection_cycle(&db, &domains, &disposition).await {
                error!("Threat scene detection cycle failed: {e}");
            }
        }
    });
}

/// Run one full detection cycle (bulk mailing + bounce harvest + internal domain impersonation).
async fn run_detection_cycle(
    db: &VigilDb,
    internal_domains: &HashSet<String>,
    disposition: &DispositionEngine,
) -> anyhow::Result<()> {
    // Load scene rules
    let rules = db.get_scene_rules().await?;

    let domain_list: Vec<String> = internal_domains.iter().cloned().collect();

    // 1. Bulk mailing detection
    if let Some(rule) = rules
        .iter()
        .find(|r| r.scene_type == ThreatSceneType::BulkMailing)
        && rule.enabled
    {
        match serde_json::from_value::<BulkMailingConfig>(rule.config.clone()) {
            Ok(config) => match config.validate() {
                Ok(()) => detect_bulk_mailing(db, &domain_list, &config, disposition).await?,
                Err(error) => {
                    warn!(scene = "bulk_mailing", %error, "Invalid threat scene configuration; skipping cycle")
                }
            },
            Err(error) => {
                warn!(scene = "bulk_mailing", %error, "Invalid threat scene configuration; skipping cycle")
            }
        }
    }

    // 2. Bounce harvest detection
    if let Some(rule) = rules
        .iter()
        .find(|r| r.scene_type == ThreatSceneType::BounceHarvest)
        && rule.enabled
    {
        let backfilled = db.backfill_recent_bounce_metadata(72, 500).await?;
        if backfilled > 0 {
            info!(backfilled, "Backfilled structured bounce metadata");
        }
        match serde_json::from_value::<BounceHarvestConfig>(rule.config.clone()) {
            Ok(config) => match config.validate() {
                Ok(()) => detect_bounce_harvest(db, &domain_list, &config, disposition).await?,
                Err(error) => {
                    warn!(scene = "bounce_harvest", %error, "Invalid threat scene configuration; skipping cycle")
                }
            },
            Err(error) => {
                warn!(scene = "bounce_harvest", %error, "Invalid threat scene configuration; skipping cycle")
            }
        }
    }

    // 3. Internal domain impersonation detection
    if let Some(rule) = rules
        .iter()
        .find(|r| r.scene_type == ThreatSceneType::InternalDomainImpersonation)
        && rule.enabled
    {
        match serde_json::from_value::<InternalDomainImpersonationConfig>(rule.config.clone()) {
            Ok(config) => match config.validate() {
                Ok(()) => {
                    detect_internal_impersonation(db, &domain_list, &config, disposition).await?
                }
                Err(error) => {
                    warn!(scene = "internal_domain_impersonation", %error, "Invalid threat scene configuration; skipping cycle")
                }
            },
            Err(error) => {
                warn!(scene = "internal_domain_impersonation", %error, "Invalid threat scene configuration; skipping cycle")
            }
        }
    }

    // 4. Auto-resolve stale scenes
    let resolved = db.auto_resolve_stale_scenes().await?;
    if resolved > 0 {
        info!("Auto-resolved {resolved} stale threat scenes");
    }

    Ok(())
}

// ─── Bulk Mailing Detection ─────────────────────────────────────────────

async fn detect_bulk_mailing(
    db: &VigilDb,
    internal_domains: &[String],
    config: &BulkMailingConfig,
    disposition: &DispositionEngine,
) -> anyhow::Result<()> {
    let hits = db.detect_bulk_mailing(internal_domains, config).await?;
    if hits.is_empty() {
        return Ok(());
    }

    for hit in &hits {
        let severity = bulk_mailing_severity(hit.unique_recipients, hit.email_count);

        // Check if an active scene already exists for this actor
        let existing = db
            .find_active_scene("bulk_mailing", &hit.sender_domain)
            .await?;

        let now = Utc::now();

        if let Some(mut scene) = existing {
            // Update existing scene
            scene.email_count = hit.email_count as i32;
            scene.unique_recipients = hit.unique_recipients as i32;
            scene.time_window_end = chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            scene.threat_level = severity;
            scene.sample_subjects = hit.sample_subjects.clone();
            scene.sample_recipients = hit.sample_recipients.clone();
            scene.updated_at = now;

            // Auto-block upgrade
            if config.auto_block_enabled
                && !scene.auto_blocked
                && hit.unique_recipients >= config.auto_block_recipient_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "bulk_mailing",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: sent {} emails to {} internal recipients within {}h",
                        hit.email_count, hit.unique_recipients, config.time_window_hours
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    recipients = hit.unique_recipients,
                    "Bulk mailing scene: auto-blocked domain"
                );
            }

            persist_scene(db, disposition, &scene).await?;
        } else {
            // Create new scene
            let mut scene = ThreatScene {
                id: Uuid::new_v4(),
                scene_type: ThreatSceneType::BulkMailing,
                actor: hit.sender_domain.clone(),
                actor_type: "domain".to_string(),
                target_domain: None,
                time_window_start: chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                time_window_end: chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                email_count: hit.email_count as i32,
                unique_recipients: hit.unique_recipients as i32,
                bounce_count: 0,
                sample_subjects: hit.sample_subjects.clone(),
                sample_recipients: hit.sample_recipients.clone(),
                threat_level: severity,
                status: ThreatSceneStatus::Active,
                auto_blocked: false,
                ioc_id: None,
                details: serde_json::json!({}),
                created_at: now,
                updated_at: now,
            };

            // Auto-block on creation if threshold exceeded
            if config.auto_block_enabled
                && hit.unique_recipients >= config.auto_block_recipient_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "bulk_mailing",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: sent {} emails to {} internal recipients within {}h",
                        hit.email_count, hit.unique_recipients, config.time_window_hours
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    recipients = hit.unique_recipients,
                    "New bulk mailing scene: auto-blocked domain"
                );
            }

            info!(
                domain = %hit.sender_domain,
                emails = hit.email_count,
                recipients = hit.unique_recipients,
                severity = %severity,
                "Detected bulk mailing scene"
            );
            persist_scene(db, disposition, &scene).await?;
        }
    }

    Ok(())
}

fn bulk_mailing_severity(unique_recipients: i64, email_count: i64) -> ThreatLevel {
    if unique_recipients >= 80 {
        ThreatLevel::Critical
    } else if unique_recipients >= 30 || email_count >= 30 {
        ThreatLevel::High
    } else if unique_recipients >= 15 || email_count >= 10 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    }
}

// ─── Bounce Harvest Detection ───────────────────────────────────────────

async fn detect_bounce_harvest(
    db: &VigilDb,
    internal_domains: &[String],
    config: &BounceHarvestConfig,
    disposition: &DispositionEngine,
) -> anyhow::Result<()> {
    let mut hits = db.detect_bounce_harvest(internal_domains, config).await?;
    let cutoff = (Utc::now() - Duration::hours(config.time_window_hours)).to_rfc3339();
    let alerts = db.detect_bounce_harvest_alert_candidates(&cutoff).await?;
    hits.extend(parse_reported_bounce_harvest(
        &alerts,
        internal_domains,
        config,
    ));
    if hits.is_empty() {
        return Ok(());
    }

    for hit in &hits {
        let severity = if hit.detection_basis == "rotating_sender_template" {
            ThreatLevel::Low
        } else {
            bounce_harvest_severity(hit.bounce_count, hit.unique_targets)
        };

        let existing = db
            .find_active_bounce_scene(&hit.sender, &hit.target_domain, &hit.source)
            .await?
            .or(db
                .find_legacy_bounce_scene(&hit.source, &hit.sender, &hit.target_domain)
                .await?);

        let now = Utc::now();

        if let Some(mut scene) = existing {
            scene.actor = hit.sender.clone();
            scene.actor_type = bounce_actor_type(hit);
            scene.target_domain = Some(hit.target_domain.clone());
            scene.time_window_start = chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(scene.time_window_start);
            scene.bounce_count = hit.bounce_count as i32;
            scene.unique_recipients = hit.unique_targets as i32;
            scene.time_window_end = chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            scene.threat_level = severity;
            scene.sample_subjects = hit.sample_subjects.clone();
            scene.sample_recipients = hit.sample_recipients.clone();
            scene.details = bounce_scene_details(hit);
            scene.updated_at = now;

            if config.auto_block_enabled
                && bounce_auto_block_eligible(hit)
                && !scene.auto_blocked
                && hit.bounce_count >= config.auto_block_bounce_threshold
            {
                // For bounce harvest, we block the target domain in a different way:
                // block the original sender/source domain. The target domain is
                // our own address space and must never be persisted as malicious.
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender,
                    "bounce_harvest",
                    config.auto_block_duration_hours,
                    &format!(
                        "Bounce harvest auto-block: {} bounces detected in {}h, {} addresses probed",
                        hit.bounce_count, config.time_window_hours, hit.unique_targets
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    target_domain = %hit.target_domain,
                    bounces = hit.bounce_count,
                    "Bounce harvest scene: auto-blocked"
                );
            }

            persist_scene(db, disposition, &scene).await?;
        } else {
            let mut scene = ThreatScene {
                id: Uuid::new_v4(),
                scene_type: ThreatSceneType::BounceHarvest,
                actor: hit.sender.clone(),
                actor_type: bounce_actor_type(hit),
                target_domain: Some(hit.target_domain.clone()),
                time_window_start: chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                time_window_end: chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                email_count: 0,
                unique_recipients: hit.unique_targets as i32,
                bounce_count: hit.bounce_count as i32,
                sample_subjects: hit.sample_subjects.clone(),
                sample_recipients: hit.sample_recipients.clone(),
                threat_level: severity,
                status: ThreatSceneStatus::Active,
                auto_blocked: false,
                ioc_id: None,
                details: serde_json::json!({}),
                created_at: now,
                updated_at: now,
            };

            scene.details = bounce_scene_details(hit);

            if config.auto_block_enabled
                && bounce_auto_block_eligible(hit)
                && hit.bounce_count >= config.auto_block_bounce_threshold
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender,
                    "bounce_harvest",
                    config.auto_block_duration_hours,
                    &format!(
                        "Bounce harvest auto-block: {} bounces detected in {}h, {} addresses probed",
                        hit.bounce_count, config.time_window_hours, hit.unique_targets
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    target_domain = %hit.target_domain,
                    bounces = hit.bounce_count,
                    "New bounce harvest scene: auto-blocked"
                );
            }

            info!(
                target_domain = %hit.target_domain,
                bounces = hit.bounce_count,
                unique_targets = hit.unique_targets,
                severity = %severity,
                "Detected bounce harvest scene (Directory Harvest Attack)"
            );
            persist_scene(db, disposition, &scene).await?;
        }
    }

    Ok(())
}

fn bounce_scene_details(hit: &BounceHarvestRow) -> serde_json::Value {
    serde_json::json!({
        "source": hit.source,
        "source_session_id": hit.source_session_id.map(|id| id.to_string()),
        "source_session_ids": hit.source_session_ids,
        "source_spans": hit.source_spans,
        "detection_basis": hit.detection_basis,
        "evidence_class": if hit.source == "reported_alert" { "observation" } else { "network_pattern" },
        "assessment": if hit.source == "reported_alert" { "needs_review" } else { "detected_pattern" },
        "sender_identity": if hit.source == "reported_alert" { "reported_unverified" } else { "envelope_recipient" },
        "speech_act": if hit.source == "reported_alert" { "report" } else { "none" },
        "quote_or_forward_status": if hit.source == "reported_alert" { "reported" } else { "original" },
        "sender_domains": hit.sender_domains,
        "address_role": match hit.source.as_str() {
            "reported_alert" => "target_addresses",
            "network_bounce_recipient_spray" => "bounce_recipient_addresses",
            _ => "sender_addresses",
        },
        "automatic_blocking_eligible": bounce_auto_block_eligible(hit),
    })
}

fn bounce_auto_block_eligible(hit: &BounceHarvestRow) -> bool {
    hit.source == "network_bounce"
}

fn bounce_actor_type(hit: &BounceHarvestRow) -> String {
    if hit.sender == "multiple_senders" {
        "group".to_string()
    } else {
        "domain".to_string()
    }
}

mod reported_bounce;
use reported_bounce::parse_reported_bounce_harvest;

fn bounce_harvest_severity(bounce_count: i64, unique_targets: i64) -> ThreatLevel {
    // Base level from bounce count
    let base = if bounce_count >= 150 {
        ThreatLevel::Critical
    } else if bounce_count >= 50 {
        ThreatLevel::High
    } else if bounce_count >= 15 {
        ThreatLevel::Medium
    } else {
        ThreatLevel::Low
    };

    // Bonus escalation if many unique targets probed
    if unique_targets >= 50 && base < ThreatLevel::High {
        ThreatLevel::High
    } else if unique_targets >= 10 && base < ThreatLevel::Medium {
        ThreatLevel::Medium
    } else {
        base
    }
}

// ─── Auto-block via IOC ─────────────────────────────────────────────────

// ─── Internal Domain Impersonation Detection ────────────────────────────

async fn detect_internal_impersonation(
    db: &VigilDb,
    internal_domains: &[String],
    config: &InternalDomainImpersonationConfig,
    disposition: &DispositionEngine,
) -> anyhow::Result<()> {
    // Get all external sender domains with aggregated stats
    let candidates = db
        .query_external_sender_stats(internal_domains, config)
        .await?;
    if candidates.is_empty() {
        return Ok(());
    }

    for hit in &candidates {
        // Check similarity against each internal domain
        let mut best_match: Option<(&str, &str, f64)> = None; // (target_domain, similarity_type, score)

        for internal in internal_domains {
            if let Some((sim_type, score)) = check_domain_similarity(&hit.sender_domain, internal)
                && best_match.as_ref().is_none_or(|m| score > m.2)
            {
                best_match = Some((internal, sim_type, score));
            }
        }

        let Some((target_domain, similarity_type, score)) = best_match else {
            continue;
        };

        let severity = impersonation_severity(hit.email_count, similarity_type, score);

        // Check if an active scene already exists for this actor
        let existing = db
            .find_active_scene("internal_domain_impersonation", &hit.sender_domain)
            .await?;

        let now = Utc::now();

        if let Some(mut scene) = existing {
            // Update existing scene
            scene.email_count = hit.email_count as i32;
            scene.unique_recipients = hit.unique_recipients as i32;
            scene.time_window_end = chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(now);
            scene.threat_level = severity;
            scene.sample_subjects = hit.sample_subjects.clone();
            scene.sample_recipients = hit.sample_recipients.clone();
            scene.details = serde_json::json!({
                "similarity_type": similarity_type,
                "target_internal_domain": target_domain,
            });
            scene.updated_at = now;

            // Auto-block upgrade: only for high-confidence types with sufficient volume
            if config.auto_block_enabled
                && !scene.auto_blocked
                && hit.email_count >= config.auto_block_min_emails
                && matches!(similarity_type, "homoglyph" | "tld_swap")
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "internal_domain_impersonation",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: domain '{}' impersonating internal domain '{}' ({}), {} emails",
                        hit.sender_domain, target_domain, similarity_type, hit.email_count
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    target = %target_domain,
                    similarity = %similarity_type,
                    "Internal domain impersonation: auto-blocked domain"
                );
            }

            persist_scene(db, disposition, &scene).await?;
        } else {
            // Create new scene
            let mut scene = ThreatScene {
                id: Uuid::new_v4(),
                scene_type: ThreatSceneType::InternalDomainImpersonation,
                actor: hit.sender_domain.clone(),
                actor_type: "domain".to_string(),
                target_domain: Some(target_domain.to_string()),
                time_window_start: chrono::DateTime::parse_from_rfc3339(&hit.window_start)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                time_window_end: chrono::DateTime::parse_from_rfc3339(&hit.window_end)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or(now),
                email_count: hit.email_count as i32,
                unique_recipients: hit.unique_recipients as i32,
                bounce_count: 0,
                sample_subjects: hit.sample_subjects.clone(),
                sample_recipients: hit.sample_recipients.clone(),
                threat_level: severity,
                status: ThreatSceneStatus::Active,
                auto_blocked: false,
                ioc_id: None,
                details: serde_json::json!({
                    "similarity_type": similarity_type,
                    "target_internal_domain": target_domain,
                }),
                created_at: now,
                updated_at: now,
            };

            // Auto-block on creation: only for high-confidence types with sufficient volume
            if config.auto_block_enabled
                && hit.email_count >= config.auto_block_min_emails
                && matches!(similarity_type, "homoglyph" | "tld_swap")
            {
                let ioc_id = auto_block_domain(
                    db,
                    &hit.sender_domain,
                    "internal_domain_impersonation",
                    config.auto_block_duration_hours,
                    &format!(
                        "Threat scene auto-block: domain '{}' impersonating internal domain '{}' ({}), {} emails",
                        hit.sender_domain, target_domain, similarity_type, hit.email_count
                    ),
                )
                .await?;
                scene.auto_blocked = true;
                scene.ioc_id = Some(ioc_id);
                scene.status = ThreatSceneStatus::AutoBlocked;
                warn!(
                    domain = %hit.sender_domain,
                    target = %target_domain,
                    similarity = %similarity_type,
                    "New internal domain impersonation scene: auto-blocked domain"
                );
            }

            info!(
                domain = %hit.sender_domain,
                target = %target_domain,
                similarity = %similarity_type,
                emails = hit.email_count,
                severity = %severity,
                "Detected internal domain impersonation scene"
            );
            persist_scene(db, disposition, &scene).await?;
        }
    }

    Ok(())
}

/// Severity for internal domain impersonation scenes.
fn impersonation_severity(email_count: i64, similarity_type: &str, score: f64) -> ThreatLevel {
    // Base level from similarity type + numeric score
    let base = match similarity_type {
        "homoglyph" => ThreatLevel::High,
        "tld_swap" if score >= 0.90 => ThreatLevel::High,
        "tld_swap" => ThreatLevel::Medium,
        "typosquatting" if score >= 0.85 => ThreatLevel::High,
        "typosquatting" => ThreatLevel::Medium,
        "subdomain_prefix" if score >= 0.80 => ThreatLevel::Medium,
        "subdomain_prefix" => ThreatLevel::Low,
        _ => ThreatLevel::Low,
    };

    // Escalate based on volume
    if email_count >= 10 && base < ThreatLevel::High {
        ThreatLevel::High
    } else if email_count >= 5 && base < ThreatLevel::Medium {
        ThreatLevel::Medium
    } else {
        base
    }
}

// ─── Domain Similarity Algorithm ────────────────────────────────────────

/// Decode Punycode-encoded IDN labels to Unicode.
///
/// SMTP transports encode IDN domains as Punycode (e.g. `xn--cccbchna-q5a.com`).
/// We need the Unicode representation for meaningful homoglyph comparison.
fn decode_punycode(domain: &str) -> String {
    if !domain.contains("xn--") {
        return domain.to_string();
    }
    // idna 1.x API: domain_to_unicode returns (String, Result<(), Errors>)
    let (decoded, result) = idna::domain_to_unicode(domain);
    if result.is_ok() {
        decoded
    } else {
        domain.to_string()
    }
}

/// Check if `external` domain is similar to `internal` domain.
/// Returns Some((similarity_type, score)) if similar, None otherwise.
fn check_domain_similarity<'a>(external: &str, internal: &str) -> Option<(&'a str, f64)> {
    // P0-3: Decode Punycode → Unicode before comparison
    let ext_decoded = decode_punycode(external);
    let int_decoded = decode_punycode(internal);

    let (ext_base, ext_tld) = split_domain(&ext_decoded);
    let (int_base, int_tld) = split_domain(&int_decoded);

    // Skip very short base names (too many false positives)
    if int_base.len() < 3 || ext_base.len() < 3 {
        return None;
    }

    // 1. Homoglyph: substitution of visually similar characters
    if ext_base != int_base && check_homoglyph(&ext_base, &int_base) {
        return Some(("homoglyph", 0.95));
    }

    // 2. TLD swap: same base name, different TLD
    if ext_base == int_base && ext_tld != int_tld {
        return Some(("tld_swap", 0.90));
    }

    // 3. Typosquatting: edit distance with length-scaled threshold
    if ext_base != int_base {
        let dist = levenshtein_distance(&ext_base, &int_base);
        let max_len = ext_base.len().max(int_base.len());
        // P1-1: Scale threshold by domain length
        let max_dist = if max_len <= 6 {
            1
        } else if max_len <= 12 {
            2
        } else {
            3
        };
        if dist > 0 && dist <= max_dist && int_base.len() >= 4 {
            // Score degrades with higher edit distance
            let score = match dist {
                1 => 0.85,
                2 => 0.75,
                _ => 0.65,
            };
            return Some(("typosquatting", score));
        }
    }

    // 4. Subdomain prefix/suffix with boundary constraints
    // P1-3: Require separator-bounded match to avoid "art" matching "restart"
    if ext_base.len() > int_base.len() && int_base.len() >= 4 {
        let is_prefix = ext_base.starts_with(&int_base)
            && ext_base
                .as_bytes()
                .get(int_base.len())
                .is_some_and(|&b| b == b'-' || b == b'.');
        let is_suffix = ext_base.ends_with(&int_base)
            && ext_base.len() > int_base.len()
            && ext_base.as_bytes()[ext_base.len() - int_base.len() - 1] == b'-';
        // Allow unbounded prefix only if external is significantly longer (e.g. "examplemail")
        let is_long_prefix =
            ext_base.starts_with(&int_base) && ext_base.len() >= int_base.len() + 3;
        if is_prefix || is_suffix || is_long_prefix {
            return Some(("subdomain_prefix", 0.70));
        }
    }

    None
}

/// Split domain into (base_name, tld).
/// Handles multi-part TLDs like .co.uk, .com.cn, .org.cn, .net.cn, .com.hk
fn split_domain(domain: &str) -> (String, String) {
    let domain = domain.to_lowercase();
    let parts: Vec<&str> = domain.split('.').collect();

    if parts.len() < 2 {
        return (domain, String::new());
    }

    // Known multi-part TLDs
    // P1-2: Expanded list covering CN, Asia, Europe, etc.
    static MULTI_TLDS: &[&str] = &[
        // UK
        "co.uk", "org.uk", "ac.uk", // China
        "com.cn", "org.cn", "net.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
        // Hong Kong / Taiwan
        "com.hk", "org.hk", "com.tw", "org.tw", // Oceania
        "com.au", "org.au", "co.nz",  // Americas
        "com.br", // Japan / Korea
        "co.jp", "or.jp", "co.kr", "or.kr", // Southeast Asia
        "com.sg", "co.in", "co.id", "co.th", "com.my", "com.ph",
        // Middle East / Europe
        "co.il", "com.es", "com.fr", "com.it",
    ];

    if parts.len() >= 3 {
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        if MULTI_TLDS.contains(&last_two.as_str()) {
            let base = parts[..parts.len() - 2].join(".");
            return (base, last_two);
        }
    }

    let base = parts[..parts.len() - 1].join(".");
    let tld = parts[parts.len() - 1].to_string();
    (base, tld)
}

/// Collapse multi-character homoglyph sequences to their canonical single-character form.
/// e.g. "rn" → "m", "cl" → "d", "vv" → "w"
fn collapse_homoglyphs(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i + 1 < chars.len() {
            let pair = [chars[i], chars[i + 1]];
            match pair {
                ['r', 'n'] => {
                    result.push('m');
                    i += 2;
                    continue;
                }
                ['c', 'l'] => {
                    result.push('d');
                    i += 2;
                    continue;
                }
                ['v', 'v'] => {
                    result.push('w');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Check if two strings are homoglyphs (visually similar character substitutions).
///
/// P0-1 fix: Two-phase approach — first collapse multi-char sequences (rn→m, cl→d, vv→w),
/// then normalize single-character homoglyphs and compare. This avoids the length guard
/// that previously made multi-char collapse dead code.
fn check_homoglyph(a: &str, b: &str) -> bool {
    // Phase 1: Collapse multi-char homoglyph sequences
    let collapsed_a = collapse_homoglyphs(a);
    let collapsed_b = collapse_homoglyphs(b);

    // Phase 2: After collapse, if lengths match, normalize single-char homoglyphs and compare
    if collapsed_a.len() == collapsed_b.len() {
        let norm_a = normalize_homoglyph(&collapsed_a);
        let norm_b = normalize_homoglyph(&collapsed_b);
        if norm_a == norm_b && a != b {
            return true;
        }
    }

    false
}

/// Normalize common homoglyph substitutions to a canonical form.
///
/// P0-2: Expanded mapping covering Cyrillic, Greek, digit substitutions, and Latin extended.
fn normalize_homoglyph(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            // ── Digits ──
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            '8' => 'b',

            // ── Cyrillic (existing + new) ──
            '\u{0430}' => 'a', // а
            '\u{0435}' => 'e', // е
            '\u{043E}' => 'o', // о
            '\u{0441}' => 'c', // с
            '\u{0440}' => 'p', // р
            '\u{0443}' => 'y', // у
            '\u{0445}' => 'x', // х
            '\u{0456}' => 'i', // і
            '\u{0458}' => 'j', // ј
            '\u{0455}' => 's', // ѕ
            '\u{0501}' => 'd', // ԁ
            '\u{044C}' => 'b', // ь (soft sign, visually close to b)

            // ── Greek ──
            '\u{03BF}' => 'o', // ο (omicron)
            '\u{03B1}' => 'a', // α (alpha)
            '\u{03B5}' => 'e', // ε (epsilon)
            '\u{03BD}' => 'v', // ν (nu)
            '\u{03C1}' => 'p', // ρ (rho)
            '\u{03C4}' => 't', // τ (tau)
            '\u{03BA}' => 'k', // κ (kappa)
            '\u{03B9}' => 'i', // ι (iota)
            '\u{03B7}' => 'n', // η (eta)
            '\u{03C9}' => 'w', // ω (omega)

            // ── Latin Extended / IPA ──
            '\u{0251}' => 'a', // ɑ (Latin alpha)
            '\u{0258}' => 'e', // ɘ (reversed e)
            '\u{026A}' => 'i', // ɪ (small capital I)
            '\u{0261}' => 'g', // ɡ (script g)
            '\u{0269}' => 'i', // ɩ (iota)
            '\u{028F}' => 'y', // ʏ (small capital Y)
            '\u{0266}' => 'h', // ɦ (hooktop h)

            _ => c,
        })
        .collect()
}

/// Levenshtein edit distance.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

// ─── Auto-block via IOC ─────────────────────────────────────────────────

async fn auto_block_domain(
    db: &VigilDb,
    domain: &str,
    attack_type: &str,
    duration_hours: i64,
    context: &str,
) -> anyhow::Result<String> {
    let now = Utc::now();
    let expires = now + Duration::hours(duration_hours);
    let id = Uuid::new_v4();

    let ioc = IocEntry {
        id,
        indicator: domain.to_lowercase(),
        ioc_type: "domain".to_string(),
        source: "scene_auto".to_string(),
        verdict: "malicious".to_string(),
        confidence: 0.85,
        attack_type: attack_type.to_string(),
        first_seen: now,
        last_seen: now,
        hit_count: 0,
        context: Some(context.to_string()),
        expires_at: Some(expires),
        created_at: now,
        updated_at: now,
    };

    db.upsert_ioc(&ioc).await?;
    Ok(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_db::security::threat_scene::BounceHarvestAlertRow;

    #[test]
    fn parses_ddei_report_into_observation_scene() {
        let alert = BounceHarvestAlertRow {
            session_id: Uuid::new_v4(),
            mail_from: Some("notifications@ddei.example".to_string()),
            client_ip: "192.0.2.41".to_string(),
            started_at: "2026-08-21T01:16:44+00:00".to_string(),
            subject: Some("DDEI 严重 - 系统警报 - 中继MTA服务器不可达".to_string()),
            body_text: "Deep Discovery Email Inspector无法发送以下邮件到中继MTA服务器：\n\
                Risk: Normal\n\
                Recipients: a@corp.example\n\
                Sender: first@sender-one.example\n\
                Subject: first\n\
                ============================================================\n\
                Risk: Normal\n\
                Recipients: b@corp.example\n\
                Sender: second@sender-two.example\n\
                Subject: second\n\
                ============================================================\n\
                Risk: Normal\n\
                Recipients: c@corp.example\n\
                Sender: third@sender-one.example\n\
                Subject: third\n\
                以下中继MTA服务器不可达：\n[198.51.100.68]:25"
                .to_string(),
        };
        let domains = vec!["corp.example".to_string()];
        let config = BounceHarvestConfig {
            min_bounces: 3,
            min_unique_targets: 3,
            ..Default::default()
        };

        let rows = parse_reported_bounce_harvest(std::slice::from_ref(&alert), &domains, &config);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_domain, "corp.example");
        assert_eq!(rows[0].bounce_count, 3);
        assert_eq!(rows[0].unique_targets, 3);
        assert_eq!(rows[0].sender, "multiple_senders");
        assert_eq!(
            rows[0].sender_domains,
            vec!["sender-one.example", "sender-two.example"]
        );
        assert_eq!(rows[0].source, "reported_alert");
        assert!(rows[0].source_session_id.is_some());
    }

    #[test]
    fn generic_mail_with_mta_words_is_not_reported_alert() {
        let alert = BounceHarvestAlertRow {
            session_id: Uuid::new_v4(),
            mail_from: Some("sender@example.com".to_string()),
            client_ip: "198.51.100.10".to_string(),
            started_at: "2026-08-21T01:16:44+00:00".to_string(),
            subject: Some("Relay MTA documentation".to_string()),
            body_text: "Recipients: a@corp.example\nSubject: relay MTA".to_string(),
        };
        let domains = vec!["corp.example".to_string()];
        let rows = parse_reported_bounce_harvest(
            std::slice::from_ref(&alert),
            &domains,
            &BounceHarvestConfig {
                min_bounces: 1,
                min_unique_targets: 1,
                ..Default::default()
            },
        );
        assert!(rows.is_empty());
    }
}
