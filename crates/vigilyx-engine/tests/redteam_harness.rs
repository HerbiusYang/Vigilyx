//! Red-team evasion harness.
//!
//! Replays raw `.eml` samples through the same inline-tier module set the MTA
//! proxy uses, then runs the clustered-DS fusion, and prints per-case module
//! threats plus the final verdict. A case whose final threat level stays below
//! `Medium` (the MTA quarantine threshold) would be DELIVERED inline.
//!
//! External-service modules (link_reputation, landing_page_scan, av_*,
//! sandbox, domain_verify, identity_anomaly, transaction_correlation) are not
//! part of the MTA inline tier and are intentionally excluded, mirroring
//! `ModuleMetadata::effective_inline_priority`.
//!
//! Run:
//!   cargo test -p vigilyx-engine --test redteam_harness -- --nocapture

use std::collections::HashMap;
use std::path::PathBuf;

use async_trait::async_trait;
use vigilyx_core::models::{EmailSession, Protocol, SessionSource, SessionStatus};
use vigilyx_core::security::{IocEntry, ThreatLevel};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{ModuleResult, SecurityModule};
use vigilyx_engine::modules::aitm_detect::AitmDetectModule;
use vigilyx_engine::modules::anomaly_detect::AnomalyDetectModule;
use vigilyx_engine::modules::attach_content::AttachContentModule;
use vigilyx_engine::modules::attach_qr_scan::AttachmentQrScanModule;
use vigilyx_engine::modules::attach_scan::AttachScanModule;
use vigilyx_engine::modules::content_scan::{
    build_effective_keyword_lists, normalize_system_keyword_seed, EffectiveKeywordLists,
    KeywordOverrides,
};
use vigilyx_engine::modules::header_scan::HeaderScanModule;
use vigilyx_engine::modules::html_pixel_art::HtmlPixelArtModule;
use vigilyx_engine::modules::html_scan::HtmlScanModule;
use vigilyx_engine::modules::link_content::LinkContentModule;
use vigilyx_engine::modules::link_scan::LinkScanModule;
use vigilyx_engine::modules::mime_scan::MimeScanModule;
use vigilyx_engine::modules::prompt_injection_scan::PromptInjectionScanModule;
use vigilyx_engine::modules::rmm_detect::RmmDetectModule;
use vigilyx_engine::modules::semantic_scan::SemanticScanModule;
use vigilyx_engine::modules::toad_detect::ToadDetectModule;
use vigilyx_engine::pipeline::config::VerdictConfig;
use vigilyx_engine::pipeline::verdict::aggregate_verdict_with_session;
use vigilyx_engine::pipeline::verdict::{
    set_runtime_scenario_patterns, ScenarioPatternLists,
};
use vigilyx_parser::mime::decode_rfc2047;
use vigilyx_parser::MimeParser;

/// No-op DB stub: unknown IOC lookups, no sender history.
struct NoDb;

#[async_trait]
impl vigilyx_engine::db_service::DbQueryService for NoDb {
    async fn find_ioc(
        &self,
        _ioc_type: &str,
        _indicator: &str,
    ) -> anyhow::Result<Option<IocEntry>> {
        Ok(None)
    }
    async fn count_sender_domain_history(
        &self,
        _sender_domain: &str,
        _exclude_session_id: &str,
    ) -> anyhow::Result<i64> {
        Ok(0)
    }
    async fn count_sender_address_history(
        &self,
        _sender_address: &str,
        _exclude_session_id: &str,
    ) -> anyhow::Result<i64> {
        Ok(0)
    }
    async fn count_distinct_senders_for_domain(
        &self,
        _sender_domain: &str,
    ) -> anyhow::Result<i64> {
        Ok(0)
    }
}

fn load_keyword_lists() -> EffectiveKeywordLists {
    let seed_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../shared/schemas/keyword_overrides_seed.json");
    let seed_json = std::fs::read_to_string(&seed_path).expect("read keyword seed");
    let seed: KeywordOverrides = serde_json::from_str(&seed_json).expect("parse keyword seed");
    let system_seed = normalize_system_keyword_seed(&seed);
    build_effective_keyword_lists(&system_seed, &KeywordOverrides::default())
}

/// Mirror of `SmtpConnection::build_email_session` in the MTA crate.
fn session_from_raw(raw: &[u8], mail_from: &str, rcpt: &str) -> Option<EmailSession> {
    let mut session = EmailSession::new(Protocol::Smtp, "203.0.113.50".into(), 40000, "10.0.0.2".into(), 25);
    session.source = SessionSource::MtaProxy;
    session.status = SessionStatus::Completed;
    session.mail_from = Some(mail_from.to_string());
    session.rcpt_to.push(rcpt.to_string());
    session.total_bytes = raw.len();
    session.email_count = 1;
    session.content = MimeParser::new().parse(raw).ok()?;
    session.content.is_complete = true;
    for (key, value) in &session.content.headers {
        if key.eq_ignore_ascii_case("subject") && session.subject.is_none() {
            let decoded = decode_rfc2047(value);
            let trimmed = decoded.trim();
            if !trimmed.is_empty() {
                session.subject = Some(trimmed.to_string());
            }
        }
    }
    Some(session)
}

fn threat_rank(level: ThreatLevel) -> u8 {
    match level {
        ThreatLevel::Safe => 0,
        ThreatLevel::Low => 1,
        ThreatLevel::Medium => 2,
        ThreatLevel::High => 3,
        ThreatLevel::Critical => 4,
    }
}

#[tokio::test]
async fn redteam_replay() {
    let lists = load_keyword_lists();
    set_runtime_scenario_patterns(ScenarioPatternLists::from(&lists));

    let db: std::sync::Arc<dyn vigilyx_engine::db_service::DbQueryService> = std::sync::Arc::new(NoDb);
    let modules: Vec<std::sync::Arc<dyn SecurityModule>> = vec![
        std::sync::Arc::new(
            vigilyx_engine::modules::content_scan::ContentScanModule::new_with_keyword_lists(
                lists.clone(),
            ),
        ),
        std::sync::Arc::new(HtmlScanModule::new()),
        std::sync::Arc::new(HtmlPixelArtModule::new()),
        std::sync::Arc::new(AttachScanModule::new()),
        std::sync::Arc::new(AttachContentModule::new_with_keyword_lists(lists.clone())),
        std::sync::Arc::new(AttachmentQrScanModule::new_with_keyword_lists(lists.clone())),
        std::sync::Arc::new(MimeScanModule::new()),
        std::sync::Arc::new(HeaderScanModule::new(db, None)),
        std::sync::Arc::new(LinkScanModule::new()),
        std::sync::Arc::new(LinkContentModule::new_with_keyword_lists(lists.clone())),
        std::sync::Arc::new(AnomalyDetectModule::new()),
        std::sync::Arc::new(AitmDetectModule::new()),
        std::sync::Arc::new(RmmDetectModule::new()),
        std::sync::Arc::new(PromptInjectionScanModule::new()),
        std::sync::Arc::new(ToadDetectModule::new()),
        std::sync::Arc::new(SemanticScanModule::new(None)),
    ];

    let cases_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/redteam_cases");
    let mut case_files: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
        .expect("redteam_cases dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "eml"))
        .collect();
    case_files.sort();

    let verdict_config = VerdictConfig::default();
    let mut delivered = Vec::new();
    let expected_inline_block = [
        "ctrl03_qp_split_keyword.eml",
        "ev01_entity_hairsp_break.eml",
        "ev02_css_hidden_char_break.eml",
        "ev03_traditional_chinese.eml",
        "ev04_trusted_platform_lure.eml",
        "ev06_html_attachment_phish.eml",
        "ev08_nested_rfc822.eml",
        "ev10_image_only_phish.eml",
        "ev13_english_spaced.eml",
    ];

    for path in &case_files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read(path).expect("read case");
        let Some(session) = session_from_raw(&raw, "sender@partner-external.com", "employee@corp.internal") else {
            println!("[{name}] PARSE FAILED — engine would tempfail (fail-closed)");
            continue;
        };
        let session = std::sync::Arc::new(session);
        let ctx = SecurityContext::new(session.clone());

        let mut results: HashMap<String, ModuleResult> = HashMap::new();
        for module in &modules {
            if !module.should_run(&ctx) {
                continue;
            }
            match module.analyze(&ctx).await {
                Ok(result) => {
                    results.insert(result.module_id.clone(), result);
                }
                Err(e) => println!("[{name}] module {} ERROR: {e}", module.metadata().id),
            }
        }

        let verdict = aggregate_verdict_with_session(
            Some(session.as_ref()),
            session.id,
            &results,
            &verdict_config,
        );

        let flagged: Vec<String> = results
            .values()
            .filter(|r| threat_rank(r.threat_level) >= 1)
            .map(|r| format!("{}={:?}", r.module_id, r.threat_level))
            .collect();

        let would_deliver = threat_rank(verdict.threat_level) < threat_rank(ThreatLevel::Medium);
        if expected_inline_block.contains(&name.as_str()) {
            assert!(
                !would_deliver,
                "red-team regression: {name} still falls below the MTA quarantine threshold; verdict={:?}, summary={}",
                verdict.threat_level,
                verdict.summary
            );
        }
        if would_deliver {
            delivered.push(name.clone());
        }
        println!(
            "[{name}] FINAL={:?} conf={:.2} flagged=[{}] summary={}{}",
            verdict.threat_level,
            verdict.confidence,
            flagged.join(","),
            verdict.summary,
            if would_deliver { "  ==> DELIVERED (below quarantine)" } else { "" }
        );
    }

    println!("\n=== DELIVERED (bypass succeeded): {} / {} ===", delivered.len(), case_files.len());
    for name in &delivered {
        println!("  BYPASSED: {name}");
    }
}
