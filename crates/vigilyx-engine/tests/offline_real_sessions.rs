//! Explicitly enabled, read-only replay of an external EmailSession bundle.
//!
//! Real mail stays outside the repository. This diagnostic runs bounded local
//! modules and fusion with frozen tenant/config snapshots, without connecting
//! to a database, fetching links, persisting verdicts, or invoking SOAR.
//! It is not an exact full-production replay or an independent holdout.
//!
//! Run the compiled test executable in a network-disabled container with:
//! VIGILYX_ALLOW_REAL_OFFLINE_REPLAY=1
//! VIGILYX_OFFLINE_REAL_BUNDLE=/audit/real-samples/email-session-bundle.json
//! VIGILYX_OFFLINE_RUNTIME_CONFIG=/audit/real-samples/runtime-config-snapshot.json
//! VIGILYX_OFFLINE_REAL_REPORT=/audit/reports/candidate-real-sessions.json
//! --ignored --exact offline_real_sessions --nocapture

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{IocEntry, ThreatLevel};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{ModuleResult, SecurityModule};
use vigilyx_engine::module_data::{ModuleDataOverrides, ModuleDataRegistry, set_module_data};
use vigilyx_engine::modules::aitm_detect::AitmDetectModule;
use vigilyx_engine::modules::anomaly_detect::AnomalyDetectModule;
use vigilyx_engine::modules::attach_content::AttachContentModule;
use vigilyx_engine::modules::attach_qr_scan::AttachmentQrScanModule;
use vigilyx_engine::modules::attach_scan::AttachScanModule;
use vigilyx_engine::modules::content_scan::{
    ContentScanModule, EffectiveKeywordLists, KeywordOverrides, build_effective_keyword_lists,
    normalize_system_keyword_seed,
};
use vigilyx_engine::modules::header_scan::HeaderScanModule;
use vigilyx_engine::modules::html_pixel_art::HtmlPixelArtModule;
use vigilyx_engine::modules::html_scan::HtmlScanModule;
use vigilyx_engine::modules::link_content::LinkContentModule;
use vigilyx_engine::modules::link_scan::LinkScanModule;
use vigilyx_engine::modules::mime_scan::MimeScanModule;
use vigilyx_engine::modules::prompt_injection_scan::PromptInjectionScanModule;
use vigilyx_engine::modules::rmm_detect::RmmDetectModule;
use vigilyx_engine::modules::toad_detect::ToadDetectModule;
use vigilyx_engine::pipeline::config::VerdictConfig;
use vigilyx_engine::pipeline::verdict::{
    ScenarioPatternLists, aggregate_verdict_with_session, set_runtime_scenario_patterns,
};
use vigilyx_engine::semantic::SemanticScanModule;
use vigilyx_parser::MimeParser;

#[derive(Deserialize)]
struct SessionBundle {
    schema_version: u32,
    internal_domains: Vec<String>,
    samples: Vec<SessionSample>,
    scope: String,
    runtime_config_snapshot_sha256: String,
}

#[derive(Deserialize)]
struct SessionSample {
    case_id: String,
    role: String,
    session: EmailSession,
}

struct NoDb;

#[async_trait]
impl vigilyx_engine::db_service::DbQueryService for NoDb {
    async fn find_ioc(&self, _: &str, _: &str) -> anyhow::Result<Option<IocEntry>> {
        Ok(None)
    }

    async fn count_sender_domain_history(&self, _: &str, _: &str) -> anyhow::Result<i64> {
        Ok(0)
    }

    async fn count_sender_address_history(&self, _: &str, _: &str) -> anyhow::Result<i64> {
        Ok(0)
    }

    async fn count_distinct_senders_for_domain(&self, _: &str) -> anyhow::Result<i64> {
        Ok(0)
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn config_value(snapshot: &Value, key: &str) -> Value {
    snapshot
        .get(key)
        .and_then(Value::as_str)
        .map(|text| serde_json::from_str(text).expect("parse frozen config value"))
        .unwrap_or(Value::Null)
}

// Mirrors the production seed backfill: preserve configured values, union
// simple lists, and merge structured profiles by their stable brand key.
fn backfill_defaults(compiled: &Value, stored: &mut Value) {
    match (compiled, stored) {
        (Value::Object(defaults), Value::Object(values)) => {
            for (key, default) in defaults {
                if let Some(value) = values.get_mut(key) {
                    backfill_defaults(default, value);
                } else {
                    values.insert(key.clone(), default.clone());
                }
            }
        }
        (Value::Array(defaults), Value::Array(values))
            if defaults.iter().all(Value::is_string) && values.iter().all(Value::is_string) =>
        {
            let mut known: HashSet<String> = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_lowercase)
                .collect();
            for default in defaults {
                if let Some(text) = default.as_str()
                    && known.insert(text.to_lowercase())
                {
                    values.push(default.clone());
                }
            }
        }
        (Value::Array(defaults), Value::Array(values)) => {
            for default in defaults {
                if let Some(brand) = default.get("brand").and_then(Value::as_str) {
                    if let Some(value) = values
                        .iter_mut()
                        .find(|value| value.get("brand").and_then(Value::as_str) == Some(brand))
                    {
                        backfill_defaults(default, value);
                    } else {
                        values.push(default.clone());
                    }
                }
            }
        }
        _ => {}
    }
}

fn initialize_config(snapshot: &Value) -> (EffectiveKeywordLists, String) {
    let compiled: Value = serde_json::from_str(vigilyx_db::security::embedded_module_data_seed())
        .expect("parse compiled module seed");
    let mut stored = config_value(snapshot, "engine_module_data_seed");
    if !stored.get("lists").is_some_and(Value::is_object) {
        stored = compiled.clone();
    } else {
        // Only list definitions are backfilled by the production loader.
        backfill_defaults(&compiled["lists"], &mut stored["lists"]);
    }
    let effective_seed = serde_json::to_string(&stored).expect("serialize effective module seed");
    let overrides: ModuleDataOverrides =
        serde_json::from_value(config_value(snapshot, "engine_module_data_overrides"))
            .expect("parse frozen module overrides");
    set_module_data(
        ModuleDataRegistry::from_seed_and_overrides(&effective_seed, &overrides)
            .expect("build effective module registry"),
    );
    let seed: KeywordOverrides =
        serde_json::from_value(config_value(snapshot, "keyword_system_seed"))
            .expect("parse frozen keyword seed");
    let overrides: KeywordOverrides =
        serde_json::from_value(config_value(snapshot, "keyword_overrides"))
            .expect("parse frozen keyword overrides");
    let lists = build_effective_keyword_lists(&normalize_system_keyword_seed(&seed), &overrides);
    set_runtime_scenario_patterns(ScenarioPatternLists::from(&lists));

    let builtin: Value = serde_json::from_str(include_str!(
        "../../../shared/schemas/system_whitelist_seed.json"
    ))
    .expect("parse built-in URL domain seed");
    let domains = |section: &str| {
        builtin[section]["items"]
            .as_array()
            .expect("domain section items")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<HashSet<_>>()
    };
    let trusted = domains("url_trusted");
    let mut safe = domains("intel_safe");
    safe.extend(trusted.iter().cloned());
    vigilyx_engine::modules::link_scan::set_trusted_url_domains(Arc::new(trusted));
    vigilyx_engine::modules::link_scan::set_well_known_safe_domains(Arc::new(safe));
    (lists, digest(effective_seed.as_bytes()))
}

fn local_modules(lists: &EffectiveKeywordLists) -> Vec<Arc<dyn SecurityModule>> {
    vec![
        Arc::new(MimeScanModule::new()),
        Arc::new(HeaderScanModule::new(Arc::new(NoDb), None)),
        Arc::new(ContentScanModule::new_with_keyword_lists(lists.clone())),
        Arc::new(HtmlScanModule::new()),
        Arc::new(HtmlPixelArtModule::new()),
        Arc::new(AttachScanModule::new()),
        Arc::new(AttachContentModule::new_with_keyword_lists(lists.clone())),
        Arc::new(AttachmentQrScanModule::new_with_keyword_lists(
            lists.clone(),
        )),
        Arc::new(LinkScanModule::new()),
        Arc::new(LinkContentModule::new_with_keyword_lists(lists.clone())),
        Arc::new(AnomalyDetectModule::new()),
        Arc::new(AitmDetectModule::new()),
        Arc::new(RmmDetectModule::new()),
        Arc::new(PromptInjectionScanModule::new()),
        Arc::new(ToadDetectModule::new()),
        Arc::new(SemanticScanModule::new(None)),
    ]
}

fn decode_json_column(value: &Value) -> Value {
    value
        .as_str()
        .map(|text| serde_json::from_str(text).expect("parse retained JSON column"))
        .unwrap_or_else(|| value.clone())
}

fn frozen_observations(directory: &Path, case_id: &str) -> (HashMap<String, ModuleResult>, Value) {
    let module_bytes = std::fs::read(directory.join(format!("{case_id}.module-results.json")))
        .expect("read frozen module rows");
    let rows: Vec<Value> = serde_json::from_slice(&module_bytes).expect("parse frozen module rows");
    let mut results = HashMap::new();
    for mut row in rows {
        assert_eq!(row["session_id"].as_str(), Some(case_id));
        if row["module_id"] == "verdict" {
            // The verdict node must never be fed back as an independent vote.
            continue;
        }
        for key in ["categories", "evidence", "details"] {
            row[key] = decode_json_column(&row[key]);
        }
        row["bpa"] =
            if row["bpa_b"].is_number() && row["bpa_d"].is_number() && row["bpa_u"].is_number() {
                json!({"b": row["bpa_b"], "d": row["bpa_d"], "u": row["bpa_u"], "epsilon": 0.0})
            } else {
                Value::Null
            };
        let result: ModuleResult = serde_json::from_value(row).expect("decode frozen ModuleResult");
        assert!(results.insert(result.module_id.clone(), result).is_none());
    }
    let snapshot_bytes = std::fs::read(directory.join(format!("{case_id}.db-snapshot.json")))
        .expect("read frozen DB snapshot");
    let snapshot: Value = serde_json::from_slice(&snapshot_bytes).expect("parse DB snapshot");
    let mut baseline = snapshot["verdicts"].clone();
    for verdict in baseline.as_array_mut().expect("stored verdict array") {
        for key in ["categories", "pillar_scores", "fusion_details"] {
            verdict[key] = decode_json_column(&verdict[key]);
        }
    }
    (
        results,
        json!({
            "module_rows_sha256": digest(&module_bytes),
            "db_snapshot_sha256": digest(&snapshot_bytes),
            "stored_production_verdicts": baseline,
            "baseline_kind": "historical_production_observation_not_a_fresh_replay"
        }),
    )
}

async fn replay(
    sample: &SessionSample,
    session: EmailSession,
    mode: &str,
    modules: &[Arc<dyn SecurityModule>],
    domains: Arc<HashSet<String>>,
    frozen: &HashMap<String, ModuleResult>,
    baseline: &Value,
) -> Vec<Value> {
    let session = Arc::new(session);
    let ctx = SecurityContext::with_internal_domains(Arc::clone(&session), domains);
    let mut results: HashMap<String, ModuleResult> = HashMap::new();
    let mut errors = BTreeMap::new();
    let mut skipped = Vec::new();
    for module in modules {
        if !module.should_run(&ctx) {
            skipped.push(module.metadata().id.clone());
            continue;
        }
        match module.analyze(&ctx).await {
            Ok(result) => {
                ctx.insert_result(result.clone()).await;
                results.insert(result.module_id.clone(), result);
            }
            Err(error) => {
                errors.insert(module.metadata().id.clone(), error.to_string());
            }
        }
    }
    let verdict = aggregate_verdict_with_session(
        Some(session.as_ref()),
        session.id,
        &results,
        &VerdictConfig::default(),
    );
    println!(
        "{} {} {} {:?} {:.3} modules={} errors={}",
        sample.case_id,
        sample.role,
        mode,
        verdict.threat_level,
        verdict.confidence,
        results.len(),
        errors.len()
    );
    let sorted_results: BTreeMap<_, _> = results.iter().collect();
    let header_details = results.get("header_scan").map(|result| &result.details);
    let data_security = json!({
        "status": "not_evaluated",
        "reason": "DLP/data-security pipeline is outside this local email-module replay"
    });
    let report = json!({
        "case_id": sample.case_id,
        "role": sample.role,
        "input_mode": mode,
        "fusion_mode": "local_modules_only",
        "historical_baseline": baseline,
        "raw_mime_retained": session.content.raw_mime.is_some(),
        "raw_mime_sha256": session.content.raw_mime.as_ref().map(|bytes| digest(bytes)),
        "envelope_and_capture_preserved": true,
        "observed_links": session.content.links,
        "module_results": sorted_results,
        "module_errors": errors,
        "modules_not_applicable": skipped,
        "verdict": verdict,
        "six_layers": {
            "threat": {"level": verdict.threat_level, "family": verdict.threat_type,
                       "confidence": verdict.confidence, "categories": verdict.categories},
            "classification": verdict.classification,
            "authentication": {"status": "not_independently_verified", "header_scan_details": header_details,
                               "reason": "No DNS/external authentication verification; SMTP envelope is observed identity, not proof"},
            "coverage": {"stored_or_parsed_complete": session.content.is_complete,
                         "stored_or_parsed_truncated": session.content.truncated,
                         "dropped_attachments": session.content.dropped_attachments,
                         "links_truncated": session.content.links_truncated,
                         "module_errors": errors,
                         "remote_modules": "not_executed", "sender_history": "NoDb/vacuous",
                         "link_transport": "not_attempted", "link_content": "not_observed",
                         "link_ownership": "unproven"},
            "data_security": data_security,
            "disposition": {"actual": "offline_observation_only", "production_write": false,
                            "soar_executed": false,
                            "would_meet_medium_alert_threshold": verdict.threat_level >= ThreatLevel::Medium}
        }
    });
    let mut mixed = frozen.clone();
    let local_ids: HashSet<_> = modules
        .iter()
        .map(|module| module.metadata().id.as_str())
        .collect();
    // A skipped or failed local re-evaluation cannot retain its stale positive.
    mixed.retain(|id, _| !local_ids.contains(id.as_str()));
    let mut frozen_ids: Vec<_> = mixed.keys().cloned().collect();
    frozen_ids.sort();
    mixed.extend(results);
    let mixed_verdict = aggregate_verdict_with_session(
        Some(session.as_ref()),
        session.id,
        &mixed,
        &VerdictConfig::default(),
    );
    println!(
        "{} {} {} frozen-external {:?} {:.3} frozen-modules={}",
        sample.case_id,
        sample.role,
        mode,
        mixed_verdict.threat_level,
        mixed_verdict.confidence,
        frozen_ids.len()
    );
    let mut mixed_report = report.clone();
    mixed_report["fusion_mode"] = json!("frozen_external_observations_with_local_replacement");
    mixed_report["frozen_external_module_ids"] = json!(frozen_ids);
    mixed_report["module_results"] = json!(mixed.iter().collect::<BTreeMap<_, _>>());
    mixed_report["verdict"] = json!(mixed_verdict);
    mixed_report["six_layers"]["threat"] = json!({
        "level": mixed_verdict.threat_level, "family": mixed_verdict.threat_type,
        "confidence": mixed_verdict.confidence, "categories": mixed_verdict.categories
    });
    mixed_report["six_layers"]["classification"] = json!(mixed_verdict.classification);
    mixed_report["six_layers"]["coverage"]["remote_modules"] =
        json!("historical_frozen_observations");
    mixed_report["six_layers"]["coverage"]["link_transport"] =
        json!("not_attempted_in_replay; historical_details_retained_per_module");
    mixed_report["six_layers"]["coverage"]["link_content"] =
        json!("not_observed_in_replay; historical_details_retained_per_module");
    mixed_report["six_layers"]["coverage"]["link_ownership"] =
        json!("not_newly_verified; historical_details_retained_per_module");
    mixed_report["six_layers"]["disposition"]["would_meet_medium_alert_threshold"] =
        json!(mixed_verdict.threat_level >= ThreatLevel::Medium);
    vec![report, mixed_report]
}

#[tokio::test]
#[ignore = "requires an explicitly authorized real-mail bundle outside the repository"]
async fn offline_real_sessions() {
    assert_eq!(
        std::env::var("VIGILYX_ALLOW_REAL_OFFLINE_REPLAY").as_deref(),
        Ok("1"),
        "explicit opt-in required"
    );
    let path =
        |name: &str| PathBuf::from(std::env::var(name).expect("external replay path required"));
    let bundle_path = path("VIGILYX_OFFLINE_REAL_BUNDLE");
    let external_directory = bundle_path.parent().expect("bundle directory");
    let bundle_bytes = std::fs::read(&bundle_path).expect("read session bundle");
    let config_bytes =
        std::fs::read(path("VIGILYX_OFFLINE_RUNTIME_CONFIG")).expect("read config snapshot");
    let bundle: SessionBundle =
        serde_json::from_slice(&bundle_bytes).expect("parse session bundle");
    assert_eq!(bundle.schema_version, 1);
    assert_eq!(bundle.runtime_config_snapshot_sha256, digest(&config_bytes));
    assert!(!bundle.samples.is_empty());
    let config: Value = serde_json::from_slice(&config_bytes).expect("parse config snapshot");
    let (lists, effective_seed_sha256) = initialize_config(&config);
    let modules = local_modules(&lists);
    let domains = Arc::new(bundle.internal_domains.iter().cloned().collect());
    let mut reports = Vec::new();
    for sample in &bundle.samples {
        assert_eq!(sample.case_id, sample.session.id.to_string());
        let (frozen, baseline) = frozen_observations(external_directory, &sample.case_id);
        reports.extend(
            replay(
                sample,
                sample.session.clone(),
                "stored_email_session",
                &modules,
                Arc::clone(&domains),
                &frozen,
                &baseline,
            )
            .await,
        );
        if let Some(raw) = sample.session.content.raw_mime.as_ref() {
            let mut reparsed = sample.session.clone();
            reparsed.content = MimeParser::new()
                .parse(raw)
                .expect("parse retained original MIME");
            // Capture gaps do not disappear because retained bytes can be parsed again.
            reparsed.content.is_complete &= sample.session.content.is_complete;
            reparsed.content.truncated |= sample.session.content.truncated;
            reparsed.content.links_truncated |= sample.session.content.links_truncated;
            reparsed.content.dropped_attachments = reparsed
                .content
                .dropped_attachments
                .max(sample.session.content.dropped_attachments);
            reports.extend(
                replay(
                    sample,
                    reparsed,
                    "retained_original_mime_reparsed",
                    &modules,
                    Arc::clone(&domains),
                    &frozen,
                    &baseline,
                )
                .await,
            );
        }
    }
    let report = json!({
        "schema_version": 1,
        "bundle_sha256": digest(&bundle_bytes),
        "runtime_config_snapshot_sha256": digest(&config_bytes),
        "effective_module_seed_sha256": effective_seed_sha256,
        "verdict_config": VerdictConfig::default(),
        "cohort_scope": bundle.scope,
        "sample_count": bundle.samples.len(),
        "replay_count": reports.len(),
        "module_scope": modules.iter().map(|module| &module.metadata().id).collect::<Vec<_>>(),
        "limitations": [
            "Diagnostic cohort, not an independent blind holdout or platform false-positive rate",
            "NoDb sender history and no live IOC database; local module subset, not exact full-production replay",
            "Frozen-external mode retains historical nonlocal module observations without re-fetching or independently verifying them",
            "No network, external intelligence, authentication DNS, landing-page fetch, DLP or SOAR",
            "Stored sessions without retained raw MIME are not reparsed from derived EML",
            "Capture gaps remain incomplete in reparsed input; positive ownership/clean-link trust is never inferred"
        ],
        "samples": reports
    });
    let output = path("VIGILYX_OFFLINE_REAL_REPORT");
    let bytes = serde_json::to_vec_pretty(&report).expect("serialize external report");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&output)
            .expect("create a new private report; preserve prior reports");
        file.write_all(&bytes).expect("write report");
    }
    #[cfg(not(unix))]
    std::fs::write(&output, bytes).expect("write report");
    assert!(
        report["samples"]
            .as_array()
            .expect("report samples")
            .iter()
            .all(|sample| sample["module_errors"]
                .as_object()
                .is_some_and(|errors| errors.is_empty())),
        "module errors: inspect external report"
    );
}
