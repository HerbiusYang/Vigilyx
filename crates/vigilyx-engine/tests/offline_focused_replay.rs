//! Explicitly enabled diagnostic replay of selected local modules only.
//!
//! Keep the bundle, frozen runtime configuration, and report outside Git.
//! The bundle contains `schema_version: 1`, `scope`, `internal_domains`, and
//! `samples: [{case_id, session: EmailSession, module_results: [DB rows]}]`.
//! An optional `runtime_config_snapshot_sha256` binds the config file bytes.
//! Optional domain lists freeze tenant additions to the compiled URL seed.
//! No MIME reparse, remote services, persistence, delivery, or SOAR runs here.
//! Historical module observations are not a fresh baseline artifact replay.
//!
//! Build on the project-required remote builder, then run the test executable
//! in a network-disabled container with private external files mounted:
//! VIGILYX_ALLOW_REAL_OFFLINE_REPLAY=1
//! VIGILYX_OFFLINE_FOCUSED_BUNDLE=/audit/session-bundle.json
//! VIGILYX_OFFLINE_RUNTIME_CONFIG=/audit/runtime-config.json
//! VIGILYX_OFFLINE_FOCUSED_REPORT=/reports/focused-replay.json
//! VIGILYX_OFFLINE_REPLACEMENT_MODULES=attach_content
//! --ignored --exact offline_focused_replay --nocapture
//!
//! Allowed replacements: attach_scan, attach_content, content_scan, html_scan,
//! semantic_scan (local fallback; AI disabled). Only selected module results
//! are replaced; all other frozen observations are retained unchanged.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{Bpa, EmailClassification, SecurityVerdict, ThreatLevel};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{ModuleResult, SecurityModule};
use vigilyx_engine::module_data::{ModuleDataOverrides, ModuleDataRegistry, set_module_data};
use vigilyx_engine::modules::attach_content::AttachContentModule;
use vigilyx_engine::modules::attach_scan::AttachScanModule;
use vigilyx_engine::modules::content_scan::{
    ContentScanModule, EffectiveKeywordLists, KeywordOverrides, build_effective_keyword_lists,
    normalize_system_keyword_seed, normalize_user_keyword_overrides,
};
use vigilyx_engine::modules::html_scan::HtmlScanModule;
use vigilyx_engine::pipeline::config::{PipelineConfig, VerdictConfig};
use vigilyx_engine::pipeline::verdict::{
    ScenarioPatternLists, aggregate_verdict_with_session, set_runtime_scenario_patterns,
};
use vigilyx_engine::semantic::SemanticScanModule;

#[derive(Deserialize)]
struct FocusedBundle {
    schema_version: u32,
    scope: String,
    internal_domains: Vec<String>,
    #[serde(default)]
    url_trusted_domains: Vec<String>,
    #[serde(default)]
    well_known_safe_domains: Vec<String>,
    #[serde(default)]
    runtime_config_snapshot_sha256: Option<String>,
    samples: Vec<FocusedSample>,
}

#[derive(Deserialize)]
struct FocusedSample {
    case_id: String,
    session: EmailSession,
    module_results: Vec<Value>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// Do not include serde errors in stdout: malformed fields can contain mail.
fn decode_json_column(value: &Value) -> Value {
    match value.as_str() {
        Some(text) => serde_json::from_str(text)
            .unwrap_or_else(|_| panic!("invalid JSON in a frozen column; inspect private input")),
        None => value.clone(),
    }
}

fn config_value(snapshot: &Value, key: &str) -> Option<Value> {
    snapshot
        .get(key)
        .filter(|value| !value.is_null())
        .map(decode_json_column)
}

// Same list-only backfill as production module_data::load_module_data_seed
// and the existing offline_real_sessions diagnostic. Persisted values win.
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

fn initialize_config(
    snapshot: &Value,
    bundle: &FocusedBundle,
) -> (EffectiveKeywordLists, VerdictConfig, Value) {
    let mut sources = BTreeMap::new();
    let compiled: Value = serde_json::from_str(vigilyx_db::security::embedded_module_data_seed())
        .expect("parse compiled module seed");
    let mut seed = match config_value(snapshot, "engine_module_data_seed") {
        Some(seed) => {
            sources.insert("module_data_seed", "frozen_snapshot_with_compiled_backfill");
            seed
        }
        None => {
            sources.insert("module_data_seed", "compiled_default_missing_snapshot");
            compiled.clone()
        }
    };
    if !seed.get("lists").is_some_and(Value::is_object) {
        sources.insert("module_data_seed", "compiled_default_invalid_seed_shape");
        seed = compiled.clone();
    } else {
        backfill_defaults(&compiled["lists"], &mut seed["lists"]);
    }
    let effective_seed = serde_json::to_string(&seed).expect("serialize effective module seed");
    let overrides = match config_value(snapshot, "engine_module_data_overrides") {
        Some(value) => {
            sources.insert("module_data_overrides", "frozen_snapshot");
            serde_json::from_value::<ModuleDataOverrides>(value)
                .unwrap_or_else(|_| panic!("invalid frozen module overrides"))
        }
        None => {
            sources.insert("module_data_overrides", "empty_default_missing_snapshot");
            ModuleDataOverrides::default()
        }
    };
    set_module_data(
        ModuleDataRegistry::from_seed_and_overrides(&effective_seed, &overrides)
            .unwrap_or_else(|_| panic!("invalid effective frozen module registry")),
    );
    let keywords = match config_value(snapshot, "keyword_system_seed") {
        Some(value) => {
            sources.insert("keyword_system_seed", "frozen_snapshot");
            serde_json::from_value::<KeywordOverrides>(value)
                .unwrap_or_else(|_| panic!("invalid frozen keyword seed"))
        }
        None => {
            // Production registry uses an empty system seed when DB has none.
            sources.insert("keyword_system_seed", "empty_default_missing_snapshot");
            KeywordOverrides::default()
        }
    };
    let keywords = normalize_system_keyword_seed(&keywords);
    let overrides = match config_value(snapshot, "keyword_overrides") {
        Some(value) => {
            sources.insert("keyword_overrides", "frozen_snapshot");
            serde_json::from_value::<KeywordOverrides>(value)
                .unwrap_or_else(|_| panic!("invalid frozen keyword overrides"))
        }
        None => {
            sources.insert("keyword_overrides", "empty_default_missing_snapshot");
            KeywordOverrides::default()
        }
    };
    let overrides = normalize_user_keyword_overrides(&keywords, &overrides);
    let lists = build_effective_keyword_lists(&keywords, &overrides);
    set_runtime_scenario_patterns(ScenarioPatternLists::from(&lists));

    let verdict_config = match config_value(snapshot, "security_pipeline") {
        Some(value) => {
            sources.insert("verdict_config", "frozen_security_pipeline");
            serde_json::from_value::<PipelineConfig>(value)
                .unwrap_or_else(|_| panic!("invalid frozen security_pipeline"))
                .verdict_config
        }
        None => {
            sources.insert("verdict_config", "compiled_default_missing_snapshot");
            VerdictConfig::default()
        }
    };
    assert!(
        verdict_config.validate().is_ok(),
        "frozen verdict configuration is invalid; no silent threshold repair"
    );

    let builtin: Value = serde_json::from_str(include_str!(
        "../../../shared/schemas/system_whitelist_seed.json"
    ))
    .expect("parse compiled URL domain seed");
    let domains = |section: &str| {
        builtin[section]["items"]
            .as_array()
            .expect("compiled domain seed items")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect::<HashSet<_>>()
    };
    let mut trusted = domains("url_trusted");
    trusted.extend(bundle.url_trusted_domains.iter().cloned());
    let mut safe = domains("intel_safe");
    safe.extend(domains("url_trusted"));
    safe.extend(bundle.well_known_safe_domains.iter().cloned());
    vigilyx_engine::modules::link_scan::set_trusted_url_domains(Arc::new(trusted));
    vigilyx_engine::modules::link_scan::set_well_known_safe_domains(Arc::new(safe));
    (
        lists,
        verdict_config,
        json!({
            "sources": sources,
            "effective_module_seed_sha256": digest(effective_seed.as_bytes()),
            "url_domain_source": "compiled_seed_plus_bundle_tenant_additions",
            "tenant_url_domain_snapshot_verified": false
        }),
    )
}

fn frozen_results(sample: &FocusedSample) -> HashMap<String, ModuleResult> {
    let mut results = HashMap::new();
    for row in &sample.module_results {
        let mut row = row.clone();
        if let Some(session_id) = row["session_id"].as_str() {
            assert!(
                session_id == sample.session.id.to_string(),
                "frozen module row belongs to another session"
            );
        }
        if row["module_id"] == "verdict" {
            continue;
        }
        for key in ["categories", "evidence", "details"] {
            row[key] = decode_json_column(&row[key]);
        }
        if let (Some(b), Some(d), Some(u)) = (
            row["bpa_b"].as_f64(),
            row["bpa_d"].as_f64(),
            row["bpa_u"].as_f64(),
        ) {
            row["bpa"] = serde_json::to_value(Bpa::new(b, d, u)).expect("serialize frozen BPA");
        }
        let result: ModuleResult = serde_json::from_value(row)
            .unwrap_or_else(|_| panic!("invalid frozen module row; inspect private input"));
        assert!(
            results.insert(result.module_id.clone(), result).is_none(),
            "duplicate frozen module_id"
        );
    }
    assert!(!results.is_empty(), "frozen module observations required");
    results
}

fn replacement_modules(lists: &EffectiveKeywordLists) -> Vec<Arc<dyn SecurityModule>> {
    let selected = std::env::var("VIGILYX_OFFLINE_REPLACEMENT_MODULES")
        .unwrap_or_else(|_| "attach_content".to_string());
    let selected: HashSet<_> = selected.split(',').map(str::trim).collect();
    assert!(
        !selected.is_empty()
            && selected.iter().all(|id| matches!(
                *id,
                "attach_scan" | "attach_content" | "content_scan" | "html_scan" | "semantic_scan"
            )),
        "replacement selection must contain supported local module IDs only"
    );
    // Stable order also respects attach_content's attachment-scan dependency.
    let local: Vec<Arc<dyn SecurityModule>> = vec![
        Arc::new(AttachScanModule::new()),
        Arc::new(AttachContentModule::new_with_keyword_lists(lists.clone())),
        Arc::new(ContentScanModule::new_with_keyword_lists(lists.clone())),
        Arc::new(HtmlScanModule::new()),
        Arc::new(SemanticScanModule::new(None)),
    ];
    local
        .into_iter()
        .filter(|module| selected.contains(module.metadata().id.as_str()))
        .collect()
}

fn external_path(name: &str, output: bool) -> PathBuf {
    let path = PathBuf::from(std::env::var(name).expect("external replay path required"));
    assert!(path.is_absolute(), "external replay paths must be absolute");
    let resolved = if output {
        path.parent()
            .expect("report parent required")
            .canonicalize()
            .expect("report parent must exist")
            .join(path.file_name().expect("report filename required"))
    } else {
        path.canonicalize().expect("external input must exist")
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository root");
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    assert!(
        !resolved.starts_with(root),
        "real inputs and reports must remain outside the repository"
    );
    resolved
}

fn six_layers(verdict: &SecurityVerdict) -> Value {
    json!({
        "threat": {"level": verdict.threat_level, "family": verdict.threat_type,
                   "confidence": verdict.confidence, "categories": verdict.categories},
        "classification": verdict.classification,
        "authentication": {"status": "not_independently_verified",
                           "source": "historical_frozen_observations_only"},
        "coverage": {"inspection": verdict.inspection_coverage,
                     "reasons": verdict.coverage_reasons,
                     "link_transport": "not_attempted",
                     "link_content": "not_observed_in_replay",
                     "link_ownership": "not_newly_verified"},
        "data_security": {"status": "not_evaluated",
                          "reason": "separate DLP pipeline is outside focused email replay"},
        "disposition": {"actual": "offline_observation_only", "production_write": false,
                        "soar_executed": false,
                        "would_meet_medium_alert_threshold": verdict.threat_level >= ThreatLevel::Medium}
    })
}

#[tokio::test]
#[ignore = "requires explicit opt-in and private external diagnostic inputs"]
async fn offline_focused_replay() {
    assert!(
        std::env::var("VIGILYX_ALLOW_REAL_OFFLINE_REPLAY").as_deref() == Ok("1"),
        "explicit real-mail replay opt-in required"
    );
    let bundle_path = external_path("VIGILYX_OFFLINE_FOCUSED_BUNDLE", false);
    let config_path = external_path("VIGILYX_OFFLINE_RUNTIME_CONFIG", false);
    let output = external_path("VIGILYX_OFFLINE_FOCUSED_REPORT", true);
    let bundle_bytes = std::fs::read(bundle_path).expect("read private session bundle");
    let config_bytes = std::fs::read(config_path).expect("read frozen runtime snapshot");
    let bundle: FocusedBundle = serde_json::from_slice(&bundle_bytes)
        .unwrap_or_else(|_| panic!("invalid private bundle; inspect input without logging mail"));
    assert!(bundle.schema_version == 1, "unsupported bundle schema");
    assert!(!bundle.samples.is_empty(), "diagnostic samples required");
    if let Some(expected) = &bundle.runtime_config_snapshot_sha256 {
        assert!(
            expected == &digest(&config_bytes),
            "runtime snapshot hash mismatch"
        );
    }
    let snapshot: Value = serde_json::from_slice(&config_bytes)
        .unwrap_or_else(|_| panic!("invalid private runtime snapshot"));
    assert!(
        snapshot.is_object(),
        "runtime snapshot must be a config-key map"
    );
    let (lists, config, config_details) = initialize_config(&snapshot, &bundle);
    let modules = replacement_modules(&lists);
    assert!(
        modules.iter().all(|module| !module.metadata().is_remote),
        "focused replay cannot use remote modules"
    );
    let selected: HashSet<_> = modules
        .iter()
        .map(|module| module.metadata().id.as_str())
        .collect();
    let domains = Arc::new(bundle.internal_domains.iter().cloned().collect());
    let mut case_ids = HashSet::new();
    let mut reports = Vec::new();
    let mut error_count = 0usize;
    for (index, sample) in bundle.samples.iter().enumerate() {
        assert!(case_ids.insert(&sample.case_id), "duplicate case_id");
        let frozen = frozen_results(sample);
        let session = Arc::new(sample.session.clone());
        let baseline =
            aggregate_verdict_with_session(Some(session.as_ref()), session.id, &frozen, &config);
        let ctx =
            SecurityContext::with_internal_domains(Arc::clone(&session), Arc::clone(&domains));
        let mut candidate_results = frozen.clone();
        // Never retain a selected module's stale positive when it fails/skips.
        candidate_results.retain(|id, _| !selected.contains(id.as_str()));
        for result in candidate_results.values() {
            ctx.insert_result(result.clone()).await;
        }
        let mut errors = BTreeMap::new();
        let mut skipped = Vec::new();
        for module in &modules {
            let id = &module.metadata().id;
            if !module.should_run(&ctx) {
                skipped.push(id.clone());
                continue;
            }
            match module.analyze(&ctx).await {
                Ok(result) => {
                    assert!(result.module_id == *id, "replacement module ID mismatch");
                    ctx.insert_result(result.clone()).await;
                    candidate_results.insert(result.module_id.clone(), result);
                }
                Err(error) => {
                    errors.insert(id.clone(), error.to_string());
                }
            }
        }
        error_count += errors.len();
        let candidate = aggregate_verdict_with_session(
            Some(session.as_ref()),
            session.id,
            &candidate_results,
            &config,
        );
        // Safe stdout summary: no subject, addresses, URLs, body, evidence,
        // hashes, or reviewer case IDs. Full diagnostics go to the 0600 file.
        println!(
            "sample={} historical-fusion={}/{:.3}/{} replacement-fusion={}/{:.3}/{} errors={}",
            index + 1,
            baseline.threat_level,
            baseline.confidence,
            baseline
                .classification
                .unwrap_or(EmailClassification::Undetermined),
            candidate.threat_level,
            candidate.confidence,
            candidate
                .classification
                .unwrap_or(EmailClassification::Undetermined),
            errors.len()
        );
        let retained_ids: Vec<_> = candidate_results
            .keys()
            .filter(|id| !selected.contains(id.as_str()))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        reports.push(json!({
            "case_id": sample.case_id,
            "session_id": session.id,
            "input_mode": "stored_email_session_without_reparse",
            "session_source": session.source,
            "historical_observation_fusion": {
                "module_results": frozen.iter().collect::<BTreeMap<_, _>>(),
                "verdict": baseline,
                "six_layers": six_layers(&baseline)
            },
            "focused_replacement_fusion": {
                "retained_frozen_module_ids": retained_ids,
                "module_results": candidate_results.iter().collect::<BTreeMap<_, _>>(),
                "verdict": candidate,
                "six_layers": six_layers(&candidate),
                "module_errors": errors,
                "modules_not_applicable": skipped
            },
            "capture_preserved": {"is_complete": session.content.is_complete,
                                  "truncated": session.content.truncated,
                                  "links_truncated": session.content.links_truncated,
                                  "dropped_attachments": session.content.dropped_attachments}
        }));
    }
    let report = json!({
        "schema_version": 1,
        "milestone": "hypothesis_only",
        "scope": bundle.scope,
        "bundle_sha256": digest(&bundle_bytes),
        "runtime_config_snapshot_sha256": digest(&config_bytes),
        "runtime_snapshot_hash_bound_by_bundle": bundle.runtime_config_snapshot_sha256.is_some(),
        "configuration": config_details,
        "verdict_config": config,
        "replacement_modules": modules.iter().map(|module| &module.metadata().id).collect::<Vec<_>>(),
        "ai_execution": "disabled; semantic_scan uses local fallback only",
        "sample_count": reports.len(),
        "module_error_count": error_count,
        "limitations": [
            "Focused diagnostic cases, not independent validation or a platform-wide quality estimate",
            "Historical observation fusion uses current fusion code; it is not a baseline engine artifact replay",
            "Unselected module results remain historical frozen observations, not independently reverified",
            "Only the stored EmailSession is used; capture gaps remain and MIME is not reparsed",
            "Domain additions must be captured separately; omitted additions leave compiled URL-domain seed only",
            "No remote AI, network, authentication DNS, link fetching, DB, separate DLP pipeline, delivery or SOAR"
        ],
        "samples": reports
    });
    let bytes = serde_json::to_vec_pretty(&report).expect("serialize private focused report");
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&output)
            .expect("create new protected report; preserve existing reports");
        file.write_all(&bytes).expect("write protected report");
    }
    #[cfg(not(unix))]
    panic!("focused real-mail report requires Unix private-file permissions");
    println!(
        "focused replay complete: samples={} errors={} verdict-config-source={}",
        bundle.samples.len(),
        error_count,
        report["configuration"]["sources"]["verdict_config"]
            .as_str()
            .expect("verdict config source recorded")
    );
    assert!(
        error_count == 0,
        "module errors recorded in the protected report"
    );
}
