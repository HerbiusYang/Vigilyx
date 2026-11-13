//! Offline text-only audit of E-PhishLLM and Fraud-R1 imports.
//! Prepare cases with scripts/prepare_semantic_corpora.py. Run explicitly on
//! the remote builder with VIGILYX_SEMANTIC_EXTERNAL_INPUT and
//! VIGILYX_SEMANTIC_EXTERNAL_OUTPUT set; no NLP, OCR or link fetching is used.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_core::security::{
    SemanticMessageContext, SemanticScenarioFinding, SemanticScenarioResolution,
};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{SecurityModule, ThreatLevel};
use vigilyx_engine::semantic::{SemanticScanModule, is_current_recipient_action};
use vigilyx_parser::MimeParser;

#[derive(Deserialize)]
struct Case {
    schema_version: u8,
    content_id: String,
    subject: Option<String>,
    body: String,
    content_type: String,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
struct Source {
    sample_id: String,
    dataset: String,
    language: String,
    data_type: String,
    variant: String,
    category: String,
    subcategory: String,
    label: String,
}

#[derive(Default, serde::Serialize)]
struct Tally {
    contents: usize,
    scenario_observed: usize,
    review_required: usize,
    actionable_extortion: usize,
    elevated_threat: usize,
    coverage_limited: usize,
    current_request: usize,
    module_errors: usize,
}

impl Tally {
    fn add(&mut self, row: &Value) {
        self.contents += 1;
        self.module_errors += usize::from(row["status"] != "ok");
        self.scenario_observed += usize::from(row["scenario_observed"] == true);
        self.review_required += usize::from(row["review_required"] == true);
        self.actionable_extortion += usize::from(row["actionable_extortion"] == true);
        self.elevated_threat += usize::from(row["elevated_threat"] == true);
        self.coverage_limited += usize::from(row["coverage_limited"] == true);
        self.current_request += usize::from(row["current_request_count"].as_u64().unwrap_or(0) > 0);
    }
}

fn collect_contexts(details: &Value) -> Vec<SemanticMessageContext> {
    let mut values = vec![
        &details["semantic_context"],
        &details["semantic_header_context"],
    ];
    if let Some(alternates) = details["semantic_alternative_contexts"].as_array() {
        values.extend(alternates.iter().map(|item| &item["semantic_context"]));
    }
    values
        .into_iter()
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(value.clone()).expect("typed semantic context"))
        .collect()
}

fn collect_findings(details: &Value) -> Vec<SemanticScenarioFinding> {
    let mut values = vec![&details["semantic_scenarios"]];
    if let Some(alternates) = details["semantic_alternative_contexts"].as_array() {
        values.extend(alternates.iter().map(|item| &item["semantic_scenarios"]));
    }
    values
        .into_iter()
        .filter_map(Value::as_array)
        .flatten()
        .map(|value| serde_json::from_value(value.clone()).expect("typed semantic finding"))
        .collect()
}

fn issue_tags(case: &Case, row: &Value) -> BTreeSet<&'static str> {
    let labels = case
        .sources
        .iter()
        .map(|source| source.label.as_str())
        .collect::<BTreeSet<_>>();
    let mut tags = BTreeSet::new();
    if labels.len() > 1 {
        tags.insert("conflicting_dataset_labels");
    }
    if row["status"] != "ok" {
        tags.insert("module_error");
        return tags;
    }
    if row["coverage_limited"] == true {
        tags.insert("coverage_limited");
    }
    if labels.contains("malicious") && row["scenario_observed"] != true {
        tags.insert("malicious_label_without_scenario_candidate");
        if row["current_request_count"] == 0 {
            tags.insert("no_current_recipient_action");
        }
        if row["claim_count"] == 0 {
            tags.insert("no_recognized_claim");
        }
    }
    if labels.contains("benign") && row["scenario_observed"] == true {
        tags.insert("benign_label_with_scenario_candidate");
    }
    if labels.contains("benign") && row["elevated_threat"] == true {
        tags.insert("benign_label_with_elevated_module_threat");
    }
    if row["observed_link_count"].as_u64().unwrap_or(0) > 0
        && row["linked_current_request_count"] == 0
    {
        tags.insert("observed_links_without_current_request_binding");
    }
    tags
}

#[tokio::test]
#[ignore = "external research corpus; run explicitly on the remote builder"]
async fn external_text_semantic_audit() {
    let input =
        PathBuf::from(std::env::var("VIGILYX_SEMANTIC_EXTERNAL_INPUT").expect("corpus JSONL path"));
    let output = PathBuf::from(
        std::env::var("VIGILYX_SEMANTIC_EXTERNAL_OUTPUT").expect("new report directory"),
    );
    std::fs::create_dir(&output)
        .expect("create a fresh report directory; do not overwrite prior runs");
    let mut report = BufWriter::new(File::create(output.join("results.jsonl")).unwrap());
    let limit = std::env::var("VIGILYX_SEMANTIC_EXTERNAL_LIMIT")
        .ok()
        .map(|value| value.parse::<usize>().expect("positive corpus limit"));
    assert!(limit != Some(0));
    let module = SemanticScanModule::new(None);
    let effective_policy = vigilyx_engine::module_data::module_data().to_effective_json();
    let policy_bytes = serde_json::to_vec(&effective_policy).unwrap();
    let policy_sha256 = hex::encode(Sha256::digest(&policy_bytes));
    std::fs::write(output.join("effective_policy.json"), &policy_bytes).unwrap();
    let mut strata = BTreeMap::<String, Tally>::new();
    let mut unique = Tally::default();
    let mut seen_content = BTreeSet::new();
    let mut seen_samples = BTreeSet::new();
    let mut issues = BTreeMap::<String, usize>::new();
    let mut input_hash = Sha256::new();
    let started = Instant::now();

    for line in BufReader::new(File::open(&input).expect("open corpus")).split(b'\n') {
        let line = line.expect("read corpus line");
        if line.is_empty() {
            continue;
        }
        if limit.is_some_and(|limit| unique.contents >= limit) {
            break;
        }
        input_hash.update(&line);
        input_hash.update(b"\n");
        let case: Case = serde_json::from_slice(&line).expect("valid corpus record");
        assert_eq!(case.schema_version, 1);
        assert_eq!(case.content_type, "text/plain");
        assert!(!case.sources.is_empty());
        assert!(
            seen_content.insert(case.content_id.clone()),
            "duplicate execution of content"
        );
        for source in &case.sources {
            assert!(
                seen_samples.insert(source.sample_id.clone()),
                "duplicate sample ID"
            );
            assert!(matches!(
                source.label.as_str(),
                "benign" | "malicious" | "spam"
            ));
        }

        // A fixed transport wrapper lets the real parser extract links. Subject
        // stays a separate supplied field: never interpolate it into MIME headers.
        // No From/To/envelope/authentication facts are manufactured from a label.
        let raw = format!(
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
            case.body
        );
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.1".into(),
            40000,
            "192.0.2.1".into(),
            25,
        );
        session.content = MimeParser::new()
            .parse(raw.as_bytes())
            .expect("parse text transport wrapper");
        session.subject = case.subject.clone();
        assert!(session.mail_from.is_none() && session.rcpt_to.is_empty());
        let item_start = Instant::now();
        let result = module
            .analyze(&SecurityContext::new(Arc::new(session)))
            .await;
        let mut row = match result {
            Ok(result) => {
                assert_ne!(
                    result.details["nlp_used"], true,
                    "external audit must stay local"
                );
                let contexts = collect_contexts(&result.details);
                let findings = collect_findings(&result.details);
                let claims = contexts
                    .iter()
                    .flat_map(|context| &context.claims)
                    .collect::<Vec<_>>();
                let requests = claims
                    .iter()
                    .copied()
                    .filter(|claim| is_current_recipient_action(claim))
                    .collect::<Vec<_>>();
                json!({
                    "status": "ok", "threat_level": result.threat_level,
                    "confidence": result.confidence,
                    "elevated_threat": result.threat_level > ThreatLevel::Safe,
                    "actionable_extortion": result.categories.iter().any(|value| value == "sextortion"),
                    "categories": result.categories,
                    "scenario_observed": findings.iter().any(|finding| finding.resolution != SemanticScenarioResolution::Countered),
                    "review_required": result.details["semantic_review_required"] == true,
                    "coverage_limited": result.details["semantic_coverage_limited"] == true
                        || !result.details["semantic_context"].is_object(),
                    "claim_count": claims.len(), "current_request_count": requests.len(),
                    "linked_current_request_count": requests.iter().filter(|claim| !claim.link_ids.is_empty()).count(),
                    "observed_link_count": contexts.iter().flat_map(|context| &context.links).map(|link| &link.original_url).collect::<BTreeSet<_>>().len(),
                    "findings": findings, "details": result.details,
                })
            }
            Err(error) => json!({"status": "module_error", "error": error.to_string()}),
        };
        row["schema_version"] = json!(1);
        row["content_id"] = json!(case.content_id);
        row["elapsed_us"] = json!(item_start.elapsed().as_micros());
        row["issue_tags"] = json!(issue_tags(&case, &row));
        for tag in row["issue_tags"].as_array().unwrap() {
            *issues.entry(tag.as_str().unwrap().to_owned()).or_default() += 1;
        }
        unique.add(&row);
        // Each content contributes at most once to any stratum, even if aliases
        // occur in several source files. Strata overlap and must not be summed.
        let keys = case
            .sources
            .iter()
            .map(|source| {
                format!(
                    "{}/{}/{}/{}/{}/{}/{}",
                    source.dataset,
                    source.language,
                    source.data_type,
                    source.variant,
                    source.label,
                    source.category,
                    source.subcategory
                )
            })
            .collect::<BTreeSet<_>>();
        for key in keys {
            strata.entry(key).or_default().add(&row);
        }
        serde_json::to_writer(&mut report, &row).unwrap();
        report.write_all(b"\n").unwrap();
        if unique.contents.is_multiple_of(500) {
            report.flush().unwrap();
            println!(
                "external semantic audit: {} unique texts, {:.1}s",
                unique.contents,
                started.elapsed().as_secs_f64()
            );
        }
    }
    report.flush().unwrap();
    assert!(unique.contents > 0, "empty corpus");
    let summary = json!({
        "schema_version": 1, "mode": "offline_plain_text_semantic_only",
        "policy_source": "compiled default registry; no database overrides",
        "effective_policy_sha256": policy_sha256,
        "crate_version": env!("CARGO_PKG_VERSION"),
        "debug_assertions": cfg!(debug_assertions),
        "architecture": std::env::consts::ARCH,
        "input_sha256": hex::encode(input_hash.finalize()), "limited_run": limit.is_some(),
        "unique_contents": unique, "source_instances": seen_samples.len(),
        "elapsed_seconds": started.elapsed().as_secs_f64(), "strata": strata,
        "issue_candidate_counts": issues,
        "interpretation": "scenario observations are not malicious verdicts; issue tags require review against exact text and dataset labels",
    });
    serde_json::to_writer_pretty(File::create(output.join("summary.json")).unwrap(), &summary)
        .unwrap();
    println!(
        "external semantic audit completed: {} unique texts; reports: {}",
        unique.contents,
        output.display()
    );
    assert_eq!(unique.module_errors, 0, "module errors retained in report");
}
