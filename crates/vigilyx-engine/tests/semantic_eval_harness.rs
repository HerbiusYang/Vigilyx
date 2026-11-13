//! Labelled-corpus evaluation of the local semantic module.
//!
//! Replays the existing red-team corpus (`tests/redteam_cases/labels.json`
//! and `tests/redteam_cases/synth/labels.jsonl`) through
//! `SemanticScanModule::new(None)` and prints per-family signal rates:
//! recall on malicious mail, false positives on benign mail. Metrics are
//! reported, not asserted; the module is one input to fusion, so these are
//! semantic-layer rates, not verdict accuracy.
//!
//! ```text
//! cargo test -p vigilyx-engine --test semantic_eval_harness -- --ignored --nocapture
//! ```
//!
//! `VIGILYX_SEMANTIC_EVAL_LIMIT=<n>` evaluates only the first n cases.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{ModuleResult, SecurityModule, ThreatLevel};
use vigilyx_engine::semantic::SemanticScanModule;
use vigilyx_parser::MimeParser;
use vigilyx_parser::mime::decode_rfc2047;

#[derive(Deserialize)]
struct LabelFile {
    cases: Vec<Label>,
}

#[derive(Deserialize, Clone)]
struct Label {
    file: String,
    label: String,
    #[serde(default)]
    family: String,
}

#[derive(Default)]
struct Tally {
    total: usize,
    scenario: usize,
    review: usize,
    sextortion: usize,
    unsafe_level: usize,
    nonsensical: usize,
    any_signal: usize,
}

impl Tally {
    fn add(&mut self, signals: &Signals) {
        self.total += 1;
        self.scenario += usize::from(signals.scenario);
        self.review += usize::from(signals.review);
        self.sextortion += usize::from(signals.sextortion);
        self.unsafe_level += usize::from(signals.unsafe_level);
        self.nonsensical += usize::from(signals.nonsensical);
        self.any_signal += usize::from(signals.scenario || signals.review || signals.sextortion);
    }

    fn rate(count: usize, total: usize) -> f64 {
        if total == 0 {
            0.0
        } else {
            count as f64 * 100.0 / total as f64
        }
    }

    fn row(&self, name: &str) -> String {
        format!(
            "{name:<34} {:>5} {:>8.1}% {:>8.1}% {:>8.1}% {:>8.1}% {:>8.1}% {:>8.1}%",
            self.total,
            Self::rate(self.any_signal, self.total),
            Self::rate(self.scenario, self.total),
            Self::rate(self.review, self.total),
            Self::rate(self.sextortion, self.total),
            Self::rate(self.unsafe_level, self.total),
            Self::rate(self.nonsensical, self.total),
        )
    }
}

struct Signals {
    scenario: bool,
    review: bool,
    sextortion: bool,
    unsafe_level: bool,
    nonsensical: bool,
}

fn signals(result: &ModuleResult) -> Signals {
    let scenario = result.details["semantic_scenarios"]
        .as_array()
        .is_some_and(|findings| {
            findings
                .iter()
                .any(|finding| finding["resolution"] != "countered")
        });
    Signals {
        scenario,
        review: result.details["semantic_review_required"] == true,
        sextortion: result
            .categories
            .iter()
            .any(|category| category == "sextortion"),
        unsafe_level: result.threat_level > ThreatLevel::Safe,
        nonsensical: result
            .categories
            .iter()
            .any(|category| category == "nonsensical_spam"),
    }
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/redteam_cases")
}

fn labels(root: &Path) -> Vec<Label> {
    let mut labels = serde_json::from_str::<LabelFile>(
        &std::fs::read_to_string(root.join("labels.json")).expect("read labels.json"),
    )
    .expect("parse labels.json")
    .cases;
    let synth = std::fs::read_to_string(root.join("synth/labels.jsonl")).unwrap_or_default();
    labels.extend(
        synth
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Label>(line).expect("parse synth label")),
    );
    labels.retain(|label| matches!(label.label.as_str(), "malicious" | "benign"));
    labels
}

/// Same shape as the MTA session builder: envelope plus parsed MIME content.
fn session_from_raw(raw: &[u8]) -> Option<EmailSession> {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.50".into(),
        40000,
        "10.0.0.2".into(),
        25,
    );
    session.mail_from = Some("sender@external.example".to_string());
    session.rcpt_to.push("employee@corp.internal".to_string());
    session.content = MimeParser::new().parse(raw).ok()?;
    let subject = session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("subject"))
        .map(|(_, value)| decode_rfc2047(value).trim().to_string())
        .filter(|value| !value.is_empty());
    session.subject = subject;
    Some(session)
}

#[tokio::test]
#[ignore = "corpus evaluation; run explicitly with --ignored --nocapture"]
async fn semantic_corpus_signal_rates() {
    let root = corpus_root();
    let mut cases = labels(&root);
    if let Some(limit) = std::env::var("VIGILYX_SEMANTIC_EVAL_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
    {
        cases.truncate(limit);
    }
    assert!(!cases.is_empty(), "labelled corpus is empty");

    let module = SemanticScanModule::new(None);
    let mut by_label: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_family: BTreeMap<(String, String), Tally> = BTreeMap::new();
    let mut unreadable = 0usize;
    for case in &cases {
        let Some(session) = std::fs::read(root.join(&case.file))
            .ok()
            .and_then(|raw| session_from_raw(&raw))
        else {
            unreadable += 1;
            continue;
        };
        let result = module
            .analyze(&SecurityContext::new(Arc::new(session)))
            .await
            .expect("semantic module result");
        let signals = signals(&result);
        by_label
            .entry(case.label.clone())
            .or_default()
            .add(&signals);
        by_family
            .entry((case.label.clone(), case.family.clone()))
            .or_default()
            .add(&signals);
    }

    let header = format!(
        "{:<34} {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "label / family", "n", "signal", "scenario", "review", "sextort", "unsafe", "gibber"
    );
    println!(
        "\nsemantic corpus evaluation ({} cases, {unreadable} unreadable)",
        cases.len()
    );
    println!(
        "signal = scenario || review || sextortion; malicious rows are recall, benign rows are false positives"
    );
    println!("{header}");
    for (label, tally) in &by_label {
        println!("{}", tally.row(label));
    }
    if let Some(benign) = by_label.get("benign") {
        println!(
            "benign semantic signals per 10k mail: {:.0}; sextortion per 10k: {:.0}",
            Tally::rate(benign.any_signal, benign.total) * 100.0,
            Tally::rate(benign.sextortion, benign.total) * 100.0,
        );
    }
    println!("\n{header}");
    for ((label, family), tally) in &by_family {
        println!("{}", tally.row(&format!("{label}/{family}")));
    }
    assert!(
        unreadable * 10 <= cases.len(),
        "more than 10% of corpus files could not be parsed: {unreadable}/{}",
        cases.len()
    );
}
