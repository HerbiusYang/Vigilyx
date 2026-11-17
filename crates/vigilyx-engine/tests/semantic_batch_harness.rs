//! Batch semantic-facts audit for large `.eml` corpora.
//!
//! This deliberately audits semantic observations separately from threat
//! verdicts.  An EML file does not contain the SMTP envelope, so this harness
//! never treats `To` as the actual delivery recipient.  Production replay can
//! provide envelope facts through the normal `EmailSession` path.
//!
//! Run on a corpus with:
//!
//! ```text
//! VIGILYX_SEMANTIC_CORPUS_DIR=/path/to/eml \
//! VIGILYX_SEMANTIC_REPORT=/tmp/semantic-facts.jsonl \
//! cargo test -p vigilyx-engine --test semantic_batch_harness -- --nocapture
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_engine::semantic::{
    evaluate_semantic_scenarios, extract_semantic_context, select_semantic_projection,
};
use vigilyx_parser::MimeParser;

fn collect_eml_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("eml"))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn enum_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn increment(map: &mut BTreeMap<String, usize>, key: String) {
    *map.entry(key).or_default() += 1;
}

fn relative_name(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

#[test]
fn semantic_batch_audit() {
    let Ok(root) = std::env::var("VIGILYX_SEMANTIC_CORPUS_DIR") else {
        println!("semantic batch audit skipped: set VIGILYX_SEMANTIC_CORPUS_DIR to run it");
        return;
    };
    let root = PathBuf::from(root);
    assert!(
        root.is_dir(),
        "semantic corpus directory does not exist: {root:?}"
    );

    let files = collect_eml_files(&root);
    assert!(
        !files.is_empty(),
        "semantic corpus contains no .eml files: {root:?}"
    );

    let mut report_lines = Vec::with_capacity(files.len());
    let mut parsed = 0usize;
    let mut parse_failed = 0usize;
    let mut no_body = 0usize;
    let mut incomplete = 0usize;
    let mut total_claims = 0usize;
    let mut speech_acts = BTreeMap::new();
    let mut polarities = BTreeMap::new();
    let mut quote_statuses = BTreeMap::new();
    let mut scenarios = BTreeMap::new();

    for path in files {
        let name = relative_name(&path, &root);
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(error) => {
                parse_failed += 1;
                report_lines.push(serde_json::json!({
                    "schema_version": 1,
                    "file": name,
                    "status": "read_error",
                    "error": format!("{error:?}"),
                }));
                continue;
            }
        };
        let content = match MimeParser::new().parse(&raw) {
            Ok(content) => content,
            Err(error) => {
                parse_failed += 1;
                report_lines.push(serde_json::json!({
                    "schema_version": 1,
                    "file": name,
                    "status": "parse_error",
                    "error": format!("{error:?}"),
                }));
                continue;
            }
        };

        let mut session = EmailSession::new(
            Protocol::Smtp,
            "0.0.0.0".to_string(),
            0,
            "0.0.0.0".to_string(),
            0,
        );
        session.content = content;
        // EML has no SMTP envelope. Keep these empty instead of guessing from
        // To/From; header claims remain available in semantic_context.
        session.subject = session.content.get_header("Subject").map(str::to_owned);
        let Some(projection) = select_semantic_projection(
            session.subject.as_deref(),
            session.content.body_text.as_deref(),
            session.content.body_html.as_deref(),
        ) else {
            no_body += 1;
            report_lines.push(serde_json::json!({
                "schema_version": 1,
                "file": name,
                "status": "no_semantic_body",
                "actual_recipient_facts": "unavailable_in_eml",
            }));
            continue;
        };

        parsed += 1;
        let mut file_incomplete = false;
        for (body, source_part) in
            std::iter::once((projection.body.as_str(), projection.source_part)).chain(
                projection
                    .alternatives
                    .iter()
                    .map(|alternate| (alternate.body.as_str(), alternate.source_part)),
            )
        {
            let mut context = extract_semantic_context(&session, body, source_part);
            if !projection.coverage_reasons.is_empty() {
                context.coverage = vigilyx_core::security::SemanticCoverageStatus::Incomplete;
                let mut reasons = context
                    .coverage_reason
                    .take()
                    .into_iter()
                    .collect::<Vec<_>>();
                reasons.extend(projection.coverage_reasons.iter().cloned());
                context.coverage_reason = Some(reasons.join("; "));
            }
            let scenario_findings = evaluate_semantic_scenarios(&context);
            file_incomplete |=
                context.coverage == vigilyx_core::security::SemanticCoverageStatus::Incomplete;
            total_claims += context.claims.len();
            for claim in &context.claims {
                increment(&mut speech_acts, enum_name(&claim.speech_act));
                increment(&mut polarities, enum_name(&claim.polarity));
                increment(
                    &mut quote_statuses,
                    enum_name(&claim.quote_or_forward_status),
                );
            }
            for finding in &scenario_findings {
                increment(&mut scenarios, enum_name(&finding.scenario_id));
            }

            report_lines.push(serde_json::json!({
                "schema_version": context.schema_version,
                "file": name,
                "status": "ok",
                "source_part": enum_name(&source_part),
                "coverage": enum_name(&context.coverage),
                "actual_recipient_facts": "unavailable_in_eml",
                "header_recipient_count": context.header_recipients.len(),
                "header_sender_present": context.header_sender.is_some(),
                "claim_count": context.claims.len(),
                "semantic_scenarios": scenario_findings
                    .iter()
                    .map(|finding| enum_name(&finding.scenario_id))
                    .collect::<Vec<_>>(),
                "speech_acts": context
                    .claims
                    .iter()
                    .fold(BTreeMap::<String, usize>::new(), |mut counts, claim| {
                        increment(&mut counts, enum_name(&claim.speech_act));
                        counts
                    }),
                "incomplete_coverage": context.coverage
                    == vigilyx_core::security::SemanticCoverageStatus::Incomplete,
                "semantic_context": context,
                "semantic_findings": scenario_findings,
            }));
        }
        incomplete += usize::from(file_incomplete);
    }

    if let Ok(report_path) = std::env::var("VIGILYX_SEMANTIC_REPORT") {
        let output = report_lines
            .iter()
            .map(|line| serde_json::to_string(line).expect("serialize semantic report line"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&report_path, format!("{output}\n")).expect("write semantic batch report");
        println!("semantic report written to {report_path}");
    }

    println!(
        "semantic batch audit: parsed={parsed} parse_failed={parse_failed} no_body={no_body} incomplete={incomplete} claims={total_claims} speech_acts={speech_acts:?} polarities={polarities:?} quote_statuses={quote_statuses:?} scenarios={scenarios:?}"
    );
}
