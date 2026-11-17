//! Latency baseline for the local semantic module on adversarial shapes and
//! a normal mail. Inputs use neutral business filler only.
//!
//! ```text
//! cargo test -p vigilyx-engine --profile release-fast --test semantic_perf_bench -- --ignored --nocapture
//! ```
//!
//! `VIGILYX_SEMANTIC_BENCH_RUNS=<n>` sets repetitions (default 20). Each run
//! builds a fresh session, so the per-session extraction cache never hits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vigilyx_core::models::{EmailSession, Protocol};
use vigilyx_core::security::SemanticSourcePart;
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::SecurityModule;
use vigilyx_engine::semantic::{SemanticScanModule, extract_semantic_context};

/// Module timeout without a remote NLP service.
const MODULE_TIMEOUT: Duration = Duration::from_millis(3000);

fn session(body_text: Option<&str>, body_html: Option<&str>) -> EmailSession {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "192.0.2.10".to_string(),
        25_000,
        "198.51.100.10".to_string(),
        25,
    );
    session.mail_from = Some("sender@example.net".to_string());
    session.rcpt_to.push("recipient@example.com".to_string());
    session.content.body_text = body_text.map(str::to_string);
    session.content.body_html = body_html.map(str::to_string);
    session.content.is_complete = true;
    session
}

fn percentile(sorted: &[Duration], percent: f64) -> Duration {
    let index = ((sorted.len() - 1) as f64 * percent / 100.0).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn summary(name: &str, mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    let p99 = percentile(&samples, 99.0);
    println!(
        "{name:<44} p50 {:>7.1} ms  p95 {:>7.1} ms  p99 {:>7.1} ms  max {:>7.1} ms",
        percentile(&samples, 50.0).as_secs_f64() * 1000.0,
        percentile(&samples, 95.0).as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
        samples.last().copied().unwrap_or_default().as_secs_f64() * 1000.0,
    );
    p99
}

fn cases() -> Vec<(&'static str, Option<String>, Option<String>)> {
    let normal = "各位同事：本周项目例会安排在周四下午两点，会议室为三楼东侧。请提前查看会议材料，\
                  并在周三前回复是否参加。会议议程包括上周进度回顾、本周风险评估以及下阶段资源安排。\n"
        .repeat(16);
    vec![
        (
            "4 KB connector sentence",
            Some(format!("{}请查看附件。", "，".repeat(1365))),
            None,
        ),
        (
            "512 full stops then a request",
            Some(format!("{}请查看附件。", "。".repeat(512))),
            None,
        ),
        (
            "300 KB single-line HTML",
            None,
            Some(format!(
                "<p>{}</p>",
                "项目进度正常，请查看附件！".repeat(300 * 1024 / 39)
            )),
        ),
        (
            "512 KiB plain short lines",
            Some("会议纪要已更新。\n".repeat(512 * 1024 / 25)),
            None,
        ),
        ("normal 5 KB Chinese mail", Some(normal), None),
    ]
}

#[tokio::test]
#[ignore = "latency baseline; run explicitly with --ignored --nocapture"]
async fn semantic_latency_baseline() {
    let runs = std::env::var("VIGILYX_SEMANTIC_BENCH_RUNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|runs| *runs > 0)
        .unwrap_or(20);
    let module = SemanticScanModule::new(None);
    println!("\nsemantic latency baseline ({runs} runs per case)");
    for (name, body_text, body_html) in cases() {
        let mut end_to_end = Vec::with_capacity(runs);
        let mut extraction = Vec::with_capacity(runs);
        for _ in 0..runs {
            let context = SecurityContext::new(Arc::new(session(
                body_text.as_deref(),
                body_html.as_deref(),
            )));
            let started = Instant::now();
            module
                .analyze(&context)
                .await
                .expect("semantic module result");
            end_to_end.push(started.elapsed());

            if let Some(body) = body_text.as_deref() {
                let fresh = session(Some(body), None);
                let started = Instant::now();
                let _ = extract_semantic_context(&fresh, body, SemanticSourcePart::PlainText);
                extraction.push(started.elapsed());
            }
        }
        let p99 = summary(&format!("{name} / module"), end_to_end);
        if !extraction.is_empty() {
            summary(&format!("{name} / extraction"), extraction);
        }
        assert!(
            p99 < MODULE_TIMEOUT,
            "{name}: module p99 {p99:?} exceeds the {MODULE_TIMEOUT:?} module timeout"
        );
    }
}
