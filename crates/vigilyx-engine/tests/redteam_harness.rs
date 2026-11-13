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
//!   VIGILYX_REDTEAM_CASES=ctrl04_utf8_ja_control.eml,ev16_iso2022jp_body_lure.eml \
//!     cargo test -p vigilyx-engine --test redteam_harness -- --nocapture

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use vigilyx_core::models::{EmailSession, Protocol, SessionSource, SessionStatus};
use vigilyx_core::security::{IocEntry, ThreatLevel, VerdictDisposition};
use vigilyx_engine::context::SecurityContext;
use vigilyx_engine::module::{ModuleResult, SecurityModule};
use vigilyx_engine::modules::aitm_detect::AitmDetectModule;
use vigilyx_engine::modules::anomaly_detect::AnomalyDetectModule;
use vigilyx_engine::modules::attach_content::AttachContentModule;
use vigilyx_engine::modules::attach_qr_scan::AttachmentQrScanModule;
use vigilyx_engine::modules::attach_scan::AttachScanModule;
use vigilyx_engine::modules::content_scan::{
    EffectiveKeywordLists, KeywordOverrides, build_effective_keyword_lists,
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
use vigilyx_engine::pipeline::verdict::aggregate_verdict_with_session;
use vigilyx_engine::pipeline::verdict::{ScenarioPatternLists, set_runtime_scenario_patterns};
use vigilyx_engine::semantic::SemanticScanModule;
use vigilyx_parser::MimeParser;
use vigilyx_parser::mime::decode_rfc2047;

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
    async fn count_distinct_senders_for_domain(&self, _sender_domain: &str) -> anyhow::Result<i64> {
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

fn load_builtin_url_domains() -> (HashSet<String>, HashSet<String>) {
    let seed_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../shared/schemas/system_whitelist_seed.json");
    let seed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(seed_path).expect("read system whitelist seed"),
    )
    .expect("parse system whitelist seed");
    let read_section = |section: &str| {
        seed.get(section)
            .and_then(|value| value.get("items"))
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect::<HashSet<_>>()
    };
    (read_section("url_trusted"), read_section("intel_safe"))
}

/// Mirror of `SmtpConnection::build_email_session` in the MTA crate.
fn session_from_raw(raw: &[u8], mail_from: &str, rcpt: &str) -> Option<EmailSession> {
    let mut session = EmailSession::new(
        Protocol::Smtp,
        "203.0.113.50".into(),
        40000,
        "10.0.0.2".into(),
        25,
    );
    session.source = SessionSource::MtaProxy;
    session.status = SessionStatus::Completed;
    session.mail_from = Some(mail_from.to_string());
    session.rcpt_to.push(rcpt.to_string());
    session.total_bytes = raw.len();
    session.email_count = 1;
    session.content = MimeParser::new().parse(raw).ok()?;
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

fn collect_eml_files(root: &Path, include_nested: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir).expect("read redteam case directory");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if include_nested {
                    pending.push(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "eml") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn is_synth_path(path: &Path, cases_dir: &Path) -> bool {
    path.strip_prefix(cases_dir)
        .ok()
        .and_then(|relative| relative.parent())
        .is_some_and(|parent| parent == Path::new("synth"))
}

fn is_ham_path(path: &Path, cases_dir: &Path) -> bool {
    path.strip_prefix(cases_dir)
        .ok()
        .and_then(|relative| relative.parent())
        .is_some_and(|parent| parent == Path::new("ham"))
}

fn first_mailbox(header: &str) -> Option<String> {
    let decoded = decode_rfc2047(header);
    let candidate = decoded
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>').map(|(address, _)| address))
        .unwrap_or_else(|| decoded.split(',').next().unwrap_or_default())
        .trim()
        .trim_matches(['"', '\'']);
    candidate.contains('@').then(|| candidate.to_string())
}

fn envelope_from_fixture(raw: &[u8]) -> (String, String) {
    let Some(content) = MimeParser::new().parse(raw).ok() else {
        return (
            "sender@partner.example".to_string(),
            "employee@corp.internal".to_string(),
        );
    };
    let header = |wanted: &str| {
        content
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(wanted))
            .and_then(|(_, value)| first_mailbox(value))
    };
    (
        header("from").unwrap_or_else(|| "sender@partner.example".to_string()),
        // Synthetic fixtures describe the visible To header, not necessarily
        // the SMTP envelope. Replay them as an inbound message to the
        // protected tenant so recipient-aware detectors exercise the same
        // production boundary as the MTA path.
        "employee@corp.internal".to_string(),
    )
}

#[derive(Debug, Clone)]
struct SynthLabel {
    expected_deliver: Option<bool>,
    family: String,
    review: bool,
    repaired: bool,
}

fn parse_synth_label(value: &serde_json::Value) -> Option<(String, SynthLabel)> {
    let raw_file = value.get("file")?.as_str()?.to_string();
    // Older labels already include the `synth/` directory, while newer
    // generated batches store only the basename. Normalize both forms to the
    // path returned by `strip_prefix(cases_dir)` so valid labels are not
    // silently counted as gray during replay.
    let file = if Path::new(&raw_file).components().count() == 1 {
        format!("synth/{raw_file}")
    } else {
        raw_file
    };
    let family = value
        .get("family")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unclassified")
        .to_string();
    let label = value.get("label").and_then(serde_json::Value::as_str);
    let format = value.get("format").and_then(serde_json::Value::as_str);
    let expected = value.get("expected");
    let explicit_review = expected.and_then(serde_json::Value::as_str) == Some("review");
    let format_decision = format.and_then(|format| match format.to_ascii_lowercase().as_str() {
        "deliver" => Some(true),
        "block" => Some(false),
        _ => None,
    });
    let expected_deliver = expected
        .and_then(|expected| {
            expected.as_str().and_then(|expected| match expected {
                "deliver" | "allow" | "accept" => Some(true),
                "block" => Some(false),
                _ => None,
            })
        })
        .or(format_decision)
        .or_else(|| {
            expected
                .and_then(|expected| expected.as_bool())
                .map(|value| label == Some("benign") && !value)
        });
    let explicit_decision = expected
        .and_then(serde_json::Value::as_str)
        .is_some_and(|expected| matches!(expected, "deliver" | "allow" | "accept" | "block"))
        || (expected.is_some_and(serde_json::Value::is_boolean) && format_decision.is_some());
    let name = Path::new(&file)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let ambiguous = value.get("ambiguous").is_some_and(|value| match value {
        serde_json::Value::Bool(ambiguous) => *ambiguous,
        serde_json::Value::String(reason) => !reason.trim().is_empty(),
        _ => false,
    });
    let review =
        explicit_review || (!explicit_decision && (ambiguous || name.starts_with("gray_")));
    let repaired = expected.is_some_and(|expected| !expected.is_string() && !expected.is_boolean())
        || (expected_deliver.is_none() && !review);
    Some((
        file,
        SynthLabel {
            expected_deliver: if review { None } else { expected_deliver },
            family,
            review,
            repaired,
        },
    ))
}

fn load_synth_labels(cases_dir: &Path) -> HashMap<String, SynthLabel> {
    let labels_path = cases_dir.join("synth/labels.jsonl");
    let Ok(raw) = std::fs::read_to_string(labels_path) else {
        return HashMap::new();
    };
    raw.lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            parse_synth_label(&value)
        })
        .collect()
}

#[test]
fn synth_label_parser_recognizes_allow_as_delivery() {
    let value = serde_json::json!({
        "file": "synth/ham_allow_control.eml",
        "label": "benign",
        "family": "ham_business",
        "expected": "allow",
        "ambiguous": false
    });
    let (_, label) = parse_synth_label(&value).expect("valid synthetic label");
    assert_eq!(label.expected_deliver, Some(true));
    assert!(!label.review);
    assert!(!label.repaired);
}

#[test]
fn synth_label_parser_normalizes_basename_paths() {
    let value = serde_json::json!({
        "file": "ham_1663_red_flush_real.eml",
        "label": "benign",
        "family": "legit_tax_redflush_notice",
        "expected": "allow",
        "ambiguous": false
    });
    let (file, label) = parse_synth_label(&value).expect("valid synthetic label");
    assert_eq!(file, "synth/ham_1663_red_flush_real.eml");
    assert_eq!(label.expected_deliver, Some(true));
    assert!(!label.repaired);
}

#[test]
fn synth_label_parser_keeps_explicit_review_out_of_error_counts() {
    let value = serde_json::json!({
        "file": "synth/mal_signature_link.eml",
        "label": "ambiguous",
        "family": "link_obfuscation",
        "expected": "review",
        "ambiguous": true
    });
    let (_, label) = parse_synth_label(&value).expect("valid synthetic label");
    assert_eq!(label.expected_deliver, None);
    assert!(label.review);
    assert!(!label.repaired);
}

#[test]
fn explicit_synth_decisions_override_ambiguity_metadata() {
    for (expected, expected_deliver) in [("deliver", true), ("block", false)] {
        let value = serde_json::json!({
            "file": "synth/paired_edge_case.eml",
            "label": if expected_deliver { "benign" } else { "malicious" },
            "family": "paired_edge_case",
            "expected": expected,
            "ambiguous": true
        });
        let (_, label) = parse_synth_label(&value).expect("valid synthetic label");
        assert_eq!(label.expected_deliver, Some(expected_deliver));
        assert!(!label.review);
        assert!(!label.repaired);
    }
}

#[test]
fn boolean_synth_decisions_use_explicit_format_and_override_ambiguity() {
    for (label_text, format, expected_deliver) in
        [("benign", "deliver", true), ("malicious", "block", false)]
    {
        let value = serde_json::json!({
            "file": "synth/paired_boolean_edge_case.eml",
            "label": label_text,
            "family": "paired_edge_case",
            "expected": true,
            "format": format,
            "ambiguous": true
        });
        let (_, label) = parse_synth_label(&value).expect("valid synthetic label");
        assert_eq!(label.expected_deliver, Some(expected_deliver));
        assert!(!label.review);
        assert!(!label.repaired);
    }
}

#[tokio::test]
async fn redteam_replay() {
    let lists = load_keyword_lists();
    set_runtime_scenario_patterns(ScenarioPatternLists::from(&lists));
    // Mirror the production registry's built-in domain setup. The no-DB
    // replay otherwise evaluates official destinations as if the engine had
    // started with empty safe-domain caches.
    let (trusted_domains, mut safe_domains) = load_builtin_url_domains();
    safe_domains.extend(trusted_domains.iter().cloned());
    vigilyx_engine::modules::link_scan::set_trusted_url_domains(Arc::new(trusted_domains));
    vigilyx_engine::modules::link_scan::set_well_known_safe_domains(Arc::new(safe_domains));

    let db: std::sync::Arc<dyn vigilyx_engine::db_service::DbQueryService> =
        std::sync::Arc::new(NoDb);
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
        std::sync::Arc::new(AttachmentQrScanModule::new_with_keyword_lists(
            lists.clone(),
        )),
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
    let synth_labels = load_synth_labels(&cases_dir);
    let include_synth = std::env::var("VIGILYX_REDTEAM_INCLUDE_SYNTH")
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
    let mut case_files = collect_eml_files(&cases_dir, include_synth);
    if let Ok(filter) = std::env::var("VIGILYX_REDTEAM_CASES") {
        let selected: Vec<&str> = filter
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        let include_synth_paths = selected
            .iter()
            .any(|name| matches!(*name, "synth/*" | "synth/**"));
        case_files.retain(|path| {
            let name = path.file_name().and_then(|name| name.to_str());
            let stem = path.file_stem().and_then(|stem| stem.to_str());
            let relative = path
                .strip_prefix(&cases_dir)
                .ok()
                .and_then(|path| path.to_str());
            name.is_some_and(|name| selected.contains(&name))
                || stem.is_some_and(|stem| selected.contains(&stem))
                || relative.is_some_and(|relative| selected.contains(&relative))
                || (include_synth_paths && is_synth_path(path, &cases_dir))
        });
        assert!(
            !case_files.is_empty(),
            "VIGILYX_REDTEAM_CASES did not select any .eml fixture: {filter}"
        );
    }

    let verdict_config = VerdictConfig::default();
    let mut delivered = Vec::new();
    let mut synth_total = 0usize;
    let mut synth_labeled = 0usize;
    let mut synth_correct = 0usize;
    let mut synth_false_positives = Vec::new();
    let mut synth_missed_detections = Vec::new();
    let mut synth_gray = 0usize;
    let mut synth_review = 0usize;
    let mut synth_repaired_labels = 0usize;
    let mut synth_threat_counts: HashMap<String, usize> = HashMap::new();
    let mut synth_classification_counts: HashMap<String, usize> = HashMap::new();
    let mut synth_family_counts: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
    let expected_inline_block = [
        "ctrl04_utf8_ja_control.eml",
        "ctrl05_cp1251_ru_control.eml",
        "ctrl03_qp_split_keyword.eml",
        "ev01_entity_hairsp_break.eml",
        "ev02_css_hidden_char_break.eml",
        "ev03_traditional_chinese.eml",
        "ev04_trusted_platform_lure.eml",
        "ev06_html_attachment_phish.eml",
        "ev08_nested_rfc822.eml",
        "ev09_alt_clean_text.eml",
        "ev10_image_only_phish.eml",
        "ev13_english_spaced.eml",
        "ev14_recipient_targeted_cn_account_lure.eml",
        "ev16_iso2022jp_body_lure.eml",
        "ev19_no_charset_ru_lure.eml",
        "ev17_class_hidden_pair_break.eml",
        "ev20_svg_vector_qr.eml",
        "ctrl06_raster_qr_control.eml",
        "ev21_image_text_lure.eml",
        "ctrl07_plain_ip_href.eml",
        "ev22_tab_entity_scheme.eml",
        "ev23_named_tab_scheme.eml",
        "ev25_base_href_relative.eml",
        "ev26_form_action_button.eml",
        "ev27_svg_xlink_anchor.eml",
        "ev28_attach_meta_refresh.eml",
        "ev29_attach_js_form.eml",
        "ev30_url_shortcut_attach.eml",
        "ev31_display_authority.eml",
        "ev32_latin_diacritics.eml",
        "ev34_folded_url_text.eml",
        "ev35_attach_trusted_refresh.eml",
        "ev36_attach_hidden_pair.eml",
        "ev37_rfc2231_pct_filename.eml",
        "ev38_ceo_homoglyph_lure.eml",
        "ev41_subject_only_lure.eml",
        "ev42_rare_traditional_fold.eml",
        "ev43_cantonese_lure.eml",
        "ev53_fake_reply_thread.eml",
        "ev54_greek_omicron_tld.eml",
        "ev55_mailto_cred_form.eml",
        "ev61_chain_traditional_base.eml",
        "ev62_banner_prefix_lure.eml",
        "ev63_autoreply_prefix_lure.eml",
        "ev64_vietnamese_lure.eml",
        "ev65_thai_lure.eml",
        "ev66_indonesian_lure.eml",
        "ev67_yao_phone.eml",
        "ev68_liang_phone.eml",
        "ev69_giftcard_bec.eml",
        "ev70_tax_rebate_paraphrase.eml",
        "ev71_pii_harvest_reply.eml",
        "ev72_trusted_open_redirect.eml",
        "ev73_interlinear_break.eml",
        "ev74_js_chunked_qr.eml",
        "ev75_inverted_qr_attach.eml",
        "ev76_paraphrase_no_keyword.eml",
        "ev77_display_internal_domain.eml",
        "ev78_100part_lure_tail.eml",
        "ev79_rtf_attach_lure.eml",
        "ev80_chain_banner_yao.eml",
        "ev81_chain_vi_redirect.eml",
        "mal_0595_replyto_split.eml",
        "mal_0596_http_internal.eml",
        "mal_0631_rich_threat_intel.eml",
        "mal_0645_quant_subpixel.eml",
        "mal_0655_sre_hidden_row.eml",
        "mal_0673_patent_litigation.eml",
        "mal_1114_speaker_slot.eml",
        "mal_1121_bec_deposit.eml",
        "mal_1142_app_review.eml",
        "mal_1755_gym_transfer_unfreeze.eml",
        "mal_1756_broadband_port_fee.eml",
        "mal_1757_pension_archive_transfer.eml",
        "mal_1758_tradein_dealer_verify.eml",
        "mal_1759_hotel_rate_activate.eml",
        "mal_1760_kindergarten_withdrawal.eml",
        "mal_1761_pressure_vessel_stamp.eml",
        "mal_1762_email_domain_unlock.eml",
        "mal_1763_driving_hours_transfer.eml",
        "mal_1764_parcel_damage_allocation.eml",
        "mal_1765_internal_promotion_slot.eml",
        "mal_1766_food_license_renewal.eml",
        "mal_1767_house_transfer_unlock.eml",
        "mal_1768_beauty_card_liquidation.eml",
        "mal_1769_dedicated_line_keepalive.eml",
        "mal_1770_hukou_waitlist_promotion.eml",
        "inc01_account_security_root_token.eml",
        "inc02_obfuscated_adult_domain.eml",
        "inc03_invoice_wechat_homophone.eml",
        "inc04_fragmented_context_invoice.eml",
        "inc05_japanese_apple_payment_update.eml",
    ];
    // The original incident row retained headers/size but not raw DATA. This
    // fixture preserves the observed identity/subject/MIME shape and marks
    // the missing-body condition as a regression contract.
    let coverage_gap_regression = "ev15_body_coverage_gap_2026_procedure_notice.eml";
    let expected_inline_deliver = [
        "ham_0554_customs_real.eml",
        "ham_0556_oauth_dataroom_real.eml",
        "ham_0558_hoa_real.eml",
        "ham_0559_npm_real.eml",
        "ham_0802_warehouse_real.eml",
    ];

    for path in &case_files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let raw = std::fs::read(path).expect("read case");
        let (mail_from, rcpt_to) =
            if is_synth_path(path, &cases_dir) || is_ham_path(path, &cases_dir) {
                envelope_from_fixture(&raw)
            } else {
                (
                    "sender@partner.example".to_string(),
                    "employee@corp.internal".to_string(),
                )
            };
        let Some(session) = session_from_raw(&raw, &mail_from, &rcpt_to) else {
            println!("[{name}] PARSE FAILED — engine would tempfail (fail-closed)");
            continue;
        };
        let session = std::sync::Arc::new(session);
        if std::env::var("VIGILYX_REDTEAM_TRACE_EVIDENCE").is_ok_and(|value| value == "1") {
            let link_hosts = session
                .content
                .links
                .iter()
                .map(|link| {
                    let host = url::Url::parse(&link.url)
                        .ok()
                        .and_then(|parsed| parsed.host_str().map(str::to_string))
                        .unwrap_or_else(|| "unparsed".to_string());
                    (host, link.suspicious)
                })
                .collect::<Vec<_>>();
            println!(
                "TRACE_SESSION[{name}] plain_chars={} html_chars={} links={link_hosts:?}",
                session
                    .content
                    .body_text
                    .as_deref()
                    .unwrap_or_default()
                    .chars()
                    .count(),
                session
                    .content
                    .body_html
                    .as_deref()
                    .unwrap_or_default()
                    .chars()
                    .count(),
            );
        }
        if matches!(
            name.as_str(),
            "ctrl04_utf8_ja_control.eml" | "ev16_iso2022jp_body_lure.eml"
        ) {
            let body = session.content.body_text.as_deref().unwrap_or_default();
            assert!(
                body.contains("アカウントが停止されました")
                    && body.contains("再ログイン")
                    && body.contains("ワンタイムパスワード"),
                "Japanese lure must be decoded before inline modules run: {name}; body={body:?}"
            );
        }
        if name == "mal_0042_ja_stop.eml" {
            let body = session.content.body_text.as_deref().unwrap_or_default();
            assert!(
                body.contains("不正なログイン")
                    && body.contains("本人確認")
                    && body.contains("アカウントを停止"),
                "Japanese account lure must retain decoded threat/action text: {body:?}"
            );
        }
        if name == coverage_gap_regression {
            assert!(
                !session.content.is_complete,
                "the regression sample must stay incomplete when its MIME entity is not retained"
            );
            assert!(
                session.content.raw_mime.as_deref() == Some(raw.as_slice()),
                "the regression sample must retain the exact original MIME"
            );
            assert_eq!(
                session.reconstruct_eml(),
                raw,
                "replay must use the original MIME bytes"
            );
        }
        // Production snapshots derive the tenant domain before constructing
        // the security context. Keep the replay equivalent so display-name
        // impersonation and external-sender gates are exercised honestly.
        let ctx = SecurityContext::with_internal_domains(
            session.clone(),
            std::sync::Arc::new(std::collections::HashSet::from([
                "corp.internal".to_string()
            ])),
        );

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

        if matches!(
            name.as_str(),
            "ev42_rare_traditional_fold.eml"
                | "ev43_cantonese_lure.eml"
                | "ev61_chain_traditional_base.eml"
        ) {
            let content = results
                .get("content_scan")
                .expect("content_scan must run for Traditional/zh-HK regressions");
            assert!(
                content
                    .categories
                    .contains(&"account_security_phishing".to_string()),
                "semantic normalization must recover the account lure, not rely on another module: {name}; {content:?}"
            );
        }
        if name == "ev53_fake_reply_thread.eml" {
            let content = results
                .get("content_scan")
                .expect("content_scan must run for reply-thread regression");
            assert!(
                content.categories.contains(&"bec".to_string()),
                "forged reply + business CTA + bare cross-domain target must be BEC evidence: {content:?}"
            );
        }
        if name == "inc04_fragmented_context_invoice.eml" {
            let content = results
                .get("content_scan")
                .expect("content_scan must run for fragmented invoice solicitation");
            assert!(
                content.categories.contains(&"invoice_spam".to_string()),
                "fragmented invoice/payment/contact compound must be recovered by content_scan: {content:?}"
            );
        }
        if name == "inc05_japanese_apple_payment_update.eml" {
            let link = results
                .get("link_content")
                .expect("link_content must run for Japanese payment-update phishing");
            for expected in [
                "credential_link_lure",
                "high_risk_credential_target",
                "brand_sender_target_mismatch",
            ] {
                assert!(
                    link.categories.contains(&expected.to_string()),
                    "Japanese Apple/from/target compound must retain {expected}: {link:?}"
                );
            }
        }
        if name == "ev54_greek_omicron_tld.eml" {
            assert!(
                session
                    .content
                    .links
                    .iter()
                    .any(|link| link.url.contains("security-check.cοm")),
                "mixed-script bare domain must be retained for link analysis: {:?}",
                session.content.links
            );
            let link_content = results
                .get("link_content")
                .expect("link_content must run for mixed-script bare-domain regression");
            assert!(
                link_content
                    .categories
                    .contains(&"idn_homograph".to_string()),
                "Greek-omicron TLD must reach the existing IDN homograph detector: {link_content:?}"
            );
            let content = results
                .get("content_scan")
                .expect("content_scan must run for homograph action-lure regression");
            assert!(
                content
                    .categories
                    .contains(&"obfuscated_domain_lure".to_string()),
                "confirmation action + confusable public suffix must become the named compound: {content:?}"
            );
        }
        if name == "ev55_mailto_cred_form.eml" {
            let html = results
                .get("html_scan")
                .expect("html_scan must run for mailto credential-form regression");
            assert!(
                html.categories
                    .contains(&"credential_exfiltration_form".to_string()),
                "mailto + password input must be actionable HTML evidence: {html:?}"
            );
        }

        if matches!(
            name.as_str(),
            "ev64_vietnamese_lure.eml"
                | "ev65_thai_lure.eml"
                | "ev66_indonesian_lure.eml"
                | "ev76_paraphrase_no_keyword.eml"
                | "ev81_chain_vi_redirect.eml"
        ) {
            let content = results
                .get("content_scan")
                .expect("content_scan must run for account-language regressions");
            assert!(
                content
                    .categories
                    .contains(&"account_security_phishing".to_string()),
                "the semantic detector must close the language/paraphrase gap directly: {name}; {content:?}"
            );
        }
        if name == "ev69_giftcard_bec.eml" {
            let content = results.get("content_scan").expect("content_scan must run");
            assert!(
                content.categories.contains(&"bec".to_string()),
                "{content:?}"
            );
        }
        if name == "ev70_tax_rebate_paraphrase.eml" {
            let content = results.get("content_scan").expect("content_scan must run");
            assert!(
                content.categories.contains(&"subsidy_fraud".to_string()),
                "{content:?}"
            );
        }
        if name == "ev71_pii_harvest_reply.eml" {
            let content = results.get("content_scan").expect("content_scan must run");
            assert!(
                content.categories.contains(&"phishing".to_string()),
                "{content:?}"
            );
        }
        if matches!(
            name.as_str(),
            "ev72_trusted_open_redirect.eml" | "ev81_chain_vi_redirect.eml"
        ) {
            let link_scan = results.get("link_scan").expect("link_scan must run");
            assert!(
                link_scan.categories.contains(&"ip_url".to_string()),
                "trusted wrapper must not hide the inner literal-IP target: {name}; {link_scan:?}"
            );
        }
        if name == "ev77_display_internal_domain.eml" {
            let header = results.get("header_scan").expect("header_scan must run");
            assert!(
                header
                    .categories
                    .contains(&"display_name_spoof".to_string())
                    && header
                        .categories
                        .contains(&"authority_display_name_lure".to_string()),
                "exact internal-domain display claim + account action must be inline identity evidence: {header:?}"
            );
        }

        if matches!(
            name.as_str(),
            "ctrl05_cp1251_ru_control.eml" | "ev19_no_charset_ru_lure.eml"
        ) {
            let body = session.content.body_text.as_deref().unwrap_or_default();
            assert!(
                body.contains("подтвердите свою учётную запись") && body.contains("введите пароль"),
                "Russian lure must be decoded before inline modules run: {name}; body={body:?}"
            );
            let mime_categories = &results
                .get("mime_scan")
                .expect("mime_scan must run for charset regression")
                .categories;
            assert_eq!(
                mime_categories.contains(&"undeclared_8bit_charset".to_string()),
                name == "ev19_no_charset_ru_lure.eml",
                "only the no-charset Russian case should emit undeclared_8bit_charset: {name}; categories={mime_categories:?}"
            );
        }

        let verdict = aggregate_verdict_with_session(
            Some(session.as_ref()),
            session.id,
            &results,
            &verdict_config,
        );

        let flagged: Vec<String> = results
            .values()
            .filter(|r| !r.categories.is_empty())
            .map(|r| {
                format!(
                    "{}={:?}/score={:.3}/categories={:?}",
                    r.module_id,
                    r.threat_level,
                    r.raw_score(),
                    r.categories
                )
            })
            .collect();

        let would_deliver = matches!(
            VerdictDisposition::from_threat_and_coverage(
                verdict.threat_level,
                verdict.has_incomplete_inspection(),
                ThreatLevel::Medium,
                ThreatLevel::Critical,
            ),
            VerdictDisposition::Accept
        );
        let relative_name = path
            .strip_prefix(&cases_dir)
            .ok()
            .and_then(|relative| relative.to_str());
        let synth_label = relative_name.and_then(|relative| synth_labels.get(relative));
        let has_category = |module_id: &str, category: &str| {
            results
                .get(module_id)
                .is_some_and(|result| result.categories.iter().any(|found| found == category))
        };
        match name.as_str() {
            "ham_0076_domain_renew.eml" => {
                assert!(
                    would_deliver,
                    "routine domain renewal was quarantined: {verdict:?}"
                );
                assert!(
                    !has_category("content_scan", "external_action_link_lure"),
                    "a bare domain mention plus an explicit no-payment-link statement is not an action link: {results:?}"
                );
            }
            "ham_0401_wx_real.eml" => {
                assert!(
                    would_deliver,
                    "completed security notice was quarantined: {verdict:?}"
                );
                assert!(
                    !has_category("content_scan", "account_security_phishing"),
                    "completed sign-out and anti-phishing advice must remain benign: {results:?}"
                );
            }
            "mal_0008_supplier_change.eml" | "mal_0074_mold_split.eml" => {
                assert!(
                    !would_deliver,
                    "payment-change BEC bypassed quarantine: {verdict:?}"
                );
                assert!(
                    has_category("content_scan", "bec_payment_change"),
                    "explicit new-account payment redirection must retain a named BEC anchor: {results:?}"
                );
            }
            "mal_0019_reimburse_card.eml" => {
                assert!(
                    !would_deliver,
                    "reply-based payroll PII collection bypassed quarantine: {verdict:?}"
                );
                assert!(
                    has_category("content_scan", "pii_collection_lure"),
                    "payroll reply must retain the external sensitive-field collection anchor: {results:?}"
                );
            }
            "mal_0033_greek_tld.eml" => {
                assert!(
                    !would_deliver,
                    "bare Greek-omicron destination bypassed quarantine: {verdict:?}"
                );
                assert!(
                    has_category("content_scan", "obfuscated_domain_lure"),
                    "homograph geometry must be paired with the browser-open instruction: {results:?}"
                );
            }
            "mal_0108_unsubscribe_call.eml"
            | "mal_0127_train_refund_call.eml"
            | "mal_0298_apt_vishing_corp.eml" => {
                assert!(
                    !would_deliver,
                    "callback-phishing message bypassed quarantine: {verdict:?}"
                );
                assert!(
                    has_category("toad_detect", "toad_callback_verb"),
                    "a recipient-directed phone action must be retained: {results:?}"
                );
            }
            "mal_0241_css_offscreen.eml"
            | "mal_0408_html_details.eml"
            | "mal_0610_font_hint.eml" => {
                assert!(
                    !would_deliver,
                    "concealed HTML action lure bypassed quarantine: {verdict:?}"
                );
                assert!(
                    has_category("content_scan", "hidden_external_action_lure"),
                    "hidden/collapsed text and its destination must stay locally related: {results:?}"
                );
            }
            "mal_0409_html_sig_link.eml" | "mal_0410_html_footer_micro.eml" => {
                assert!(
                    synth_label.is_some_and(|label| {
                        label.review && !label.repaired && label.expected_deliver.is_none()
                    }),
                    "weak signature/footer-only ground truth must remain analyst review"
                );
                assert!(
                    would_deliver,
                    "ambiguous signature/footer link must not be auto-blocked: {verdict:?}"
                );
            }
            _ => {}
        }
        if is_synth_path(path, &cases_dir) {
            synth_total += 1;
            *synth_threat_counts
                .entry(format!("{:?}", verdict.threat_level))
                .or_default() += 1;
            *synth_classification_counts
                .entry(
                    verdict
                        .classification
                        .map(|classification| classification.to_string())
                        .unwrap_or_else(|| "undetermined".to_string()),
                )
                .or_default() += 1;
            if let Some(label) = synth_label {
                synth_repaired_labels += usize::from(label.repaired);
                if label.review {
                    synth_review += 1;
                }
            }
            match synth_label.and_then(|label| label.expected_deliver) {
                Some(expected_deliver) => {
                    synth_labeled += 1;
                    let family = synth_label
                        .map(|label| label.family.clone())
                        .unwrap_or_else(|| "unclassified".to_string());
                    let stats = synth_family_counts.entry(family).or_default();
                    stats.0 += 1;
                    if expected_deliver == would_deliver {
                        synth_correct += 1;
                        stats.1 += 1;
                    } else if expected_deliver {
                        stats.2 += 1;
                        synth_false_positives.push(format!(
                            "{name}: family={} expected=DELIVERED actual={:?} classification={:?}",
                            synth_label
                                .map(|label| label.family.as_str())
                                .unwrap_or("unclassified"),
                            verdict.threat_level,
                            verdict.classification
                        ));
                    } else {
                        stats.3 += 1;
                        synth_missed_detections.push(format!(
                            "{name}: family={} expected=BLOCK actual={:?} classification={:?}",
                            synth_label
                                .map(|label| label.family.as_str())
                                .unwrap_or("unclassified"),
                            verdict.threat_level,
                            verdict.classification
                        ));
                    }
                }
                None => {
                    synth_gray += 1;
                }
            }
        }
        // Optional regression telemetry only: preserve the exact synthetic
        // session/module snapshot for offline baseline/candidate fusion replay.
        // Labels are joined externally from the immutable capability inventory;
        // this known development corpus is never a blind holdout.
        if let Some(export_path) = std::env::var_os("VIGILYX_REDTEAM_EXPORT_JSONL") {
            let disposition = VerdictDisposition::from_threat_and_coverage(
                verdict.threat_level,
                verdict.has_incomplete_inspection(),
                ThreatLevel::Medium,
                ThreatLevel::Critical,
            );
            let export_record = serde_json::json!({
                "schema_version": 1,
                "record_type": "synthetic_capability_regression",
                "independent_holdout": false,
                "file": relative_name.unwrap_or(&name),
                "threat_level": verdict.threat_level,
                "classification": verdict.classification,
                "inspection_coverage": verdict.inspection_coverage,
                "coverage_reasons": &verdict.coverage_reasons,
                "would_deliver": would_deliver,
                "risk_single": verdict.fusion_details.as_ref().map(|fusion| fusion.risk_single),
                "risk_base": verdict.fusion_details.as_ref()
                    .and_then(|fusion| fusion.primary_result.as_ref())
                    .map(|primary| primary.risk_base),
                "active_constraints": verdict.fusion_details.as_ref()
                    .and_then(|fusion| fusion.primary_result.as_ref())
                    .map(|primary| &primary.active_constraints),
                "six_layer_outcomes": {
                    "threat": verdict.threat_level,
                    "classification": verdict.classification,
                    "authentication": {"status": "not_aggregated_by_harness"},
                    "coverage": verdict.inspection_coverage,
                    "data_security": {"status": "not_evaluated_by_harness"},
                    "disposition": disposition.to_string(),
                },
                "session": session.as_ref(),
                "module_results": &results,
                "verdict": &verdict,
                "verdict_config": &verdict_config,
            });
            let mut export_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(export_path)
                .expect("open synthetic regression JSONL export");
            serde_json::to_writer(&mut export_file, &export_record)
                .expect("serialize synthetic regression JSONL export");
            export_file
                .write_all(b"\n")
                .expect("append synthetic regression JSONL newline");
        }
        println!(
            "[{name}] FINAL={:?} class={:?} conf={:.2} modules=[{}] summary={}{}",
            verdict.threat_level,
            verdict.classification,
            verdict.confidence,
            flagged.join(","),
            verdict.summary,
            if would_deliver {
                "  ==> DELIVERED (below quarantine)"
            } else {
                ""
            }
        );
        if std::env::var("VIGILYX_REDTEAM_TRACE_EVIDENCE").is_ok_and(|value| value == "1") {
            for module_id in ["content_scan", "link_scan", "link_content", "html_scan"] {
                if let Some(result) = results.get(module_id) {
                    for item in &result.evidence {
                        println!(
                            "  EVIDENCE[{name}][{module_id}] {} location={:?} snippet={:?}",
                            item.description, item.location, item.snippet
                        );
                    }
                }
            }
        }
        if expected_inline_block.contains(&name.as_str()) {
            assert!(
                !would_deliver
                    && (verdict.has_incomplete_inspection()
                        || verdict.threat_level >= ThreatLevel::Medium),
                "red-team regression: {name} must retain its native-threat or incomplete-inspection quarantine contract; verdict={:?}, summary={}",
                verdict.threat_level,
                verdict.summary
            );
        }
        if verdict.has_incomplete_inspection() {
            assert_eq!(
                verdict.inspection_coverage,
                vigilyx_core::security::InspectionCoverage::Limited
            );
            assert!(
                !verdict.coverage_reasons.is_empty(),
                "{name}: missing coverage reason"
            );
        }
        if [
            "ctrl07_plain_ip_href.eml",
            "ev22_tab_entity_scheme.eml",
            "ev23_named_tab_scheme.eml",
            "ev25_base_href_relative.eml",
            "ev26_form_action_button.eml",
            "ev27_svg_xlink_anchor.eml",
            "ev34_folded_url_text.eml",
            "ev44_crlf_folded_scheme.eml",
            "ev58_chain_canto_greek_form.eml",
        ]
        .contains(&name.as_str())
        {
            assert!(
                verdict.threat_level >= ThreatLevel::Medium,
                "{name}: a coverage-only quarantine cannot preserve native link detection"
            );
            let qualified = &results["link_content"].details["qualified_link_compounds"];
            assert!(
                qualified
                    .as_array()
                    .is_some_and(|records| records.iter().any(|record| {
                        let claim = &record["claim"];
                        record["category"] == "ip_action_target"
                            && record["original_url"]
                                .as_str()
                                .is_some_and(|value| value.contains("203.0.113.60/verify"))
                            && matches!(
                                record["link_extraction_source"].as_str(),
                                Some("href" | "form_action" | "plain_text")
                            )
                            && claim["actor_role"] == "sender"
                            && claim["target_role"] == "recipient"
                            && matches!(
                                claim["speech_act"].as_str(),
                                Some("request" | "instruction")
                            )
                            && claim["polarity"] == "action"
                            && claim["quote_or_forward_status"] == "original"
                            && claim["counter_context_ids"]
                                .as_array()
                                .is_none_or(Vec::is_empty)
                            && claim["link_ids"]
                                .as_array()
                                .is_some_and(|links| !links.is_empty())
                    })),
                "{name}: native IP action must retain its actual same-link claim: {qualified}"
            );
        }
        if expected_inline_deliver.contains(&name.as_str()) {
            assert!(
                would_deliver,
                "benign calibration regression: {name} must remain below the MTA quarantine threshold; verdict={:?}, summary={}",
                verdict.threat_level, verdict.summary
            );
        }
        if name == coverage_gap_regression {
            assert!(
                verdict.summary.contains("captured evidence only")
                    || verdict.summary.contains("Inspection incomplete"),
                "coverage-gap regression must not produce a content-safe conclusion: {:?}",
                verdict
            );
        }
        if would_deliver {
            delivered.push(name.clone());
        }
    }

    println!(
        "\n=== DELIVERED (bypass succeeded): {} / {} ===",
        delivered.len(),
        case_files.len()
    );
    for name in &delivered {
        println!("  BYPASSED: {name}");
    }

    if include_synth {
        println!(
            "\n=== SYNTH AUDIT: total={} labeled={} correct={} accuracy={:.2}% gray={} review={} repaired_labels={} false_positives={} missed_detections={} ===",
            synth_total,
            synth_labeled,
            synth_correct,
            if synth_labeled == 0 {
                0.0
            } else {
                synth_correct as f64 * 100.0 / synth_labeled as f64
            },
            synth_gray,
            synth_review,
            synth_repaired_labels,
            synth_false_positives.len(),
            synth_missed_detections.len()
        );
        println!("SYNTH THREATS: {synth_threat_counts:?}");
        println!("SYNTH CLASSIFICATIONS: {synth_classification_counts:?}");
        println!("SYNTH FAMILIES: {synth_family_counts:?}");
        for item in &synth_false_positives {
            println!("  FALSE_POSITIVE: {item}");
        }
        for item in &synth_missed_detections {
            println!("  MISSED_DETECTION: {item}");
        }
        if std::env::var("VIGILYX_REDTEAM_ASSERT_SYNTH").is_ok_and(|value| value == "1") {
            assert!(
                synth_false_positives.is_empty() && synth_missed_detections.is_empty(),
                "synth audit found false positives or missed detections"
            );
        }
    }
}
