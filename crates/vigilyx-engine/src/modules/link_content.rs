//! URL content detection module - URL structural heuristic analysis
//!
//! Detects: suspicious URL path keywords, suspicious query parameters, encoding anomalies,
//! abnormal URL length, sensitive operation paths, fragment routing analysis, path typosquatting, etc.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine as _;
use chrono::Utc;
use rayon::prelude::*;
use regex::Regex;
use serde::Deserialize;
use sha1::Sha1;
use sha2::Digest;
use sha2::Sha256;

use crate::context::SecurityContext;
use crate::error::EngineError;
use crate::module::{
    Bpa, Evidence, ModuleMetadata, ModuleResult, Pillar, SecurityModule, ThreatLevel,
};
use crate::modules::common::{
    extract_domain_from_url, is_probable_cloud_asset_host,
    is_probable_non_clickable_render_asset_url, is_probable_opaque_mail_callback_url,
    is_probable_safe_static_asset_url, is_probable_schema_reference_url,
    is_probable_static_asset_path, organizational_domain,
};
use crate::modules::content_scan::html_utils::strip_html_tags;
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_text};
use crate::semantic::{
    extract_semantic_context, is_current_recipient_action, semantic_text_projection,
};
use unicode_normalization::UnicodeNormalization;
use vigilyx_core::models::email_domain;
use vigilyx_core::security::{
    SemanticClaim, SemanticCoverageStatus, SemanticLinkExtractionSource, SemanticMessageContext,
    SemanticSourcePart,
};

/// Long random hex string detection (DGA indicators) - static to avoid recompilation
static RE_HEX_DGA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9a-f]{8,}").unwrap());

/// URLs and mailbox addresses are identifiers, not visible brand claims. In
/// particular, a Safe Links href must not make a generic message appear to
/// claim the Microsoft/Outlook brand.
static RE_BRAND_CONTEXT_IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:https?://|www\.)[^\s<>()]+|[[:alnum:]_.+%-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}",
    )
    .expect("brand context identifier regex")
});
static RE_VISIBLE_HTML_BRAND_ATTRIBUTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\b(?:alt|title)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        .expect("visible HTML brand attribute regex")
});

/// Minimum number of URL words to trigger parallel Levenshtein computation.
const TYPO_PAR_THRESHOLD: usize = 20;

pub struct LinkContentModule {
    meta: ModuleMetadata,
    phishing_keywords: Vec<String>,
    #[cfg(test)]
    brand_profiles_override: Option<Vec<AccountActionBrandProfile>>,
}

impl Default for LinkContentModule {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkContentModule {
    pub fn new() -> Self {
        Self::new_with_keyword_lists(EffectiveKeywordLists::default())
    }

    pub fn new_with_keyword_lists(effective: EffectiveKeywordLists) -> Self {
        let mut phishing_keywords = effective.phishing_keywords;
        for keyword in effective.weak_phishing_keywords {
            if !phishing_keywords.contains(&keyword) {
                phishing_keywords.push(keyword);
            }
        }
        Self {
            meta: ModuleMetadata {
                id: "link_content".to_string(),
                name: "URL Content Analysis".to_string(),
                description:
                    "URL path, parameter, and fragment heuristic analysis + typosquatting detection"
                        .to_string(),
                pillar: Pillar::Link,
                depends_on: vec![],
                timeout_ms: 5000,
                is_remote: false,
                supports_ai: true,
                cpu_bound: true,
                inline_priority: None,
            },
            phishing_keywords,
            #[cfg(test)]
            brand_profiles_override: None,
        }
    }

    #[cfg(test)]
    fn with_test_brand_profiles(mut self, profiles: Vec<AccountActionBrandProfile>) -> Self {
        self.brand_profiles_override = Some(profiles);
        self
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AccountActionBrandProfile {
    brand: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    sender_domains: Vec<String>,
    #[serde(default)]
    landing_domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct CredentialBrandTargetPolicy {
    enabled: bool,
    cta_list: String,
    brand_profiles_list: String,
    content_instruction_list: String,
    content_auth_path_list: String,
    content_auth_anchor_list: String,
    official_sso_domains_list: String,
    #[serde(default)]
    risky_target_categories: Vec<String>,
    credential_link_category: String,
    high_risk_target_category: String,
    brand_mismatch_category: String,
    cta_target_score: f64,
    brand_mismatch_score: f64,
    content_external_sender_score: f64,
    content_well_known_sender_score: f64,
    credential_link_scale: f64,
    brand_mismatch_scale: f64,
    redirect_target_category: String,
    redirect_target_score: f64,
    redirect_target_scale: f64,
    redirect_target_floor: f64,
    minimum_redirect_link_score: f64,
}

fn parse_credential_brand_target_policy(
    value: serde_json::Value,
) -> Option<CredentialBrandTargetPolicy> {
    let policy = serde_json::from_value::<CredentialBrandTargetPolicy>(value).ok()?;
    (policy.enabled
        && !policy.cta_list.trim().is_empty()
        && !policy.brand_profiles_list.trim().is_empty()
        && !policy.content_instruction_list.trim().is_empty()
        && !policy.content_auth_path_list.trim().is_empty()
        && !policy.content_auth_anchor_list.trim().is_empty()
        && !policy.official_sso_domains_list.trim().is_empty()
        && !policy.risky_target_categories.is_empty()
        && !policy.credential_link_category.trim().is_empty()
        && !policy.high_risk_target_category.trim().is_empty()
        && !policy.brand_mismatch_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.cta_target_score)
        && (0.0..=1.0).contains(&policy.brand_mismatch_score)
        && (0.0..=1.0).contains(&policy.content_external_sender_score)
        && (0.0..=1.0).contains(&policy.content_well_known_sender_score)
        && (0.0..=1.0).contains(&policy.credential_link_scale)
        && (0.0..=1.0).contains(&policy.brand_mismatch_scale)
        && !policy.redirect_target_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.redirect_target_score)
        && (0.0..=1.0).contains(&policy.redirect_target_scale)
        && (0.0..=1.0).contains(&policy.redirect_target_floor)
        && (0.0..=1.0).contains(&policy.minimum_redirect_link_score))
    .then_some(policy)
}

fn credential_brand_target_policy() -> Option<CredentialBrandTargetPolicy> {
    parse_credential_brand_target_policy(
        crate::module_data::module_data()
            .get_structured("credential_brand_target_policy_v1")?
            .clone(),
    )
}

fn account_action_brand_profiles(list_name: &str) -> Vec<AccountActionBrandProfile> {
    crate::module_data::module_data()
        .get_structured(list_name)
        .cloned()
        .and_then(|value| serde_json::from_value::<Vec<AccountActionBrandProfile>>(value).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|profile: &AccountActionBrandProfile| {
            !profile.brand.trim().is_empty()
                && !profile.aliases.is_empty()
                && !profile.sender_domains.is_empty()
                && !profile.landing_domains.is_empty()
        })
        .collect()
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
    !suffix.is_empty() && (domain == suffix || domain.ends_with(&format!(".{suffix}")))
}

fn domain_matches_brand_profile(domain: &str, configured_domains: &[String]) -> bool {
    configured_domains
        .iter()
        .any(|suffix| domain_matches_suffix(domain, suffix))
}

fn normalized_text_contains_phrase(normalized_text: &str, phrase: &str) -> bool {
    let normalized_phrase = normalize_text(&phrase.to_lowercase());
    if normalized_phrase.is_empty() {
        return false;
    }

    normalized_text
        .match_indices(&normalized_phrase)
        .any(|(start, matched)| {
            if !normalized_phrase
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric())
            {
                return true;
            }
            let end = start + matched.len();
            let left_is_word = normalized_text[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_ascii_alphanumeric());
            let right_is_word = normalized_text[end..]
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphanumeric());
            !left_is_word && !right_is_word
        })
}

fn configured_phrase_match(text: &str, list_name: &str) -> Option<String> {
    let normalized = normalize_text(&text.to_lowercase());
    crate::module_data::module_data()
        .get_list(list_name)
        .iter()
        .find(|phrase| normalized_text_contains_phrase(&normalized, phrase))
        .cloned()
}

fn claimed_brand_profile(
    context: &str,
    profiles: &[AccountActionBrandProfile],
) -> Option<AccountActionBrandProfile> {
    let normalized = normalize_text(&context.to_lowercase());
    profiles
        .iter()
        .filter_map(|profile| {
            profile
                .aliases
                .iter()
                .filter(|alias| normalized_text_contains_phrase(&normalized, alias))
                .max_by_key(|alias| normalize_text(alias).chars().count())
                .map(|alias| (profile, normalize_text(alias).chars().count()))
        })
        .max_by_key(|(_, alias_len)| *alias_len)
        .map(|(profile, _)| profile.clone())
}

fn from_header_domain(ctx: &SecurityContext) -> Option<String> {
    ctx.session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        .and_then(|(_, value)| email_domain(value))
        .or_else(|| ctx.session.mail_from.as_deref().and_then(email_domain))
}

/// Return the URL that should be used for structural analysis and whether it
/// was successfully recovered from a configured mail-security gateway.
///
/// Entity decoding is kept here so the compound path observes the same href
/// representation as the URL analyzer. The wrapper itself is transport
/// context only; downstream policy decides whether CTA/account context makes
/// the recovered target actionable.
fn effective_link_target(url: &str) -> (String, bool) {
    let decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"");
    let is_gateway = crate::modules::link_scan::is_mail_security_gateway_pub(&decoded);
    let target = crate::modules::link_scan::unwrap_redirect_target_for_analysis(&decoded);
    match target {
        Some(target) if target != decoded => (target, is_gateway),
        _ => (decoded, false),
    }
}

// SUSPICIOUS_PATH_KEYWORDS: moved to module_data JSON (key: "suspicious_path_keywords")
// SUSPICIOUS_PARAMS: moved to module_data JSON (key: "suspicious_query_params")
// COMMON_URL_WORDS: moved to module_data JSON (key: "common_url_words")
// AUTH_BARRIER_TERMS: moved to module_data JSON (key: "auth_barrier_terms")
// OAUTH_FLOW_TERMS: moved to module_data JSON (key: "oauth_flow_terms")
// OFFICIAL_LOGIN_SUFFIXES: moved to module_data JSON (key: "official_login_suffixes")

/// Compute edit distance (Levenshtein distance) between two strings
fn edit_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Extract word segments from URL path/fragment (split by / - _ . and camelCase)
fn extract_url_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    // Split by / - _ .
    for segment in text.split(['/', '-', '_', '.']) {
        if segment.is_empty() {
            continue;
        }
        // Split by camelCase/PascalCase: "InvoiveDown" -> ["Invoive", "Down"]
        let mut current = String::new();
        for ch in segment.chars() {
            if ch.is_uppercase() && !current.is_empty() {
                if current.len() >= 3 {
                    words.push(current.to_lowercase());
                }
                current = String::new();
            }
            current.push(ch);
        }
        if current.len() >= 3 {
            words.push(current.to_lowercase());
        }
    }
    words
}

fn consonant_metrics(alpha_bytes: &[u8]) -> (u32, f64) {
    let vowels = b"aeiou";
    let mut max_consonant_run = 0u32;
    let mut current_run = 0u32;
    for &b in alpha_bytes {
        if !vowels.contains(&b.to_ascii_lowercase()) {
            current_run += 1;
            max_consonant_run = max_consonant_run.max(current_run);
        } else {
            current_run = 0;
        }
    }

    let consonant_count = alpha_bytes
        .iter()
        .filter(|b| !vowels.contains(&b.to_ascii_lowercase()))
        .count();
    let consonant_ratio = consonant_count as f64 / alpha_bytes.len() as f64;

    (max_consonant_run, consonant_ratio)
}

fn is_human_readable_label_segment(segment: &str) -> bool {
    let normalized = segment.to_ascii_lowercase();
    if crate::modules::identity_anomaly::is_human_readable_domain_label(&normalized) {
        return true;
    }
    if normalized.len() < 4 || !normalized.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }
    let alpha_bytes = normalized.as_bytes();
    let has_vowel = alpha_bytes
        .iter()
        .any(|b| b"aeiou".contains(&b.to_ascii_lowercase()));
    let (max_consonant_run, consonant_ratio) = consonant_metrics(alpha_bytes);
    has_vowel && max_consonant_run <= 2 && consonant_ratio < 0.75
}

/// Check one word against the dictionary for near-misses.
fn find_typo_match(word: &str) -> Option<(String, String)> {
    let md = crate::module_data::module_data();
    for dict_word in md.get_list("common_url_words") {
        let len_diff = (word.len() as i32 - dict_word.len() as i32).unsigned_abs() as usize;
        if len_diff > 2 {
            continue;
        }
        let dist = edit_distance(word, dict_word);
        let same_boundary_chars = word.chars().next() == dict_word.chars().next()
            && word.chars().last() == dict_word.chars().last();
        let max_len = word.len().max(dict_word.len());
        if (dist == 1 && max_len >= 5) || (dist == 2 && max_len >= 8 && same_boundary_chars) {
            return Some((
                format!(
                    "URL path typosquatting: \"{}\" likely misspelling of \"{}\" (edit distance={})",
                    word, dict_word, dist
                ),
                "url_typo".to_string(),
            ));
        }
    }
    None
}

/// Detect typosquatting anomalies in URL path/fragment
/// Returns (score, findings) - each typosquatting match found
fn detect_typos(text: &str) -> (f64, Vec<(String, String)>) {
    let url_words = extract_url_words(text);

    let md = crate::module_data::module_data();
    // Filter candidates (too short or exact match -> skip)
    let candidates: Vec<&String> = url_words
        .iter()
        .filter(|w| w.len() >= 4 && !md.contains("common_url_words", w))
        .collect();

    let findings: Vec<(String, String)> = if candidates.len() >= TYPO_PAR_THRESHOLD {
        candidates
            .par_iter()
            .filter_map(|word| find_typo_match(word))
            .collect()
    } else {
        candidates
            .iter()
            .filter_map(|word| find_typo_match(word))
            .collect()
    };

    // Each typosquatting finding is a moderate signal; cap at 3+ findings
    let score = (findings.len() as f64 * 0.10).min(0.30);
    (score, findings)
}

fn contains_any_suspicious_path_keywords(haystack: &str) -> bool {
    crate::matcher::suspicious_path_keywords()
        .scan(haystack)
        .distinct_patterns()
        .iter()
        .any(|keyword| suspicious_path_keyword_is_actionable(haystack, keyword))
}

/// Some short localized account words can be prefixes of ordinary CSS values.
/// JSON-managed boundary-sensitive terms are actionable as path tokens, but
/// not when embedded in longer values such as `object-fit:contain`.
fn suspicious_path_keyword_is_actionable(haystack: &str, keyword: &str) -> bool {
    if !crate::module_data::module_data().contains("token_boundary_path_keywords", keyword) {
        return true;
    }

    haystack.match_indices(keyword).any(|(start, matched)| {
        let end = start + matched.len();
        let left_is_word = haystack[..start]
            .chars()
            .next_back()
            .is_some_and(|ch| ch.is_ascii_alphanumeric());
        let right_is_word = haystack[end..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric());
        !left_is_word && !right_is_word
    })
}

fn domain_matches_official_login_suffix(domain: &str) -> bool {
    let md = crate::module_data::module_data();
    for suffix in md.get_list("official_login_suffixes") {
        if domain == suffix || domain.ends_with(&format!(".{}", suffix)) {
            return true;
        }
    }
    false
}

fn build_email_context(ctx: &SecurityContext) -> String {
    let mut context = String::new();
    if let Some(subject) = ctx.session.subject.as_deref() {
        context.push_str(subject);
        context.push(' ');
    }
    if let Some(body) = ctx.session.content.body_text.as_deref() {
        context.push_str(body);
        context.push(' ');
    }
    if let Some(body_html) = ctx.session.content.body_html.as_deref() {
        context.push_str(body_html);
        context.push(' ');
    }
    for link in &ctx.session.content.links {
        if let Some(text) = link.text.as_deref() {
            context.push_str(text);
            context.push(' ');
        }
    }
    for attachment in &ctx.session.content.attachments {
        context.push_str(&attachment.filename);
        context.push(' ');
    }
    context.to_lowercase()
}

/// Keep body projections separate: a quote in HTML must not become a new
/// sender instruction merely because a plain alternative contains the same
/// button label. A candidate needs a locally bound claim, not message keywords.
fn semantic_link_projections(ctx: &SecurityContext) -> Vec<(String, SemanticMessageContext)> {
    let mut projections = Vec::new();
    for (body, source) in [
        (
            ctx.session.content.body_text.as_deref(),
            SemanticSourcePart::PlainText,
        ),
        (
            ctx.session.content.body_html.as_deref(),
            SemanticSourcePart::Html,
        ),
    ] {
        if let Some(body) = body {
            let text = semantic_text_projection(body, source);
            let mut context = extract_semantic_context(&ctx.session, &text, source);
            if source == SemanticSourcePart::PlainText && text.len() < body.len() {
                context.coverage = SemanticCoverageStatus::Incomplete;
                let reason = format!(
                    "plain-text semantic projection inspected {} of {} source bytes",
                    text.len(),
                    body.len()
                );
                context.coverage_reason = Some(context.coverage_reason.map_or_else(
                    || reason.clone(),
                    |existing| format!("{existing}; {reason}"),
                ));
            }
            projections.push((text, context));
        }
    }
    projections
}

fn scoped_link_action<'a>(
    projections: &'a [(String, SemanticMessageContext)],
    link: &vigilyx_core::models::EmailLink,
) -> Option<(&'a SemanticClaim, &'a str)> {
    let mut candidates = Vec::new();
    for (body, context) in projections {
        let link_ids = context
            .links
            .iter()
            .filter(|observed| observed.original_url == link.url)
            .map(|observed| observed.link_id.as_str())
            .collect::<BTreeSet<_>>();
        for claim in &context.claims {
            let Some(span) = body.get(claim.span.start_byte..claim.span.end_byte) else {
                continue;
            };
            let linked = claim
                .link_ids
                .iter()
                .any(|id| link_ids.contains(id.as_str()));
            // Older captures can lack extraction provenance. An exact
            // locally visible URL can still establish the text edge; a
            // detached parser anchor cannot fill unknown authorship/scope.
            if linked {
                candidates.push((claim, span));
            }
        }
    }
    // A quoted mention of this URL cannot suppress a separately adopted
    // current request. Admission is per bounded claim, never whole-message.
    candidates
        .into_iter()
        .find(|(claim, _)| is_current_recipient_action(claim))
}

fn scoped_qr_action<'a>(
    ctx: &SecurityContext,
    projections: &'a [(String, SemanticMessageContext)],
    url: &str,
) -> Option<(&'a SemanticClaim, &'a str)> {
    // A uniquely decoded rendered QR carrier is an observed target. Ordinary
    // hyperlinks cannot borrow a scan instruction elsewhere in the message.
    if ctx.decoded_qr_urls().len() != 1 || ctx.decoded_qr_urls()[0] != url {
        return None;
    }
    projections.iter().find_map(|(body, context)| {
        context.claims.iter().find_map(|claim| {
            let text = body.get(claim.span.start_byte..claim.span.end_byte)?;
            (is_current_recipient_action(claim)
                && claim.link_ids.is_empty()
                && has_qr_lure_context(&text.to_lowercase()))
            .then_some((claim, text))
        })
    })
}

fn qualified_link_record(
    projections: &[(String, SemanticMessageContext)],
    category: &str,
    claim: &SemanticClaim,
    original_url: &str,
    effective_url: &str,
    score: f64,
) -> serde_json::Value {
    let extraction_source = projections
        .iter()
        .find_map(|(_, context)| {
            context
                .links
                .iter()
                .find(|observed| {
                    observed.original_url == original_url
                        && observed.source_span_id.as_deref() == Some(claim.source_span_id.as_str())
                        && claim.link_ids.contains(&observed.link_id)
                })
                .map(|observed| observed.extraction_source)
        })
        .unwrap_or(SemanticLinkExtractionSource::Unknown);
    serde_json::json!({
        "category": category,
        "claim": claim,
        "original_url": original_url,
        "effective_url": effective_url,
        "link_extraction_source": extraction_source,
        "causal_key": extract_domain_from_url(effective_url).map(|host| format!("host:{host}")),
        "score": score,
        "confidence": 0.75,
        "link_transport_status": "not_attempted",
        "link_content_status": "not_observed",
        "link_ownership_status": "unknown",
        "coverage_reason": "static link relation; transport, content and ownership are unverified"
    })
}

/// Item strength belongs to this category on this target, never to the
/// module's sum of findings across the message. Repeated views of one target
/// retain the strongest observation instead of accumulating duplicate mass.
fn record_causal_score(
    scores: &mut BTreeMap<(String, String), f64>,
    effective_url: &str,
    category: &str,
    score: f64,
) {
    let key = extract_domain_from_url(effective_url)
        .map(|host| format!("host:{host}"))
        .unwrap_or_else(|| format!("url:{}", hex_digest::<Sha256>(effective_url)));
    let current = scores.entry((key, category.to_string())).or_default();
    *current = current.max(score.clamp(0.0, 1.0));
}

fn attach_semantic_link_coverage(result: &mut ModuleResult, limited: bool) {
    if limited {
        result
            .categories
            .push("inspection_coverage_incomplete".to_string());
        result.details["semantic_link_coverage_limited"] = serde_json::json!(true);
        result.summary = format!(
            "Link semantic attribution incomplete; observed threat evidence retained. {}",
            result.summary
        );
        if result.threat_level == ThreatLevel::Safe {
            result.bpa = Some(Bpa::vacuous());
            result.confidence = result.confidence.min(0.50);
        }
    }
}

/// Return true when the message contains a configured instruction to continue
/// an account-authentication flow.  The phrase is deliberately evaluated
/// across the same subject/body/anchor context used by the link module; a
/// recipient token alone remains an observation.
fn has_credential_continuation_context(context: &str) -> bool {
    let normalized = normalize_text(&context.to_lowercase());
    crate::module_data::module_data()
        .get_list("credential_continuation_phrases")
        .iter()
        .any(|phrase| normalized.contains(phrase))
}

fn append_brand_claim_text(context: &mut String, value: &str) {
    let visible = RE_BRAND_CONTEXT_IDENTIFIER.replace_all(value, " ");
    context.push_str(&visible);
    context.push(' ');
}

fn append_html_brand_claim_text(context: &mut String, html: &str) {
    append_brand_claim_text(context, &strip_html_tags(html));
    for captures in RE_VISIBLE_HTML_BRAND_ATTRIBUTE.captures_iter(html) {
        if let Some(value) = captures
            .get(1)
            .or_else(|| captures.get(2))
            .or_else(|| captures.get(3))
        {
            append_brand_claim_text(context, value.as_str());
        }
    }
}

/// Build brand-claim context from text presented to the recipient. Raw hrefs,
/// mailbox domains, attachment names, and HTML markup are deliberately
/// excluded because they are evidence to compare against a claim, not claims
/// themselves.
fn build_brand_claim_context(ctx: &SecurityContext) -> String {
    let mut context = String::new();
    if let Some(subject) = ctx.session.subject.as_deref() {
        append_brand_claim_text(&mut context, subject);
    }
    if let Some((_, from_value)) = ctx
        .session
        .content
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("from"))
        && let Some((display_name, _)) = from_value.split_once('<')
    {
        append_brand_claim_text(&mut context, display_name.trim_matches([' ', '"']));
    }
    context.to_lowercase()
}

fn scoped_brand_claim_context(
    ctx: &SecurityContext,
    link: &vigilyx_core::models::EmailLink,
    action_text: &str,
) -> String {
    let mut context = build_brand_claim_context(ctx);
    append_brand_claim_text(&mut context, action_text);
    // A logo/alt adjacent to this exact visible button can describe its brand.
    // Do not search other blocks, quoted sections, or unrelated link labels.
    if let Some(html) = ctx.session.content.body_html.as_deref()
        && html.matches(&link.url).count() == 1
        && let Some(position) = html.find(&link.url)
    {
        let mut start = position.saturating_sub(384);
        while !html.is_char_boundary(start) {
            start += 1;
        }
        let prefix = &html[start..position];
        let lower_prefix = prefix.to_ascii_lowercase();
        let boundary = ["</p>", "</div>", "</blockquote>", "</q>"]
            .iter()
            .filter_map(|end| lower_prefix.rfind(end).map(|offset| offset + end.len()))
            .max()
            .unwrap_or(0);
        append_html_brand_claim_text(&mut context, &prefix[boundary..]);
    }
    context.to_lowercase()
}

fn has_keyword_context(text: &str, keywords: &[String]) -> bool {
    let normalized = normalize_text(text);
    keywords.iter().any(|keyword| normalized.contains(keyword))
}

fn has_qr_lure_context(text: &str) -> bool {
    const QR_TERMS: &[&str] = &[
        "qr code",
        "scan the code",
        "scan qr",
        "scan to login",
        "二维码",
        "扫码",
        "扫描二维码",
        "扫码登录",
    ];

    QR_TERMS.iter().any(|term| text.contains(term))
}

fn is_public_literal_ip_target(url: &str) -> bool {
    let Some(host) = url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
    else {
        return false;
    };
    let Ok(std::net::IpAddr::V4(ip)) = host.parse() else {
        return false;
    };
    let octets = ip.octets();
    !(octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168))
}

fn has_action_cta_context(text: &str) -> bool {
    [
        "click",
        "view",
        "confirm",
        "verify",
        "enter",
        "activate",
        "review",
        "update",
        "submit",
        "log in",
        "login",
        "查看",
        "详情",
        "入口",
        "操作",
        "确认",
        "验证",
        "点击",
        "立即",
        "xác minh",
        "nhấp",
        "bấm",
        "đăng nhập",
        "คลิก",
        "ยืนยัน",
        "ตรวจสอบ",
        "เข้าสู่ระบบ",
        "klik",
        "verifikasi",
        "konfirmasi",
        "masuk",
    ]
    .iter()
    .any(|term| text.contains(term))
}

fn is_ip_action_target(url: &str, context: &str) -> bool {
    if !is_public_literal_ip_target(url) || !has_action_cta_context(context) {
        return false;
    }
    let Some(parsed) = url::Url::parse(url).ok() else {
        return false;
    };
    let path = format!(
        "{} {}",
        parsed.path().to_ascii_lowercase(),
        parsed.query().unwrap_or_default().to_ascii_lowercase()
    );
    [
        "login", "signin", "verify", "account", "password", "secure", "confirm", "update",
    ]
    .iter()
    .any(|term| path.contains(term))
}

fn url_looks_like_device_code_flow(url_lower: &str) -> bool {
    url_lower.contains("microsoft.com/devicelogin")
        || url_lower.contains("/deviceauth")
        || (url_lower.contains("device") && url_lower.contains("code"))
}

fn url_looks_like_oauth_flow(url_lower: &str) -> bool {
    let md = crate::module_data::module_data();
    // `profile`, `email`, and `openid` are common path/query words on
    // ordinary business-card and mail pages. They only become OAuth evidence
    // when paired with a flow marker such as /authorize, client_id, or scope.
    const CONTEXT_ONLY_TERMS: &[&str] = &["profile", "email", "openid", "saml"];
    md.get_list("oauth_flow_terms")
        .iter()
        .any(|term| !CONTEXT_ONLY_TERMS.contains(&term.as_str()) && url_lower.contains(term))
}

fn url_looks_like_auth_barrier(url_lower: &str) -> bool {
    let md = crate::module_data::module_data();
    for term in md.get_list("auth_barrier_terms") {
        if url_lower.contains(term) {
            return true;
        }
    }
    false
}

/// Fullwidth Latin letters (U+FF21-FF3A / U+FF41-FF5A) are visually identical
/// to ASCII Latin and collapse to it under NFKC.
fn is_fullwidth_latin(c: char) -> bool {
    ('\u{ff21}'..='\u{ff3a}').contains(&c) || ('\u{ff41}'..='\u{ff5a}').contains(&c)
}

/// Match the homoglyph skeleton of a non-ASCII domain against known brand
/// domains (`official_login_suffixes`). NFKC first folds fullwidth/compatibility
/// characters to ASCII, then header_scan's look-alike map folds Cyrillic/digit
/// substitutions to Latin. Returns the matched brand domain, if any.
fn match_idn_skeleton_brand(domain_part: &str) -> Option<String> {
    let folded: String = domain_part.nfkc().collect();
    let skeleton =
        crate::modules::header_scan::checks::normalize_homoglyph_simple(&folded).to_lowercase();
    // No folding happened -> nothing visually confusable with Latin brands.
    if skeleton == domain_part.to_lowercase() {
        return None;
    }
    let md = crate::module_data::module_data();
    md.get_list("official_login_suffixes")
        .iter()
        .find(|brand| skeleton == **brand || skeleton.ends_with(&format!(".{}", brand)))
        .cloned()
}

/// A non-ASCII look-alike inside the public suffix (for example `.cοm`,
/// Greek omicron) is materially stronger than an arbitrary mixed-script label:
/// it counterfeits browser-recognisable routing infrastructure rather than a
/// free-form registrant name. Limit the promotion to a small deterministic set
/// of common ASCII suffixes so legitimate IDN suffixes remain at the ordinary
/// mixed-script weight.
fn confusable_common_public_suffix(domain_part: &str) -> Option<(String, String)> {
    const COMMON_SUFFIXES: &[&str] = &["com", "org", "net", "cn", "edu", "gov", "mil", "io", "co"];

    let suffix = domain_part.rsplit('.').next()?.to_lowercase();
    if suffix.is_ascii() {
        return None;
    }
    let folded: String = suffix.nfkc().collect();
    let skeleton =
        crate::modules::header_scan::checks::normalize_homoglyph_simple(&folded).to_lowercase();
    if skeleton == suffix || !COMMON_SUFFIXES.contains(&skeleton.as_str()) {
        return None;
    }
    Some((suffix, skeleton))
}

pub(crate) fn has_confusable_common_public_suffix(host: &str) -> bool {
    let unicode_host = idna::domain_to_unicode(host).0.to_lowercase();
    confusable_common_public_suffix(&unicode_host).is_some()
}

fn hex_digest<D>(value: &str) -> String
where
    D: Digest + Default,
{
    let mut hasher = D::default();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn url_contains_recipient(ctx: &SecurityContext, url: &str) -> bool {
    let decoded_url = crate::modules::common::percent_decode(&url.to_lowercase());
    ctx.session.rcpt_to.iter().any(|rcpt| {
        let rcpt_lower = rcpt.to_lowercase();
        decoded_url.contains(&rcpt_lower)
            || decoded_url.contains(&rcpt_lower.replace('@', "%40"))
            || decoded_url.contains(&hex_digest::<Sha1>(&rcpt_lower))
            || decoded_url.contains(&hex_digest::<Sha256>(&rcpt_lower))
    })
}

/// Recipient identifiers are normal metadata on unsubscribe, preference,
/// open-tracking, and delivery callback endpoints. Without an authentication
/// context they must not be promoted to credential-phishing evidence.
fn is_recipient_metadata_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    let path = normalize_text(&parsed.path().to_ascii_lowercase());
    const METADATA_PATH_MARKERS: &[&str] = &[
        "unsubscribe",
        "opt-out",
        "optout",
        "preference",
        "subscription",
        "email-settings",
        "email_settings",
        "/trace/",
        "/tracking/",
        "/track/",
        "/open/",
        "/pixel/",
        "/webhook",
        "/callback",
    ];
    METADATA_PATH_MARKERS
        .iter()
        .any(|marker| path.contains(marker))
        || path.ends_with("/track")
        || path.ends_with("/open")
        || path.ends_with("/report")
}

fn detect_external_brand_host(host: &str) -> Option<(String, String, f64)> {
    let decoded = idna::domain_to_unicode(host).0.to_ascii_lowercase();
    let md = crate::module_data::module_data();
    let anchors = md.get_structured("brand_anchor_domains")?.as_array()?;
    let anchors = anchors
        .iter()
        .filter_map(|entry| {
            Some((
                entry.get("keyword")?.as_str()?,
                entry.get("domain")?.as_str()?,
            ))
        })
        .collect::<Vec<_>>();

    // A host that belongs to any configured official anchor must leave the
    // comparison before it is tested against a different, similarly-spelled
    // brand. Without this all-anchor guard, abchina.com was first accepted as
    // ABC and then incorrectly compared with cmbchina.com.
    if anchors.iter().any(|(_, anchor)| {
        crate::modules::common::host_matches_domain_or_subdomain(&decoded, anchor)
    }) {
        return None;
    }

    let registrable = organizational_domain(&decoded)?;
    let base = registrable.split('.').next()?;
    for (brand, anchor) in anchors {
        let anchor_base = anchor.split('.').next()?;
        if base == anchor_base {
            continue;
        }
        let normalized_base = crate::modules::header_scan::checks::normalize_homoglyph_simple(base);
        let normalized_anchor =
            crate::modules::header_scan::checks::normalize_homoglyph_simple(anchor_base);
        if normalized_base != base && normalized_base == normalized_anchor {
            return Some((brand.to_string(), anchor.to_string(), 0.45));
        }
        let distance = edit_distance(base, anchor_base);
        let max_len = base.len().max(anchor_base.len());
        if (distance == 1 && max_len >= 5) || (distance == 2 && max_len >= 8) {
            return Some((brand.to_string(), anchor.to_string(), 0.35));
        }
    }
    None
}

/// Object-storage / CDN "content override" query parameters
/// (`?response-content-type=text/html`, `?response-content-disposition=...`)
/// rewrite the served response headers of a stored object. Attackers abuse
/// them to make an exempt `.../malware.jpg` URL return an HTML phishing page,
/// so any URL carrying them must lose the static-asset exemption.
pub(crate) fn has_content_override_params(url: &str) -> bool {
    let Some((_, query)) = url.split_once('?') else {
        return false;
    };
    let query = query.split('#').next().unwrap_or(query);
    query.split('&').any(|pair| {
        let name = crate::modules::common::percent_decode(pair.split('=').next().unwrap_or(""))
            .to_ascii_lowercase();
        matches!(
            name.as_str(),
            "response-content-type"
                | "response-content-disposition"
                | "response-content-language"
                | "response-content-encoding"
                | "response-cache-control"
                | "response-expires"
        )
    })
}

/// Decide whether an encoded separator changes path semantics rather than
/// representing one character inside an opaque route token.
///
/// Standard Base64 uses `/`, so encrypted identifiers placed in a single URL
/// segment commonly encode that character as `%2F`. Treating every such byte
/// as route obfuscation creates a standalone Low finding. The exception stays
/// deliberately narrow: the complete decoded segment must be valid
/// Base64/Base64URL and use only that closed alphabet. Encoded backslashes,
/// traversal punctuation, route keywords, nested URLs, and second-layer
/// encoding therefore remain actionable.
fn is_opaque_token_segment_with_encoded_slash(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    if segment.len() < 40 || !lower.contains("%2f") || lower.contains("%25") {
        return false;
    }

    let decoded = crate::modules::common::percent_decode(segment);
    if decoded.len() < 32
        || !decoded.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
    {
        return false;
    }

    // Route words are JSON-managed detector data. A token-looking segment
    // that decodes to an actual route such as `.../login` must not enter the
    // opaque-token exception.
    if contains_any_suspicious_path_keywords(&decoded.to_ascii_lowercase()) {
        return false;
    }

    // Padding is valid only at the end and is bounded by Base64's two-byte
    // quantum. This prevents arbitrary `=`-delimited path syntax from entering
    // the exception.
    if let Some(padding_start) = decoded.find('=') {
        let padding = &decoded[padding_start..];
        if padding.len() > 2 || !padding.bytes().all(|byte| byte == b'=') {
            return false;
        }
    }

    // A closed alphabet alone is insufficient: require the complete segment
    // to be a syntactically valid Base64 token. Ciphertext can legitimately
    // contain `/X/` (a one-character chunk when viewed as a path), so chunk
    // length is not a sound route-semantic test.
    let token_bytes = decoded.as_bytes();
    let decoded_token = base64::engine::general_purpose::STANDARD
        .decode(token_bytes)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(token_bytes))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(token_bytes))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token_bytes));
    if decoded_token.is_err() {
        return false;
    }

    let mut classes = 0u8;
    classes += u8::from(decoded.bytes().any(|byte| byte.is_ascii_lowercase()));
    classes += u8::from(decoded.bytes().any(|byte| byte.is_ascii_uppercase()));
    classes += u8::from(decoded.bytes().any(|byte| byte.is_ascii_digit()));
    classes >= 2
}

fn has_actionable_encoded_path_separator(path: &str) -> bool {
    let path_lower = path.to_ascii_lowercase();
    if path_lower.contains("%5c") {
        return true;
    }
    if !path_lower.contains("%2f") {
        return false;
    }

    path.split('/').any(|segment| {
        segment.to_ascii_lowercase().contains("%2f")
            && !is_opaque_token_segment_with_encoded_slash(segment)
    })
}

/// URL heuristic analysis (includes fragment and typosquatting detection)
pub(crate) fn analyze_url(url: &str) -> (f64, Vec<(String, String)>) {
    analyze_url_with_anchor_context(url, false, false)
}

fn analyze_url_with_anchor_context(
    url: &str,
    has_anchor_text: bool,
    first_party: bool,
) -> (f64, Vec<(String, String)>) {
    let (score, findings, _) =
        analyze_url_with_anchor_context_scored(url, has_anchor_text, first_party);
    (score, findings)
}

type ScoredUrlAnalysis = (f64, Vec<(String, String)>, BTreeMap<String, f64>);

fn analyze_url_with_anchor_context_scored(
    url: &str,
    has_anchor_text: bool,
    first_party: bool,
) -> ScoredUrlAnalysis {
    let mut score: f64 = 0.0;
    let mut findings: Vec<(String, String)> = Vec::new();
    let mut category_scores: BTreeMap<String, f64> = BTreeMap::new();
    macro_rules! add_score {
        ($category:expr, $amount:expr) => {{
            let amount: f64 = $amount;
            score += amount;
            *category_scores.entry($category.to_string()).or_default() += amount;
        }};
    }
    if is_probable_schema_reference_url(url)
        || is_probable_opaque_mail_callback_url(url)
        || crate::modules::link_scan::is_known_safe_tokenized_resource_url(url)
    {
        return (score, findings, category_scores);
    }
    // Decode HTML entities (URLs in email body may contain &amp; etc.)
    let url_decoded = url
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"");
    let effective_url =
        crate::modules::link_scan::unwrap_redirect_target_for_analysis(&url_decoded)
            .unwrap_or_else(|| url_decoded.clone());
    let url_lower = effective_url.to_lowercase();

    // Parse URL with the WHATWG parser. The old hand-rolled splitter was
    // blind in two ways:
    // - userinfo (`http://mail.qq.com:443@evil.tk/login`): the userinfo
    //   segment was mistaken for the host, so the fake "trusted" prefix hit
    //   safe-domain exemptions while the real host after `@` was never
    //   checked;
    // - backslash separators (`http:/\evil.com/login`): `strip_prefix` failed
    //   and the "host" collapsed to the literal string "http".
    // The WHATWG parser normalizes both (`\` becomes `/` in special schemes)
    // and always exposes the real host via `host_str()`.
    let Ok(parsed_url) = url::Url::parse(&effective_url) else {
        // Unparsable hrefs are preserved at extraction time and scored by
        // link_scan's unparseable_url category; no reliable host/path signal
        // can be derived here.
        return (score, findings, category_scores);
    };
    let host_for_check = parsed_url.host_str().unwrap_or("");
    let path = parsed_url.path();
    let query = parsed_url.query();
    let fragment = parsed_url.fragment();
    // Operator/system-whitelisted roots are first-party infrastructure.  A
    // subdomain such as `ebank.internal.example` must not be compared against an
    // unrelated external brand merely because its second-level label is close
    // to that brand's configured anchor.
    let domain_trusted =
        first_party || crate::modules::link_scan::is_trusted_url_domain(host_for_check);
    let hosted_platform = crate::modules::link_scan::is_shared_hosting_platform(host_for_check);
    let host_under_safe_domain =
        crate::modules::link_scan::is_well_known_safe_domain(host_for_check);

    // Static image/font/script assets hosted on object storage frequently use
    // bucket labels and long query strings, but they are not landing pages and
    // should not trigger login-path/DGA heuristics on their own. The same
    // treatment applies to static assets hosted under curated well-known safe
    // domains such as provider CDN roots (for example *.127.net).
    //
    // The exemption is deliberately narrow:
    // - it never applies to clickable links carrying anchor text (an
    //   attacker-lured <a> "static" URL is a landing-page candidate);
    // - it never applies when the query rewrites the served response headers
    //   (`response-content-type=text/html` turns a stored ".jpg" into an
    //   HTML phishing page).
    let looks_like_static_asset = is_probable_safe_static_asset_url(&effective_url)
        || ((is_probable_cloud_asset_host(host_for_check) || host_under_safe_domain)
            && is_probable_static_asset_path(path));
    if looks_like_static_asset && !has_anchor_text && !has_content_override_params(&effective_url) {
        return (score, findings, category_scores);
    }
    if looks_like_static_asset && has_content_override_params(&effective_url) {
        add_score!("oss_content_override", 0.30);
        findings.push((
            "Static-asset URL carries object-storage content-override parameters (response-content-type/disposition) — served Content-Type can be rewritten to HTML".to_string(),
            "oss_content_override".to_string(),
        ));
    }

    if !domain_trusted
        && !host_under_safe_domain
        && !crate::modules::link_scan::is_official_claimed_domain(host_for_check)
        && let Some((brand, anchor, brand_score)) = detect_external_brand_host(host_for_check)
    {
        add_score!("brand_typosquatting", brand_score);
        findings.push((
            format!(
                "External brand typosquatting: host '{}' resembles {} ({})",
                host_for_check, brand, anchor
            ),
            "brand_typosquatting".to_string(),
        ));
    }

    // The wrapper has already been removed. Score the real destination's TLD
    // from the JSON-managed policy list; the trusted DDEI hostname never
    // contributes to this finding.
    let md = crate::module_data::module_data();
    if md.get_list("suspicious_tlds").iter().any(|suffix| {
        host_for_check == suffix.as_str() || host_for_check.ends_with(&format!(".{suffix}"))
    }) {
        add_score!("suspicious_tld", 0.12);
        findings.push((
            format!("Destination uses high-risk TLD: {host_for_check}"),
            "suspicious_tld".to_string(),
        ));
    }

    // 1. Suspicious path keywords (check both path and fragment)
    let combined_path = if let Some(frag) = fragment {
        format!("{} {}", path, frag)
    } else {
        path.to_string()
    };

    // Trusted domains (IOC verdict=clean) get reduced structural check weight
    // A trusted first-party asset may bypass noisy token/URL checks, but a
    // shared tenant platform (Forms/Notion/Workers/Functions) is attacker
    // controlled and must retain normal phishing weights.
    let structural_trusted = domain_trusted && !hosted_platform;

    // Percent-encoding must not hide keywords (e.g. %6c%6f%67%69%6e = login):
    // decode one layer before the Aho-Corasick scan. The %25 double-encoding
    // check below still inspects the raw path.
    let combined_path_decoded =
        crate::modules::common::percent_decode(&combined_path).to_lowercase();
    let path_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
        .scan(&combined_path_decoded)
        .distinct_patterns()
        .into_iter()
        .filter(|keyword| suspicious_path_keyword_is_actionable(&combined_path_decoded, keyword))
        .collect();
    if !path_hits.is_empty() {
        let weight = if structural_trusted { 0.02 } else { 0.10 };
        add_score!(
            "suspicious_path",
            (path_hits.len() as f64 * weight).min(0.30)
        );
        findings.push((
            format!(
                "URL path contains suspicious keywords: {}{}",
                path_hits.join(", "),
                if structural_trusted {
                    " (trusted domain, reduced weight)"
                } else {
                    ""
                }
            ),
            "suspicious_path".to_string(),
        ));
    }

    // 2. Suspicious query parameters (parameter name matching)
    if let Some(q) = query {
        let mut param_hits: Vec<String> = Vec::new();
        // Decode each parameter name before matching so that encoded names
        // (e.g. tok%65n = token) cannot bypass the suspicious-params list.
        let param_names: Vec<String> = q
            .split('&')
            .filter_map(|pair| {
                let name = pair.split('=').next()?;
                if name.is_empty() {
                    None
                } else {
                    Some(crate::modules::common::percent_decode(name).to_lowercase())
                }
            })
            .collect();
        let benign_token_path = md
            .get_list("benign_token_path_keywords")
            .iter()
            .map(|keyword| keyword.to_ascii_lowercase())
            .any(|keyword| {
                combined_path_decoded
                    .split(|ch: char| !ch.is_ascii_alphanumeric())
                    .any(|segment| segment == keyword)
            });
        for suspicious in md.get_list("suspicious_query_params") {
            let token_on_preference_path = suspicious == "token" && benign_token_path;
            if param_names.contains(suspicious) && !token_on_preference_path {
                param_hits.push(suspicious.to_string());
            }
        }
        // Generic identifiers are ubiquitous in agreement, statement and
        // preference links. They become suspicious only when the local path
        // already carries a phishing action; the vocabulary remains runtime
        // JSON data rather than a Rust exception list.
        if !path_hits.is_empty() {
            for contextual in md.get_list("contextual_query_params") {
                if param_names.contains(contextual) {
                    param_hits.push(contextual.to_string());
                }
            }
        }
        param_hits.sort_unstable();
        param_hits.dedup();
        if !param_hits.is_empty() {
            let pw = if structural_trusted { 0.02 } else { 0.08 };
            add_score!(
                "suspicious_params",
                (param_hits.len() as f64 * pw).min(0.25)
            );
            findings.push((
                format!(
                    "URL query parameters suspicious: {}{}",
                    param_hits.join(", "),
                    if structural_trusted {
                        " (trusted domain, reduced weight)"
                    } else {
                        ""
                    }
                ),
                "suspicious_params".to_string(),
            ));
        }

        // Parameter *values* are scanned as well: phishing kits hide protocol
        // handlers and keywords behind percent-encoding in redirect
        // parameters (e.g. ?next=%6A%61%76%61%73%63%72%69%70%74%3A... =
        // javascript:). Decoded values that are themselves plain http(s) URLs
        // or bare paths are skipped for the keyword scan — legitimate
        // SSO/redirect targets routinely contain words like "login".
        let mut value_protocol_hit = false;
        let mut value_keyword_hits: Vec<String> = Vec::new();
        for pair in q.split('&') {
            let Some((_, value)) = pair.split_once('=') else {
                continue;
            };
            if value.len() < 4 {
                continue;
            }
            let decoded_value = crate::modules::common::percent_decode(value).to_lowercase();
            if decoded_value.contains("javascript:")
                || decoded_value.contains("vbscript:")
                || decoded_value.contains("data:text/html")
            {
                value_protocol_hit = true;
            }
            let was_encoded = value.contains('%');
            if was_encoded
                && !decoded_value.starts_with("http://")
                && !decoded_value.starts_with("https://")
                && !decoded_value.starts_with('/')
            {
                value_keyword_hits.extend(
                    crate::matcher::suspicious_path_keywords()
                        .scan(&decoded_value)
                        .distinct_patterns(),
                );
            }
        }
        if value_protocol_hit {
            add_score!("encoded_protocol_param", 0.30);
            findings.push((
                "Percent-encoded query parameter value resolves to a dangerous protocol (javascript:/vbscript:/data:)".to_string(),
                "encoded_protocol_param".to_string(),
            ));
        }
        if !value_keyword_hits.is_empty() {
            value_keyword_hits.sort();
            value_keyword_hits.dedup();
            let vw = if structural_trusted { 0.02 } else { 0.08 };
            add_score!(
                "suspicious_param_value",
                (value_keyword_hits.len() as f64 * vw).min(0.25)
            );
            findings.push((
                format!(
                    "URL query parameter values contain suspicious keywords: {}",
                    value_keyword_hits.join(", ")
                ),
                "suspicious_param_value".to_string(),
            ));
        }
    }

    // URL length by itself is common in signed links, tracking callbacks, and
    // electronic statements. The module-level analyzer retains a count in
    // `diagnostic_observations`; length is not positive attack evidence.

    // 4. Encoding anomalies (check path, query and fragment for abnormal URL
    // encoding). Browsers never decode the fragment — phishing pages decode
    // #%25xx themselves in JS — so %25 double-encoding must be checked on
    // every component, not just the path.
    let path_lower = path.to_lowercase();
    let mut double_encoded_parts: Vec<&str> = Vec::new();
    if path_lower.contains("%25") {
        double_encoded_parts.push("path");
    }
    if query.is_some_and(|q| q.to_lowercase().contains("%25")) {
        double_encoded_parts.push("query");
    }
    if fragment.is_some_and(|f| f.to_lowercase().contains("%25")) {
        double_encoded_parts.push("fragment");
    }
    if !double_encoded_parts.is_empty() {
        add_score!("double_encoding", 0.25);
        findings.push((
            format!(
                "URL {} contains double percent-encoding (%25)",
                double_encoded_parts.join("/")
            ),
            "double_encoding".to_string(),
        ));

        // Decode a second layer (bounded at exactly two layers, no exponential
        // fan-out) so payloads like %253A%252F%252F (%3A%2F%2F -> ://) or
        // double-encoded javascript:/login keywords do not stop at the
        // double_encoding label without their content ever being inspected.
        let raw_components = format!(
            "{} {} {}",
            path,
            query.unwrap_or(""),
            fragment.unwrap_or("")
        );
        let second_decoded = crate::modules::common::percent_decode(
            &crate::modules::common::percent_decode(&raw_components),
        )
        .to_lowercase();
        let mut second_layer_reasons: Vec<String> = Vec::new();
        if second_decoded.contains("javascript:")
            || second_decoded.contains("vbscript:")
            || second_decoded.contains("data:text/html")
        {
            second_layer_reasons.push("dangerous protocol".to_string());
        }
        let second_keyword_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
            .scan(&second_decoded)
            .distinct_patterns();
        if !second_keyword_hits.is_empty() {
            second_layer_reasons.push(format!("keywords: {}", second_keyword_hits.join(", ")));
        }
        if !second_layer_reasons.is_empty() {
            add_score!("double_encoded_payload", 0.20);
            findings.push((
                format!(
                    "Second-layer percent-decoding reveals {}",
                    second_layer_reasons.join("; ")
                ),
                "double_encoded_payload".to_string(),
            ));
        }
    }
    if has_actionable_encoded_path_separator(path) {
        add_score!("encoded_separator", 0.15);
        findings.push((
            "URL path contains encoded path separators".to_string(),
            "encoded_separator".to_string(),
        ));
    }

    // 5. @ sign in URL (domain obfuscation)
    // Only userinfo in the authority is flagged, not @ in query strings
    // e.g. http://user@evil.com is suspicious, but ?wght@700 (Google Fonts) is benign
    if !parsed_url.username().is_empty() || parsed_url.password().is_some() {
        add_score!("at_sign_obfuscation", 0.35);
        findings.push((
            "URL contains @ sign in authority (potentially hiding real domain)".to_string(),
            "at_sign_obfuscation".to_string(),
        ));
    }

    // 5b. DGA/random domain detection (consonant clustering analysis)
    // e.g., rqvzkqb.shbllgs.cn is likely DGA-generated
    if !host_under_safe_domain
        && (!is_probable_static_asset_path(path) || has_content_override_params(&effective_url))
    {
        let domain_part = host_for_check;
        // Tenant labels under a hosted mail platform are assigned identifiers.
        // Keep the platform suffix itself in the scan; drop only the prefix.
        let platform_labels = crate::modules::common::hosted_identity_platform(domain_part)
            .as_deref()
            .map(|suffix| suffix.split('.').count());
        let all_labels: Vec<&str> = domain_part.split('.').collect();
        let labels: Vec<&str> = match platform_labels {
            Some(count) if all_labels.len() >= count => {
                all_labels[all_labels.len() - count..].to_vec()
            }
            _ => all_labels,
        };
        let md = crate::module_data::module_data();
        let common_subdomains = md.get_list("common_service_subdomains");
        for label in &labels {
            if label.len() < 5 {
                continue;
            }
            // Skip well-known service subdomain prefixes (fonts, static, cdn, track, etc.)
            if common_subdomains
                .iter()
                .any(|s| s.eq_ignore_ascii_case(label))
            {
                continue;
            }
            // Only check ASCII labels
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                continue;
            }
            let normalized_label = label.to_ascii_lowercase();
            let label_segments: Vec<&str> = normalized_label
                .split('-')
                .filter(|segment| !segment.is_empty())
                .collect();
            if label_segments.len() > 1
                && label_segments
                    .iter()
                    .all(|segment| is_human_readable_label_segment(segment))
            {
                continue;
            }

            let dga_candidates: Vec<&str> = if label_segments.len() > 1 {
                label_segments
            } else {
                vec![normalized_label.as_str()]
            };
            for candidate in dga_candidates {
                let alpha_bytes: Vec<u8> = candidate
                    .bytes()
                    .filter(|b| b.is_ascii_alphabetic())
                    .collect();
                if alpha_bytes.len() < 5 {
                    continue;
                }
                if crate::modules::identity_anomaly::is_human_readable_domain_label(candidate) {
                    continue;
                }
                // A short label that still contains a vowel is an institutional
                // abbreviation (shcpe), not a consonant-run DGA. Vowel-less
                // short labels such as xvkrz stay eligible. Pinyin-initial
                // abbreviations are already excluded above.
                let has_vowel = alpha_bytes.iter().any(|byte| {
                    matches!(byte.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u')
                });
                if alpha_bytes.len() <= 6 && has_vowel {
                    continue;
                }

                let (max_consonant_run, consonant_ratio) = consonant_metrics(&alpha_bytes);
                if max_consonant_run >= 4
                    || (max_consonant_run >= 3 && consonant_ratio > 0.80 && alpha_bytes.len() >= 8)
                {
                    let dga_weight = if structural_trusted { 0.05 } else { 0.30 };
                    add_score!("dga_random_domain", dga_weight);
                    findings.push((
                        format!(
                            "Domain label \"{}\" likely DGA-generated (consecutive consonants={}, consonant ratio={:.0}%)",
                            candidate, max_consonant_run, consonant_ratio * 100.0
                        ),
                        "dga_random_domain".to_string(),
                    ));
                    break; // One DGA finding per URL is sufficient
                }
            }

            if findings
                .iter()
                .any(|(_, category)| category == "dga_random_domain")
            {
                break;
            }
        }
    }

    // 5c. IDN homograph attack detection (Cyrillic/Greek characters in domain)
    // e.g., аpple.com (Cyrillic U+0430) vs apple.com (Latin a U+0061)
    {
        // Stored links are normalized to punycode by the WHATWG parser; decode
        // back to Unicode before script analysis.
        let domain_part = idna::domain_to_unicode(host_for_check).0.to_lowercase();
        // Fullwidth Latin (U+FF21+) counts as Latin script: it is visually
        // identical to ASCII Latin and folds to it under NFKC.
        let has_latin = domain_part
            .chars()
            .any(|c| c.is_ascii_alphabetic() || is_fullwidth_latin(c));
        let has_non_latin_script = domain_part.chars().any(|c| {
            !c.is_ascii() && c.is_alphabetic()
                && !is_fullwidth_latin(c)
                && !('\u{4e00}'..='\u{9fff}').contains(&c) // Exclude CJK (normal in Chinese domains)
                && !('\u{3040}'..='\u{30ff}').contains(&c) // Exclude Japanese kana
                && !('\u{ac00}'..='\u{d7af}').contains(&c) // Exclude Korean
        });
        if has_latin && has_non_latin_script {
            let confusable_suffix = confusable_common_public_suffix(&domain_part);
            add_score!(
                "idn_homograph",
                if confusable_suffix.is_some() {
                    0.65
                } else {
                    0.40
                }
            );
            findings.push((
                if let Some((suffix, skeleton)) = confusable_suffix {
                    format!(
                        "Mixed-script domain uses confusable public suffix '.{suffix}' resembling '.{skeleton}': {domain_part}"
                    )
                } else {
                    format!(
                        "Mixed-script domain (IDN homograph attack): {} — potentially impersonating legitimate domain",
                        domain_part
                    )
                },
                "idn_homograph".to_string(),
            ));
        } else if !domain_part.is_ascii()
            && let Some(brand) = match_idn_skeleton_brand(&domain_part)
        {
            // Pure non-Latin letter-script (e.g. all-Cyrillic "аррӏе.com") and
            // fullwidth-Latin ("ａｐｐｌｅ.com") domains produce no mixed-script
            // signal; flag them only when their homoglyph skeleton matches a
            // known brand domain. CJK-only domains never match - CJK ideographs
            // have no Latin skeleton mapping.
            add_score!("idn_homograph", 0.40);
            findings.push((
                format!(
                    "Non-Latin lookalike domain (IDN homograph attack): {} — homoglyph skeleton matches brand \"{}\"",
                    domain_part, brand
                ),
                "idn_homograph".to_string(),
            ));
        }
    }

    // 6. Multiple redirect parameters
    let redirect_count = url_lower.matches("redirect").count()
        + url_lower.matches("return").count()
        + url_lower.matches("next=").count()
        + url_lower.matches("url=").count();
    if redirect_count >= 2 {
        add_score!("multiple_redirects", 0.20);
        findings.push((
            format!(
                "URL contains multiple redirect parameters ({} occurrences)",
                redirect_count
            ),
            "multiple_redirects".to_string(),
        ));
    }

    // 7. Non-standard port (`Url::port()` is None for scheme-default ports
    // 80/443, so any value returned here is already non-default)
    if !first_party
        && let Some(port) = parsed_url.port()
        && port != 8080
        && port != 8443
    {
        add_score!("unusual_port", 0.15);
        findings.push((
            format!("URL uses non-standard port: {}", port),
            "unusual_port".to_string(),
        ));
    }

    // 8. Fragment (SPA RoadBy) Analyze
    if let Some(frag) = fragment
        && !frag.is_empty()
    {
        // Fragment contains multi-level path (common in SPA-based phishing)
        let frag_depth = frag.matches('/').count();
        if frag_depth >= 2 && !structural_trusted {
            add_score!("deep_fragment_route", 0.10);
            findings.push((
                format!(
                    "URL fragment contains multi-level SPA routing: #{} (depth={})",
                    frag, frag_depth
                ),
                "deep_fragment_route".to_string(),
            ));
        }

        // Suspicious keywords in fragment (decoded so %-encoding cannot hide them)
        let frag_decoded = crate::modules::common::percent_decode(frag).to_lowercase();
        let frag_hits: Vec<String> = crate::matcher::suspicious_path_keywords()
            .scan(&frag_decoded)
            .distinct_patterns();
        if !frag_hits.is_empty() {
            add_score!(
                "suspicious_fragment",
                (frag_hits.len() as f64 * 0.10).min(0.25)
            );
            findings.push((
                format!(
                    "URL fragment contains suspicious keywords: #{} [{}]",
                    frag,
                    frag_hits.join(", ")
                ),
                "suspicious_fragment".to_string(),
            ));
        }

        // Fragment typosquatting is useful on untrusted hosts, but normal
        // first-party SPAs frequently use internal route/component names that
        // are not dictionary words (and may contain harmless spelling drift).
        if !structural_trusted {
            let (typo_score, typo_findings) = detect_typos(frag);
            if typo_score > 0.0 {
                add_score!("url_typo", typo_score);
                findings.extend(typo_findings);
            }
        }
    }

    // 9. Path typosquatting detection (check URL path)
    if !structural_trusted {
        let (path_typo_score, path_typo_findings) = detect_typos(path);
        if path_typo_score > 0.0 {
            add_score!("url_typo", path_typo_score);
            findings.extend(path_typo_findings);
        }
    }

    (score, findings, category_scores)
}

#[async_trait]
impl SecurityModule for LinkContentModule {
    fn metadata(&self) -> &ModuleMetadata {
        &self.meta
    }

    fn should_run(&self, _ctx: &SecurityContext) -> bool {
        true
    }

    async fn analyze(&self, ctx: &SecurityContext) -> Result<ModuleResult, EngineError> {
        let start = Instant::now();
        let links = ctx.analysis_links();

        if links.is_empty() {
            let duration_ms = start.elapsed().as_millis() as u64;
            return Ok(ModuleResult::not_applicable(
                &self.meta.id,
                &self.meta.name,
                self.meta.pillar,
                "No links found in email",
                duration_ms,
            ));
        }

        let mut evidence = Vec::new();
        let mut categories = Vec::new();
        let mut total_score: f64 = 0.0;
        let mut suspicious_urls: Vec<String> = Vec::new();
        let mut seen_link_findings: HashSet<(String, String, String)> = HashSet::new();
        let mut seen_compound_findings: HashSet<(String, String)> = HashSet::new();
        let mut compound_link_observations: Vec<serde_json::Value> = Vec::new();
        let mut qualified_link_compounds: Vec<serde_json::Value> = Vec::new();
        let semantic_projections = semantic_link_projections(ctx);
        let semantic_link_coverage_limited = semantic_projections
            .iter()
            .any(|(_, context)| context.coverage != SemanticCoverageStatus::Complete);
        let mut relational_target_observations: Vec<serde_json::Value> = Vec::new();
        let mut relational_targets_truncated = false;
        // Each category retains its own strength on the effective target.
        // Wrapper and direct views of the same target cannot multiply mass.
        let mut causal_findings: BTreeMap<(String, String), f64> = BTreeMap::new();
        let mut long_url_count = 0usize;
        let email_context = build_email_context(ctx);
        let credential_policy = credential_brand_target_policy();
        #[cfg(not(test))]
        let brand_profiles = credential_policy
            .as_ref()
            .map(|policy| account_action_brand_profiles(&policy.brand_profiles_list))
            .unwrap_or_default();
        #[cfg(test)]
        let brand_profiles = self.brand_profiles_override.clone().unwrap_or_else(|| {
            credential_policy
                .as_ref()
                .map(|policy| account_action_brand_profiles(&policy.brand_profiles_list))
                .unwrap_or_default()
        });
        let sender_domain = from_header_domain(ctx);

        for link in &links {
            let (effective_url, gateway_target_unwrapped) = effective_link_target(&link.url);
            let scoped_action = scoped_link_action(&semantic_projections, link);
            let claimed_brand = scoped_action.and_then(|(_, text)| {
                claimed_brand_profile(
                    &scoped_brand_claim_context(ctx, link, text),
                    &brand_profiles,
                )
            });
            let internal_target = extract_domain_from_url(&effective_url).is_some_and(|domain| {
                let domain = domain.to_ascii_lowercase();
                ctx.internal_domains.iter().any(|configured| {
                    let configured = configured.trim_end_matches('.').to_ascii_lowercase();
                    domain == configured || domain.ends_with(&format!(".{configured}"))
                })
            });
            let link_text_empty = link
                .text
                .as_deref()
                .map(str::trim)
                .is_none_or(str::is_empty);
            if link_text_empty
                && (is_probable_non_clickable_render_asset_url(&effective_url)
                    || is_probable_opaque_mail_callback_url(&effective_url))
                && !has_content_override_params(&effective_url)
            {
                if relational_target_observations.len() < 512
                    && link.url.len() <= 16_384
                    && effective_url.len() <= 16_384
                {
                    relational_target_observations.push(serde_json::json!({
                        "original_url": link.url,
                        "effective_url": effective_url,
                        "anchor_text": serde_json::Value::Null,
                        "risky_target_categories": [],
                        "claimed_brand": serde_json::Value::Null,
                        "from_domain": sender_domain,
                        "target_domain": extract_domain_from_url(&effective_url),
                        "sender_brand_aligned": serde_json::Value::Null,
                        "target_brand_aligned": serde_json::Value::Null,
                        "brand_sender_target_mismatch": serde_json::Value::Null,
                        "observation_complete": true
                    }));
                } else {
                    relational_targets_truncated = true;
                }
                continue;
            }
            if effective_url.len() > 400 {
                long_url_count += 1;
            }

            let (url_score, findings, category_scores) = analyze_url_with_anchor_context_scored(
                &effective_url,
                !link_text_empty,
                internal_target,
            );
            let finding_categories: Vec<String> = findings
                .iter()
                .map(|(_, category)| category.clone())
                .collect();
            for (category, score) in category_scores {
                record_causal_score(&mut causal_findings, &effective_url, &category, score);
            }

            // Independent input contract for relational V2. Keep same-link
            // target facts before legacy CTA/score gates can discard them.
            // The relation path uses the local anchor only; it never borrows
            // a brand claim from another link or from message-level text.
            if relational_target_observations.len() < 512
                && link.url.len() <= 16_384
                && effective_url.len() <= 16_384
                && link.text.as_ref().is_none_or(|text| text.len() <= 8192)
            {
                let local_brand = link
                    .text
                    .as_deref()
                    .and_then(|anchor| claimed_brand_profile(anchor, &brand_profiles));
                let target_domain = extract_domain_from_url(&effective_url);
                let sender_aligned =
                    local_brand
                        .as_ref()
                        .zip(sender_domain.as_deref())
                        .map(|(brand, domain)| {
                            domain_matches_brand_profile(domain, &brand.sender_domains)
                        });
                let target_aligned =
                    local_brand
                        .as_ref()
                        .zip(target_domain.as_deref())
                        .map(|(brand, domain)| {
                            domain_matches_brand_profile(domain, &brand.landing_domains)
                        });
                let mismatch = sender_aligned
                    .zip(target_aligned)
                    .map(|(sender, target)| !sender && !target);
                relational_target_observations.push(serde_json::json!({
                    "original_url": link.url,
                    "effective_url": effective_url,
                    "anchor_text": link.text,
                    "risky_target_categories": finding_categories,
                    "claimed_brand": local_brand.as_ref().map(|brand| &brand.brand),
                    "from_domain": sender_domain,
                    "target_domain": target_domain,
                    "sender_brand_aligned": sender_aligned,
                    "target_brand_aligned": target_aligned,
                    "brand_sender_target_mismatch": mismatch,
                    "observation_complete": true
                }));
            } else {
                relational_targets_truncated = true;
            }

            // A recipient-bound URL is common in campaign metadata, so it is
            // still only an observation on its own.  Promote it here only
            // when the same untrusted target also carries a configured
            // authentication CTA.  This same-link compound is the stable
            // anchor for Safe-Link/gateway lures that were previously
            // diluted to Low after fusion.
            let recipient_bound_target = url_contains_recipient(ctx, &effective_url);
            let risky_target = credential_policy.as_ref().is_some_and(|policy| {
                finding_categories.iter().any(|category| {
                    policy
                        .risky_target_categories
                        .iter()
                        .any(|configured| configured == category)
                })
            });
            let auth_cta = credential_policy.as_ref().and_then(|policy| {
                link.text
                    .as_deref()
                    .filter(|text| !text.trim().is_empty())
                    .and_then(|text| {
                        configured_phrase_match(text, &policy.cta_list).or_else(|| {
                            configured_phrase_match(text, &policy.content_auth_anchor_list)
                        })
                    })
            });
            let external_sender = sender_domain.as_deref().is_none_or(|domain| {
                !ctx.is_internal_domain(domain)
                    && !crate::module_data::module_data().contains("protected_domains", domain)
            });
            if recipient_bound_target
                && risky_target
                && auth_cta.is_some()
                && external_sender
                && let Some((claim, _)) = scoped_action
            {
                let link_key = effective_url.to_ascii_lowercase();
                if seen_compound_findings
                    .insert((link_key, "targeted_credential_phishing".to_string()))
                {
                    total_score += 0.30;
                    categories.push("targeted_credential_phishing".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "targeted_credential_phishing",
                        claim,
                        &link.url,
                        &effective_url,
                        0.30,
                    ));
                    suspicious_urls.push(link.url.clone());
                    evidence.push(Evidence {
                        description: format!(
                            "Recipient-bound untrusted target uses configured authentication CTA '{}', forming a targeted credential-phishing chain",
                            auth_cta.as_deref().unwrap_or("configured CTA")
                        ),
                        location: Some("recipient + link text + effective target".to_string()),
                        snippet: Some(effective_url.clone()),
                    });
                }
            }

            // A public literal-IP auth/action target paired with a recipient
            // CTA is a concrete landing-page signal, not merely the sum of
            // ip_url plus a weak path observation. Keep the condition narrow
            // so a plain operational IP link without an action context stays
            // low-risk.
            if let Some((claim, action_text)) = scoped_action
                && is_ip_action_target(&effective_url, action_text)
            {
                let link_key = effective_url.to_ascii_lowercase();
                if seen_compound_findings.insert((link_key, "ip_action_target".to_string())) {
                    total_score += 0.26;
                    categories.push("ip_action_target".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "ip_action_target",
                        claim,
                        &link.url,
                        &effective_url,
                        0.26,
                    ));
                    suspicious_urls.push(link.url.clone());
                    evidence.push(Evidence {
                        description:
                            "Public literal-IP URL carries an authentication/action path and recipient-facing CTA"
                                .to_string(),
                        location: Some("links + body CTA".to_string()),
                        snippet: Some(effective_url.clone()),
                    });
                }
            }

            // A mail-security gateway is transport context, not trust and not
            // malicious evidence by itself. Preserve a configured low-weight
            // observation for the recovered risky target; clustered policy
            // may arm a floor only when account-action/CTA context also exists.
            if let Some(policy) = credential_policy.as_ref()
                && gateway_target_unwrapped
            {
                let risky_categories: Vec<String> = finding_categories
                    .iter()
                    .filter(|category| {
                        policy
                            .risky_target_categories
                            .iter()
                            .any(|configured| configured == *category)
                    })
                    .cloned()
                    .collect();
                if !risky_categories.is_empty() {
                    let link_key = effective_url.to_ascii_lowercase();
                    if seen_compound_findings
                        .insert((link_key, policy.redirect_target_category.clone()))
                    {
                        total_score += policy.redirect_target_score;
                        categories.push(policy.redirect_target_category.clone());
                        record_causal_score(
                            &mut causal_findings,
                            &effective_url,
                            &policy.redirect_target_category,
                            policy.redirect_target_score,
                        );
                        suspicious_urls.push(link.url.clone());
                        evidence.push(Evidence {
                            description: format!(
                                "Mail-security gateway target was unwrapped and contains structural risk evidence: {}",
                                risky_categories.join(", ")
                            ),
                            location: Some("gateway wrapper + effective target".to_string()),
                            snippet: Some(effective_url.clone()),
                        });
                    }
                    compound_link_observations.push(serde_json::json!({
                        "original_url": link.url.clone(),
                        "effective_url": effective_url.clone(),
                        "gateway_unwrapped": true,
                        "anchor_text": link.text.as_deref(),
                        "matched_cta_phrase": serde_json::Value::Null,
                        "risky_target_categories": risky_categories,
                        "compound_signal": policy.redirect_target_category,
                    }));
                }
            }

            if let Some(policy) = credential_policy.as_ref()
                && let Some(anchor_text) =
                    link.text.as_deref().filter(|text| !text.trim().is_empty())
                && let Some(cta_phrase) = configured_phrase_match(anchor_text, &policy.cta_list)
                && let Some((claim, _)) = scoped_action
            {
                let risky_categories: Vec<String> = finding_categories
                    .iter()
                    .filter(|category| {
                        policy
                            .risky_target_categories
                            .iter()
                            .any(|configured| configured == *category)
                    })
                    .cloned()
                    .collect();
                if !risky_categories.is_empty() {
                    let target_domain = extract_domain_from_url(&effective_url)
                        .map(|domain| domain.to_ascii_lowercase());
                    let link_key = effective_url.to_ascii_lowercase();
                    if seen_compound_findings
                        .insert((link_key.clone(), policy.credential_link_category.clone()))
                    {
                        total_score += policy.cta_target_score;
                        categories.push(policy.credential_link_category.clone());
                        categories.push(policy.high_risk_target_category.clone());
                        qualified_link_compounds.push(qualified_link_record(
                            &semantic_projections,
                            &policy.credential_link_category,
                            claim,
                            &link.url,
                            &effective_url,
                            policy.cta_target_score,
                        ));
                        qualified_link_compounds.push(qualified_link_record(
                            &semantic_projections,
                            &policy.high_risk_target_category,
                            claim,
                            &link.url,
                            &effective_url,
                            policy.cta_target_score,
                        ));
                        suspicious_urls.push(link.url.clone());
                        evidence.push(Evidence {
                            description: format!(
                                "Configured account-action CTA '{}' points to {}target with structural risk evidence: {}",
                                cta_phrase,
                                if gateway_target_unwrapped { "a gateway-unwrapped " } else { "an effective " },
                                risky_categories.join(", ")
                            ),
                            location: Some("link text + effective target".to_string()),
                            snippet: Some(effective_url.clone()),
                        });
                    }

                    let mut brand_mismatch = false;
                    let mut sender_brand_aligned = None;
                    let mut target_brand_aligned = None;
                    if let (Some(profile), Some(sender), Some(target)) = (
                        claimed_brand.as_ref(),
                        sender_domain.as_deref(),
                        target_domain.as_deref(),
                    ) {
                        let sender_aligned =
                            domain_matches_brand_profile(sender, &profile.sender_domains);
                        let target_aligned =
                            domain_matches_brand_profile(target, &profile.landing_domains);
                        sender_brand_aligned = Some(sender_aligned);
                        target_brand_aligned = Some(target_aligned);
                        if !sender_aligned
                            && !target_aligned
                            && seen_compound_findings
                                .insert((link_key, policy.brand_mismatch_category.clone()))
                        {
                            brand_mismatch = true;
                            total_score += policy.brand_mismatch_score;
                            categories.push(policy.brand_mismatch_category.clone());
                            let mut relation_record = qualified_link_record(
                                &semantic_projections,
                                &policy.brand_mismatch_category,
                                claim,
                                &link.url,
                                &effective_url,
                                policy.brand_mismatch_score,
                            );
                            relation_record["brand_proof"] = serde_json::json!({
                                "claimed_brand": profile.brand,
                                "from_domain": sender,
                                "target_domain": target,
                                "sender_brand_aligned": false,
                                "target_brand_aligned": false
                            });
                            qualified_link_compounds.push(relation_record);
                            evidence.push(Evidence {
                                description: format!(
                                    "Claimed brand '{}' is unaligned with both From domain '{}' and effective landing domain '{}'",
                                    profile.brand, sender, target
                                ),
                                location: Some("brand + From + effective target".to_string()),
                                snippet: Some(effective_url.clone()),
                            });
                        }
                    }

                    compound_link_observations.push(serde_json::json!({
                        "original_url": link.url.clone(),
                        "effective_url": effective_url.clone(),
                        "gateway_unwrapped": gateway_target_unwrapped,
                        "anchor_text": anchor_text,
                        "matched_cta_phrase": cta_phrase,
                        "risky_target_categories": risky_categories,
                        "claimed_brand": claimed_brand.as_ref().map(|profile| profile.brand.as_str()),
                        "from_domain": sender_domain.as_deref(),
                        "target_domain": target_domain.as_deref(),
                        "sender_brand_aligned": sender_brand_aligned,
                        "target_brand_aligned": target_brand_aligned,
                        "brand_sender_target_mismatch": brand_mismatch,
                    }));
                }
            }
            if url_score > 0.0 && !findings.is_empty() {
                let source_domain = extract_domain_from_url(&effective_url)
                    .unwrap_or_else(|| "<unparseable>".to_string());
                let finding_count = findings.len();
                let fresh_findings: Vec<(String, String)> = findings
                    .into_iter()
                    .filter(|(description, category)| {
                        seen_link_findings.insert((
                            source_domain.clone(),
                            category.clone(),
                            description.clone(),
                        ))
                    })
                    .collect();
                if fresh_findings.is_empty() {
                    continue;
                }
                total_score += url_score * (fresh_findings.len() as f64 / finding_count as f64);
                suspicious_urls.push(link.url.clone());
                for (desc, category) in fresh_findings {
                    categories.push(category);
                    evidence.push(Evidence {
                        description: desc,
                        location: Some("links".to_string()),
                        snippet: Some(if link.url.len() > 120 {
                            // UTF-8 safe truncation: never split a multi-byte character
                            format!("{}...", link.url.get(..120).unwrap_or(&link.url))
                        } else {
                            link.url.clone()
                        }),
                    });
                }
            }
        }

        // Additional phishing URL pattern detection

        // 10. Recipient email embedded in URL (targeted phishing)
        // e.g., phishing link contains the recipient's email address as a parameter
        for link in &links {
            let effective_url =
                crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                    .unwrap_or_else(|| link.url.clone());
            let effective_url_lower = effective_url.to_lowercase();
            if is_recipient_metadata_url(&effective_url_lower) {
                continue;
            }
            let link_domain = extract_domain_from_url(&effective_url_lower);
            let is_trusted = link_domain
                .as_ref()
                .is_some_and(|d| crate::modules::link_scan::is_trusted_url_domain(d));
            if is_trusted
                && !link_domain
                    .as_deref()
                    .is_some_and(crate::modules::link_scan::is_shared_hosting_platform)
            {
                continue;
            }
            let has_recipient = ctx.session.rcpt_to.iter().any(|rcpt| {
                let rcpt_lower = rcpt.to_lowercase();
                let decoded_url = crate::modules::common::percent_decode(&effective_url_lower);
                if decoded_url.contains(&rcpt_lower)
                    || decoded_url.contains(&rcpt_lower.replace('@', "%40"))
                {
                    return true;
                }

                // Targeted campaigns increasingly embed a digest rather than
                // the clear-text mailbox.  Check both common cryptographic
                // encodings against the URL after percent decoding.
                let sha1_hex = hex_digest::<Sha1>(&rcpt_lower);
                let sha256_hex = hex_digest::<Sha256>(&rcpt_lower);
                decoded_url.contains(&sha1_hex) || decoded_url.contains(&sha256_hex)
            });
            if has_recipient {
                total_score += 0.40;
                categories.push("recipient_in_url".to_string());
                record_causal_score(
                    &mut causal_findings,
                    &effective_url,
                    "recipient_in_url",
                    0.40,
                );
                evidence.push(Evidence {
                    description: "URL contains recipient email or a SHA-1/SHA-256 mailbox digest (targeted credential phishing)".to_string(),
                    location: Some("links".to_string()),
                    snippet: Some(if effective_url.len() > 120 {
                        // UTF-8 safe truncation: never split a multi-byte character
                        format!("{}...", effective_url.get(..120).unwrap_or(&effective_url))
                    } else {
                        effective_url
                    }),
                });

                // Admitted targeting evidence requires Medium review. Known
                // preference/metadata and trusted destinations were excluded
                // above. Only add a credential-phishing compound when the
                // same message also asks the recipient to
                // continue an account-authentication flow and the destination
                // is outside configured/internal sender trust.  This is the
                // named compound needed for targeted credential lures whose
                // URL has no login-looking path or @-obfuscation.
                let sender_is_external = sender_domain.as_deref().is_none_or(|domain| {
                    !ctx.is_internal_domain(domain)
                        && !crate::module_data::module_data().contains("protected_domains", domain)
                });
                if sender_is_external
                    && let Some((claim, action_text)) =
                        scoped_link_action(&semantic_projections, link)
                    && has_credential_continuation_context(action_text)
                    && seen_compound_findings.insert((
                        effective_url_lower.clone(),
                        "targeted_credential_phishing".to_string(),
                    ))
                {
                    total_score += 0.30;
                    categories.push("targeted_credential_phishing".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "targeted_credential_phishing",
                        claim,
                        &link.url,
                        &effective_url_lower,
                        0.30,
                    ));
                    evidence.push(Evidence {
                        description:
                            "External message combines an account-authentication instruction with a recipient-specific untrusted URL"
                                .to_string(),
                        location: Some("body + links".to_string()),
                        snippet: None,
                    });
                }
                // Continue: an unrelated recipient token must not prevent a
                // later, independently bound attack link from being checked.
            }
        }

        // 10b. @ obfuscation + recipient email compound signal
        // If the same email has both URL @ sign obfuscation and embedded recipient address,
        // this is a strong credential phishing indicator (e.g., spoofed Apple ID attack pattern)
        {
            for link in &links {
                let (effective_url, _) = effective_link_target(&link.url);
                let (_, findings) = analyze_url(&effective_url);
                if findings
                    .iter()
                    .any(|(_, category)| category == "at_sign_obfuscation")
                    && url_contains_recipient(ctx, &effective_url)
                    && let Some((claim, _)) = scoped_link_action(&semantic_projections, link)
                    && seen_compound_findings.insert((
                        effective_url.to_ascii_lowercase(),
                        "targeted_credential_phishing".to_string(),
                    ))
                {
                    total_score += 0.30;
                    categories.push("targeted_credential_phishing".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "targeted_credential_phishing",
                        claim,
                        &link.url,
                        &effective_url,
                        0.30,
                    ));
                    evidence.push(Evidence {
                    description:
                        "URL combines @ sign obfuscation + embedded recipient email — high-confidence targeted credential theft"
                            .to_string(),
                    location: Some("links".to_string()),
                    snippet: None,
                });
                }
            }
        }

        // 11. Organization domain mimicry in URL subdomain
        {
            let org_domains: &[&str] = &["corp-internal.com"];
            for link in &links {
                let effective_url =
                    crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if is_probable_opaque_mail_callback_url(&effective_url) {
                    continue;
                }
                if let Ok(parsed) = url::Url::parse(&effective_url)
                    && let Some(host) = parsed.host_str()
                {
                    let host_lower = host.to_lowercase();
                    for org in org_domains {
                        let org_name = org.split('.').next().unwrap_or(org);
                        if host_lower.contains(org_name) && !host_lower.ends_with(org) {
                            total_score += 0.30;
                            categories.push("org_domain_mimicry".to_string());
                            record_causal_score(
                                &mut causal_findings,
                                &effective_url,
                                "org_domain_mimicry",
                                0.30,
                            );
                            evidence.push(Evidence {
                                description: format!(
                                    "URL subdomain mimics organization domain '{}': {}",
                                    org, host
                                ),
                                location: Some("links".to_string()),
                                snippet: Some(effective_url.clone()),
                            });
                        }
                    }
                }
            }
        }

        // 12. Long random hex in subdomain (DGA indicator)
        {
            for link in &links {
                let effective_url =
                    crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if is_probable_opaque_mail_callback_url(&effective_url) {
                    continue;
                }
                if let Ok(parsed) = url::Url::parse(&effective_url)
                    && let Some(host) = parsed.host_str()
                {
                    // A subdomain requires an actual registrable-domain label
                    // below it. Treating the first label of a two-label host
                    // (`20260101010203.pdf`) as a "subdomain" turns an
                    // attachment filename promoted by an upstream parser into
                    // DGA evidence. Other URL heuristics still inspect the
                    // apex host, while this specifically named signal only
                    // applies to hosts with at least three labels.
                    let labels: Vec<&str> = host
                        .trim_end_matches('.')
                        .split('.')
                        .filter(|label| !label.is_empty())
                        .collect();
                    let first_label = labels.first().copied().unwrap_or("");
                    if labels.len() >= 3 && RE_HEX_DGA.is_match(first_label) {
                        total_score += 0.15;
                        categories.push("hex_subdomain".to_string());
                        record_causal_score(
                            &mut causal_findings,
                            &effective_url,
                            "hex_subdomain",
                            0.15,
                        );
                        evidence.push(Evidence {
                            description: format!(
                                "URL subdomain contains long random hex string (DGA indicator): {}",
                                host
                            ),
                            location: Some("links".to_string()),
                            snippet: Some(effective_url),
                        });
                        break;
                    }
                }
            }
        }

        // The manually copied destination must belong to this current request.
        for link in &links {
            let Some((claim, text)) = scoped_link_action(&semantic_projections, link) else {
                continue;
            };
            if ["复制地址到", "复制链接到", "手机浏览器", "手机查看"]
                .iter()
                .any(|phrase| text.contains(phrase))
            {
                total_score += 0.20;
                categories.push("mobile_redirect".to_string());
                qualified_link_compounds.push(qualified_link_record(
                    &semantic_projections,
                    "mobile_redirect",
                    claim,
                    &link.url,
                    &effective_link_target(&link.url).0,
                    0.20,
                ));
                evidence.push(Evidence {
                    description: "Current request asks the recipient to copy its destination into a mobile browser".to_string(),
                    location: Some("body".to_string()), snippet: Some(link.url.clone()),
                });
                break;
            }
        }

        let keyword_context = has_keyword_context(&email_context, &self.phishing_keywords);
        let qr_lure_context = has_qr_lure_context(&email_context);

        if keyword_context {
            for link in &links {
                let Some((claim, action_text)) = scoped_link_action(&semantic_projections, link)
                else {
                    continue;
                };
                if !has_keyword_context(action_text, &self.phishing_keywords) {
                    continue;
                }
                let effective_url =
                    crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
                let effective_lower = effective_url.to_lowercase();
                let link_domain = extract_domain_from_url(&effective_lower);

                if url_looks_like_device_code_flow(&effective_lower) {
                    total_score += 0.40;
                    categories.push("device_code_phishing".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "device_code_phishing",
                        claim,
                        &link.url,
                        &effective_url,
                        0.40,
                    ));
                    evidence.push(Evidence {
                        description:
                            "Email uses a device-code lure and links to a device-login workflow"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }

                if link_domain
                    .as_deref()
                    .is_some_and(domain_matches_official_login_suffix)
                    && url_looks_like_oauth_flow(&effective_lower)
                {
                    total_score += 0.25;
                    categories.push("oauth_device_flow".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "oauth_device_flow",
                        claim,
                        &link.url,
                        &effective_url,
                        0.25,
                    ));
                    evidence.push(Evidence {
                        description:
                            "Email pairs a device-code lure with an OAuth authorization URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }
            }
        }

        if qr_lure_context {
            for link in &links {
                let effective_url =
                    crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                let Some((claim, action_text)) = scoped_link_action(&semantic_projections, link)
                    .or_else(|| scoped_qr_action(ctx, &semantic_projections, &effective_url))
                else {
                    continue;
                };
                if !has_qr_lure_context(&action_text.to_lowercase()) {
                    continue;
                }
                if is_probable_schema_reference_url(&effective_url) {
                    continue;
                }
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
                let effective_lower = effective_url.to_lowercase();
                // Decode one percent-encoding layer so obfuscated login/oauth
                // URLs cannot slip past the structure checks.
                let effective_decoded =
                    crate::modules::common::percent_decode(&effective_lower).to_lowercase();
                let login_or_auth_target =
                    contains_any_suspicious_path_keywords(&effective_decoded)
                        || url_looks_like_oauth_flow(&effective_decoded)
                        || url_looks_like_device_code_flow(&effective_decoded);
                if login_or_auth_target {
                    total_score += 0.20;
                    categories.push("qr_to_login_chain".to_string());
                    let mut qr_record = qualified_link_record(
                        &semantic_projections,
                        "qr_to_login_chain",
                        claim,
                        &link.url,
                        &effective_url,
                        0.20,
                    );
                    if ctx
                        .decoded_qr_urls()
                        .iter()
                        .any(|url| url == &effective_url)
                    {
                        qr_record["link_extraction_source"] = serde_json::json!("qr");
                    }
                    qualified_link_compounds.push(qr_record);
                    if url_contains_recipient(ctx, &effective_url)
                        && sender_domain.as_deref().is_some_and(|domain| {
                            !ctx.is_internal_domain(domain)
                                && !crate::module_data::module_data()
                                    .contains("protected_domains", domain)
                        })
                        && seen_compound_findings.insert((
                            effective_url.to_ascii_lowercase(),
                            "targeted_credential_phishing".to_string(),
                        ))
                    {
                        total_score += 0.30;
                        categories.push("targeted_credential_phishing".to_string());
                        let mut targeted_record = qualified_link_record(
                            &semantic_projections,
                            "targeted_credential_phishing",
                            claim,
                            &link.url,
                            &effective_url,
                            0.30,
                        );
                        if ctx
                            .decoded_qr_urls()
                            .iter()
                            .any(|url| url == &effective_url)
                        {
                            targeted_record["link_extraction_source"] = serde_json::json!("qr");
                        }
                        qualified_link_compounds.push(targeted_record);
                    }
                    evidence.push(Evidence {
                        description:
                            "Email contains a QR lure and a follow-on login / authorization URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url.clone()),
                    });
                    let decoded_from_qr = ctx
                        .decoded_qr_urls()
                        .iter()
                        .any(|decoded| decoded.eq_ignore_ascii_case(&effective_url));
                    if decoded_from_qr
                        && crate::modules::link_scan::url_host_is_ip(&effective_decoded)
                    {
                        // QR + explicit scan instruction + IP-literal login
                        // target is a named phishing chain, not a generic QR
                        // observation. Keep the promotion local to this
                        // compound so ordinary QR/login links stay unchanged.
                        total_score += 0.32;
                        categories.push("qr_ip_login_chain".to_string());
                        let mut qr_record = qualified_link_record(
                            &semantic_projections,
                            "qr_ip_login_chain",
                            claim,
                            &link.url,
                            &effective_url,
                            0.32,
                        );
                        qr_record["link_extraction_source"] = serde_json::json!("qr");
                        qualified_link_compounds.push(qr_record);
                        evidence.push(Evidence {
                            description:
                                "QR scan lure resolves to a non-domain IP-literal login target"
                                    .to_string(),
                            location: Some("links:qr_compound".to_string()),
                            snippet: Some(effective_url),
                        });
                    }
                    break;
                }
            }
        }

        if keyword_context {
            for link in &links {
                let Some((claim, action_text)) = scoped_link_action(&semantic_projections, link)
                else {
                    continue;
                };
                if !has_keyword_context(action_text, &self.phishing_keywords) {
                    continue;
                }
                let effective_url =
                    crate::modules::link_scan::unwrap_redirect_target_for_analysis(&link.url)
                        .unwrap_or_else(|| link.url.clone());
                if crate::modules::link_scan::is_known_safe_tokenized_resource_url(&effective_url) {
                    continue;
                }
                let effective_lower = effective_url.to_lowercase();
                // Decode one percent-encoding layer so obfuscated barrier/login
                // URLs cannot slip past the structure checks.
                let effective_decoded =
                    crate::modules::common::percent_decode(&effective_lower).to_lowercase();
                if url_looks_like_auth_barrier(&effective_decoded)
                    && (contains_any_suspicious_path_keywords(&effective_decoded)
                        || url_looks_like_oauth_flow(&effective_decoded)
                        || url_looks_like_device_code_flow(&effective_decoded))
                {
                    total_score += 0.18;
                    categories.push("auth_barrier_url".to_string());
                    qualified_link_compounds.push(qualified_link_record(
                        &semantic_projections,
                        "auth_barrier_url",
                        claim,
                        &link.url,
                        &effective_url,
                        0.18,
                    ));
                    evidence.push(Evidence {
                        description:
                            "Login-themed email routes through a CAPTCHA / auth-barrier URL"
                                .to_string(),
                        location: Some("links".to_string()),
                        snippet: Some(effective_url),
                    });
                    break;
                }
            }
        }

        total_score = total_score.min(1.0);
        categories.sort();
        categories.dedup();
        suspicious_urls.sort();
        suspicious_urls.dedup();

        for record in &qualified_link_compounds {
            if let (Some(url), Some(category), Some(score)) = (
                record["effective_url"].as_str(),
                record["category"].as_str(),
                record["score"].as_f64(),
            ) {
                record_causal_score(&mut causal_findings, url, category, score);
            }
        }
        let causal_findings: Vec<serde_json::Value> = causal_findings
            .into_iter()
            .map(|((causal_key, category), score)| {
                serde_json::json!({
                    "causal_key": causal_key,
                    "categories": [category],
                    "score": score,
                    "confidence": 0.75,
                })
            })
            .collect();

        let duration_ms = start.elapsed().as_millis() as u64;
        let threat_level = ThreatLevel::from_score(total_score);
        // Preserve weak URL observations before the legacy Safe return clears
        // categories/evidence. Relational V2 reads this as telemetry only.
        let observation_snapshot = vigilyx_core::security::relational::ObservationSnapshot::capture(
            &categories,
            evidence.len(),
        );

        if threat_level == ThreatLevel::Safe {
            let mut result = ModuleResult {
                module_id: self.meta.id.clone(),
                module_name: self.meta.name.clone(),
                pillar: self.meta.pillar,
                threat_level: ThreatLevel::Safe,
                confidence: 0.85,
                categories: vec![],
                summary: format!(
                    "Analyzed {} links, no suspicious content found",
                    links.len()
                ),
                evidence: vec![],
                details: serde_json::json!({
                    "score": 0.0,
                    "observation_snapshot": observation_snapshot,
                    "total_links": links.len(),
                    "qr_decoded_links": ctx.decoded_qr_urls().len(),
                    "diagnostic_observations": {
                        "long_url_count": long_url_count,
                        "long_url_threshold": 400,
                    },
                    "credential_target_observations": compound_link_observations,
                    "relational_target_observations": relational_target_observations,
                    "relational_targets_truncated": relational_targets_truncated,
                    "evidence_items_version": 1,
                    "causal_findings": causal_findings,
                    "qualified_link_compounds": qualified_link_compounds,
                    "semantic_link_contexts": semantic_projections.iter().map(|(_, context)| context).collect::<Vec<_>>(),
                }),
                duration_ms,
                analyzed_at: Utc::now(),
                bpa: Some(Bpa::safe_analyzed()),
                engine_id: None,
            };
            attach_semantic_link_coverage(&mut result, semantic_link_coverage_limited);
            return Ok(result);
        }

        let mut result = ModuleResult {
            module_id: self.meta.id.clone(),
            module_name: self.meta.name.clone(),
            pillar: self.meta.pillar,
            threat_level,
            confidence: 0.75,
            categories,
            summary: format!(
                "URL content analysis found {} anomalies across {} suspicious URLs",
                evidence.len(),
                suspicious_urls.len()
            ),
            evidence,
            details: serde_json::json!({
                "score": total_score,
                "observation_snapshot": observation_snapshot,
                "suspicious_urls": suspicious_urls,
                "total_links": links.len(),
                "qr_decoded_links": ctx.decoded_qr_urls().len(),
                "diagnostic_observations": {
                    "long_url_count": long_url_count,
                    "long_url_threshold": 400,
                },
                "credential_target_observations": compound_link_observations,
                "relational_target_observations": relational_target_observations,
                "relational_targets_truncated": relational_targets_truncated,
                "evidence_items_version": 1,
                "causal_findings": causal_findings,
                "qualified_link_compounds": qualified_link_compounds,
                "semantic_link_contexts": semantic_projections.iter().map(|(_, context)| context).collect::<Vec<_>>(),
            }),
            duration_ms,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        };
        attach_semantic_link_coverage(&mut result, semantic_link_coverage_limited);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use vigilyx_core::models::{EmailContent, EmailLink, EmailSession, Protocol};

    fn analyze_with_runtime(module: &LinkContentModule, ctx: &SecurityContext) -> ModuleResult {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(module.analyze(ctx))
            .unwrap()
    }

    fn reset_url_domain_sets() {
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::new()));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));
    }

    fn make_ctx_with_body(
        link: &str,
        body_text: Option<&str>,
        subject: Option<&str>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = subject.map(str::to_string);
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            is_complete: true,
            body_text: body_text.map(|body| {
                // The fixture must retain the target in the original body;
                // detached parser links cannot prove a recipient instruction.
                let boundary = body
                    .char_indices()
                    .find_map(|(offset, ch)| {
                        matches!(ch, '。' | '，' | '.' | '!' | '?').then_some(offset)
                    })
                    .unwrap_or(body.len());
                format!("{} {link}{}", &body[..boundary], &body[boundary..])
            }),
            links: vec![EmailLink {
                url: link.to_string(),
                text: None,
                suspicious: false,
            }],
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_ctx(link: &str) -> SecurityContext {
        make_ctx_with_body(link, None, None)
    }

    fn make_projection_ctx(
        link: &str,
        body_text: Option<&str>,
        body_html: Option<&str>,
    ) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            25_000,
            "198.51.100.10".to_string(),
            25,
        );
        session.rcpt_to.push("recipient@example.com".to_string());
        session.content = EmailContent {
            is_complete: true,
            body_text: body_text.map(str::to_string),
            body_html: body_html.map(str::to_string),
            links: vec![EmailLink {
                url: link.to_string(),
                text: None,
                suspicious: false,
            }],
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    #[test]
    fn plain_projection_truncation_preserves_native_prefix_and_marks_coverage() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = "https://evil.example/login";
        let short = format!("Please verify your account at {url}.\n");
        let long = format!(
            "{short}{}Tail omitted from inspection.",
            " ".repeat(512 * 1024)
        );
        for (body, limited) in [(&short, false), (&long, true)] {
            let ctx = make_projection_ctx(url, Some(body), None);
            let projections = semantic_link_projections(&ctx);
            assert!(
                scoped_link_action(&projections, &ctx.session.content.links[0]).is_some(),
                "the inspected native prefix must retain admission"
            );
            assert_eq!(
                projections[0].1.coverage != SemanticCoverageStatus::Complete,
                limited
            );
            if limited {
                assert!(
                    projections[0]
                        .1
                        .coverage_reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("source bytes"))
                );
            }
            let result = analyze_with_runtime(&LinkContentModule::new(), &ctx);
            assert_eq!(
                result
                    .categories
                    .contains(&"inspection_coverage_incomplete".to_string()),
                limited,
                "{result:?}"
            );
            if limited {
                assert_eq!(result.details["semantic_link_coverage_limited"], true);
            }
        }
    }

    #[test]
    fn qualified_link_record_preserves_observed_extraction_source() {
        let url = "https://evil.example/login";
        let plain = format!("Please verify your account at {url}.");
        let href =
            format!("<p>Please verify your account at <a href=\"{url}\">this portal</a>.</p>");
        let html_text = format!("<p>Please verify your account at {url}.</p>");
        for (ctx, source) in [
            (make_projection_ctx(url, Some(&plain), None), "plain_text"),
            (make_projection_ctx(url, None, Some(&href)), "href"),
            (
                make_projection_ctx(url, None, Some(&html_text)),
                "html_text",
            ),
        ] {
            let projections = semantic_link_projections(&ctx);
            let (claim, _) = scoped_link_action(&projections, &ctx.session.content.links[0])
                .expect("each visible current action must bind its actual target");
            let record = qualified_link_record(
                &projections,
                "targeted_credential_phishing",
                claim,
                url,
                url,
                0.30,
            );
            assert_eq!(record["link_extraction_source"], source);
            let mut detached = claim.clone();
            detached.link_ids.clear();
            let unknown = qualified_link_record(
                &projections,
                "targeted_credential_phishing",
                &detached,
                url,
                url,
                0.30,
            );
            assert_eq!(
                unknown["link_extraction_source"], "unknown",
                "source-part identity cannot manufacture extraction provenance"
            );
        }
    }

    #[test]
    fn qualified_form_action_source_requires_current_bound_submit() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = "https://evil.example/login";
        let current =
            format!("<form action='{url}'><button>Please verify your account</button></form>");
        let detached = format!(
            "<p>Please verify your account.</p><form action='{url}'><button>Release notes</button></form>"
        );
        let quoted = format!(
            "<blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div>{current}</blockquote>"
        );
        let bare_quote = format!("<blockquote>{current}</blockquote>");
        for (html, verified_thread, admissible) in [
            (&current, false, true),
            (&detached, false, false),
            (&quoted, true, false),
            (&bare_quote, true, true),
            (&bare_quote, false, true),
        ] {
            let mut ctx = make_projection_ctx(url, None, Some(html));
            let content = &mut Arc::get_mut(&mut ctx.session).unwrap().content;
            if verified_thread {
                // Model a corroborated reply for the quote control. A bare
                // blockquote is still original content even when a reply
                // header is present; the body needs a real reply attribution.
                content.headers.push((
                    "In-Reply-To".into(),
                    "<original-form-request@example.invalid>".into(),
                ));
            }
            content.links.clear();
            content.extract_links_from_html();
            let target = ctx
                .session
                .content
                .links
                .iter()
                .find(|link| link.url == url)
                .expect("the real form action must be retained by the parser");
            let projections = semantic_link_projections(&ctx);
            let action = scoped_link_action(&projections, target);
            assert_eq!(
                action.is_some(),
                admissible,
                "form attribution must use thread evidence={verified_thread}: {projections:?}"
            );
            if let Some((claim, _)) = action {
                let record = qualified_link_record(
                    &projections,
                    "targeted_credential_phishing",
                    claim,
                    url,
                    url,
                    0.30,
                );
                assert_eq!(record["link_extraction_source"], "form_action");
                assert_eq!(record["original_url"], url);
                assert_eq!(record["claim"]["source_part"], "html");
            } else {
                let result = analyze_with_runtime(&LinkContentModule::new(), &ctx);
                assert!(
                    result.details["qualified_link_compounds"]
                        .as_array()
                        .is_none_or(|records| records.is_empty()),
                    "detached and quoted forms must stay unqualified: {result:?}"
                );
            }
        }
    }

    fn make_credential_chain_ctx(links: Vec<(&str, &str)>, from_header: &str) -> SecurityContext {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            2525,
            "192.0.2.20".to_string(),
            25,
        );
        session.subject = Some("Fixture Identity account security review".to_string());
        session.mail_from = Some("notice@sender.invalid".to_string());
        session.rcpt_to.push("recipient@example.com".to_string());
        session.content = EmailContent {
            is_complete: true,
            headers: vec![("From".to_string(), from_header.to_string())],
            body_text: Some(
                "A new device was detected. Review the account security activity.".to_string(),
            ),
            body_html: Some(
                links
                    .iter()
                    .map(|(url, text)| format!("<p><a href=\"{url}\">{text}</a></p>"))
                    .collect::<String>(),
            ),
            links: links
                .into_iter()
                .map(|(url, text)| EmailLink {
                    url: url.to_string(),
                    text: Some(text.to_string()),
                    suspicious: false,
                })
                .collect(),
            ..Default::default()
        };
        SecurityContext::new(Arc::new(session))
    }

    fn make_credential_test_module() -> LinkContentModule {
        LinkContentModule::new().with_test_brand_profiles(vec![AccountActionBrandProfile {
            brand: "fixture_identity".to_string(),
            aliases: vec!["fixture identity".to_string(), "fixtureid".to_string()],
            sender_domains: vec!["identity.example".to_string()],
            landing_domains: vec!["identity.example".to_string()],
        }])
    }

    #[test]
    fn weak_url_observation_survives_without_legacy_score_inflation() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx("https://portal.vendor.invalid/#one/two/three"),
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            result.categories.is_empty(),
            "legacy categories remain empty: {result:?}"
        );
        assert_eq!(result.details["score"], serde_json::json!(0.0));
        assert!(
            result.details["observation_snapshot"]["categories"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "deep_fragment_route")
        );
    }

    fn make_module_with_keywords(keywords: &[&str]) -> LinkContentModule {
        LinkContentModule::new_with_keyword_lists(EffectiveKeywordLists {
            phishing_keywords: keywords
                .iter()
                .map(|keyword| normalize_text(keyword))
                .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn test_gateway_target_url_is_used_for_recipient_matching() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin%3Fuser%3Dvictim%40example.com",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(result.categories.contains(&"recipient_in_url".to_string()));
    }

    #[test]
    fn trusted_recipient_url_does_not_enter_medium_review() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "trusted.vendor.example".to_string(),
        ])));
        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx("https://trusted.vendor.example/?member=victim%40example.com"),
        );
        reset_url_domain_sets();
        assert!(!result.categories.contains(&"recipient_in_url".to_string()));
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_preference_url_recipient_digest_is_marketing_metadata() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let digest = hex_digest::<Sha256>("victim@example.com");
        let url = format!(
            "https://preferences.vendor.example/set-user-preferences?hea={digest}&elq=campaign"
        );

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));

        assert!(
            !result.categories.contains(&"recipient_in_url".to_string()),
            "preference metadata must not become credential evidence: {:?}",
            result.categories
        );
        assert!(result.threat_level < ThreatLevel::Medium);
    }

    #[test]
    fn test_login_url_recipient_digest_remains_targeting_evidence() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let digest = hex_digest::<Sha256>("victim@example.com");
        let url = format!("https://evil.example/login?hea={digest}");

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));

        assert!(
            result.categories.contains(&"recipient_in_url".to_string()),
            "recipient digest on a login endpoint must remain targeting evidence: {:?}",
            result.categories
        );
    }

    #[test]
    fn recipient_account_instruction_promotes_targeted_credential_compound() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx_with_body(
                "https://evil.example/?token=victim%40example.com",
                Some("请验证账户为本人使用，未验证账户将被禁用。"),
                Some("账户验证"),
            ),
        );

        assert!(result.categories.contains(&"recipient_in_url".to_string()));
        assert!(
            result
                .categories
                .contains(&"targeted_credential_phishing".to_string()),
            "account instruction plus recipient-specific untrusted URL must be actionable: {:?}",
            result.categories
        );
    }

    #[test]
    fn gateway_recipient_cta_is_targeted_credential_compound() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            2525,
            "192.0.2.20".to_string(),
            25,
        );
        session.mail_from = Some("notice@external.example".to_string());
        session.rcpt_to.push("victim@example.com".to_string());
        session.subject = Some("安全状态确认".to_string());
        session.content = EmailContent {
            is_complete: true,
            body_text: Some("请前往安全认证完成账号确认。".to_string()),
            body_html: Some("<p>请<a href=\"https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fkvzlbpt.aveonph.com%2F%3Fm%3Dvictim%2540example.com\">前往安全认证</a>完成账号确认。</p>".to_string()),
            links: vec![EmailLink {
                url: "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fkvzlbpt.aveonph.com%2F%3Fm%3Dvictim%2540example.com".to_string(),
                text: Some("前往安全认证".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );

        assert!(
            result
                .categories
                .contains(&"targeted_credential_phishing".to_string()),
            "gateway + recipient + authentication CTA must be actionable: {result:?}"
        );
    }

    #[test]
    fn recipient_token_without_account_instruction_requires_medium_review_only() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx_with_body(
                "https://evil.example/?token=victim%40example.com",
                Some("Read the latest compliance newsletter."),
                Some("August newsletter"),
            ),
        );

        assert!(result.categories.contains(&"recipient_in_url".to_string()));
        assert_eq!(result.threat_level, ThreatLevel::Medium);
        assert!(
            !result
                .categories
                .contains(&"targeted_credential_phishing".to_string()),
            "targeting alone must not fabricate a credential-phishing compound: {:?}",
            result.categories
        );
    }

    fn causal_item<'a>(
        result: &'a ModuleResult,
        key: &str,
        category: &str,
    ) -> &'a serde_json::Value {
        result.details["causal_findings"]
            .as_array()
            .expect("item-level evidence")
            .iter()
            .find(|item| {
                item["causal_key"] == key && item["categories"] == serde_json::json!([category])
            })
            .expect("scored category on its own target")
    }

    #[test]
    fn scored_payload_is_unchanged_by_same_or_other_target_observations() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let target = "https://payload.example/?next=javascript%3Aalert(1)";
        let module = LinkContentModule::new();
        let base_ctx = make_ctx(target);
        let baseline = analyze_with_runtime(&module, &base_ctx);
        let base_item = causal_item(&baseline, "host:payload.example", "encoded_protocol_param");
        assert_eq!(base_item["score"], 0.30);
        assert_eq!(base_item["confidence"], 0.75);

        let mut session = (*base_ctx.session).clone();
        for url in [
            "https://payload.example/read?member=victim%40example.com",
            "https://newsletter.example/read?member=victim%40example.com",
        ] {
            session.content.links.push(EmailLink {
                url: url.into(),
                text: None,
                suspicious: false,
            });
        }
        let expanded = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
        assert!(expanded.raw_score() > baseline.raw_score());
        assert_eq!(expanded.details["evidence_items_version"], 1);
        assert_eq!(
            causal_item(&expanded, "host:payload.example", "encoded_protocol_param"),
            base_item,
            "excluded observations must not strengthen admitted evidence"
        );
        assert_eq!(
            causal_item(&expanded, "host:newsletter.example", "recipient_in_url")["score"],
            0.40
        );
        assert!(
            !expanded
                .categories
                .iter()
                .any(|category| { category == "targeted_credential_phishing" })
        );
    }

    #[test]
    fn qualified_target_preserves_its_branch_strength_and_semantic_proof() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let ctx = make_ctx_with_body(
            "https://account-check.example/?m=victim%40example.com",
            Some("Please verify your account to continue."),
            Some("Account verification"),
        );
        let result = analyze_with_runtime(&LinkContentModule::new(), &ctx);
        let record = result.details["qualified_link_compounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["category"] == "targeted_credential_phishing")
            .expect("same-target recipient and current account request");
        let item = causal_item(
            &result,
            "host:account-check.example",
            "targeted_credential_phishing",
        );
        assert_eq!(record["score"], 0.30);
        assert_eq!(record["score"], item["score"]);
        assert_eq!(record["confidence"], item["confidence"]);
        assert_eq!(record["claim"]["actor_role"], "sender");
        assert_eq!(record["claim"]["target_role"], "recipient");
        assert_eq!(record["claim"]["polarity"], "action");
        assert_eq!(record["claim"]["quote_or_forward_status"], "original");
        assert_eq!(record["link_transport_status"], "not_attempted");
        assert_eq!(record["link_ownership_status"], "unknown");
        for category in &result.categories {
            if category == "inspection_coverage_incomplete" {
                continue;
            }
            assert!(
                result.details["causal_findings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|item| {
                        item["categories"] == serde_json::json!([category])
                            && item["score"]
                                .as_f64()
                                .is_some_and(|score| score > 0.0 && score <= 1.0)
                            && item["confidence"] == 0.75
                    }),
                "every emitted finding must retain its own score: {category}"
            );
        }
    }

    #[test]
    fn long_tracking_url_is_diagnostic_only() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = format!(
            "https://news.vendor.example/archive?campaign={}",
            "a".repeat(450)
        );

        let (score, findings) = analyze_url(&url);
        assert_eq!(
            score, 0.0,
            "URL length alone must not add risk: {findings:?}"
        );
        assert!(
            findings.iter().all(|(_, category)| category != "long_url"),
            "URL length must stay out of actionable categories: {findings:?}"
        );

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(result.categories.is_empty(), "{result:?}");
        assert_eq!(
            result.details["diagnostic_observations"]["long_url_count"],
            1
        );
    }

    #[test]
    fn same_effective_redirect_target_emits_one_causal_key() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            is_complete: true,
            links: vec![
                EmailLink {
                    url: "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fqxvzr.invalid%2F".to_string(),
                    text: Some("查看发票".to_string()),
                    suspicious: false,
                },
                EmailLink {
                    url: "https://qxvzr.invalid/".to_string(),
                    text: Some("直接查看".to_string()),
                    suspicious: false,
                },
            ],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );
        let causal_findings = result.details["causal_findings"]
            .as_array()
            .expect("causal findings array");

        let causal_keys: BTreeSet<_> = causal_findings
            .iter()
            .map(|item| item["causal_key"].as_str().expect("runtime causal key"))
            .collect();
        assert_eq!(
            causal_keys,
            BTreeSet::from(["host:qxvzr.invalid"]),
            "wrapper and direct URL must describe the same object: {result:?}"
        );
        for (category, score) in [
            ("dga_random_domain", 0.30),
            ("gateway_unwrapped_risky_target", 0.05),
        ] {
            let items = causal_findings
                .iter()
                .filter(|item| item["categories"] == serde_json::json!([category]))
                .collect::<Vec<_>>();
            assert_eq!(
                items.len(),
                1,
                "same-target category must not repeat: {category}"
            );
            assert_eq!(
                items[0]["score"], score,
                "duplicate views must not add strength"
            );
            assert_eq!(items[0]["confidence"], 0.75);
        }
    }

    #[test]
    fn long_url_with_active_encoded_payload_stays_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = format!(
            "https://portal.vendor.example/%256c%256f%2567%2569%256e?campaign={}",
            "a".repeat(450)
        );

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(&url));

        assert!(result.threat_level > ThreatLevel::Safe, "{result:?}");
        assert!(
            result.categories.iter().any(|category| {
                matches!(
                    category.as_str(),
                    "double_encoding" | "double_encoded_payload"
                )
            }),
            "active encoded payload evidence must survive: {result:?}"
        );
        assert_eq!(
            result.details["diagnostic_observations"]["long_url_count"],
            1
        );
    }

    #[test]
    fn short_vowel_abbreviation_is_not_dga_and_vowel_less_label_still_is() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let announcement = analyze_with_runtime(
            &module,
            &make_ctx(
                "http://www.shcpe.com.cn/content/shcpe/news/announce.html?articleType=news-announce",
            ),
        );
        assert!(
            !announcement
                .categories
                .contains(&"dga_random_domain".to_string()),
            "shcpe is a short institutional abbreviation: {announcement:?}"
        );

        // xqzpk is entirely pinyin initials, so the existing abbreviation
        // exemption applies. xvkrz has no vowel and contains a non-initial.
        let hosted =
            analyze_with_runtime(&module, &make_ctx("https://xvkrz.wecom.work/mail/download"));
        assert!(
            !hosted.categories.contains(&"dga_random_domain".to_string()),
            "a WeCom tenant label is not a DGA domain: {hosted:?}"
        );
        let random = analyze_with_runtime(&module, &make_ctx("https://xvkrz.example/status"));
        assert!(
            random.categories.contains(&"dga_random_domain".to_string()),
            "a vowel-less short label remains DGA: {random:?}"
        );
    }

    #[test]
    fn test_human_readable_service_label_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://portal.mailservice.example/report/clearance");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "Human-readable service labels should not be marked as DGA: {:?}",
            result.categories
        );
    }

    #[test]
    fn filename_shaped_apex_host_is_not_marked_as_hex_subdomain() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx("https://20260101010203.pdf"),
        );

        assert!(
            !result.categories.contains(&"hex_subdomain".to_string()),
            "an apex filename-shaped host is not a subdomain: {result:?}"
        );
    }

    #[test]
    fn real_hex_subdomain_remains_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &make_ctx("https://20260101010203.example.invalid"),
        );

        assert!(
            result.categories.contains(&"hex_subdomain".to_string()),
            "a true three-label hex subdomain must remain observable: {result:?}"
        );
    }

    #[test]
    fn test_bootcdn_service_label_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://cdn.bootcdn.invalid/library/normalize/8.0.1");

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "BootCDN is a consonant-heavy service label, not a DGA: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_object_storage_static_asset_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login-banner.png?x-oss-process=image/resize,w_600",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.is_empty(),
            "static cloud asset should be ignored: {:?}",
            result.categories
        );
        assert_eq!(result.threat_level, ThreatLevel::Safe);
    }

    #[test]
    fn test_gateway_wrapped_showimg_asset_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://urldefense.proofpoint.com/v2/url?url=https%3A%2F%2Fassets.vendor.example%2Frender%2FshowImg%3Fid%3Dfixture-image",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "gateway-wrapped non-clickable render assets should be ignored: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_cloudses_callback_webhook_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://1254335589-hk.callback.cloudses.com/api/webhook?upn=eb4ffc552935405db76234bb95083795f5831773d61927b5570fc6a831840ab1e14a24f90146ee0acaa8686e500ef2d19b18f996d9bd793495d67541b7d8a00231607ea8ae2fad80dcd113e71697a8ac2304bb479066ea23679c0ec3543cb6f2d824b17c1975aa08cc55e23ac9a94d16a4563e9298a6311f9d03143bc0b68f97b35b1ed43efa99779fd84e2b5c04f28e98a37bafbdc2f29dbfada478edc0fd48009894dc0c55df9eb4c5616bd93d42e49d9d57d20952d8b2535c7114ccd935a29b7eb38020056d02e9cb6d8f2219ca7aec3deddc123165c20c194e9d1cea8538160e652b7ec0018d2beb47d6740482cba4cf66bd443f07f2e42353dd4eb477a7261775245e32b1253bb8b1c8e98e8fd323f54bd8629fc625815dbe07040d8a5a0a8a9cf27f9fba890a63b682546f23cb40999b8abb70119612d759d5431793df9d18bdbb7a436cf4d41510aed45a9463e49c52b94d293c387d162367732cc814a05710f72728d612af8ced3ea0fb7dcd",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "opaque cloudses callback URLs should skip structural link heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_schema_reference_url_is_ignored() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("http://schemas.microsoft.com/office/2004/12/omml");

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "namespace/schema references should not be treated as user-facing links: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_well_known_safe_cdn_asset_is_not_flagged_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::from([
            "127.net".to_string(),
        ])));
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://mail-online.nosdn.127.net/wzpmmc/b7713ee39fc6d0272a61196c395ab44e.jpg",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "curated safe CDN assets should not trip DGA heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_sendcloud_tracking_domain_is_not_marked_as_dga_when_seeded_safe() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::from([
            "sendcloud.net".to_string(),
        ])));
        let module = LinkContentModule::new();
        let ctx = make_ctx(
            "https://sctrack.sendcloud.net/track/open2/eNptjsEKwjAQRP8leExCts0mm5v_IVLSbYqtmoJpDyr-uy09eJG5DPOGYU4VgPcohZBiNc6agJYw2AYAA7hm5w1ZD7qwAqOCAkIFjtSQ22nJnTm042t8xiNzbPky5Kh5ugtpVok-3kraxsFrNNpZDVCLX74h7gkt1FQRIdvkGIld7QJWgVKHe6vw_Ih81SXljm_T0umcZiHfH7k_lTVJ8ffI-Qtx8j7M.gif",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "seeded safe tracking domains should not trip DGA heuristics: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_qr_to_login_chain_requires_real_qr_lure_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx_with_body(
            "https://www.swift.com/myswift/billing/direct-debit",
            Some(
                "Please review your invoice and settle the overdue amount through the billing portal.",
            ),
            None,
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"qr_to_login_chain".to_string()),
            "billing/login links without any QR lure context should not trip QR-chain detection: {:?}",
            result.categories
        );
    }

    #[test]
    fn ip_action_target_requires_current_same_url_request() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ip = "http://203.0.113.60/login";
        for (html, verified_thread, expected) in [
            (
                format!(
                    "<p>Please click to verify your account <a href='{ip}'>Verify account</a>.</p>"
                ),
                false,
                true,
            ),
            (
                format!(
                    "<blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div><p>Please click to verify your account <a href='{ip}'>Verify account</a>.</p></blockquote>"
                ),
                true,
                false,
            ),
            (
                format!(
                    "<blockquote>Please click to verify your account <a href='{ip}'>Verify account</a>.</blockquote>"
                ),
                false,
                true,
            ),
            (
                format!(
                    "<blockquote>Please click to verify your account <a href='{ip}'>Verify account</a>.</blockquote>"
                ),
                true,
                true,
            ),
            (
                format!(
                    "<p>Do not click or verify your account at <a href='{ip}'>Verify account</a>.</p>"
                ),
                false,
                false,
            ),
            (
                format!(
                    "<p>For security training, here is an example: <a href='{ip}'>Verify account</a>.</p>"
                ),
                false,
                false,
            ),
            (
                format!(
                    "<p>Please click <a href='https://portal.example/view'>View report</a>.</p><p>Incident indicator: <a href='{ip}'>IP address</a>.</p>"
                ),
                false,
                false,
            ),
            (
                format!(
                    "<blockquote><div>On Mon, 26 Oct 2026, alice@example.invalid wrote:</div><p>Please click <a href='{ip}'>Verify account</a>.</p></blockquote><p>Please verify your account <a href='{ip}'>Verify account</a>.</p>"
                ),
                true,
                true,
            ),
        ] {
            let mut session = (*make_ctx(ip).session).clone();
            if verified_thread {
                session.content.headers.push((
                    "In-Reply-To".into(),
                    "<original-ip-request@example.invalid>".into(),
                ));
            }
            session.content.body_html = Some(html.clone());
            let result = analyze_with_runtime(&module, &SecurityContext::new(Arc::new(session)));
            assert_eq!(
                result
                    .categories
                    .iter()
                    .any(|category| category == "ip_action_target"),
                expected,
                "{html}, thread evidence={verified_thread}: {:?}",
                result.categories
            );
            if !expected {
                assert!(
                    !result
                        .categories
                        .iter()
                        .any(|category| category == "inspection_coverage_incomplete"),
                    "attribution is a bounded negative/observation, not skipped inspection"
                );
            }
        }
    }

    #[test]
    fn trusted_open_redirect_ip_login_target_keeps_action_causality() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx_with_body(
            "https://docs.google.com/url?q=http%3A%2F%2F203.0.113.60%2Flogin",
            Some("请点击下方入口查看详情并完成相应操作。"),
            Some("系统通知"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"ip_action_target".to_string()),
            "the inner IP login target and CTA must remain causally linked: {result:?}"
        );
        assert!(
            result.evidence.iter().any(|item| item
                .snippet
                .as_deref()
                .is_some_and(|snippet| snippet.contains("203.0.113.60/login"))),
            "evidence must identify the recovered destination: {result:?}"
        );
    }

    #[test]
    fn multilingual_cta_keeps_redirected_ip_login_causality() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        for body in [
            "Vui lòng xác minh danh tính ngay.",
            "กรุณายืนยันและเข้าสู่ระบบทันที",
            "Segera klik untuk verifikasi identitas Anda.",
        ] {
            let ctx = make_ctx_with_body(
                "https://docs.google.com/url?q=http%3A%2F%2F203.0.113.60%2Flogin",
                Some(body),
                Some("Account notice"),
            );
            let result = analyze_with_runtime(&module, &ctx);
            assert!(
                result.categories.contains(&"ip_action_target".to_string()),
                "multilingual CTA must bind to the recovered IP login target: {result:?}"
            );
        }
    }

    #[test]
    fn ordinary_shared_document_query_does_not_create_ip_action_target() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx_with_body(
            "https://docs.google.com/document/d/benign?src=http%3A%2F%2F203.0.113.60%2Flogin",
            Some("请查看文档说明。"),
            Some("项目文档"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"ip_action_target".to_string()),
            "a normal document query is not a redirect destination: {result:?}"
        );
    }

    #[test]
    fn test_qr_ip_login_chain_promotes_only_the_named_compound() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        let mut malicious_ctx = make_ctx_with_body(
            "http://203.0.113.60/sso/login",
            Some("请扫描二维码登录完成验证"),
            None,
        );
        Arc::get_mut(&mut malicious_ctx.session)
            .expect("test context has a unique session")
            .content
            .body_html = Some(include_str!("../../tests/redteam_cases/assets/qr.svg").to_string());
        let malicious = analyze_with_runtime(&module, &malicious_ctx);
        assert!(
            malicious
                .categories
                .contains(&"qr_ip_login_chain".to_string()),
            "IP-literal login target with scan lure must be named: {:?}",
            malicious.categories
        );

        let benign_host = analyze_with_runtime(
            &module,
            &make_ctx_with_body(
                "https://example.com/sso/login",
                Some("请扫描二维码登录完成验证"),
                None,
            ),
        );
        assert!(
            !benign_host
                .categories
                .contains(&"qr_ip_login_chain".to_string()),
            "domain-hosted QR login must not receive the IP compound: {:?}",
            benign_host.categories
        );
    }

    #[test]
    fn test_login_landing_page_still_has_structural_path_signal() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) =
            analyze_url("https://pro.qcc.com/login?path=investigation/automation-check");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path")
        );
    }

    #[test]
    fn test_hyphenated_human_readable_domain_is_not_marked_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://product-support.chaitin.cn/package/detail?id=12345");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "human-readable hyphenated labels should not be marked as DGA: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_receive_path_is_not_treated_as_receipt_typo() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) =
            analyze_url("https://product-support.chaitin.cn/message/receive?id=12345");

        assert!(
            !findings.iter().any(|(_, category)| category == "url_typo"),
            "common verbs like receive should not be treated as receipt typos: {:?}",
            findings
        );
    }

    #[test]
    fn test_device_code_flow_requires_keyword_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["secure voicemail", "device code"]);
        let url = "https://microsoft.com/devicelogin";
        let body = format!("Please enter the device code for secure voicemail at {url}.");
        let ctx = make_projection_ctx(url, Some(&body), None);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result
                .categories
                .contains(&"device_code_phishing".to_string()),
            "device-code structure should only fire with keyword context: {:?}",
            result.categories
        );
        for missing_proof in [
            "Secure voicemail: device code".to_string(),
            "Please enter the device code for secure voicemail.".to_string(),
            format!("> {body}"),
        ] {
            let negative = analyze_with_runtime(
                &module,
                &make_projection_ctx(url, Some(&missing_proof), None),
            );
            assert!(
                !negative
                    .categories
                    .contains(&"device_code_phishing".to_string()),
                "a noun, detached URL or quoted instruction cannot supply current action proof: {negative:?}"
            );
        }
    }

    #[test]
    fn test_device_code_flow_without_keyword_context_stays_clean() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let ctx = make_ctx("https://microsoft.com/devicelogin");

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            !result
                .categories
                .contains(&"device_code_phishing".to_string()),
            "device-code URL alone should not trip the dynamic-keyword gate: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_business_card_profile_path_is_not_oauth_flow() {
        assert!(!url_looks_like_oauth_flow(
            "https://work.weixin.qq.com/wework_admin/user/h5/qqmail_user_card/vc123?from=myprofile"
        ));
        assert!(url_looks_like_oauth_flow(
            "https://login.example.com/oauth2/authorize?client_id=abc&scope=openid"
        ));
    }

    #[test]
    fn qq_ftn_download_url_is_clean_in_link_content_analysis() {
        let (score, findings) = analyze_url(
            "https://wx.mail.qq.com/ftn/download?func=3&k=opaque-download-token&key=opaque-download-token&code=opaque-code&from=",
        );

        assert_eq!(score, 0.0);
        assert!(findings.is_empty(), "findings={findings:?}");
    }

    #[test]
    fn aliyun_directmail_trace_url_is_clean_in_link_content_analysis() {
        let (score, findings) = analyze_url(
            "https://dm-cn.aliyuncs.com/trace/v1/report?bid=1&mf=sender%40mail.example&msgid=id&to=recipient%40example.com&tag=opentag&tid=&sign=opaque-sign",
        );

        assert_eq!(score, 0.0);
        assert!(findings.is_empty(), "findings={findings:?}");
    }

    #[test]
    fn test_auth_barrier_url_uses_dynamic_keyword_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["mailbox alert", "review now"]);
        let ctx = make_ctx_with_body(
            "https://example.com/security-check/captcha?redirect_uri=https://login.microsoftonline.com",
            Some("Mailbox alert review now"),
            Some("Mailbox alert"),
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"auth_barrier_url".to_string()),
            "auth-barrier URL should use runtime keywords instead of hardcoded lure text: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_gateway_without_extractable_target_still_runs_structural_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Mail security gateway domain whose query carries no valid embedded
        // target URL: unwrapping fails, so structural checks must still run.
        let (_, findings) =
            analyze_url("https://urldefense.proofpoint.com/v2/url?token=fixture-opaque-token");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "gateway URL without a valid embedded target must not be exempted: {:?}",
            findings
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "a gateway URL without an embedded target must not invent a destination TLD: {:?}",
            findings
        );
    }

    #[test]
    fn subscription_token_is_not_a_phishing_parameter_without_action_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) = analyze_url(
            "https://mailer.example.invalid/subscribe/index?token=fixture-opaque-token",
        );

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "subscribe tokens are recipient metadata, not credential evidence: {findings:?}"
        );
    }

    #[test]
    fn storage_provider_name_does_not_create_an_implicit_trust_exception() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) = analyze_url_with_anchor_context(
            "https://xqvtrn-26.s3.region.object-storage.example.invalid/login/index.html?token=fixture&AWSAccessKeyId=fixture&Expires=123&Signature=fixture",
            true,
            false,
        );

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path")
                && findings
                    .iter()
                    .any(|(_, category)| category == "suspicious_params"),
            "storage-shaped host names must remain analyzable without a provider allowlist: {findings:?}"
        );
    }

    #[test]
    fn test_unwrapped_gateway_target_is_exempt_from_wrapper_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Successful unwrap: the wrapper's own params must not be flagged.
        let (_, findings) = analyze_url(
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fportal.example.com%2Fhome",
        );

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "unwrapped gateway target should not inherit wrapper params: {:?}",
            findings
        );
    }

    #[test]
    fn test_userinfo_url_analyzes_real_host_after_at() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC (B1-1): the hand-rolled splitter treated the userinfo segment
        // "mail.qq.com:443" as the host, so the fake trusted prefix hit
        // safe-domain logic and the real destination (evil.tk) was never
        // checked. WHATWG parsing exposes the host after `@`.
        let (_, findings) = analyze_url("http://mail.qq.com:443@evil.tk/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "at_sign_obfuscation"),
            "userinfo authority must be flagged: {:?}",
            findings
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "the real host evil.tk must drive host-based checks: {:?}",
            findings
        );
    }

    #[test]
    fn test_backslash_url_host_is_visible_to_checks() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC (B1-2): for `http:/\evil.tk/login` the old splitter failed
        // `strip_prefix("http://")` and collapsed the host to the literal
        // string "http", blinding every host-based check. WHATWG parsing
        // normalizes `\` to `/` in special schemes, exposing evil.tk.
        let (_, findings) = analyze_url("http:/\\xkqzvwp.tk/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_tld"),
            "backslash URL host must participate in TLD checks: {:?}",
            findings
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "backslash URL path must still be scanned: {:?}",
            findings
        );
    }

    #[test]
    fn test_unwrapped_gateway_target_itself_is_still_analyzed() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) = analyze_url(
            "https://redirector.invalid/query?url=https%3A%2F%2Fquota-lure.invalid%2F%3Ftoken%3Dfixture-token&auth=fixture-signature",
        );

        assert!(
            score >= 0.20,
            "target findings should be visible at low risk"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "the embedded destination token must be analyzed: {:?}",
            findings
        );
    }

    #[test]
    fn test_idn_pure_cyrillic_brand_spoof_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // All-Cyrillic "аррӏе.сом" (incl. Cyrillic TLD) has no ASCII Latin at
        // all, so the mixed-script check cannot fire; the homoglyph skeleton
        // still matches the brand "apple.com".
        let (_, findings) = analyze_url("https://аррӏе.сом/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "pure Cyrillic brand spoof should be detected: {:?}",
            findings
        );
    }

    #[test]
    fn test_external_brand_host_typosquatting_detected_realtime() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (score, findings) = analyze_url("https://microsft.com/login");
        assert!(score > 0.0);
        assert!(
            findings
                .iter()
                .any(|(_, category)| { category == "brand_typosquatting" })
        );
    }

    #[test]
    fn test_short_legitimate_labels_are_not_brand_edit_distance_false_positives() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        for url in [
            "https://flights.ctrip.invalid/booking/detail",
            "https://mail-dispatcher.intsig.invalid/campaign/open",
        ] {
            let (_, findings) = analyze_url(url);
            assert!(
                !findings
                    .iter()
                    .any(|(_, category)| category == "brand_typosquatting"),
                "short legitimate label must not resemble an unrelated brand: {url} {findings:?}"
            );
        }
    }

    #[test]
    fn test_seeded_travel_asset_labels_are_not_lexical_dga_findings() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        for url in [
            "https://flights.ctrip.invalid/booking/detail",
            "https://images4.c-ctrip.invalid/target/notice.png",
            "https://dimg04.tripcdn.invalid/images/invoice-banner.png",
        ] {
            let (_, findings) = analyze_url(url);
            assert!(
                !findings
                    .iter()
                    .any(|(_, category)| category == "dga_random_domain"),
                "legitimate travel/CDN label must not be treated as DGA: {url} {findings:?}"
            );
        }
    }

    #[test]
    fn test_css_contain_fragment_is_not_portuguese_account_path() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) =
            analyze_url("https://img2.xfb315.invalid/synthetic/object-fit:contain;");

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "CSS contain parser artifact must not match the Portuguese conta token: {findings:?}"
        );
    }

    #[test]
    fn test_trusted_org_subdomain_is_not_external_brand_typosquatting() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "*.internal.example".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        let (score, findings) = analyze_url(
            "https://ebank.internal.example/mbank/wap/index.html?filuqeid=fixture-token#InvoiceDown/Index/Index",
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "brand_typosquatting"),
            "trusted organization subdomains must not be compared to external brands: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "deep_fragment_route"),
            "trusted first-party SPA routes must not be flagged as deep fragments: {findings:?}"
        );
        assert_eq!(
            score, 0.0,
            "trusted invoice route should have no structural score: {findings:?}"
        );

        reset_url_domain_sets();
    }

    #[test]
    fn configured_official_brand_is_not_compared_with_another_brand() {
        assert_eq!(detect_external_brand_host("www.abchina.com"), None);
        assert_eq!(detect_external_brand_host("wx.abchina.com"), None);
        assert_eq!(detect_external_brand_host("message.cmbchina.com"), None);
    }

    #[test]
    fn adjacent_abc_typosquat_remains_detectable() {
        let hit = detect_external_brand_host("www.abchino.com");
        assert!(
            hit.as_ref()
                .is_some_and(|(brand, anchor, _)| brand == "abc" && anchor == "abchina.com"),
            "adjacent typo must retain ABC brand evidence: {hit:?}"
        );
    }

    #[test]
    fn trusted_abc_statement_routes_have_no_structural_findings() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "abchina.com".to_string(),
            "*.abchina.com".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        for url in [
            "https://www.abchina.com/web2native|channel=credit_trans_repay*menu=credit*step=02*param=1110",
            "https://wx.abchina.com/Apply/index.html#/?param=direct=c3ludGhldGljLWZpeHR1cmU=&mgr=share",
            "http://media.abchina.com/creditcard/ebill/email/202508/statement.png",
        ] {
            let (score, findings) = analyze_url(url);
            assert_eq!(
                score, 0.0,
                "official ABC URL must be safe: {url} {findings:?}"
            );
            assert!(findings.is_empty(), "official ABC URL: {url} {findings:?}");
        }

        reset_url_domain_sets();
    }

    #[test]
    fn test_trusted_synthetic_newsletter_routes_are_not_typosquatting() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        crate::modules::link_scan::set_trusted_url_domains(Arc::new(HashSet::from([
            "*.newsletter.example".to_string(),
            "*.assets.example".to_string(),
            "*.short.example".to_string(),
        ])));
        crate::modules::link_scan::set_well_known_safe_domains(Arc::new(HashSet::new()));

        for url in [
            "https://portal.newsletter.example/newsletter/url-link?campaign=fixture&format=html",
            "https://go.short.example/c/fixture?variant=3",
            "https://site.assets.example/Router/invoke.html?url=fixtureapp%3A%2F%2Fopen%2Fitem",
            "https://portal.newsletter.example/help/fixture-topic",
        ] {
            let (score, findings) = analyze_url(url);
            assert!(
                !findings.iter().any(|(_, category)| {
                    matches!(
                        category.as_str(),
                        "brand_typosquatting" | "url_typo" | "redirect_url" | "deep_fragment_route"
                    )
                }),
                "trusted synthetic newsletter URL must not produce structural false positives: {url}: {findings:?}"
            );
            assert_eq!(
                score, 0.0,
                "trusted synthetic newsletter URL should have no structural score: {url}"
            );
        }

        reset_url_domain_sets();
    }

    #[test]
    fn test_fullwidth_latin_folds_to_canonical_domain_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Fullwidth Latin (U+FF41+) is mapped to ASCII by UTS-46 host
        // processing — the browser also navigates to plain "apple.com", so
        // this is the canonical domain, NOT an IDN spoof. Guard against
        // false positives: idn_homograph must not fire.
        let (_, findings) = analyze_url("https://ａｐｐｌｅ.ｃｏｍ/login");

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "fullwidth Latin folds to the canonical domain and must not be flagged: {:?}",
            findings
        );
    }

    #[test]
    fn test_internal_monitoring_url_nonstandard_port_is_not_a_threat_signal() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let base = make_ctx("https://monitor.internal.example:8085/h5/review/");
        let ctx = SecurityContext::with_internal_domains(
            base.session.clone(),
            Arc::new(HashSet::from(["internal.example".to_string()])),
        );

        let result = analyze_with_runtime(&LinkContentModule::new(), &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result.categories.contains(&"unusual_port".to_string()),
            "internal services may legitimately use configured application ports"
        );
    }

    #[test]
    fn test_idn_mixed_script_still_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Cyrillic 'а' (U+0430) mixed into an ASCII domain - pre-existing behavior.
        let (_, findings) = analyze_url("https://аpple.com/login");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "mixed-script domain should still be detected: {:?}",
            findings
        );
    }

    #[test]
    fn test_confusable_common_public_suffix_gets_high_weight() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) = analyze_url("https://security-check.cοm/");

        assert!(
            score >= 0.65,
            "confusable .com suffix must be actionable: {score}"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "confusable public suffix should remain in the IDN evidence family: {findings:?}"
        );
    }

    #[test]
    fn test_legitimate_non_ascii_suffix_keeps_ordinary_mixed_script_weight() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) = analyze_url("https://example.ελ/");

        assert!(
            (score - 0.40).abs() < f64::EPSILON,
            "a legitimate IDN suffix must not receive the confusable-common-suffix promotion: {score}, {findings:?}"
        );
    }

    #[test]
    fn test_idn_pure_cjk_domain_is_not_flagged() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // CJK ideographs are not letter-script lookalikes and are exempt.
        let (_, findings) = analyze_url("https://清华大学.cn/");

        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "idn_homograph"),
            "pure CJK domain must not be flagged as IDN homograph: {:?}",
            findings
        );
    }

    #[test]
    fn test_qq_qlogo_render_endpoint_is_not_flagged_as_dga() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        let (score, findings) =
            analyze_url("http://thirdqq.qlogo.cn/g?b=oidb&k=avatar-token&s=100&t=1700000000");

        assert_eq!(
            score, 0.0,
            "qlogo render asset should be exempt: {findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "dga_random_domain"),
            "QQ avatar host is provider infrastructure, not DGA: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_path_keyword_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // %6c%6f%67%69%6e decodes to "login": before the fix the raw path
        // carried no literal keyword and the Aho-Corasick scan never fired.
        let (score, findings) = analyze_url("https://evil.example/%6c%6f%67%69%6e");

        assert!(score > 0.0);
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "percent-encoded login path must not bypass the keyword scan: {findings:?}"
        );
    }

    #[test]
    fn opaque_path_token_with_encoded_base64_slash_is_safe() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = "https://portal.example/records/item/Ab3DefGh7JkLmN9PqRsTuVwXyZ0aBcD%2FEf4GhIjK5LmNoP6QrStUvW7XyZaB%2BCd8";

        let (score, findings) = analyze_url(url);
        assert_eq!(
            score, 0.0,
            "opaque token must not add URL risk: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .all(|(_, category)| category != "encoded_separator"),
            "Base64 slash inside one opaque segment is transport encoding: {findings:?}"
        );

        let result = analyze_with_runtime(&LinkContentModule::new(), &make_ctx(url));
        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(result.categories.is_empty(), "{result:?}");

        // Base64 ciphertext can contain adjacent slash symbols separated by
        // only one alphabet character. That shape is still one opaque token,
        // not a decoded route hierarchy.
        let short_chunk_url = "https://portal.example/records/item/Ab3DefGh7JkL%2FX%2FMn9PqRsTuVwXyZ0aBcDEf4GhIjK5LmNoP6QrStUvW7XyZaBCd";
        let (score, findings) = analyze_url(short_chunk_url);
        assert_eq!(score, 0.0, "opaque token must stay safe: {findings:?}");
        assert!(
            findings
                .iter()
                .all(|(_, category)| category != "encoded_separator"),
            "short Base64 slash chunks are token data: {findings:?}"
        );
    }

    #[test]
    fn encoded_separator_that_changes_route_stays_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        for url in [
            "https://portal.example/archive/%2e%2e%2fprivate/document",
            "https://portal.example/Ab3DefGh7JkLmN9PqRsTuVwXyZ0aBcD%2Flogin",
            "https://portal.example/archive%5cprivate%5cdocument",
        ] {
            let (score, findings) = analyze_url(url);
            assert!(
                score >= 0.15,
                "encoded route escape must score: {url} {findings:?}"
            );
            assert!(
                findings
                    .iter()
                    .any(|(_, category)| category == "encoded_separator"),
                "encoded route escape must retain its category: {url} {findings:?}"
            );
        }
    }

    #[test]
    fn test_percent_encoded_query_param_name_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // tok%65n decodes to "token": encoded parameter names previously
        // bypassed the suspicious_query_params list entirely.
        let (_, findings) = analyze_url("https://evil.example/page?tok%65n=abc123");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "percent-encoded query parameter name must not bypass the param scan: {findings:?}"
        );
    }

    #[test]
    fn generic_id_on_synthetic_agreement_link_is_context_only() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (score, findings) = analyze_url(
            "https://billing.vendor.invalid/agreementDisplay?id=SYNTHETIC-AGREEMENT-01",
        );

        assert_eq!(score, 0.0, "{findings:?}");
        assert!(
            !findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "{findings:?}"
        );
    }

    #[test]
    fn generic_id_is_actionable_when_login_path_corroborates_it() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let (_, findings) =
            analyze_url("https://portal.vendor.invalid/login?id=SYNTHETIC-RECIPIENT");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_params"),
            "{findings:?}"
        );
    }

    #[test]
    fn test_observed_huawei_telemetry_callbacks_have_no_content_score() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        for url in [
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/clicknum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&urlPageIndex=f7cf6546-809b-4359-b402-b04ae180817a&urlIndex=d5431c23-7909-41fa-8c8b-0541cfd1ff17&key=92e3d69690d94e58685eec9ecaf3e3e93d5d63f6716ad3543aa4caa6869b9de6",
            "https://svc-drcn.developer.huawei.com/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82",
        ] {
            let (score, findings) = analyze_url(url);
            assert_eq!(
                score, 0.0,
                "validated callback must not score: {findings:?}"
            );
            assert!(
                findings.is_empty(),
                "validated callback must not emit findings: {findings:?}"
            );
        }
    }

    #[test]
    fn test_huawei_lookalike_with_redirect_target_remains_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let url = "https://svc-drcn.developer.huawei.com.evil.example/partnermessage/dadian/v2/opennum?localMsgID=afef48094a5f43d6bc18ff838fe3615a&msgType=1&key=f0f19cf0e507a9fb1fb0bfeae2419ad3debdebaab1189e956a674303ca27af82&url=https%3A%2F%2Fevil.example%2Flogin";

        let (score, findings) = analyze_url(url);
        assert!(score > 0.0, "lookalike redirect must remain scored");
        assert!(
            findings.iter().any(|(_, category)| {
                matches!(category.as_str(), "suspicious_params" | "redirect_url")
            }),
            "lookalike redirect must remain analyzable: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_fragment_keyword_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // Encoded SPA route: #%6c%6f%67%69%6e decodes to #login.
        let (_, findings) = analyze_url("https://evil.example/app#%6c%6f%67%69%6e");

        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "suspicious_path"),
            "percent-encoded login fragment must not bypass the keyword scan: {findings:?}"
        );
    }

    #[test]
    fn test_qr_to_login_chain_detects_percent_encoded_login_url() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let url = "https://evil.example/%6c%6f%67%69%6e";
        let body = "请扫描二维码登录完成验证";
        // This rendered carrier encodes the exact percent-encoded URL. It is
        // generated with Segno, rather than inserting decoded metadata by hand.
        let carrier = r##"<?xml version="1.0" encoding="utf-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="148" height="148" class="segno"><path transform="scale(4)" class="qrline" stroke="#000" d="M4 4.5h7m3 0h1m3 0h1m1 0h1m2 0h2m1 0h7m-29 1h1m5 0h1m3 0h1m1 0h1m2 0h1m2 0h1m1 0h1m1 0h1m5 0h1m-29 1h1m1 0h3m1 0h1m2 0h2m1 0h1m4 0h2m1 0h1m1 0h1m1 0h3m1 0h1m-29 1h1m1 0h3m1 0h1m4 0h3m1 0h1m2 0h2m2 0h1m1 0h3m1 0h1m-29 1h1m1 0h3m1 0h1m3 0h3m1 0h3m1 0h1m1 0h1m1 0h1m1 0h3m1 0h1m-29 1h1m5 0h1m1 0h2m1 0h1m3 0h1m1 0h1m1 0h1m2 0h1m5 0h1m-29 1h7m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h1m1 0h7m-20 1h1m1 0h1m1 0h1m3 0h4m-21 1h1m2 0h1m1 0h2m1 0h3m3 0h1m3 0h2m1 0h1m1 0h1m-24 1h1m1 0h1m5 0h2m1 0h1m1 0h1m3 0h1m3 0h3m1 0h1m2 0h1m-29 1h4m1 0h3m2 0h1m1 0h3m1 0h1m2 0h1m1 0h2m1 0h4m-28 1h1m1 0h2m3 0h1m2 0h2m1 0h1m1 0h2m1 0h2m1 0h4m1 0h2m-27 1h1m3 0h4m3 0h1m1 0h1m1 0h3m1 0h3m2 0h1m1 0h2m-29 1h1m1 0h1m2 0h1m1 0h1m1 0h6m1 0h6m-22 1h1m1 0h1m2 0h2m1 0h2m3 0h2m6 0h2m1 0h5m-26 1h3m2 0h3m1 0h1m2 0h1m1 0h1m1 0h2m2 0h3m1 0h1m-28 1h1m1 0h5m1 0h2m1 0h3m1 0h3m2 0h2m5 0h1m-26 1h2m3 0h3m1 0h4m7 0h2m1 0h1m2 0h1m-29 1h1m3 0h7m3 0h1m1 0h2m2 0h1m6 0h2m-21 1h5m1 0h1m2 0h1m3 0h2m4 0h2m-29 1h1m3 0h1m1 0h1m2 0h1m2 0h1m5 0h1m1 0h5m1 0h1m-19 1h1m2 0h1m2 0h1m2 0h1m2 0h1m3 0h1m1 0h3m-29 1h7m2 0h1m1 0h1m4 0h1m3 0h1m1 0h1m1 0h1m2 0h1m-28 1h1m5 0h1m1 0h2m4 0h3m1 0h1m1 0h1m3 0h4m-28 1h1m1 0h3m1 0h1m9 0h3m1 0h5m2 0h2m-29 1h1m1 0h3m1 0h1m1 0h1m2 0h3m2 0h4m2 0h1m1 0h4m-28 1h1m1 0h3m1 0h1m3 0h3m1 0h1m4 0h2m3 0h3m1 0h1m-29 1h1m5 0h1m6 0h1m2 0h2m1 0h3m5 0h1m-28 1h7m1 0h1m1 0h5m1 0h3m1 0h2m1 0h3m1 0h1"/></svg>
"##;
        let mut ctx = make_projection_ctx(url, Some(body), Some(carrier));
        Arc::get_mut(&mut ctx.session)
            .unwrap()
            .content
            .links
            .clear();
        assert_eq!(ctx.decoded_qr_urls(), &[url.to_string()]);
        let result = analyze_with_runtime(&module, &ctx);
        assert!(
            result.categories.contains(&"qr_to_login_chain".to_string()),
            "current QR action plus the decoded encoded-login target must remain detected: {result:?}"
        );
        assert!(
            result.details["qualified_link_compounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|record| record["category"] == "qr_to_login_chain"
                    && record["original_url"] == url
                    && record["link_extraction_source"] == "qr")
        );

        let missing_carrier = make_projection_ctx(url, Some(body), None);
        assert!(missing_carrier.decoded_qr_urls().is_empty());
        let negative = analyze_with_runtime(&module, &missing_carrier);
        assert!(
            !negative
                .categories
                .contains(&"qr_to_login_chain".to_string()),
            "a detached parser URL cannot manufacture a decoded QR carrier: {negative:?}"
        );
        let quoted_body = format!("> {body}");
        let mut quoted = make_projection_ctx(url, Some(&quoted_body), Some(carrier));
        Arc::get_mut(&mut quoted.session)
            .unwrap()
            .content
            .links
            .clear();
        assert_eq!(quoted.decoded_qr_urls(), &[url.to_string()]);
        let negative = analyze_with_runtime(&module, &quoted);
        assert!(
            !negative
                .categories
                .contains(&"qr_to_login_chain".to_string()),
            "a real QR carrier cannot turn a quoted scan request into a current action: {negative:?}"
        );
    }

    #[test]
    fn test_auth_barrier_detects_percent_encoded_barrier_term() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = make_module_with_keywords(&["mailbox alert"]);
        // %63%61%70%74%63%68%61 decodes to "captcha" (an auth-barrier term);
        // only the decoded form satisfies url_looks_like_auth_barrier, so this
        // URL slipped through before the fix.
        let url = "https://evil.example/%63%61%70%74%63%68%61/login";
        let body = format!("Please verify your account for the mailbox alert at {url}.");
        let ctx = make_projection_ctx(url, Some(&body), None);

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.categories.contains(&"auth_barrier_url".to_string()),
            "auth-barrier URL with percent-encoded barrier term must be detected: {:?}",
            result.categories
        );
        for missing_proof in [
            "Mailbox alert".to_string(),
            "Please verify your account for the mailbox alert.".to_string(),
            format!("> {body}"),
        ] {
            let negative = analyze_with_runtime(
                &module,
                &make_projection_ctx(url, Some(&missing_proof), None),
            );
            assert!(
                !negative
                    .categories
                    .contains(&"auth_barrier_url".to_string()),
                "encoded target shape cannot borrow a noun, detached URL or quote: {negative:?}"
            );
        }
    }

    #[test]
    fn test_double_encoded_fragment_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ①: browsers never decode the fragment — the phishing page's own
        // JS decodes #%256c%256f... (%6c%6f%67%69%6e -> "login"). Before the
        // fix the %25 check only inspected the path, so the fragment payload
        // was completely invisible.
        let (score, findings) = analyze_url("https://evil.example/app#%256c%256f%2567%2569%256e");

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoding"),
            "fragment %25 double-encoding must be flagged: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoded_payload"),
            "second-layer decode must reveal the login keyword: {findings:?}"
        );
    }

    #[test]
    fn test_percent_encoded_query_value_protocol_is_detected() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ②: query parameter *values* were never scanned, so
        // ?next=%6A%61%76%61%73%63%72%69%70%74%3A... (= javascript:alert(1))
        // escaped every protocol check.
        let (score, findings) = analyze_url(
            "https://evil.example/landing?next=%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29",
        );

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "encoded_protocol_param"),
            "encoded javascript: in a query value must be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_double_encoded_path_payload_is_unwrapped() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();

        // PoC ③: %256a%2561... double-encodes "javascript:". Before the fix
        // the first-layer decode produced still-encoded %6a%61... which no
        // keyword/protocol scan ever inspected.
        let (score, findings) = analyze_url(
            "https://evil.example/r/%256a%2561%2576%2561%2573%2563%2572%2569%2570%2574%253a",
        );

        assert!(score >= 0.15, "score must reach Low: {score}");
        assert!(
            findings
                .iter()
                .any(|(_, category)| category == "double_encoding"),
            "path %25 double-encoding must be flagged: {findings:?}"
        );
        assert!(
            findings.iter().any(|(desc, category)| {
                category == "double_encoded_payload" && desc.contains("dangerous protocol")
            }),
            "second-layer decode must reveal the javascript: protocol: {findings:?}"
        );
    }

    #[test]
    fn test_oss_content_override_cancels_static_asset_exemption() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // PoC ④: ?response-content-type=text/html rewrites the served
        // Content-Type of the stored object — the "static" .jpg URL actually
        // returns an HTML phishing page, so the static-asset exemption must
        // not apply even without anchor text. "login" in the path is the
        // second signal.
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/login.jpg?response-content-type=text/html",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.threat_level >= ThreatLevel::Low,
            "override-param asset must score: {:?}",
            result
        );
        assert!(
            result
                .categories
                .contains(&"oss_content_override".to_string()),
            "content-override parameters must cancel the exemption: {:?}",
            result.categories
        );
        assert!(
            result.categories.contains(&"suspicious_path".to_string()),
            "structural checks must run once the exemption is gone: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_anchor_texted_oss_static_asset_loses_exemption() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // PoC ④b: the exemption exists for chrome-less render resources
        // (<img>/<link>/<script> src). A clickable <a> with anchor text
        // pointing at OSS "static" content is a landing-page candidate and
        // must go through structural analysis.
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.rcpt_to.push("victim@example.com".to_string());
        session.content = EmailContent {
            is_complete: true,
            links: vec![EmailLink {
                url: "https://evil-bucket.oss-cn-hangzhou.aliyuncs.com/login/verify.jpg"
                    .to_string(),
                text: Some("点击验证您的账户".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };
        let ctx = SecurityContext::new(Arc::new(session));

        let result = analyze_with_runtime(&module, &ctx);

        assert!(
            result.threat_level >= ThreatLevel::Low,
            "anchor-texted asset must score: {:?}",
            result
        );
        assert!(
            result.categories.contains(&"suspicious_path".to_string()),
            "login/verify path keywords must be scored on a clickable link: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_clickable_bcebos_image_does_not_create_dga_evidence() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            12345,
            "10.0.0.2".to_string(),
            25,
        );
        session.content = EmailContent {
            is_complete: true,
            links: vec![EmailLink {
                url: "https://synthetic-bucket.gz.bcebos.com/fixture.jpg".to_string(),
                text: Some("活动图片".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );

        assert!(
            !result.categories.contains(&"dga_random_domain".to_string()),
            "a clickable static image still gets structural checks, but its bucket label is not DGA evidence: {:?}",
            result.categories
        );
    }

    #[test]
    fn test_render_asset_without_anchor_or_override_stays_exempt() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();

        // Guard: the legitimate exemption case (no anchor text, no override
        // params) must keep working — x-oss-process is an image-processing
        // parameter, not a response-header override.
        let ctx = make_ctx(
            "https://qfk-files.oss-cn-hangzhou.aliyuncs.com/assets/banner.jpg?x-oss-process=image/resize,w_600",
        );

        let result = analyze_with_runtime(&module, &ctx);

        assert_eq!(result.threat_level, ThreatLevel::Safe);
        assert!(
            result.categories.is_empty(),
            "plain render asset must stay exempt: {:?}",
            result.categories
        );
    }

    #[test]
    fn gateway_unwrapped_dga_is_auditable_but_stays_low_without_account_context() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let module = LinkContentModule::new();
        let direct = analyze_with_runtime(&module, &make_ctx("https://qxvzr.invalid/"));
        let wrapped = analyze_with_runtime(
            &module,
            &make_ctx(
                "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fqxvzr.invalid%2F",
            ),
        );

        assert_eq!(
            direct.threat_level,
            ThreatLevel::Low,
            "direct DGA: {direct:?}"
        );
        assert_eq!(
            wrapped.threat_level,
            ThreatLevel::Low,
            "gateway context alone must remain a weak structural signal: {wrapped:?}"
        );
        let policy = credential_brand_target_policy().expect("embedded policy");
        assert!(
            wrapped
                .categories
                .contains(&policy.redirect_target_category),
            "gateway target category must be visible to downstream fusion: {wrapped:?}"
        );
        assert_eq!(
            wrapped.details["credential_target_observations"][0]["effective_url"],
            serde_json::json!("https://qxvzr.invalid/")
        );
    }

    #[test]
    fn credential_cta_correlates_with_unwrapped_root_target_and_brand_triad() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let wrapped =
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fqxvzr.invalid%2F";
        let ctx = make_credential_chain_ctx(
            vec![(wrapped, "Activate your trusted device")],
            "Fixture Identity <notice@sender.invalid>",
        );

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"credential_link_lure".to_string()),
            "the configured CTA must correlate with the same link's unwrapped target: {result:?}"
        );
        assert!(
            result
                .categories
                .contains(&"high_risk_credential_target".to_string()),
            "a root path must not suppress domain-level target evidence: {result:?}"
        );
        assert!(
            result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "the claimed brand must be compared with both From and effective target domains: {result:?}"
        );
        assert_eq!(
            result.details["credential_target_observations"][0]["effective_url"],
            serde_json::json!("https://qxvzr.invalid/")
        );
    }

    #[test]
    fn credential_cta_does_not_borrow_risk_from_an_unrelated_link() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let ctx = make_credential_chain_ctx(
            vec![
                ("https://identity.example/", "Activate your trusted device"),
                ("https://qxvzr.invalid/", "Read the release notes"),
            ],
            "Fixture Identity <notice@sender.invalid>",
        );

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(result.categories.contains(&"dga_random_domain".to_string()));
        assert!(
            !result
                .categories
                .contains(&"credential_link_lure".to_string()),
            "CTA and risky target must belong to the same clickable link: {result:?}"
        );
        assert!(
            !result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "an unrelated risky link must not complete the brand triad: {result:?}"
        );
    }

    #[test]
    fn official_brand_sender_prevents_only_the_triad_mismatch() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let ctx = make_credential_chain_ctx(
            vec![("https://qxvzr.invalid/", "Activate your trusted device")],
            "Fixture Identity <notice@identity.example>",
        );

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"credential_link_lure".to_string()),
            "official sender alignment must not hide the risky CTA target: {result:?}"
        );
        assert!(
            !result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "an official From domain must suppress only the three-way mismatch finding: {result:?}"
        );
    }

    #[test]
    fn official_brand_landing_prevents_only_the_triad_mismatch() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let ctx = make_credential_chain_ctx(
            vec![(
                "https://identity.example/?next=javascript%3Aalert(1)",
                "Activate your trusted device",
            )],
            "Fixture Identity <notice@sender.invalid>",
        );

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"credential_link_lure".to_string()),
            "target alignment must not hide a structurally risky CTA: {result:?}"
        );
        assert!(
            !result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "an official landing suffix must suppress only the three-way mismatch: {result:?}"
        );
    }

    #[test]
    fn brand_suffix_embedded_in_attacker_domain_does_not_align() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let ctx = make_credential_chain_ctx(
            vec![(
                "https://identity.example.qxvzr.invalid/",
                "Activate your trusted device",
            )],
            "Fixture Identity <notice@identity.example.qxvzr.invalid>",
        );

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "domain matching must use an exact DNS-label boundary: {result:?}"
        );
    }

    #[test]
    fn gateway_href_does_not_manufacture_a_brand_claim() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let wrapped =
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fqxvzr.invalid%2F";
        let mut ctx = make_credential_chain_ctx(
            vec![(wrapped, "Activate your trusted device")],
            "Security Service <notice@sender.invalid>",
        );
        let session = Arc::make_mut(&mut ctx.session);
        session.subject = Some("Account security review".to_string());
        session.content.body_text = Some("A new device was detected.".to_string());
        session.content.body_html = Some(format!(
            "<p>A new device was detected.</p><img src=\"https://fixture-identity.invalid/pixel.png\"><a href=\"{wrapped}\">Activate your trusted device</a>"
        ));

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"credential_link_lure".to_string()),
            "the account CTA and recovered target must remain visible: {result:?}"
        );
        assert!(
            !result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "an href or image URL is transport metadata, not a visible brand claim: {result:?}"
        );
        assert!(
            result.details["credential_target_observations"]
                .as_array()
                .is_some_and(|items| items.iter().all(|item| item["claimed_brand"].is_null())),
            "the observation must expose that no visible brand was claimed: {result:?}"
        );
    }

    #[test]
    fn visible_image_alt_text_can_supply_the_brand_claim() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let wrapped =
            "https://safelinks.protection.outlook.com/?url=https%3A%2F%2Fqxvzr.invalid%2F";
        let mut ctx = make_credential_chain_ctx(
            vec![(wrapped, "Activate your trusted device")],
            "Security Service <notice@sender.invalid>",
        );
        let session = Arc::make_mut(&mut ctx.session);
        session.subject = Some("Account security review".to_string());
        session.content.body_text = Some("A new device was detected.".to_string());
        session.content.body_html = Some(format!(
            "<img src=\"cid:brand-logo\" alt=\"Fixture Identity\"><a href=\"{wrapped}\">Activate your trusted device</a>"
        ));

        let result = analyze_with_runtime(&make_credential_test_module(), &ctx);

        assert!(
            result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "recipient-visible image alt text must participate in the brand triad: {result:?}"
        );
    }

    #[test]
    fn japanese_payment_update_cta_completes_apple_brand_target_chain() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            2525,
            "192.0.2.20".to_string(),
            25,
        );
        session.subject = Some("ご利用明細をご確認ください".to_string());
        session.mail_from = Some("apple-noreply@billing-jp.example".to_string());
        session.rcpt_to.push("employee@example.invalid".to_string());
        session.content = EmailContent {
            is_complete: true,
            headers: vec![(
                "From".to_string(),
                "\"Apple\" <apple-noreply@billing-jp.example>".to_string(),
            )],
            body_text: Some(
                "お支払い方法に問題があります。サービスを引き続き利用するには、お支払い情報を更新してください。"
                    .to_string(),
            ),
            body_html: Some("<p>お支払い情報を更新してください。<a href=\"https://q9v2k7.info/account\">お支払い情報の更新</a></p>".to_string()),
            links: vec![EmailLink {
                url: "https://q9v2k7.info/account".to_string(),
                text: Some("お支払い情報の更新".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );

        for expected in [
            "credential_link_lure",
            "high_risk_credential_target",
            "brand_sender_target_mismatch",
        ] {
            assert!(
                result.categories.contains(&expected.to_string()),
                "Japanese payment CTA must preserve the Apple/from/target compound ({expected}): {result:?}"
            );
        }
        assert!(result.threat_level >= ThreatLevel::Medium, "{result:?}");
    }

    #[test]
    fn japanese_payment_update_cta_to_official_apple_target_stays_safe() {
        let _guard = crate::modules::link_scan::lock_url_domain_set_test_guard();
        reset_url_domain_sets();
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "192.0.2.10".to_string(),
            2525,
            "192.0.2.20".to_string(),
            25,
        );
        session.subject = Some("Apple お支払い情報のご案内".to_string());
        session.mail_from = Some("no_reply@apple.com".to_string());
        session.rcpt_to.push("employee@example.invalid".to_string());
        session.content = EmailContent {
            is_complete: true,
            headers: vec![(
                "From".to_string(),
                "\"Apple\" <no_reply@apple.com>".to_string(),
            )],
            body_text: Some("お支払い情報をご確認ください。".to_string()),
            body_html: Some("<p>お支払い情報をご確認ください。<a href=\"https://apple.com/account\">お支払い情報の更新</a></p>".to_string()),
            links: vec![EmailLink {
                url: "https://apple.com/account".to_string(),
                text: Some("お支払い情報の更新".to_string()),
                suspicious: false,
            }],
            ..Default::default()
        };

        let result = analyze_with_runtime(
            &LinkContentModule::new(),
            &SecurityContext::new(Arc::new(session)),
        );

        assert_eq!(result.threat_level, ThreatLevel::Safe, "{result:?}");
        assert!(
            !result
                .categories
                .contains(&"brand_sender_target_mismatch".to_string()),
            "official sender and landing domain must not become a brand mismatch: {result:?}"
        );
    }

    #[test]
    fn zero_width_cta_variant_matches_the_json_phrase() {
        assert_eq!(
            configured_phrase_match(
                "Activate\u{200b} your trusted device",
                "credential_cta_action_phrases"
            )
            .as_deref(),
            Some("activate your trusted device")
        );
    }

    #[test]
    fn malformed_credential_policy_disables_the_compound_detector() {
        assert!(
            parse_credential_brand_target_policy(serde_json::json!({
                "enabled": true,
                "cta_list": "credential_cta_action_phrases"
            }))
            .is_none(),
            "missing scenario fields must disable the detector without panicking"
        );

        let mut invalid_score = crate::module_data::module_data()
            .get_structured("credential_brand_target_policy_v1")
            .expect("embedded policy")
            .clone();
        invalid_score["cta_target_score"] = serde_json::json!(1.5);
        assert!(
            parse_credential_brand_target_policy(invalid_score).is_none(),
            "out-of-range policy scores must fail closed"
        );
    }
}
