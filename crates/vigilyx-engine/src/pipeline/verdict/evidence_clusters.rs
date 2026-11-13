use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock, RwLock};

use crate::semantic::is_current_recipient_action;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::{
    Bpa, EmailClassification, ModuleResult, SemanticClaim, classify_email_classification,
};

use crate::config::VerdictConfig;
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_keyword_list};

const ENGINE_MODULE_DATA_SEED_JSON: &str =
    include_str!("../../../../../shared/schemas/engine_module_data_seed.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EvidenceClusterId {
    InheritedGatewayPrior,
    DeliveryIntegrity,
    SenderIdentityAuthenticity,
    LinkAndHtmlDeception,
    PayloadMalware,
    ExternalReputationIoc,
    SocialEngineeringIntent,
    BusinessSensitivity,
}

impl EvidenceClusterId {
    pub const ALL: [Self; 8] = [
        Self::InheritedGatewayPrior,
        Self::DeliveryIntegrity,
        Self::SenderIdentityAuthenticity,
        Self::LinkAndHtmlDeception,
        Self::PayloadMalware,
        Self::ExternalReputationIoc,
        Self::SocialEngineeringIntent,
        Self::BusinessSensitivity,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::InheritedGatewayPrior => "inherited_gateway_prior",
            Self::DeliveryIntegrity => "delivery_integrity",
            Self::SenderIdentityAuthenticity => "sender_identity_authenticity",
            Self::LinkAndHtmlDeception => "link_and_html_deception",
            Self::PayloadMalware => "payload_malware",
            Self::ExternalReputationIoc => "external_reputation_ioc",
            Self::SocialEngineeringIntent => "social_engineering_intent",
            Self::BusinessSensitivity => "business_sensitivity",
        }
    }

    pub const fn score_cap(self) -> f64 {
        match self {
            Self::InheritedGatewayPrior => 0.35,
            Self::DeliveryIntegrity => 0.40,
            Self::SenderIdentityAuthenticity => 0.85,
            Self::LinkAndHtmlDeception => 0.90,
            Self::PayloadMalware => 0.95,
            Self::ExternalReputationIoc => 0.75,
            Self::SocialEngineeringIntent => 0.78,
            Self::BusinessSensitivity => 0.45,
        }
    }

    pub const fn confidence_scale(self) -> f64 {
        match self {
            Self::InheritedGatewayPrior => 0.45,
            Self::DeliveryIntegrity => 0.55,
            Self::SenderIdentityAuthenticity => 0.82,
            Self::LinkAndHtmlDeception => 0.86,
            Self::PayloadMalware => 0.92,
            Self::ExternalReputationIoc => 0.72,
            Self::SocialEngineeringIntent => 0.76,
            Self::BusinessSensitivity => 0.50,
        }
    }

    pub const fn threat_scale(self) -> f64 {
        match self {
            Self::InheritedGatewayPrior => 0.45,
            Self::DeliveryIntegrity => 0.55,
            Self::SenderIdentityAuthenticity => 1.0,
            Self::LinkAndHtmlDeception => 1.0,
            Self::PayloadMalware => 1.05,
            Self::ExternalReputationIoc => 0.85,
            Self::SocialEngineeringIntent => 0.92,
            Self::BusinessSensitivity => 0.45,
        }
    }
}

/// A single admitted source view. Preserve the score/confidence pair from
/// its producer; a cluster's aggregate is diagnostic, not a vote for each key.
#[derive(Debug, Clone)]
pub struct CausalAtom {
    pub causal_key: String,
    pub score: f64,
    pub confidence: f64,
    pub breaker_eligible: bool,
}

#[derive(Debug, Clone)]
pub struct ClusterEvidence {
    pub id: EvidenceClusterId,
    pub score: f64,
    // Aggregate diagnostics are retained only for normalizer regression tests.
    // Runtime constraints consume the attributed causal atoms below.
    #[cfg(test)]
    pub confidence: f64,
    /// Whether this cluster contains an independently strong signal allowed
    /// to activate the generic hard risk-floor circuit breaker.
    #[cfg(test)]
    pub breaker_eligible: bool,
    /// Stable causes represented by this cluster.  URL heuristics that point
    /// at the same target share one key, so DGA/path/TLD/intel aliases cannot
    /// manufacture independent convergence evidence.
    #[cfg(test)]
    pub causal_keys: Vec<String>,
    pub causal_atoms: Vec<CausalAtom>,
    #[cfg(test)]
    pub modules: Vec<String>,
    #[cfg(test)]
    pub key_factors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioContext {
    pub tags: Vec<String>,
    /// Content compounds whose actor/action/target relation and distinct
    /// source keys survived semantic admission. Labels alone cannot arm floors.
    pub qualified_content_compounds: BTreeSet<String>,
    /// Positive native categories that passed producer and runtime admission.
    /// Raw observations are retained separately and cannot arm risk floors.
    pub admitted_categories: BTreeSet<String>,
    pub qualified_link_compounds: BTreeSet<String>,
    /// Account content that actually contributed an admitted fusion signal.
    /// Retained subject-only observations cannot arm the account floors.
    pub has_admitted_content_account_signal: bool,
    /// One admitted recipient-action/target/brand relation. Its derivative
    /// categories are aliases of this native compound, not independent votes.
    pub qualified_credential_brand_target: bool,
    pub gateway_banner_polluted: bool,
    pub notice_banner_polluted: bool,
    pub dsn_like_system_mail: bool,
    pub auto_reply_like: bool,
    pub semantic_nlp_only_signal: bool,
    pub transcript_like_structure: bool,
    /// A weak image-only layout observation retained as zero-weight context.
    /// It becomes actionable only when qualified link categories corroborate it.
    pub image_only_layout_observed: bool,
    pub sender_alignment_verified: bool,
    pub has_header_spoof_signal: bool,
    pub has_payment_change_signal: bool,
    pub has_account_security_signal: bool,
    pub has_credential_link_signal: bool,
    pub has_high_risk_credential_target_signal: bool,
    pub has_brand_sender_target_mismatch_signal: bool,
    pub has_gateway_unwrapped_risky_target_signal: bool,
    pub has_malicious_ioc_signal: bool,
    pub has_subsidy_fraud_signal: bool,
    pub has_invoice_spam_signal: bool,
    pub has_crypto_wallet_signal: bool,
    pub has_attachment_phishing_signal: bool,
    pub has_attachment_sensitive_data_signal: bool,
    pub has_high_risk_attachment_content: bool,
    /// Structural threat signals independent of NLP/banner text pollution.
    /// Weak URL shape, tracking, redirect, and port observations are kept
    /// out; strong impersonation and qualified target signals remain here.
    pub has_structural_threat_signal: bool,
    pub alignment_score: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageOnlyPhishingMediumPolicy {
    pub enabled: bool,
    pub trigger_category: String,
    pub minimum_social_score: f64,
    pub verdict_floor: f64,
    pub require_unverified_sender: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HighConfidenceLinkImpersonationPolicy {
    pub enabled: bool,
    pub trigger_categories: Vec<String>,
    pub verdict_floor: f64,
}

fn parse_image_only_phishing_medium_policy(
    value: serde_json::Value,
) -> Option<ImageOnlyPhishingMediumPolicy> {
    let policy = serde_json::from_value::<ImageOnlyPhishingMediumPolicy>(value).ok()?;
    (policy.enabled
        && !policy.trigger_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.minimum_social_score)
        && (0.40..=1.0).contains(&policy.verdict_floor))
    .then_some(policy)
}

pub fn image_only_phishing_medium_policy() -> Option<ImageOnlyPhishingMediumPolicy> {
    parse_image_only_phishing_medium_policy(
        crate::module_data::module_data()
            .get_structured("image_only_phishing_medium_policy_v1")?
            .clone(),
    )
}

fn parse_high_confidence_link_impersonation_policy(
    value: serde_json::Value,
) -> Option<HighConfidenceLinkImpersonationPolicy> {
    let policy = serde_json::from_value::<HighConfidenceLinkImpersonationPolicy>(value).ok()?;
    (policy.enabled
        && !policy.trigger_categories.is_empty()
        && policy
            .trigger_categories
            .iter()
            .all(|category| !category.trim().is_empty())
        && (0.40..=1.0).contains(&policy.verdict_floor))
    .then_some(policy)
}

pub fn high_confidence_link_impersonation_policy() -> Option<HighConfidenceLinkImpersonationPolicy>
{
    parse_high_confidence_link_impersonation_policy(
        crate::module_data::module_data()
            .get_structured("high_confidence_link_impersonation_policy_v1")?
            .clone(),
    )
}

#[derive(Debug, Clone, Deserialize)]
pub struct ObfuscatedDomainLureVerdictPolicy {
    pub enabled: bool,
    pub result_category: String,
    pub minimum_social_score: f64,
    pub verdict_floor: f64,
}

fn parse_obfuscated_domain_lure_verdict_policy(
    value: serde_json::Value,
) -> Option<ObfuscatedDomainLureVerdictPolicy> {
    let policy = serde_json::from_value::<ObfuscatedDomainLureVerdictPolicy>(value).ok()?;
    (policy.enabled
        && !policy.result_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.minimum_social_score)
        && (0.40..=1.0).contains(&policy.verdict_floor))
    .then_some(policy)
}

pub fn obfuscated_domain_lure_verdict_policy() -> Option<ObfuscatedDomainLureVerdictPolicy> {
    parse_obfuscated_domain_lure_verdict_policy(
        crate::module_data::module_data()
            .get_structured("obfuscated_domain_lure_policy_v1")?
            .clone(),
    )
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredentialBrandTargetScenarioPolicy {
    pub enabled: bool,
    pub credential_link_category: String,
    pub high_risk_target_category: String,
    pub brand_mismatch_category: String,
    pub credential_link_scale: f64,
    pub brand_mismatch_scale: f64,
    pub redirect_target_category: String,
    pub redirect_target_scale: f64,
    pub redirect_target_floor: f64,
    pub minimum_redirect_link_score: f64,
    pub verdict_floor: f64,
    pub minimum_identity_score: f64,
    pub minimum_link_score: f64,
    pub minimum_social_score: f64,
}

fn parse_credential_brand_target_scenario_policy(
    value: serde_json::Value,
) -> Option<CredentialBrandTargetScenarioPolicy> {
    let policy = serde_json::from_value::<CredentialBrandTargetScenarioPolicy>(value).ok()?;
    (policy.enabled
        && !policy.credential_link_category.trim().is_empty()
        && !policy.high_risk_target_category.trim().is_empty()
        && !policy.brand_mismatch_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.credential_link_scale)
        && (0.0..=1.0).contains(&policy.brand_mismatch_scale)
        && !policy.redirect_target_category.trim().is_empty()
        && (0.0..=1.0).contains(&policy.redirect_target_scale)
        && (0.0..=1.0).contains(&policy.redirect_target_floor)
        && (0.0..=1.0).contains(&policy.minimum_redirect_link_score)
        && (0.0..=1.0).contains(&policy.verdict_floor)
        && (0.0..=1.0).contains(&policy.minimum_identity_score)
        && (0.0..=1.0).contains(&policy.minimum_link_score)
        && (0.0..=1.0).contains(&policy.minimum_social_score))
    .then_some(policy)
}

pub fn credential_brand_target_scenario_policy() -> Option<CredentialBrandTargetScenarioPolicy> {
    parse_credential_brand_target_scenario_policy(
        crate::module_data::module_data()
            .get_structured("credential_brand_target_policy_v1")?
            .clone(),
    )
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioPatternLists {
    pub gateway_banner_patterns: Vec<String>,
    pub notice_banner_patterns: Vec<String>,
    pub dsn_patterns: Vec<String>,
    pub auto_reply_patterns: Vec<String>,
}

impl From<&EffectiveKeywordLists> for ScenarioPatternLists {
    fn from(effective: &EffectiveKeywordLists) -> Self {
        Self {
            gateway_banner_patterns: effective.gateway_banner_patterns.clone(),
            notice_banner_patterns: effective.notice_banner_patterns.clone(),
            dsn_patterns: effective.dsn_patterns.clone(),
            auto_reply_patterns: effective.auto_reply_patterns.clone(),
        }
    }
}

static GLOBAL_SCENARIO_PATTERNS: OnceLock<Arc<RwLock<ScenarioPatternLists>>> = OnceLock::new();

fn scenario_patterns_handle() -> &'static Arc<RwLock<ScenarioPatternLists>> {
    GLOBAL_SCENARIO_PATTERNS.get_or_init(|| Arc::new(RwLock::new(ScenarioPatternLists::default())))
}

pub fn set_runtime_scenario_patterns(mut patterns: ScenarioPatternLists) {
    // This setter is also called directly by reload/test paths, so enforce the
    // same canonical matching representation as ContentScanModule instead of
    // relying on every caller to have passed through the seed builder.
    patterns.gateway_banner_patterns = normalize_keyword_list(&patterns.gateway_banner_patterns);
    patterns.notice_banner_patterns = normalize_keyword_list(&patterns.notice_banner_patterns);
    patterns.dsn_patterns = normalize_keyword_list(&patterns.dsn_patterns);
    patterns.auto_reply_patterns = normalize_keyword_list(&patterns.auto_reply_patterns);
    *scenario_patterns_handle()
        .write()
        .expect("scenario pattern lock poisoned") = patterns;
}

fn current_scenario_patterns() -> ScenarioPatternLists {
    scenario_patterns_handle()
        .read()
        .expect("scenario pattern lock poisoned")
        .clone()
}

pub fn runtime_scenario_patterns() -> ScenarioPatternLists {
    current_scenario_patterns()
}

#[derive(Debug, Clone)]
pub struct NormalizedEvidence {
    pub clusters: Vec<ClusterEvidence>,
    pub categories: Vec<String>,
    pub modules_run: u32,
    pub modules_flagged: u32,
    pub total_duration_ms: u64,
    pub scenario: ScenarioContext,
}

#[derive(Debug, Clone, Copy)]
struct MappedSignal {
    cluster: EvidenceClusterId,
    family: &'static str,
    scale: f64,
}

#[derive(Debug, Default)]
struct FamilyAccumulator {
    score: f64,
    confidence: f64,
    breaker_eligible: bool,
    categories: BTreeSet<String>,
    modules: BTreeSet<String>,
    factors: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct ClusterAccumulator {
    families: HashMap<String, FamilyAccumulator>,
    categories: BTreeSet<String>,
    modules: BTreeSet<String>,
    breaker_eligible: bool,
}

fn is_causally_deduplicated_url_signal(module_id: &str, category: &str) -> bool {
    match module_id {
        "link_content" => matches!(
            category,
            "suspicious_params"
                | "targeted_credential_phishing"
                | "dga_random_domain"
                | "gateway_unwrapped_risky_target"
                | "long_domain"
                | "deep_subdomain"
                | "random_domain"
                | "suspicious_tld"
                | "redirect_target"
                | "redirect_url"
                | "long_url"
                | "multiple_redirects"
                | "credential_link_lure"
                | "high_risk_credential_target"
                | "brand_sender_target_mismatch"
                | "idn_homograph"
                | "mixed_script_domain"
                | "at_sign_obfuscation"
                | "org_domain_mimicry"
                | "url_typo"
                | "hex_subdomain"
                | "encoded_separator"
                | "suspicious_path"
                | "credential_pathing"
                | "ip_action_target"
        ),
        "link_reputation" => matches!(
            category,
            "long_domain"
                | "deep_subdomain"
                | "random_domain"
                | "suspicious_tld"
                | "free_hosting"
                | "numeric_domain"
                | "embedded_ip"
                | "redirect_target"
                | "redirect_url"
                | "brand_impersonation"
                | "idn_homograph"
                | "mixed_script_domain"
                | "suspicious_path"
        ),
        _ => false,
    }
}

fn causal_family_name(result: &ModuleResult, category: &str, default_family: &str) -> String {
    if !is_causally_deduplicated_url_signal(&result.module_id, category) {
        return default_family.to_string();
    }

    let Some(entries) = result
        .details
        .get("causal_findings")
        .and_then(serde_json::Value::as_array)
    else {
        return default_family.to_string();
    };

    let mut keys = BTreeSet::new();
    for entry in entries {
        let Some(categories) = entry
            .get("categories")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        if !categories
            .iter()
            .any(|item| item.as_str() == Some(category))
        {
            continue;
        }
        if let Some(key) = entry.get("causal_key").and_then(serde_json::Value::as_str)
            && !key.trim().is_empty()
        {
            keys.insert(key.to_string());
        }
    }

    if keys.len() == 1 {
        format!(
            "url_structural:{}",
            keys.into_iter().next().unwrap_or_default()
        )
    } else {
        // Multiple hosts in one category are not safely collapsible without
        // an item-level key; preserve the existing conservative family.
        default_family.to_string()
    }
}

pub(super) fn is_runtime_causal_key(key: &str) -> bool {
    if key != key.trim() {
        return false;
    }
    let Some((source, value)) = key.split_once(':') else {
        return false;
    };
    !value.trim().is_empty()
        && !matches!(value, "unknown" | "unbound" | "none" | "not_observed")
        && matches!(
            source,
            "host"
                | "url"
                | "sender_ip"
                | "artifact"
                | "header_identity"
                | "compound_claim"
                | "body_relation"
                | "semantic_span"
                | "semantic_url"
                | "reply_target"
        )
}

fn causal_family_names(
    session: Option<&EmailSession>,
    result: &ModuleResult,
    category: &str,
    default_family: &str,
) -> Vec<String> {
    if result.module_id == "link_content" && governed_link_compound(category) {
        return qualified_link_claim_keys(result, category)
            .into_iter()
            .map(|key| format!("url_structural:{key}"))
            .collect();
    }
    if let Some(entries) = result
        .details
        .get("causal_findings")
        .and_then(serde_json::Value::as_array)
    {
        let keys = entries
            .iter()
            .filter(|entry| {
                entry
                    .get("categories")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|categories| {
                        categories
                            .iter()
                            .any(|value| value.as_str() == Some(category))
                    })
            })
            .filter_map(|entry| entry.get("causal_key").and_then(serde_json::Value::as_str))
            .filter(|key| is_runtime_causal_key(key))
            .collect::<BTreeSet<_>>();
        if !keys.is_empty() {
            return keys
                .into_iter()
                .map(|key| format!("url_structural:{key}"))
                .collect();
        }
    }
    if let Some(session) = session {
        let attachment_modules = matches!(
            result.module_id.as_str(),
            "av_attach_scan" | "attach_scan" | "attach_content"
        );
        if attachment_modules {
            let infected = result
                .details
                .get("infected_files")
                .and_then(serde_json::Value::as_array);
            let artifacts = session
                .content
                .attachments
                .iter()
                .filter(|attachment| {
                    attachment.hash.len() == 64
                        && attachment.hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                        && (infected.is_some_and(|files| {
                            files
                                .iter()
                                .any(|file| file.as_str() == Some(attachment.filename.as_str()))
                        }) || result.evidence.iter().any(|evidence| {
                            evidence.location.as_deref()
                                == Some(format!("attachment:{}", attachment.filename).as_str())
                        }))
                })
                .map(|attachment| {
                    format!(
                        "url_structural:artifact:{}",
                        attachment.hash.to_ascii_lowercase()
                    )
                })
                .collect::<BTreeSet<_>>();
            // A native antivirus verdict identifies each infected file. Other
            // producers have category-level summaries, so attribute only when
            // every actionable finding refers to the same retained artifact.
            if !artifacts.is_empty()
                && (artifacts.len() == 1
                    || (result.module_id == "av_attach_scan" && infected.is_some()))
            {
                return artifacts.into_iter().collect();
            }
        }
        if matches!(
            result.module_id.as_str(),
            "header_scan" | "identity_anomaly"
        ) && (!session.content.headers.is_empty() || session.mail_from.is_some())
        {
            let mut digest = Sha256::new();
            for value in session.mail_from.iter().map(String::as_str).chain(
                session
                    .content
                    .headers
                    .iter()
                    .flat_map(|(name, value)| [name.as_str(), value.as_str()]),
            ) {
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value.as_bytes());
            }
            return vec![format!(
                "url_structural:header_identity:{}",
                hex::encode(digest.finalize())
            )];
        }
    }
    if result.module_id == "content_scan"
        && matches!(
            category,
            "external_action_link_lure" | "pii_collection_lure"
        )
    {
        return qualified_content_claim_keys(result, category)
            .into_iter()
            .map(|key| format!("url_structural:{key}"))
            .collect();
    }
    vec![causal_family_name(result, category, default_family)]
}

/// One attributed producer finding. Scores belong to this concrete cause,
/// never to every category emitted by a module. Legacy summaries remain
/// explicitly distinguishable until their producers supply item-level scores.
#[derive(Debug, Clone)]
pub(super) struct AttributedFinding {
    pub causal_key: Option<String>,
    pub score: f64,
    pub confidence: f64,
    pub item_scored: bool,
}

pub(super) fn attributed_findings(
    session: Option<&EmailSession>,
    result: &ModuleResult,
    category: &str,
) -> Vec<AttributedFinding> {
    let strict = result.details.get("evidence_items_version").is_some();
    if strict && result.details["evidence_items_version"].as_u64() != Some(1) {
        return vec![];
    }
    let mass_inputs = |record: &serde_json::Value| {
        if result.module_id == "link_reputation"
            && matches!(category, "url_intel_suspicious" | "intel_suspicious")
        {
            let source = record
                .get("source")
                .or_else(|| (!strict).then(|| result.details.get("source")).flatten());
            if !source
                .and_then(serde_json::Value::as_str)
                .is_some_and(|source| {
                    source.split('+').map(str::trim).any(|part| {
                        !part.is_empty() && !matches!(part, "auto_reference" | "reference")
                    })
                })
            {
                return None;
            }
        }
        let item_scored = record.get("score").is_some();
        if strict && !item_scored {
            return None;
        }
        let score = if item_scored {
            record.get("score")?.as_f64()?
        } else {
            result.raw_score()
        };
        let confidence = if record.get("confidence").is_some() {
            record.get("confidence")?.as_f64()?
        } else if strict {
            return None;
        } else {
            result.confidence
        };
        (score.is_finite()
            && confidence.is_finite()
            && (0.0..=1.0).contains(&score)
            && (0.0..=1.0).contains(&confidence))
        .then_some((score, confidence, item_scored))
    };
    let mut findings = Vec::new();
    let qualified_field = if result.module_id == "link_content" && governed_link_compound(category)
    {
        Some("qualified_link_compounds")
    } else if result.module_id == "content_scan"
        && matches!(
            category,
            "external_action_link_lure" | "pii_collection_lure"
        )
    {
        Some("qualified_compounds")
    } else {
        None
    };
    if let Some(field) = qualified_field {
        for record in result.details[field].as_array().into_iter().flatten() {
            let key = if field == "qualified_link_compounds" {
                qualified_link_record_key(record, category)
            } else {
                // Reuse the exact semantic admission contract for each record;
                // a valid sibling record must not authorize an invalid one.
                let mut single = result.clone();
                single.details = serde_json::json!({"qualified_compounds": [record]});
                qualified_content_claim_keys(&single, category)
                    .into_iter()
                    .next()
            };
            if let Some(key) = key
                && let Some((score, confidence, item_scored)) = mass_inputs(record)
            {
                findings.push(AttributedFinding {
                    causal_key: Some(key),
                    score,
                    confidence,
                    item_scored,
                });
            }
        }
        return findings;
    }
    let mut matching_records = false;
    for record in result.details["causal_findings"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if !record["categories"].as_array().is_some_and(|categories| {
            categories
                .iter()
                .any(|value| value.as_str() == Some(category))
        }) {
            continue;
        }
        matching_records = true;
        let Some(key) = record["causal_key"]
            .as_str()
            .map(str::trim)
            .filter(|key| !key.is_empty())
        else {
            continue;
        };
        if strict && !is_runtime_causal_key(key) {
            continue;
        }
        if let Some((score, confidence, item_scored)) = mass_inputs(record) {
            findings.push(AttributedFinding {
                causal_key: Some(key.to_string()),
                score,
                confidence,
                item_scored,
            });
        }
    }
    if matching_records || strict {
        return findings;
    }
    let Some((score, confidence, item_scored)) = mass_inputs(&serde_json::Value::Null) else {
        return findings;
    };
    let family = map_signal(&result.module_id, category).map_or("legacy", |mapped| mapped.family);
    for key in causal_family_names(session, result, category, family) {
        findings.push(AttributedFinding {
            causal_key: key.strip_prefix("url_structural:").map(str::to_string),
            score,
            confidence,
            item_scored,
        });
    }
    findings
}

#[derive(Debug, Clone, Deserialize)]
struct EvidenceAdmissionPolicy {
    enabled: bool,
    #[serde(default)]
    diagnostic_only: HashMap<String, BTreeSet<String>>,
    #[serde(default)]
    observation_only: HashMap<String, BTreeSet<String>>,
}

impl EvidenceAdmissionPolicy {
    fn contains(
        tiers: &HashMap<String, BTreeSet<String>>,
        module_id: &str,
        category: &str,
    ) -> bool {
        tiers
            .get(module_id)
            .is_some_and(|categories| categories.contains(category))
    }

    fn is_diagnostic_only(&self, module_id: &str, category: &str) -> bool {
        Self::contains(&self.diagnostic_only, module_id, category)
    }

    fn is_observation_only(&self, module_id: &str, category: &str) -> bool {
        Self::contains(&self.observation_only, module_id, category)
    }
}

fn parse_evidence_admission_policy(value: serde_json::Value) -> Option<EvidenceAdmissionPolicy> {
    let policy = serde_json::from_value::<EvidenceAdmissionPolicy>(value).ok()?;
    let tiers_are_valid = policy
        .diagnostic_only
        .iter()
        .chain(policy.observation_only.iter())
        .all(|(module_id, categories)| {
            !module_id.trim().is_empty()
                && !categories.is_empty()
                && categories
                    .iter()
                    .all(|category| !category.trim().is_empty())
        });

    (policy.enabled
        && tiers_are_valid
        && (!policy.diagnostic_only.is_empty() || !policy.observation_only.is_empty()))
    .then_some(policy)
}

/// Use the compiled, versioned admission tiers when a runtime override is
/// missing or malformed. Keeping fallback categories in the shared JSON seed
/// prevents an invalid DB policy from silently restoring weak URL-shape
/// findings to threat fusion.
fn compiled_evidence_admission_policy() -> Option<&'static EvidenceAdmissionPolicy> {
    static POLICY: OnceLock<Option<EvidenceAdmissionPolicy>> = OnceLock::new();
    POLICY
        .get_or_init(|| {
            let seed =
                serde_json::from_str::<serde_json::Value>(ENGINE_MODULE_DATA_SEED_JSON).ok()?;
            let items = seed
                .get("lists")?
                .get("evidence_admission_policy_v1")?
                .get("items")?
                .clone();
            parse_evidence_admission_policy(items)
        })
        .as_ref()
}

/// Conservative Stage-A fallback for known weak observations.  The runtime
/// policy is authoritative when present, but a missing/malformed policy must
/// not silently promote URL shape noise into threat evidence.  Strong
/// categories (for example `url_intel_malicious`) are deliberately absent.
fn builtin_observation_only(result: &ModuleResult, category: &str) -> bool {
    if category == "inspection_coverage_incomplete" {
        return true;
    }
    if result.module_id == "link_content"
        && governed_link_compound(category)
        && qualified_link_claim_keys(result, category).is_empty()
    {
        return true;
    }
    match (result.module_id.as_str(), category) {
        ("content_scan", "external_action_link_lure" | "pii_collection_lure") => {
            !qualified_content_compound(result, category)
        }
        // Content-scan observations are deliberately retained in the final
        // category list even when the module is Safe, so the verdict explains
        // why the message was reviewed without turning context into fusion
        // belief.  Image-only layout keeps its historical scenario-only path.
        (
            "content_scan",
            "adult_content_observed"
            | "generic_lure_observed"
            | "empty_body_observed"
            | "html_visual_text_uncovered"
            | "html_external_visual_unresolved"
            | "transactional_notice"
            | "attachment_delivery_observed"
            | "invoice_spam",
        ) => true,
        ("url_sandbox_scan", "sandbox_url_network_observed" | "scan_incomplete") => true,
        ("process_sandbox_scan", "scan_incomplete") => true,
        // Attachment URL shape is retained for analyst context, but a raw IP
        // or generic auth-looking path alone is not fusion-grade evidence.
        ("attach_content", "attachment_url_shape_observation") => true,
        // Attachment content reuses the legacy generic labels, while the
        // attachment-specific URL/form/payload categories carry the actual
        // actionable anchor.
        ("attach_content", "phishing" | "bec" | "weak_phishing" | "bec_no_ioc_social") => true,
        // A legacy Office container (OLE) carrying a .docx name, or another
        // non-executable format drift, is a useful analyst observation but is
        // not independent malware evidence.  Keep this fallback aligned with
        // the versioned admission policy so persisted pre-policy registries do
        // not reintroduce the false-positive path.
        ("attach_scan", "mime_mismatch" | "type_mismatch") => true,
        // PDF JavaScript and ordinary form/navigation actions are useful
        // analyst context, but require a separately qualified payload signal
        // before they can contribute malicious belief.
        ("attach_scan", "active_content" | "pdf_active_content") => true,
        // Envelope/From disagreement is retained as an identity observation.
        // Forwarders, delegated senders, and gateway boundaries can produce it
        // without proving impersonation. Stronger identity or payload/link
        // evidence remains independently actionable.
        ("header_scan", "envelope_spoofing" | "protected_domain_spoof") => true,
        // A display-name mismatch is not an impersonation verdict by itself.
        // Keep the finding visible, but require an authority/brand/reply
        // anchor before it participates in fusion.
        ("header_scan" | "identity_anomaly", "display_name_spoof") => true,
        ("identity_anomaly", "envelope_mismatch") => true,
        (
            "identity_anomaly",
            "first_contact"
            | "new_sender_on_known_domain"
            | "random_domain"
            | "random_sender"
            | "suspicious_client",
        ) => true,
        ("link_content", "url_typo")
        | ("link_content", "recipient_in_url")
        | ("link_content", "suspicious_path")
        | ("link_content", "suspicious_params")
        | ("link_content", "long_url")
        | ("link_content", "long_domain")
        | ("link_content", "deep_subdomain")
        | ("link_content", "multiple_redirects")
        | ("link_content", "unusual_port")
        | ("link_content", "dga_random_domain")
        | ("link_content", "random_domain")
        | ("link_content", "suspicious_tld")
        | ("link_content", "tracking_parameter")
        | ("link_content", "hex_subdomain")
        | ("link_content", "encoded_separator")
        | ("link_content", "at_sign_obfuscation")
        | ("link_content", "org_domain_mimicry")
        | ("link_reputation", "random_domain")
        | ("link_reputation", "suspicious_tld")
        | ("link_reputation", "long_domain")
        | ("link_reputation", "deep_subdomain")
        | ("link_reputation", "unusual_port")
        | ("link_reputation", "free_hosting")
        | ("link_reputation", "numeric_domain")
        | ("link_reputation", "embedded_ip")
        | ("link_reputation", "suspicious_path")
        | ("link_reputation", "brand_impersonation")
        | ("link_reputation", "suspicious_sender_domain")
        | ("link_scan", "redirect_url")
        | ("link_scan", "suspicious_params")
        | ("link_scan", "excessive_links")
        | ("link_scan", "url_shortener")
        | ("link_scan", "unparseable_url") => true,
        // Auto/reference intel is a lookup hint, not an independent external
        // IOC.  Treat missing provenance conservatively as observation too.
        ("link_reputation", "url_intel_suspicious") | ("link_reputation", "intel_suspicious") => {
            !attributed_findings(None, result, category)
                .iter()
                .any(|item| item.score > 1e-12 && item.confidence > 1e-12)
        }
        // CSS hiding is useful coverage telemetry, but without an active
        // payload/target it is normal responsive-email structure rather than
        // fusion-grade threat evidence.
        ("html_scan", "css_hidden_content") => true,
        // Generic text labels are compatibility categories emitted by several
        // qualified detectors. The detector-specific compound category is the
        // actionable admission point; the generic label must not create a
        // second threat family or turn ordinary business vocabulary into a
        // phishing verdict.
        (
            "content_scan",
            "phishing"
            | "phishing_subject"
            | "phishing_no_ioc"
            | "bec_no_ioc_social"
            | "weak_phishing"
            | "phone_in_subject"
            | "phone_in_body"
            | "multilingual_gibberish"
            | "lang_inconsistency",
        ) => true,
        // Named no-IOC BEC compounds retain their high-score generic `bec`
        // label for backward compatibility. Low-score generic BEC results are
        // observations only; qualified results still fuse through
        // `bec_payment_change`, `bec_external_compound`, or their high-score
        // named compound evidence.
        ("content_scan", "bec") => {
            result.raw_score() < 0.70
                && !result.categories.iter().any(|candidate| {
                    matches!(
                        candidate.as_str(),
                        "bec_payment_change" | "bec_external_compound"
                    )
                })
        }
        // A subject-only keyword hit is a triage observation.  Account
        // phishing becomes actionable when the body, links, or another
        // evidence location supplies a recipient-facing operation/target.
        ("content_scan", "account_security_phishing") => {
            !result.evidence.is_empty()
                && result
                    .evidence
                    .iter()
                    .all(|e| e.location.as_deref() == Some("subject"))
        }
        _ => false,
    }
}

fn governed_link_compound(category: &str) -> bool {
    matches!(
        category,
        "targeted_credential_phishing"
            | "ip_action_target"
            | "qr_to_login_chain"
            | "qr_ip_login_chain"
            | "device_code_phishing"
            | "oauth_device_flow"
            | "auth_barrier_url"
            | "mobile_redirect"
    ) || credential_brand_target_scenario_policy().is_some_and(|policy| {
        category == policy.credential_link_category
            || category == policy.high_risk_target_category
            || category == policy.brand_mismatch_category
    })
}

fn qualified_link_record_key(record: &serde_json::Value, category: &str) -> Option<String> {
    if record.get("category").and_then(serde_json::Value::as_str) != Some(category) {
        return None;
    }
    let claim = serde_json::from_value::<SemanticClaim>(record.get("claim")?.clone()).ok()?;
    if !is_current_recipient_action(&claim)
        || claim.source_span_id.trim().is_empty()
        || claim.span.start_byte >= claim.span.end_byte
        || !claim.confidence.is_finite()
        || !(0.0..=1.0).contains(&claim.confidence)
    {
        return None;
    }
    let original = url::Url::parse(record.get("original_url")?.as_str()?).ok()?;
    let effective = url::Url::parse(record.get("effective_url")?.as_str()?).ok()?;
    if !matches!(original.scheme(), "http" | "https")
        || original.host_str().is_none()
        || !matches!(effective.scheme(), "http" | "https")
    {
        return None;
    }
    if !matches!(
        record
            .get("link_extraction_source")
            .and_then(serde_json::Value::as_str),
        Some("href" | "plain_text" | "html_text" | "form_action" | "qr")
    ) {
        return None;
    }
    let key = format!("host:{}", effective.host_str()?);
    (record.get("causal_key").and_then(serde_json::Value::as_str) == Some(key.as_str())
        && [
            "link_transport_status",
            "link_content_status",
            "link_ownership_status",
            "coverage_reason",
        ]
        .iter()
        .all(|field| {
            record
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        }))
    .then_some(key)
}

fn qualified_link_claim_keys(result: &ModuleResult, category: &str) -> BTreeSet<String> {
    result
        .details
        .get("qualified_link_compounds")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|record| qualified_link_record_key(record, category))
        .collect()
}

fn qualified_gateway_credential_relation(result: &ModuleResult) -> bool {
    let Some(policy) = credential_brand_target_scenario_policy() else {
        return false;
    };
    if !result.categories.contains(&policy.redirect_target_category) {
        return false;
    }
    let Some(records) = result
        .details
        .get("qualified_link_compounds")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let Some(observations) = result
        .details
        .get("credential_target_observations")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    records.iter().any(|record| {
        qualified_link_record_key(record, &policy.credential_link_category).is_some()
            && observations.iter().any(|observation| {
                observation
                    .get("gateway_unwrapped")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                    && observation.get("original_url") == record.get("original_url")
                    && observation.get("effective_url") == record.get("effective_url")
                    && record.get("original_url") != record.get("effective_url")
            })
    })
}

fn qualified_credential_brand_relation(result: &ModuleResult) -> bool {
    let Some(policy) = credential_brand_target_scenario_policy() else {
        return false;
    };
    let Some(records) = result
        .details
        .get("qualified_link_compounds")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    records.iter().any(|record| {
        if record.get("category").and_then(serde_json::Value::as_str)
            != Some(policy.brand_mismatch_category.as_str())
            || qualified_link_record_key(record, &policy.brand_mismatch_category).is_none()
        {
            return false;
        }
        let Some(proof) = record.get("brand_proof") else {
            return false;
        };
        if proof
            .get("sender_brand_aligned")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
            || proof
                .get("target_brand_aligned")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
            || ["claimed_brand", "from_domain", "target_domain"]
                .iter()
                .any(|field| {
                    proof
                        .get(field)
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(str::is_empty)
                })
        {
            return false;
        }
        let target_host = record
            .get("effective_url")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| url::Url::parse(raw).ok())
            .and_then(|url| url.host_str().map(str::to_string));
        if proof
            .get("target_domain")
            .and_then(serde_json::Value::as_str)
            != target_host.as_deref()
        {
            return false;
        }
        let span = record.pointer("/claim/source_span_id");
        let original = record.get("original_url");
        let effective = record.get("effective_url");
        [
            &policy.credential_link_category,
            &policy.high_risk_target_category,
        ]
        .iter()
        .all(|category| {
            records.iter().any(|candidate| {
                qualified_link_record_key(candidate, category).is_some()
                    && candidate.pointer("/claim/source_span_id") == span
                    && candidate.get("claim") == record.get("claim")
                    && candidate.get("original_url") == original
                    && candidate.get("effective_url") == effective
            })
        })
    })
}

fn has_admitted_identity_anchor(
    result: &ModuleResult,
    policy: Option<&EvidenceAdmissionPolicy>,
) -> bool {
    result.categories.iter().any(|candidate| {
        matches!(
            candidate.as_str(),
            "authority_display_name_lure"
                | "authority_localpart_lure"
                | "brand_spoof_reply_to"
                | "known_impersonation_domain"
                | "local_part_brand_spoof"
                | "reply_chain_anomaly"
        ) && !policy.is_some_and(|policy| {
            policy.is_diagnostic_only(&result.module_id, candidate)
                || policy.is_observation_only(&result.module_id, candidate)
        }) && !builtin_observation_only(result, candidate)
            && map_signal(&result.module_id, candidate).is_some()
    })
}

/// A producer's policy-excluded anchor cannot lend authority to its display
/// observation. Use the same gate for fusion and persisted classification.
fn observation_only_with_policy(
    result: &ModuleResult,
    category: &str,
    policy: Option<&EvidenceAdmissionPolicy>,
) -> bool {
    if policy.is_some_and(|policy| policy.is_observation_only(&result.module_id, category)) {
        return true;
    }
    if matches!(
        result.module_id.as_str(),
        "header_scan" | "identity_anomaly"
    ) && category == "display_name_spoof"
    {
        return !has_admitted_identity_anchor(result, policy);
    }
    builtin_observation_only(result, category)
}

/// A legacy label or malformed record is an observation, not an actionable
/// request. URL inspection/ownership may remain unknown, but that state must
/// be explicit and cannot be silently presented as a verified clean target.
fn qualified_content_compound(result: &ModuleResult, category: &str) -> bool {
    !qualified_content_claim_keys(result, category).is_empty()
}

/// A request and its observed destination form one cause. Do not count the
/// request span and URL as two independent clusters, or count two detector
/// names for the same compound as independent convergence evidence.
fn qualified_content_claim_keys(result: &ModuleResult, category: &str) -> BTreeSet<String> {
    result
        .details
        .get("qualified_compounds")
        .and_then(serde_json::Value::as_array)
        .map(|records| {
            records
                .iter()
                .filter_map(|record| {
                    let field = |name: &str| record.get(name).and_then(serde_json::Value::as_str);
                    let span = field("source_span_id")
                        .filter(|span| span.starts_with("body:") && span.len() > 5)?;
                    if field("category") != Some(category)
                        || field("actor_role") != Some("sender")
                        || field("target_role") != Some("recipient")
                        || !matches!(field("speech_act"), Some("request" | "instruction"))
                        || field("polarity") != Some("action")
                        || field("quote_or_forward_status") != Some("original")
                        || record
                            .get("counter_context_ids")
                            .and_then(serde_json::Value::as_array)
                            .is_none_or(|contexts| !contexts.is_empty())
                        || [
                            "link_transport_status",
                            "link_content_status",
                            "link_ownership_status",
                            "coverage_reason",
                        ]
                        .iter()
                        .any(|name| field(name).is_none_or(|value| value.trim().is_empty()))
                    {
                        return None;
                    }
                    let raw_keys = record
                        .get("causal_keys")
                        .and_then(serde_json::Value::as_array)?;
                    let keys: BTreeSet<&str> = raw_keys
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .filter(|key| !key.trim().is_empty())
                        .collect();
                    if keys.len() < 2 || keys.len() != raw_keys.len() || !keys.contains(span) {
                        return None;
                    }
                    let observed_target = match field("link_extraction_source") {
                        Some("href" | "plain_text" | "html_text" | "form_action") => {
                            field("original_url").is_some_and(|url| {
                                url::Url::parse(url).ok().is_some_and(|parsed| {
                                    matches!(parsed.scheme(), "http" | "https")
                                        && parsed.host_str().is_some()
                                })
                            }) && field("effective_url").is_some_and(|url| {
                                url::Url::parse(url).ok().is_some_and(|parsed| {
                                    matches!(parsed.scheme(), "http" | "https")
                                        && parsed.host_str().is_some()
                                })
                            }) && keys
                                .iter()
                                .any(|key| key.starts_with("url:") && key.len() > 4)
                        }
                        Some("none") if category == "pii_collection_lure" => field("reply_target")
                            .is_some_and(|target| {
                                target.starts_with("reply_target:")
                                    && target.len() > 13
                                    && keys.contains(target)
                            }),
                        _ => false,
                    };
                    if !observed_target {
                        return None;
                    }
                    if let Some(url) = field("effective_url")
                        && let Ok(parsed) = url::Url::parse(url)
                        && let Some(host) = parsed.host_str()
                    {
                        // URL-bearing content and link producers describe the
                        // same destination. The native request/URL proof stays
                        // in details; it does not establish a second cause.
                        return Some(format!("host:{host}"));
                    }
                    let mut digest = Sha256::new();
                    for key in keys {
                        // Length-prefixing makes the ordered compound unambiguous.
                        digest.update((key.len() as u64).to_be_bytes());
                        digest.update(key.as_bytes());
                    }
                    Some(format!("compound_claim:{}", hex::encode(digest.finalize())))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn evidence_admission_policy() -> Option<EvidenceAdmissionPolicy> {
    parse_evidence_admission_policy(
        crate::module_data::module_data()
            .get_structured("evidence_admission_policy_v1")?
            .clone(),
    )
}

fn admitted_classification_signal(
    result: &ModuleResult,
    category: &str,
    config: &VerdictConfig,
    policy: Option<&EvidenceAdmissionPolicy>,
) -> bool {
    let weight = config
        .weights
        .get(&result.module_id)
        .copied()
        .unwrap_or(1.0);
    result.threat_level > vigilyx_core::security::ThreatLevel::Safe
        && attributed_findings(None, result, category)
            .iter()
            .any(|item| (item.score * weight).clamp(0.0, 1.0) > 1e-12 && item.confidence > 1e-12)
        && !result.bpa.as_ref().is_some_and(|bpa| bpa.b <= 1e-12)
        && !policy.is_some_and(|policy| {
            policy.is_diagnostic_only(&result.module_id, category)
                || policy.is_observation_only(&result.module_id, category)
        })
        && !observation_only_with_policy(result, category, policy)
        && map_signal(&result.module_id, category).is_some()
}

/// Freeze the same category-level evidence admission used by classification.
/// V2 consumes this snapshot before forming artifact BPA values.
pub(super) fn actionable_fusion_categories(
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> BTreeSet<(String, String)> {
    let runtime = evidence_admission_policy();
    let policy = match runtime.as_ref() {
        Some(policy) => Some(policy),
        None => compiled_evidence_admission_policy(),
    };
    results
        .values()
        .flat_map(|result| {
            result
                .categories
                .iter()
                .filter(|category| admitted_classification_signal(result, category, config, policy))
                .map(|category| (result.module_id.clone(), category.clone()))
        })
        .collect()
}

fn attack_classification(category: &str) -> bool {
    matches!(
        classify_email_classification(&[category.to_string()]),
        EmailClassification::Malware
            | EmailClassification::Phishing
            | EmailClassification::Bec
            | EmailClassification::Impersonation
            | EmailClassification::Scam
            | EmailClassification::SocialEngineering
    )
}

/// Canonical top-level categories survive database reconstruction. Keep the
/// original labels in module results, but do not persist an attack
/// classification alias when its only producer supplied an observation.
/// Classification-only spam/transactional facts are intentionally unaffected.
pub(super) fn canonicalize_observed_attack_classification_categories(
    categories: &mut Vec<String>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> BTreeSet<String> {
    let runtime_policy = evidence_admission_policy();
    let policy = match runtime_policy.as_ref() {
        Some(policy) => Some(policy),
        None => compiled_evidence_admission_policy(),
    };
    canonicalize_observed_attack_classification_categories_with_policy(
        categories, results, config, policy,
    )
}

fn canonicalize_observed_attack_classification_categories_with_policy(
    categories: &mut Vec<String>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
    policy: Option<&EvidenceAdmissionPolicy>,
) -> BTreeSet<String> {
    let policy = match policy {
        Some(policy) => Some(policy),
        None => compiled_evidence_admission_policy(),
    };
    let mut observations = BTreeSet::new();
    for category in categories.iter_mut() {
        if !attack_classification(category)
            || !results.values().any(|result| {
                result.categories.contains(category)
                    && (result.module_id == "content_scan"
                        || (matches!(
                            result.module_id.as_str(),
                            "header_scan" | "identity_anomaly"
                        ) && category == "display_name_spoof")
                        || observation_only_with_policy(result, category, policy)
                        || policy.is_some_and(|policy| {
                            policy.is_diagnostic_only(&result.module_id, category)
                                || policy.is_observation_only(&result.module_id, category)
                        }))
            })
        {
            continue;
        }
        let supported = results.values().any(|result| {
            if !result.categories.contains(category) {
                return false;
            }
            if admitted_classification_signal(result, category, config, policy) {
                return true;
            }
            // A weak routing/display alias may describe a proven identity
            // attack only when the same producer also admitted an independent
            // registered identity anchor. A stale-date or first-contact fact
            // cannot supply that authority.
            if matches!(
                result.module_id.as_str(),
                "header_scan" | "identity_anomaly"
            ) && classify_email_classification(std::slice::from_ref(category))
                == EmailClassification::Impersonation
                && result.categories.iter().any(|candidate| {
                    matches!(
                        candidate.as_str(),
                        "authority_display_name_lure"
                            | "authority_localpart_lure"
                            | "brand_spoof_reply_to"
                            | "known_impersonation_domain"
                            | "local_part_brand_spoof"
                    ) && admitted_classification_signal(result, candidate, config, policy)
                })
            {
                return true;
            }
            // Generic labels are compatibility aliases for existing named
            // compounds, including PII reply harvesting whose specific name
            // is not a standalone entry in the core classification taxonomy.
            if !matches!(
                category.as_str(),
                "phishing" | "phishing_subject" | "phishing_no_ioc" | "bec" | "bec_no_ioc_social"
            ) {
                return false;
            }
            result.categories.iter().any(|candidate| {
                candidate.as_str() != category.as_str()
                    && admitted_classification_signal(result, candidate, config, policy)
                    && map_signal(&result.module_id, candidate).is_some_and(|mapped| {
                        !matches!(
                            mapped.cluster,
                            EvidenceClusterId::InheritedGatewayPrior
                                | EvidenceClusterId::DeliveryIntegrity
                        )
                    })
                    && !matches!(
                        classify_email_classification(std::slice::from_ref(candidate)),
                        EmailClassification::Spam
                            | EmailClassification::Business
                            | EmailClassification::Transactional
                            | EmailClassification::Marketing
                    )
            })
        });
        if !supported {
            observations.insert(category.clone());
            *category = "generic_lure_observed".to_string();
        }
    }
    categories.sort();
    categories.dedup();
    observations
}

pub fn normalize_results(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> NormalizedEvidence {
    // Load once per verdict so one message sees one internally consistent
    // admission policy even if module data is reloaded concurrently. Missing
    // or malformed policy uses the conservative built-in weak-observation
    // fallback below; it never promotes known URL shape noise.
    let admission_policy = evidence_admission_policy();
    normalize_results_with_admission_policy(session, results, config, admission_policy.as_ref())
}

fn normalize_results_with_admission_policy(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
    admission_policy: Option<&EvidenceAdmissionPolicy>,
) -> NormalizedEvidence {
    let admission_policy = match admission_policy {
        Some(policy) => Some(policy),
        None => compiled_evidence_admission_policy(),
    };
    let mut accumulators: HashMap<EvidenceClusterId, ClusterAccumulator> = HashMap::new();
    let mut categories = BTreeSet::new();
    let mut modules_run = 0u32;
    let mut modules_flagged = 0u32;
    let mut total_duration_ms = 0u64;
    let mut admitted_content_account_signal = false;
    let mut admitted_content_compounds = BTreeSet::new();
    let mut admitted_link_compounds = BTreeSet::new();
    let mut admitted_categories = BTreeSet::new();

    for result in results
        .values()
        .filter(|result| result.module_id != "verdict")
    {
        modules_run += 1;
        total_duration_ms += result.duration_ms;

        if result.threat_level <= vigilyx_core::security::ThreatLevel::Safe {
            for category in &result.categories {
                if observation_only_with_policy(result, category, admission_policy) {
                    categories.insert(category.clone());
                }
            }
            continue;
        }

        // A stale/legacy unsafe level must not turn a zero-belief diagnostic
        // result into threat evidence. Likewise, a module with no surviving
        // actionable categories has nothing eligible for fusion.
        let qualified_categories: Vec<&String> = result
            .categories
            .iter()
            .filter(|category| {
                !admission_policy
                    .is_some_and(|policy| policy.is_diagnostic_only(&result.module_id, category))
            })
            .collect();
        if result.bpa.as_ref().is_some_and(|bpa| bpa.b <= 1e-12) || qualified_categories.is_empty()
        {
            continue;
        }

        let module_weight = config
            .weights
            .get(&result.module_id)
            .copied()
            .unwrap_or(1.0);
        let mut module_actionable = false;
        for category in qualified_categories {
            categories.insert(category.clone());
            if observation_only_with_policy(result, category, admission_policy) {
                continue;
            }
            if let Some(mapped) = map_signal(&result.module_id, category) {
                let items = attributed_findings(session, result, category);
                let positive_content_evidence = items
                    .iter()
                    .any(|item| item.score * module_weight > 1e-12 && item.confidence > 1e-12);
                if !positive_content_evidence {
                    continue;
                }
                module_actionable = true;
                if positive_content_evidence {
                    admitted_categories.insert(category.clone());
                }
                if positive_content_evidence
                    && result.module_id == "link_content"
                    && governed_link_compound(category)
                {
                    admitted_link_compounds.insert(category.clone());
                }
                admitted_content_account_signal |= positive_content_evidence
                    && result.module_id == "content_scan"
                    && category == "account_security_phishing";
                if positive_content_evidence
                    && result.module_id == "content_scan"
                    && matches!(
                        category.as_str(),
                        "external_action_link_lure" | "pii_collection_lure"
                    )
                {
                    admitted_content_compounds.insert(category.clone());
                }
                let cluster = accumulators.entry(mapped.cluster).or_default();
                cluster.categories.insert(category.clone());
                cluster.modules.insert(result.module_id.clone());
                cluster.breaker_eligible |= is_breaker_eligible_signal(&result.module_id, category);

                for item in items {
                    let family_name = item.causal_key.map_or_else(
                        || causal_family_name(result, category, mapped.family),
                        |key| format!("url_structural:{key}"),
                    );
                    let family = cluster.families.entry(family_name).or_default();
                    let base_score = (item.score * module_weight).clamp(0.0, 1.0);
                    let confidence = item.confidence;
                    let score = (base_score * mapped.scale).clamp(0.0, 1.0);
                    let native = is_breaker_eligible_signal(&result.module_id, category);
                    let risk = Bpa::from_score_confidence(
                        (score.min(mapped.cluster.score_cap()) * mapped.cluster.threat_scale())
                            .min(1.0),
                        (confidence * mapped.cluster.confidence_scale()).clamp(0.20, 0.95),
                    )
                    .risk_score(config.eta);
                    let previous_risk = Bpa::from_score_confidence(
                        (family.score.min(mapped.cluster.score_cap())
                            * mapped.cluster.threat_scale())
                        .min(1.0),
                        (family.confidence * mapped.cluster.confidence_scale()).clamp(0.20, 0.95),
                    )
                    .risk_score(config.eta);
                    let order = risk
                        .total_cmp(&previous_risk)
                        .then_with(|| score.total_cmp(&family.score))
                        .then_with(|| confidence.total_cmp(&family.confidence))
                        .then_with(|| native.cmp(&family.breaker_eligible));
                    if family.categories.is_empty() || order.is_gt() {
                        family.score = score;
                        family.confidence = confidence;
                        family.breaker_eligible = native;
                    }
                    family.categories.insert(category.clone());
                    family.modules.insert(result.module_id.clone());
                    family
                        .factors
                        .insert(key_factor_for_signal(result, category));
                }
            }
        }
        // Preserve the public field for compatibility, but make its meaning
        // explicit: only modules that contributed at least one actionable
        // fusion signal count as flagged. Observation-only and diagnostic
        // results remain visible through categories/details instead of being
        // presented as threat-bearing modules.
        if module_actionable {
            modules_flagged += 1;
        }
    }

    // Context can annotate/cap a verdict, but cannot become a native floor
    // input merely because its diagnostic label survived persistence.
    let mut scenario_categories = admitted_categories.clone();
    scenario_categories.extend(
        categories
            .iter()
            .filter(|category| {
                matches!(
                    category.as_str(),
                    "gateway_pre_classified"
                        | "nlp_phishing"
                        | "nlp_scam"
                        | "nlp_bec"
                        | "nlp_spam"
                        | "nonsensical_spam"
                        | "image_only_layout_observed"
                        | "invoice_spam"
                )
            })
            .cloned(),
    );
    if let Some(policy) = credential_brand_target_scenario_policy()
        && admitted_link_compounds.contains(&policy.credential_link_category)
        && results.values().any(|result| {
            result.module_id == "link_content" && qualified_gateway_credential_relation(result)
        })
    {
        // Transport annotation stays outside native categories. It is legal
        // only for the same original/effective URL as an admitted CTA record.
        scenario_categories.insert(policy.redirect_target_category);
    }
    let mut scenario = detect_scenarios(session, &scenario_categories, results);
    scenario.has_admitted_content_account_signal = admitted_content_account_signal;
    scenario.qualified_content_compounds = admitted_content_compounds;
    scenario.admitted_categories = admitted_categories;
    scenario.qualified_link_compounds = admitted_link_compounds;
    scenario.qualified_credential_brand_target =
        results.get("link_content").is_some_and(|result| {
            result.raw_score() > 1e-12
                && result.confidence > 1e-12
                && qualified_credential_brand_relation(result)
        });
    if !scenario.sender_alignment_verified
        && !scenario.dsn_like_system_mail
        && !scenario.auto_reply_like
    {
        for compound in forged_sender_compounds(results, &scenario.admitted_categories) {
            scenario.admitted_categories.insert(compound.to_string());
            categories.insert(compound.to_string());
        }
    }
    let mut clusters = Vec::new();

    for cluster_id in EvidenceClusterId::ALL {
        let Some(cluster) = accumulators.remove(&cluster_id) else {
            continue;
        };
        if cluster.families.is_empty() {
            continue;
        }

        let runtime_families = cluster
            .families
            .iter()
            .filter(|(key, _)| {
                key.starts_with("url_structural:") || key.starts_with("compound_claim:")
            })
            .collect::<Vec<_>>();
        let unknown_score = cluster
            .families
            .iter()
            .filter(|(key, _)| {
                !key.starts_with("url_structural:") && !key.starts_with("compound_claim:")
            })
            .map(|(_, family)| family.score)
            .fold(0.0, f64::max);
        let base_score = 1.0
            - runtime_families
                .iter()
                .fold(1.0, |acc, (_, family)| acc * (1.0 - family.score));
        let synergy = (runtime_families.len().saturating_sub(1).min(3) as f64) * 0.04;
        // A category name cannot establish an independent source. Unknown
        // native observations retain their individual strength via max only.
        #[cfg(test)]
        let runtime_wins = base_score + synergy >= unknown_score;
        let mut score = (base_score + synergy)
            .max(unknown_score)
            .min(cluster_id.score_cap());
        // Structural URL heuristics can be numerous but are not independent
        // proof of credential theft. Keep a weak-only link cluster below High
        // until a breaker-eligible anchor is present.
        if cluster_id == EvidenceClusterId::LinkAndHtmlDeception && !cluster.breaker_eligible {
            score = score.min(0.44);
        }

        let causal_atoms = cluster
            .families
            .iter()
            .map(|(family_key, family)| {
                let causal_key = family_key
                    .strip_prefix("url_structural:")
                    .map_or_else(|| format!("family:{family_key}"), str::to_string);
                let mut atom_score = family.score.min(cluster_id.score_cap());
                if cluster_id == EvidenceClusterId::LinkAndHtmlDeception && !family.breaker_eligible
                {
                    atom_score = atom_score.min(0.44);
                }
                CausalAtom {
                    causal_key,
                    score: atom_score,
                    confidence: (family.confidence * cluster_id.confidence_scale())
                        .clamp(0.20, 0.95),
                    breaker_eligible: family.breaker_eligible,
                }
            })
            .collect::<Vec<_>>();
        #[cfg(test)]
        let causal_keys: BTreeSet<String> = causal_atoms
            .iter()
            .map(|atom| atom.causal_key.clone())
            .collect();
        #[cfg(test)]
        let (confidence, key_factors) = {
            let mut max_confidence: f64 = 0.0;
            let mut key_factors = BTreeSet::new();
            for (key, family) in &cluster.families {
                if (key.starts_with("url_structural:") || key.starts_with("compound_claim:"))
                    == runtime_wins
                {
                    max_confidence = max_confidence.max(family.confidence);
                }
                for factor in family.factors.iter().take(2) {
                    key_factors.insert(factor.clone());
                }
            }
            let confidence = ((max_confidence * cluster_id.confidence_scale())
                + if runtime_wins {
                    0.03 * (runtime_families.len().saturating_sub(1).min(3) as f64)
                } else {
                    0.0
                })
            .clamp(0.20, 0.95);
            (confidence, key_factors)
        };

        clusters.push(ClusterEvidence {
            id: cluster_id,
            score,
            #[cfg(test)]
            confidence,
            #[cfg(test)]
            breaker_eligible: cluster.breaker_eligible,
            #[cfg(test)]
            causal_keys: causal_keys.into_iter().collect(),
            causal_atoms,
            #[cfg(test)]
            modules: cluster.modules.into_iter().collect(),
            #[cfg(test)]
            key_factors: key_factors.into_iter().take(4).collect(),
        });
    }

    clusters.sort_by_key(|cluster| cluster.id);

    NormalizedEvidence {
        clusters,
        categories: categories.into_iter().collect(),
        modules_run,
        modules_flagged,
        total_duration_ms,
        scenario,
    }
}

/// Forged/unauthenticated sender plus an admitted account-security lure.
pub(super) const FORGED_SENDER_ACCOUNT_LURE: &str = "forged_sender_account_lure";
/// Forged sender plus a recipient-bound or obfuscated link, corroborated by a
/// High identity result or an admitted content lure.
pub(super) const FORGED_SENDER_LINK_LURE_CORROBORATED: &str =
    "forged_sender_link_lure_corroborated";
/// Forged sender plus a recipient-bound or obfuscated link.
pub(super) const FORGED_SENDER_LINK_LURE: &str = "forged_sender_link_lure";
/// Header envelope forgery, failed/missing authentication and a High identity result.
pub(super) const FORGED_SENDER_UNAUTHENTICATED: &str = "forged_sender_unauthenticated";

/// Named compounds over individually observation-only sender and link facts.
///
/// Envelope/From disagreement, a missing Received chain, randomised sender
/// names, a recipient address in a URL or a DGA-shaped link host each have
/// benign explanations (forwarders, ESPs, tracking links) and therefore never
/// enter fusion alone. Commodity credential phishing, delivery scams and
/// template spam combine them, and observed production samples ended Safe
/// because no module had admitted evidence. Facts are attributed to the module
/// that reported them, so a random *link* domain cannot stand in for a random
/// *sender* domain. Header and identity analysis describe one envelope, so
/// their facts are alternatives for a single forged-sender condition.
fn forged_sender_compounds(
    results: &HashMap<String, ModuleResult>,
    admitted: &BTreeSet<String>,
) -> Vec<&'static str> {
    let flagged = |module: &str, wanted: &[&str]| {
        results.get(module).is_some_and(|result| {
            result.threat_level > vigilyx_core::security::ThreatLevel::Safe
                && result
                    .categories
                    .iter()
                    .any(|category| wanted.contains(&category.as_str()))
        })
    };
    let forged_sender = flagged("header_scan", &["envelope_spoofing"])
        || flagged("identity_anomaly", &["envelope_mismatch"])
        || (flagged("header_scan", &["domain_mismatch"])
            && flagged("header_scan", &["no_received"]))
        || (flagged("identity_anomaly", &["random_domain"])
            && flagged("identity_anomaly", &["random_sender"]));
    if !forged_sender {
        return Vec::new();
    }
    // Tracking parameters, redirects and long URLs are ordinary marketing
    // structure; only recipient-bound or obfuscated destinations qualify.
    let targeted_link = flagged(
        "link_content",
        &[
            "recipient_in_url",
            "dga_random_domain",
            "url_typo",
            "at_sign_obfuscation",
            "org_domain_mimicry",
            "idn_homograph",
        ],
    ) || flagged(
        "link_scan",
        &["href_text_mismatch", "ip_url", "userinfo_in_url"],
    );
    let account_lure = admitted.contains("account_security_phishing")
        || admitted.contains("targeted_credential_phishing");
    let identity_high = results
        .get("identity_anomaly")
        .is_some_and(|result| result.threat_level >= vigilyx_core::security::ThreatLevel::High);
    let content_lure = results.get("content_scan").is_some_and(|result| {
        result.threat_level > vigilyx_core::security::ThreatLevel::Safe
            && result
                .categories
                .iter()
                .any(|category| !category.starts_with("gateway_") && admitted.contains(category))
    });
    let unauthenticated = flagged(
        "header_scan",
        &[
            "no_auth_results",
            "dkim_unverified",
            "untrusted_auth_results",
            "no_received",
        ],
    );

    let mut compounds = Vec::new();
    if account_lure {
        compounds.push(FORGED_SENDER_ACCOUNT_LURE);
    }
    if targeted_link {
        compounds.push(if identity_high || content_lure {
            FORGED_SENDER_LINK_LURE_CORROBORATED
        } else {
            FORGED_SENDER_LINK_LURE
        });
    }
    if identity_high && unauthenticated && flagged("header_scan", &["envelope_spoofing"]) {
        compounds.push(FORGED_SENDER_UNAUTHENTICATED);
    }
    compounds
}

fn detect_scenarios(
    session: Option<&EmailSession>,
    categories: &BTreeSet<String>,
    results: &HashMap<String, ModuleResult>,
) -> ScenarioContext {
    let scenario_patterns = current_scenario_patterns();
    detect_scenarios_with_patterns(session, categories, results, &scenario_patterns)
}

fn detect_scenarios_with_patterns(
    session: Option<&EmailSession>,
    categories: &BTreeSet<String>,
    results: &HashMap<String, ModuleResult>,
    scenario_patterns: &ScenarioPatternLists,
) -> ScenarioContext {
    let mut context = ScenarioContext {
        alignment_score: extract_alignment_score(results),
        ..ScenarioContext::default()
    };
    if let Some(result) = results.get("content_scan") {
        context.qualified_content_compounds = result
            .categories
            .iter()
            .filter(|category| {
                matches!(
                    category.as_str(),
                    "external_action_link_lure" | "pii_collection_lure"
                )
            })
            .filter(|category| qualified_content_compound(result, category))
            .cloned()
            .collect();
    }
    let credential_brand_policy = credential_brand_target_scenario_policy();

    if results.get("content_scan").is_some_and(|result| {
        result.categories.iter().any(|category| {
            matches!(
                category.as_str(),
                "image_only_phishing" | "image_only_layout_observed"
            )
        })
    }) {
        context.image_only_layout_observed = true;
        context.tags.push("image_only_layout_observed".to_string());
    }

    let subject_lower = session
        .and_then(|session| session.subject.as_deref())
        .unwrap_or_default()
        .to_lowercase();
    let body_lower = session
        .and_then(|session| session.content.body_text.as_deref())
        .unwrap_or_default()
        .to_lowercase();
    let sender_lower = session
        .and_then(|session| session.mail_from.as_deref())
        .unwrap_or_default()
        .to_lowercase();

    let has_gateway_prior = categories.contains("gateway_pre_classified");
    // Only genuine NLP model verdicts count as an echo of the polluted body.
    // `nonsensical_spam` is a purely statistical CJK observation that an
    // attacker can self-induce (rare/random characters); letting it qualify
    // would turn "statistical noise + forged body notice" into a 0.12 cap.
    let has_nlp_echo = categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "nlp_phishing" | "nlp_scam" | "nlp_bec" | "nlp_spam"
        )
    });
    // The banner pattern must actually appear in the body. A subject tag
    // alone ("[外部邮件]") costs an attacker nothing to add to their own
    // phishing mail, and a subject-only tag does not pollute the body text
    // that downstream NLP/content signals consume — treating it as gateway
    // pollution would hand attackers a one-word score cap.
    if has_gateway_prior
        && scenario_patterns
            .gateway_banner_patterns
            .iter()
            .any(|pattern| body_lower.contains(pattern))
    {
        context.gateway_banner_polluted = true;
        context.tags.push("gateway_banner_polluted".to_string());
    }

    // Same rule as the gateway banner above: the notice pattern must appear
    // in the body. A subject-only notice tag ("[警告：无法扫描邮件附件…]")
    // costs an attacker one subject line to add to their own BEC mail, and a
    // subject tag does not pollute the body text the NLP echo consumed —
    // treating it as notice pollution capped a pure-text payment-change mail
    // back to Safe (semantic_notice_only → min(0.12)).
    if has_nlp_echo
        && scenario_patterns
            .notice_banner_patterns
            .iter()
            .any(|pattern| body_lower.contains(pattern))
    {
        context.notice_banner_polluted = true;
        context.tags.push("notice_banner_polluted".to_string());
    }

    let has_auto_submitted_header = session.is_some_and(|session| {
        session.content.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("auto-submitted")
                && value.to_ascii_lowercase().contains("auto-")
        })
    });
    let is_system_sender = sender_lower.contains("mailer-daemon")
        || sender_lower.contains("postmaster")
        || sender_lower.contains("mail delivery system");
    // DSNs use an empty reverse-path (MAIL FROM:<>). Only an explicitly empty
    // or "<>" envelope counts — a missing envelope is unknown, not empty.
    let has_empty_return_path = session
        .and_then(|session| session.mail_from.as_deref())
        .is_some_and(|sender| {
            let trimmed = sender.trim();
            trimmed.is_empty() || trimmed == "<>"
        });
    let is_multipart_report = session.is_some_and(|session| {
        session.content.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value.to_ascii_lowercase().contains("multipart/report")
        })
    });
    let is_dsn_subject = scenario_patterns
        .dsn_patterns
        .iter()
        .any(|pattern| subject_lower.contains(pattern));
    let is_auto_reply_subject = scenario_patterns
        .auto_reply_patterns
        .iter()
        .any(|pattern| subject_lower.contains(pattern));
    // Every system-mail trait on its own costs an attacker one envelope
    // address or one header/subject line to forge (e.g. MAIL FROM:
    // <MAILER-DAEMON@...> on a plain-text BEC mail). Suppression therefore
    // requires at least two independent corroborating traits, or a
    // corroborated Auto-Submitted header (which already bundles two:
    // the header itself plus one of the traits below).
    let auto_submitted_corroborated = has_auto_submitted_header
        && (is_system_sender
            || has_empty_return_path
            || is_multipart_report
            || is_dsn_subject
            || is_auto_reply_subject);
    let dsn_trait_count = u8::from(is_system_sender)
        + u8::from(has_empty_return_path)
        + u8::from(is_multipart_report)
        + u8::from(is_dsn_subject);
    if auto_submitted_corroborated || dsn_trait_count >= 2 {
        context.dsn_like_system_mail = true;
        context.tags.push("dsn_like_system_mail".to_string());
    }

    let auto_reply_corroborated =
        is_auto_reply_subject && (is_system_sender || has_empty_return_path || is_multipart_report);
    if auto_submitted_corroborated || auto_reply_corroborated {
        context.auto_reply_like = true;
        context.tags.push("auto_reply_like".to_string());
    }

    let flagged_modules: Vec<&ModuleResult> = results
        .values()
        .filter(|result| {
            result.module_id != "verdict"
                && result.threat_level > vigilyx_core::security::ThreatLevel::Safe
        })
        .collect();
    let semantic_only_categories = categories.iter().all(|category| {
        matches!(
            category.as_str(),
            "nlp_phishing"
                | "nlp_scam"
                | "nlp_bec"
                | "nlp_spam"
                | "nonsensical_spam"
                | "foreign_to_cn_corp"
                | "japanese_to_cn_corp"
                | "japanese_unexpected"
        )
    });
    if !flagged_modules.is_empty()
        && flagged_modules
            .iter()
            .all(|result| result.module_id == "semantic_scan")
        && semantic_only_categories
    {
        context.semantic_nlp_only_signal = true;
        context.tags.push("semantic_nlp_only_signal".to_string());
    }
    if context.semantic_nlp_only_signal && has_transcript_like_structure(&body_lower) {
        context.transcript_like_structure = true;
        context.tags.push("transcript_like_structure".to_string());
    }

    if context.alignment_score >= 0.55 {
        context.sender_alignment_verified = true;
        context.tags.push("sender_alignment_verified".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "payment_change"
                | "bec_payment_change"
                | "wire_transfer"
                | "bank_account_detected"
                | "iban_detected"
                | "swift_code_detected"
                | "crypto_wallet"
        )
    }) {
        context.has_payment_change_signal = true;
        context.tags.push("payment_change_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "account_security_phishing"
                | "targeted_credential_phishing"
                | "subject_account_expiry_lure"
        )
    }) || credential_brand_policy
        .as_ref()
        .is_some_and(|policy| categories.contains(policy.credential_link_category.as_str()))
    {
        context.has_account_security_signal = true;
        context.tags.push("account_security_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "targeted_credential_phishing"
                | "attachment_phishing_url"
                | "device_code_phishing_combo"
                | "aitm_hosted_platform_auth"
                | "aitm_hosted_credential_lure"
                | "aitm_brand_subdomain_login"
                | "aitm_brand_path_login"
                | "aitm_homograph_login"
                | "aitm_hosted_brand_lure"
                | "aitm_compound_platform_mfa"
                | "aitm_compound_brand_captcha"
                | "aitm_compound_redirect_mfa"
                | "aitm_multi_convergence"
        )
    }) || credential_brand_policy
        .as_ref()
        .is_some_and(|policy| categories.contains(policy.credential_link_category.as_str()))
    {
        context.has_credential_link_signal = true;
        context.tags.push("credential_link_signal".to_string());
    }

    if credential_brand_policy
        .as_ref()
        .is_some_and(|policy| categories.contains(policy.high_risk_target_category.as_str()))
    {
        context.has_high_risk_credential_target_signal = true;
        context
            .tags
            .push("high_risk_credential_target_signal".to_string());
    }

    if credential_brand_policy
        .as_ref()
        .is_some_and(|policy| categories.contains(policy.brand_mismatch_category.as_str()))
    {
        context.has_brand_sender_target_mismatch_signal = true;
        context
            .tags
            .push("brand_sender_target_mismatch_signal".to_string());
    }

    // A gateway-unwrapped target is transport provenance plus a structural
    // observation.  It becomes a scenario signal only when an independent
    // account/credential cue is present; otherwise a redirect wrapper must
    // not manufacture an actionable threat on its own.
    if credential_brand_policy.as_ref().is_some_and(|policy| {
        categories.contains(policy.redirect_target_category.as_str())
            && (context.has_account_security_signal
                || context.has_credential_link_signal
                || context.has_high_risk_credential_target_signal
                || context.has_brand_sender_target_mismatch_signal)
    }) {
        context.has_gateway_unwrapped_risky_target_signal = true;
        context
            .tags
            .push("gateway_unwrapped_risky_target_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "ioc_ip_hit"
                | "sender_ip_malicious"
                | "intel_malicious"
                | "url_intel_malicious"
                | "hash_intel_malicious"
        )
    }) {
        context.has_malicious_ioc_signal = true;
        context.tags.push("malicious_ioc_signal".to_string());
    }

    // Structural threat signals that are independent of NLP/banner text.
    // These come from DNS, header analysis, attachment analysis etc.,
    // NOT from scanning email body text (which the gateway banner pollutes).
    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "brand_spoof_reply_to"
                | "protected_domain_spoof"
                | "envelope_spoofing"
                | "display_name_spoof"
                | "authority_display_name_lure"
                | "authority_localpart_lure"
                | "external_impersonation"
                | "domain_mismatch"
        )
    }) {
        context.has_header_spoof_signal = true;
        context.tags.push("header_spoof_signal".to_string());
    }

    if categories.contains("subsidy_fraud") {
        context.has_subsidy_fraud_signal = true;
        context.tags.push("subsidy_fraud_signal".to_string());
    }

    if categories.contains("invoice_spam") || categories.contains("invoice_fraud") {
        context.has_invoice_spam_signal = true;
        context.tags.push(if categories.contains("invoice_fraud") {
            "invoice_fraud_signal".to_string()
        } else {
            "invoice_spam_signal".to_string()
        });
    }

    if categories
        .iter()
        .any(|category| matches!(category.as_str(), "crypto_wallet" | "ransomware_indicator"))
    {
        context.has_crypto_wallet_signal = true;
        context.tags.push("crypto_wallet_signal".to_string());
    }

    if let Some(attach_result) = results.get("attach_content") {
        if attach_result.categories.iter().any(|category| {
            matches!(
                category.as_str(),
                "phishing" | "bec" | "weak_phishing" | "attachment_phishing_url"
            )
        }) {
            context.has_attachment_phishing_signal = true;
            context.tags.push("attachment_phishing_signal".to_string());
        }
        if attach_result
            .categories
            .iter()
            .any(|category| matches!(category.as_str(), "dlp_credit_card" | "dlp_id_number"))
        {
            context.has_attachment_sensitive_data_signal = true;
            context
                .tags
                .push("attachment_sensitive_data_signal".to_string());
        }
        if attach_result.threat_level >= vigilyx_core::security::ThreatLevel::High {
            context.has_high_risk_attachment_content = true;
            context
                .tags
                .push("high_risk_attachment_content".to_string());
        }
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "external_impersonation"
                | "domain_mismatch"
                | "idn_homograph"
                | "mixed_script_domain"
                | "at_sign_obfuscation"
                | "org_domain_mimicry"
                | "url_typo"
                | "attachment_phishing_url"
                | "ip_action_target"
        )
    }) || context.has_high_risk_credential_target_signal
        || context.has_brand_sender_target_mismatch_signal
    {
        context.has_structural_threat_signal = true;
        context.tags.push("structural_threat_signal".to_string());
    }

    context
}

fn has_transcript_like_structure(text: &str) -> bool {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() < 4 {
        return false;
    }

    let short_lines = lines
        .iter()
        .filter(|line| line.chars().count() <= 48)
        .count();
    let speaker_turns = lines
        .iter()
        .filter(|line| looks_like_speaker_turn(line))
        .count();
    let timestamps = lines
        .iter()
        .filter(|line| contains_timestamp_like_pattern(line))
        .count();

    short_lines * 2 >= lines.len() && (speaker_turns >= 2 || timestamps >= 2)
}

fn looks_like_speaker_turn(line: &str) -> bool {
    let mut parts = line.splitn(2, ['：', ':']);
    let Some(prefix) = parts.next().map(str::trim) else {
        return false;
    };
    let Some(content) = parts.next().map(str::trim) else {
        return false;
    };

    let prefix_len = prefix.chars().count();
    let content_len = content.chars().count();
    (1..=24).contains(&prefix_len)
        && (1..=120).contains(&content_len)
        && !prefix.chars().all(|ch| ch.is_ascii_digit())
}

fn contains_timestamp_like_pattern(line: &str) -> bool {
    let chars: Vec<char> = line.chars().collect();
    chars.windows(5).any(|window| {
        window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2] == ':'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
    })
}

fn key_factor_for_signal(result: &ModuleResult, category: &str) -> String {
    if result.categories.len() <= 1 {
        return result
            .evidence
            .first()
            .map(|e| e.description.clone())
            .unwrap_or_else(|| humanize_category(category));
    }

    humanize_category(category)
}

fn humanize_category(category: &str) -> String {
    match category {
        "account_security_phishing" => return "Account Security Phishing".to_string(),
        "credential_link_lure" => return "Credential Verification Link Lure".to_string(),
        "high_risk_credential_target" => return "High-Risk Credential Target".to_string(),
        "brand_sender_target_mismatch" => {
            return "Brand, Sender, and Landing Domain Mismatch".to_string();
        }
        "gateway_unwrapped_risky_target" => {
            return "Risky Gateway-Unwrapped Target".to_string();
        }
        "targeted_credential_phishing" => return "Targeted Credential Phishing".to_string(),
        "bec" => return "Business Email Compromise".to_string(),
        "gateway_pre_classified" => return "Upstream Gateway Prior".to_string(),
        "subject_contact_lure" => return "Subject Contact Lure".to_string(),
        "mailbox_enumeration_probe" => return "Mailbox Enumeration Probe".to_string(),
        "adult_content_lure" => return "Adult-Content Lure".to_string(),
        "adult_content_observed" => return "Adult-Content Observation".to_string(),
        "generic_lure_observed" => return "Generic Lure Observation".to_string(),
        "empty_body_observed" => return "Empty Body Observation".to_string(),
        "ioc_ip_hit" => return "IOC-Matched Sender IP".to_string(),
        "sender_ip_malicious" => return "Malicious Sender IP".to_string(),
        "intel_malicious" => return "Malicious External Intel Match".to_string(),
        "url_intel_malicious" => return "Malicious URL Intel Match".to_string(),
        "dlp_api_key" => return "DLP API Key Exposure".to_string(),
        _ => {}
    }

    category
        .split('_')
        .map(|segment| {
            if segment.eq_ignore_ascii_case("ioc") || segment.eq_ignore_ascii_case("dlp") {
                segment.to_ascii_uppercase()
            } else {
                let mut chars = segment.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn extract_alignment_score(results: &HashMap<String, ModuleResult>) -> f64 {
    results
        .get("domain_verify")
        .filter(|result| result.details.get("verified").and_then(|v| v.as_bool()) == Some(true))
        .and_then(|result| result.details.get("trust_score"))
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0)
        .clamp(0.0, 1.0)
}

fn map_signal(module_id: &str, category: &str) -> Option<MappedSignal> {
    match module_id {
        "domain_verify" => None,
        "content_scan" => map_content_signal(category),
        "attach_content" => map_attach_content_signal(category),
        "attach_scan" => match category {
            // Coverage gaps and generic active-content labels are retained for
            // analysts, but only a qualified payload category enters the
            // Payload Malware evidence cluster.
            "attachment_inspection_limited"
            | "unsupported_container"
            | "encrypted_attachment"
            | "encrypted_archive"
            | "encrypted_pdf"
            | "ocr_unavailable"
            | "active_content"
            | "pdf_active_content" => None,
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::PayloadMalware,
                family: "attachment_anomaly",
                scale: 0.72,
            }),
        },
        "attach_hash" => match category {
            "hash_intel_malicious" | "hash_intel_suspicious" => Some(MappedSignal {
                cluster: EvidenceClusterId::ExternalReputationIoc,
                family: "hash_reputation",
                scale: 0.82,
            }),
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::PayloadMalware,
                family: "malware_signature",
                scale: 0.92,
            }),
        },
        "av_eml_scan" | "av_attach_scan" | "sandbox_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "malware_signature",
            scale: 0.95,
        }),
        "url_sandbox_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "dynamic_url_sandbox",
            scale: 0.92,
        }),
        "yara_scan" => map_yara_signal(category),
        "header_scan" => map_header_signal(category),
        "mime_scan" => match category {
            // Parser/capture quality notes are surfaced separately and must
            // not create a delivery-threat cluster on their own.
            "missing_content_type" | "missing_from" | "missing_to" | "empty_subject" => None,
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::DeliveryIntegrity,
                family: "mime_integrity",
                scale: 0.58,
            }),
        },
        "identity_anomaly" => map_identity_signal(category),
        "aitm_detect" => map_aitm_signal(category),
        "html_scan" | "html_pixel_art" => {
            let credential_exfiltration = module_id == "html_scan"
                && crate::modules::html_scan::is_credential_exfiltration_form_category(category);
            Some(MappedSignal {
                cluster: EvidenceClusterId::LinkAndHtmlDeception,
                family: if credential_exfiltration {
                    "credential_exfiltration"
                } else {
                    "html_obfuscation"
                },
                scale: if credential_exfiltration { 0.92 } else { 0.74 },
            })
        }
        "link_scan" => map_link_scan_signal(category),
        "link_content" => map_link_content_signal(category),
        "link_reputation" => map_link_reputation_signal(category),
        "semantic_scan" => map_semantic_signal(category),
        "toad_detect" => map_toad_signal(category),
        "anomaly_detect" => match category {
            "no_recipients" | "recipient_metadata_incomplete" => None,
            "mailbox_enumeration_probe" => Some(MappedSignal {
                cluster: EvidenceClusterId::SenderIdentityAuthenticity,
                family: "recipient_enumeration",
                scale: 0.76,
            }),
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::SocialEngineeringIntent,
                family: "behavioral_pattern",
                scale: 0.52,
            }),
        },
        "transaction_correlation" => match category {
            "payment_change" => Some(MappedSignal {
                cluster: EvidenceClusterId::BusinessSensitivity,
                family: transaction_family(category),
                scale: transaction_scale(category),
            }),
            // A bank/account noun without a change instruction is business
            // context, not BEC evidence.
            "bank_account_detected" | "financial_entity" | "amount_reference" => None,
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::BusinessSensitivity,
                family: transaction_family(category),
                scale: transaction_scale(category),
            }),
        },
        _ => map_fallback_signal(category),
    }
}

fn map_content_signal(category: &str) -> Option<MappedSignal> {
    if let Some(policy) = credential_brand_target_scenario_policy()
        && category == policy.credential_link_category
    {
        return Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "credential_lure",
            scale: policy.credential_link_scale,
        });
    }
    match category {
        "gateway_pre_classified" => Some(MappedSignal {
            cluster: EvidenceClusterId::InheritedGatewayPrior,
            family: "gateway_banner",
            scale: 0.18,
        }),
        // DLP categories are recorded in verdict.categories for compliance visibility
        // but excluded from threat scoring — for banks, credit card / ID numbers in email
        // are normal business, not security threats.
        "dlp_credit_card" | "dlp_id_number" | "dlp_api_key" => None,
        "external_impersonation" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "external_impersonation",
            scale: 0.78,
        }),
        "pii_reply_harvest_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "pii_collection_lure",
            scale: 0.86,
        }),
        "external_reply_to_social_engineering" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "external_reply_to_social_engineering",
            scale: 0.90,
        }),
        "external_identity_consent_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "external_identity_consent_lure",
            scale: 0.86,
        }),
        "external_internal_service_link" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "external_internal_service_link",
            scale: 0.84,
        }),
        // Payment-account-change BEC from an external sender (detectors.rs
        // emits this with a score of up to 0.78) is concrete business
        // sensitivity evidence — it must not be dropped on the floor.
        "bec_payment_change" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: transaction_family(category),
            scale: transaction_scale(category),
        }),
        "bec_external_compound" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: "external_bec_compound",
            scale: 0.82,
        }),
        "qr_text_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "text_qr_lure",
            scale: 0.82,
        }),
        "clickfix_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "clickfix_command_paste",
            scale: 0.92,
        }),
        "base_href_action_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "html_base_href_redirect",
            scale: 0.82,
        }),
        "social_trust_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "social_trust_payment_lure",
            scale: 0.78,
        }),
        "targeted_recruitment_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "targeted_recruitment_spearphish",
            scale: 0.78,
        }),
        "image_alt_phishing" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "image_alt_credential_lure",
            scale: 0.84,
        }),
        "embedded_image_qr_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "embedded_image_qr_lure",
            scale: 0.84,
        }),
        "embedded_iframe_auth_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "embedded_iframe_auth_lure",
            scale: 0.86,
        }),
        "external_action_link_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "external_action_link_lure",
            scale: 0.82,
        }),
        "credential_exfiltration_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "credential_exfiltration_lure",
            scale: 0.86,
        }),
        "protocol_execution_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "protocol_execution_lure",
            scale: 0.92,
        }),
        "hidden_external_action_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "hidden_external_action_lure",
            scale: 0.82,
        }),
        "attachment_delivery_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "attachment_delivery_lure",
            scale: 0.78,
        }),
        "subject_contact_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "off_platform_contact_lure",
            scale: 0.50,
        }),
        "subject_account_expiry_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "subject_account_expiry_lure",
            scale: 0.78,
        }),
        "bec"
        | "image_only_phishing"
        | "account_security_phishing"
        | "pii_collection_lure"
        | "subsidy_fraud"
        | "invoice_fraud"
        | "adult_content_lure"
        | "obfuscated_domain_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: social_family(category),
            scale: social_scale(category),
        }),
        _ => None,
    }
}

fn map_attach_content_signal(category: &str) -> Option<MappedSignal> {
    match category {
        // DLP in attachments: same policy — record but don't score
        "dlp_credit_card"
        | "dlp_id_number"
        | "nested_message_observed"
        | "attachment_business_keyword_observation"
        | "attachment_url_shape_observation" => None,
        "attachment_phishing_url" | "attachment_redirect_lure" | "attachment_payment_lure" => {
            Some(MappedSignal {
                cluster: EvidenceClusterId::LinkAndHtmlDeception,
                family: "attachment_embedded_url",
                scale: 0.74,
            })
        }
        // A meta-refresh target inside an HTML attachment is the same kind of
        // embedded-URL evidence as a phishing URL — one family, one signal.
        "attachment_meta_refresh" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_embedded_url",
            scale: 0.70,
        }),
        "ics_url_credential_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_calendar_credential_lure",
            scale: 0.82,
        }),
        "attachment_contact_redirect" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_contact_redirect",
            scale: 0.76,
        }),
        "attachment_credential_form" | "nested_message_phishing" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_embedded_phishing",
            scale: 0.86,
        }),
        "office_active_content_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "office_active_content_lure",
            scale: 0.86,
        }),
        "security_rule_archive_lure" | "svg_active_content" | "external_executable_attachment" => {
            Some(MappedSignal {
                cluster: EvidenceClusterId::PayloadMalware,
                family: "attachment_active_payload",
                scale: 0.88,
            })
        }
        "ics_embedded_executable" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "attachment_embedded_payload",
            scale: 0.80,
        }),
        "dangerous_container_lure"
        | "html_smuggling"
        | "polyglot_container"
        | "executable_delivery_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "attachment_active_container_lure",
            scale: 0.86,
        }),
        "ics_urgency" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "attachment_weak_phishing",
            scale: 0.42,
        }),
        "phishing" | "bec" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: social_family(category),
            scale: 0.74,
        }),
        "weak_phishing" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "attachment_weak_phishing",
            scale: 0.42,
        }),
        _ => None,
    }
}

fn map_header_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "ioc_ip_hit" | "sender_ip_malicious" | "sender_ip_suspicious" => Some(MappedSignal {
            cluster: EvidenceClusterId::ExternalReputationIoc,
            family: "sender_ip_reputation",
            scale: if category == "sender_ip_malicious" {
                0.88
            } else {
                0.72
            },
        }),
        // This is a routing mismatch, not proof of impersonation. Keep the
        // category visible and let an independently qualified identity or
        // content relation establish an actionable verdict.
        "envelope_spoofing" | "protected_domain_spoof" => None,
        // Outsourced reply handling is common in legitimate marketing and
        // transactional mail. Preserve the mismatch in verdict categories
        // and scenario context, but do not manufacture an identity cluster
        // from this routing observation alone. Compound spoof/lure scenarios
        // still consume `has_header_spoof_signal` below.
        "domain_mismatch" => None,
        "brand_spoof_reply_to"
        | "known_impersonation_domain"
        | "display_name_spoof"
        | "authority_display_name_lure"
        | "authority_localpart_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "protected_identity",
            scale: if category.starts_with("authority_") {
                0.92
            } else {
                0.80
            },
        }),
        // X-Mailer is a self-declared client fingerprint. It is useful
        // analyst context, but it has no independent malicious meaning and
        // therefore cannot enter D-S even when another header fact makes the
        // module result non-Safe.
        "suspicious_mailer" => None,
        "auth_spf_dmarc_fail"
        | "auth_spf_fail"
        | "auth_dmarc_fail"
        | "future_date"
        | "stale_date"
        | "missing_date"
        | "missing_message_id"
        | "excessive_hops"
        | "header_injection" => Some(MappedSignal {
            cluster: EvidenceClusterId::DeliveryIntegrity,
            family: delivery_family(category),
            scale: delivery_scale(category),
        }),
        _ => None,
    }
}

fn map_identity_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "display_name_spoof" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "display_name",
            scale: 0.82,
        }),
        "envelope_mismatch" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "envelope_alignment",
            scale: 0.64,
        }),
        "reply_chain_anomaly" | "suspicious_client" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "mail_client_identity",
            scale: 0.64,
        }),
        "first_contact" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "sender_novelty",
            scale: 0.42,
        }),
        "random_domain" | "random_sender" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "sender_randomness",
            // Domain shape alone is weak; reputation, auth, content or link
            // corroboration must provide the actionable signal.
            scale: 0.50,
        }),
        _ => None,
    }
}

fn map_aitm_signal(category: &str) -> Option<MappedSignal> {
    let (family, scale) = match category {
        "device_code_phishing_combo" => ("device_code_phishing", 0.92),
        "device_code_login_url" | "device_code_user_code" | "device_code_enter_phrase" => {
            ("device_code_phishing", 0.55)
        }
        "aitm_hosted_platform_auth"
        | "aitm_hosted_credential_lure"
        | "aitm_brand_subdomain_login"
        | "aitm_brand_path_login"
        | "aitm_homograph_login"
        | "aitm_hosted_brand_lure" => ("credential_proxy", 0.82),
        "aitm_mfa_bait" | "aitm_mfa_urgency" => ("weak_link_context", 0.70),
        "aitm_captcha_auth" | "aitm_turnstile_body" => ("credential_lure", 0.70),
        "oauth_redirect_hijack" | "oauth_redirect_to_aitm" | "aitm_redirect_chain" => {
            ("oauth_redirect", 0.78)
        }
        "aitm_compound_platform_mfa"
        | "aitm_compound_brand_captcha"
        | "aitm_compound_redirect_mfa"
        | "aitm_multi_convergence" => ("aitm_convergence", 0.88),
        "aitm_platform_login" | "aitm_platform_domain" | "aitm_subdomain_auth" => {
            ("credential_proxy", 0.58)
        }
        _ => return None,
    };

    Some(MappedSignal {
        cluster: EvidenceClusterId::LinkAndHtmlDeception,
        family,
        scale,
    })
}

fn map_link_content_signal(category: &str) -> Option<MappedSignal> {
    if category == "ip_action_target" {
        return Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "ip_action_target",
            scale: 0.92,
        });
    }
    if let Some(policy) = credential_brand_target_scenario_policy() {
        if category == policy.brand_mismatch_category {
            return Some(MappedSignal {
                cluster: EvidenceClusterId::SenderIdentityAuthenticity,
                family: "brand_target_alignment",
                scale: policy.brand_mismatch_scale,
            });
        }
        if category == policy.credential_link_category {
            return Some(MappedSignal {
                cluster: EvidenceClusterId::SocialEngineeringIntent,
                family: "credential_theft_intent",
                scale: policy.credential_link_scale,
            });
        }
        if category == policy.high_risk_target_category {
            return Some(MappedSignal {
                cluster: EvidenceClusterId::LinkAndHtmlDeception,
                family: "credential_target_chain",
                scale: policy.credential_link_scale,
            });
        }
        if category == policy.redirect_target_category {
            return Some(MappedSignal {
                cluster: EvidenceClusterId::LinkAndHtmlDeception,
                family: "gateway_target_chain",
                scale: policy.redirect_target_scale,
            });
        }
    }
    Some(MappedSignal {
        cluster: EvidenceClusterId::LinkAndHtmlDeception,
        family: link_content_family(category),
        scale: link_content_scale(category),
    })
}

fn map_yara_signal(category: &str) -> Option<MappedSignal> {
    let scale = match category {
        // Coverage is operational state, never evidence that a payload is
        // malicious. Keep it in module details without feeding fusion.
        "attachment_inspection_limited" | "yara_match" | "structural_payload_validation" => {
            return None;
        }
        // These categories can only be emitted after exact-signature opt-in,
        // format-aware payload validation, or the separately feature-flagged
        // LNK execution-chain admission in `yara_scan`.
        "verified_yara_signature" | "verified_payload_anchor" => 0.98,
        "weaponized_lnk_execution" => 0.98,
        "verified_executable_payload" => 0.94,
        // Candidate rules are hunting leads. They remain visible as module
        // observations until a separate structural validator confirms an
        // executable payload.
        "pe_structural_candidate" => return None,
        // A container polyglot (image with an appended ZIP) is strong
        // evasion evidence, but it is not proof of a malicious payload.
        "polyglot_container" => return None,
        // Legacy/custom rule labels (for example `webshell` and
        // `malware_family`) are hunting observations. They may remain
        // visible on the module card, but without an exact signature or a
        // validated payload they must not acquire D-S threat mass merely by
        // falling through to a generic YARA scale.
        _ => return None,
    };

    Some(MappedSignal {
        cluster: EvidenceClusterId::PayloadMalware,
        // All categories emitted by one YARA module result describe the same
        // underlying scan event. One family makes normalization take the
        // strongest category instead of multiplying aliases from one match.
        family: "yara_evidence",
        scale,
    })
}

fn map_link_scan_signal(category: &str) -> Option<MappedSignal> {
    if category == "shared_hosted_redirect_lure" {
        return Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "shared_hosted_redirect_lure",
            scale: 0.86,
        });
    }
    let family = match category {
        "redirect_url" | "suspicious_params" | "excessive_links" | "url_shortener"
        | "unparseable_url" => "weak_link_context",
        "href_text_mismatch"
        | "userinfo_in_url"
        | "official_domain_text_mismatch"
        | "sender_domain_nested_in_untrusted_host" => "link_impersonation",
        "javascript_uri" | "data_uri" | "ip_url" => "active_link_payload",
        _ => "link_structure_other",
    };
    let scale = match category {
        // A raw href that no WHATWG parser can read is a weak anomaly, not
        // link evidence — keep it well below the family default.
        "unparseable_url" => 0.40,
        _ => 0.78,
    };
    Some(MappedSignal {
        cluster: EvidenceClusterId::LinkAndHtmlDeception,
        family,
        scale,
    })
}

pub(super) fn is_breaker_eligible_signal(module_id: &str, category: &str) -> bool {
    if matches!(module_id, "av_eml_scan" | "av_attach_scan" | "sandbox_scan") {
        return true;
    }
    if module_id == "url_sandbox_scan" {
        return category == "sandbox_url_malicious";
    }

    // A generic/custom YARA match is not automatically equivalent to an AV
    // conviction. Only an explicitly exact signature, the structural
    // validator's active-payload anchor, or the separately governed and
    // format-anchored LNK execution chain may impose a hard risk floor.
    if module_id == "yara_scan" {
        return matches!(
            category,
            "verified_yara_signature" | "verified_payload_anchor" | "weaponized_lnk_execution"
        );
    }

    if module_id == "html_scan"
        && crate::modules::html_scan::is_credential_exfiltration_form_category(category)
    {
        return true;
    }

    matches!(
        category,
        "malware_hash"
            | "virus_detected"
            | "sandbox_malicious"
            | "sandbox_c2_detected"
            | "sandbox_url_malicious"
            | "malicious_document"
            | "webshell"
            | "hash_intel_malicious"
            | "intel_malicious"
            | "url_intel_malicious"
            | "sender_ip_malicious"
            | "ioc_ip_hit"
            | "blacklisted_domain"
            | "blacklisted_parent_domain"
            | "known_impersonation_domain"
            | "brand_spoof_reply_to"
            | "targeted_credential_phishing"
            | "device_code_phishing_combo"
            | "aitm_compound_platform_mfa"
            | "aitm_compound_brand_captcha"
            | "aitm_compound_redirect_mfa"
            | "aitm_multi_convergence"
            | "javascript_uri"
            | "data_uri"
            | "ip_action_target"
    )
}

fn map_link_reputation_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "intel_malicious"
        | "intel_suspicious"
        | "url_intel_malicious"
        | "url_intel_suspicious"
        | "blacklisted_domain"
        | "blacklisted_parent_domain"
        | "suspicious_sender_domain" => Some(MappedSignal {
            cluster: EvidenceClusterId::ExternalReputationIoc,
            family: external_family(category),
            scale: external_scale(category),
        }),
        _ => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: link_reputation_family(category),
            scale: link_reputation_scale(category),
        }),
    }
}

/// Semantic coverage/diagnostic labels describe what the scanner could not
/// inspect (budget, truncation, AI unavailability, review required). Like the
/// attachment/YARA coverage labels, they are operational state and must never
/// be mapped into threat evidence. Covers `semantic_inspection_limited`,
/// `semantic_ai_inspection_limited`, any future `*_inspection_limited` label,
/// and `semantic_review_required`.
fn is_semantic_coverage_category(category: &str) -> bool {
    category.ends_with("_inspection_limited") || category.ends_with("semantic_review_required")
}

fn map_semantic_signal(category: &str) -> Option<MappedSignal> {
    // The local text classifier was trained on research corpora without
    // Chinese benign controls; it stays a module-level review signal until
    // its false-positive rate is validated on real traffic.
    if is_semantic_coverage_category(category)
        || category == "repetitive_template_text"
        || category == crate::semantic::TEXT_CLASSIFIER_CATEGORY
    {
        return None;
    }
    Some(MappedSignal {
        cluster: EvidenceClusterId::SocialEngineeringIntent,
        family: social_family(category),
        scale: social_scale(category),
    })
}

fn map_toad_signal(category: &str) -> Option<MappedSignal> {
    let scale = match category {
        "toad_combo" => 0.92,
        "toad_callback_verb" => 0.72,
        "toad_urgency_phrase" | "toad_brand_impersonation" => 0.68,
        "toad_phone_present" => 0.52,
        _ => return None,
    };
    Some(MappedSignal {
        cluster: EvidenceClusterId::SocialEngineeringIntent,
        family: "toad_callback_phishing",
        scale,
    })
}

fn map_fallback_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "nlp_phishing" | "nlp_scam" | "nlp_bec" | "nlp_spam" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: social_family(category),
            scale: social_scale(category),
        }),
        _ => None,
    }
}

fn delivery_family(category: &str) -> &'static str {
    match category {
        "auth_spf_dmarc_fail" | "auth_spf_fail" | "auth_dmarc_fail" | "no_auth_results" => {
            "auth_chain"
        }
        "future_date" | "stale_date" | "missing_date" => "date_integrity",
        "missing_message_id" | "header_injection" => "header_integrity",
        "excessive_hops" => "received_chain",
        "suspicious_mailer" => "mailer_identity",
        _ => "delivery_other",
    }
}

fn delivery_scale(category: &str) -> f64 {
    match category {
        "auth_spf_dmarc_fail" => 0.72,
        "auth_spf_fail" | "auth_dmarc_fail" => 0.65,
        "no_auth_results" => 0.50,
        "header_injection" => 0.75,
        _ => 0.55,
    }
}

fn social_family(category: &str) -> &'static str {
    match category {
        "phishing"
        | "phishing_subject"
        | "account_security_phishing"
        | "image_only_phishing"
        | "targeted_credential_phishing" => "credential_theft_intent",
        "bec" | "bec_no_ioc_social" | "nlp_bec" => "bec_intent",
        "subsidy_fraud" | "invoice_spam" | "invoice_fraud" | "nlp_scam" => "financial_fraud_intent",
        "sextortion" | "extortion_threat" => "extortion_intent",
        "nlp_spam" | "nonsensical_spam" | "mass_mailing" | "spam_cannon" => "bulk_spam_intent",
        "foreign_to_cn_corp" | "japanese_to_cn_corp" | "japanese_unexpected" => "language_context",
        "phone_in_subject" | "phone_in_body" => "contact_urgency",
        "subject_contact_lure" | "adult_content_lure" | "obfuscated_domain_lure" => {
            "off_platform_contact_lure"
        }
        "llm_injection_suspected" => "ai_integrity",
        "lang_inconsistency" | "multilingual_gibberish" => "language_anomaly",
        crate::semantic::INTENT_MODEL_CATEGORY => "model_intent",
        _ => "social_other",
    }
}

fn social_scale(category: &str) -> f64 {
    match category {
        "account_security_phishing" => 0.88,
        "phishing" | "phishing_subject" | "nlp_phishing" => 0.76,
        "bec" | "bec_no_ioc_social" | "nlp_bec" => 0.72,
        "subsidy_fraud" | "invoice_spam" | "nlp_scam" => 0.66,
        "invoice_fraud" => 0.78,
        "adult_content_lure" => 0.58,
        "obfuscated_domain_lure" => 0.72,
        "sextortion" | "extortion_threat" => 0.82,
        "gateway_pre_classified" => 0.30,
        "foreign_to_cn_corp" | "japanese_to_cn_corp" | "japanese_unexpected" => 0.42,
        "subject_contact_lure" => 0.50,
        // A forged LLM verdict means the attacker is poking the
        // second-opinion channel — but the signal is *attacker-self-induced*:
        // anyone can stuff an injected verdict into their own mail. Keep it at
        // inspection-note weight so a single planted injection can never lift
        // a harmless mail past Low (availability/alert-storm guard, A6).
        "llm_injection_suspected" => 0.15,
        "nlp_spam" | "nonsensical_spam" => 0.46,
        // The module already caps a model hit at a review-level Low score;
        // full scale lets that score reach the verdict unchanged.
        crate::semantic::INTENT_MODEL_CATEGORY => 1.0,
        _ => 0.56,
    }
}

fn transaction_family(category: &str) -> &'static str {
    match category {
        "iban_detected" | "swift_code_detected" | "bank_account_detected" => "banking_identifier",
        "wire_transfer" | "crypto_wallet" => "payment_rail",
        "payment_change" | "bec_payment_change" => "payment_change",
        "urgency_financial_combo" => "financial_urgency",
        "multi_financial_entities" => "financial_density",
        _ => "business_other",
    }
}

fn transaction_scale(category: &str) -> f64 {
    match category {
        "payment_change" | "bec_payment_change" => 0.76,
        "wire_transfer" | "crypto_wallet" => 0.70,
        "multi_financial_entities" => 0.52,
        "urgency_financial_combo" => 0.60,
        _ => 0.62,
    }
}

fn link_content_family(category: &str) -> &'static str {
    match category {
        "targeted_credential_phishing" => "targeted_link",
        "recipient_in_url"
        | "long_url"
        | "suspicious_params"
        | "suspicious_param_value"
        | "double_encoding"
        | "multiple_redirects" => "weak_link_context",
        "at_sign_obfuscation" | "idn_homograph" | "org_domain_mimicry" | "url_typo" => {
            "link_impersonation"
        }
        "dga_random_domain"
        | "hex_subdomain"
        | "encoded_separator"
        | "unusual_port"
        | "oss_content_override" => "link_obfuscation",
        // Percent-decoded layers that resolve to a dangerous protocol are
        // active payloads, not context — same family link_scan uses for
        // javascript:/data: URIs so one underlying signal is not double-counted.
        "encoded_protocol_param" | "double_encoded_payload" => "active_link_payload",
        "deep_fragment_route" | "suspicious_fragment" | "mobile_redirect" => "fragment_obfuscation",
        "suspicious_path" => "credential_pathing",
        "qr_ip_login_chain" => "credential_target_chain",
        _ => "link_content_other",
    }
}

fn link_content_scale(category: &str) -> f64 {
    match category {
        "targeted_credential_phishing" => 0.92,
        "recipient_in_url"
        | "at_sign_obfuscation"
        | "idn_homograph"
        | "org_domain_mimicry"
        | "encoded_protocol_param" => 0.82,
        "dga_random_domain" | "double_encoded_payload" | "oss_content_override" => 0.72,
        "mobile_redirect" => 0.60,
        "qr_ip_login_chain" => 0.90,
        _ => 0.66,
    }
}

fn link_reputation_family(category: &str) -> &'static str {
    match category {
        "redirect_target" | "redirect_url" => "weak_link_context",
        "brand_impersonation" | "www_impersonation" => "brand_impersonation",
        "suspicious_tld" | "free_hosting" | "long_domain" | "deep_subdomain" | "random_domain"
        | "numeric_domain" | "embedded_ip" => "domain_shape",
        _ => "link_reputation_other",
    }
}

fn link_reputation_scale(category: &str) -> f64 {
    match category {
        "brand_impersonation" => 0.78,
        "redirect_target" | "redirect_url" => 0.68,
        "random_domain" | "embedded_ip" => 0.72,
        _ => 0.62,
    }
}

fn external_family(category: &str) -> &'static str {
    match category {
        "intel_malicious" | "url_intel_malicious" | "hash_intel_malicious" => "malicious_intel",
        "intel_suspicious" | "url_intel_suspicious" | "hash_intel_suspicious" => "suspicious_intel",
        "blacklisted_domain" | "blacklisted_parent_domain" => "blacklist",
        "ioc_ip_hit" | "sender_ip_malicious" | "sender_ip_suspicious" => "sender_ip_ioc",
        "suspicious_sender_domain" => "sender_domain_reputation",
        _ => "external_other",
    }
}

fn external_scale(category: &str) -> f64 {
    match category {
        "intel_malicious" | "url_intel_malicious" | "hash_intel_malicious" => 0.86,
        "blacklisted_domain" | "blacklisted_parent_domain" | "sender_ip_malicious" => 0.82,
        "ioc_ip_hit" | "intel_suspicious" | "url_intel_suspicious" | "hash_intel_suspicious" => {
            0.70
        }
        _ => 0.64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::collections::{BTreeSet, HashMap};
    use vigilyx_core::models::{EmailContent, EmailSession, Protocol};
    use vigilyx_core::security::{Bpa, Evidence, ModuleResult, Pillar, ThreatLevel};

    fn make_session(subject: &str, body: &str, sender: &str) -> EmailSession {
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "10.0.0.1".to_string(),
            2525,
            "10.0.0.2".to_string(),
            25,
        );
        session.subject = Some(subject.to_string());
        session.mail_from = Some(sender.to_string());
        session.content = EmailContent {
            body_text: Some(body.to_string()),
            ..Default::default()
        };
        session
    }

    fn make_result(
        module_id: &str,
        pillar: Pillar,
        threat_level: ThreatLevel,
        categories: &[&str],
    ) -> ModuleResult {
        let mut result = ModuleResult {
            module_id: module_id.to_string(),
            module_name: module_id.to_string(),
            pillar,
            threat_level,
            confidence: 0.85,
            categories: categories.iter().map(|c| (*c).to_string()).collect(),
            summary: "test".to_string(),
            evidence: vec![],
            details: json!({ "score": 0.80 }),
            duration_ms: 5,
            analyzed_at: Utc::now(),
            bpa: None,
            engine_id: None,
        };
        qualify_link_fixture(&mut result);
        result
    }

    fn qualify_link_fixture(result: &mut ModuleResult) {
        if result.module_id != "link_content" {
            return;
        }
        let records = result.categories.iter().filter(|category| governed_link_compound(category)).map(|category| json!({
            "category": category,
            "claim": {
                "source_span_id": "html:0:90", "source_part": "html",
                "span": {"start_byte": 0, "end_byte": 90}, "actor_role": "sender", "target_role": "recipient",
                "speech_act": "request", "polarity": "action", "quote_or_forward_status": "original",
                "actions": ["verify"], "objects": ["account"], "link_ids": ["link:fixture"],
                "counter_context_ids": [], "confidence": 0.85, "causal_key": "claim:fixture"
            },
            "original_url": "https://capture.attacker.example/login", "effective_url": "https://capture.attacker.example/login",
            "link_extraction_source": "href", "causal_key": "host:capture.attacker.example",
            "link_transport_status": "not_attempted", "link_content_status": "not_observed",
            "link_ownership_status": "unknown", "coverage_reason": "fixture has static source only",
            "brand_proof": {"claimed_brand": "Acme", "from_domain": "sender.invalid", "target_domain": "capture.attacker.example", "sender_brand_aligned": false, "target_brand_aligned": false}
        })).collect::<Vec<_>>();
        result.details["qualified_link_compounds"] = json!(records);
    }

    #[test]
    fn item_protocol_rejects_malformed_mass_without_module_score_fallback() {
        let mut result = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["encoded_protocol_param"],
        );
        let valid = json!({"causal_key": "host:payload.example",
            "categories": ["encoded_protocol_param"], "score": 0.30, "confidence": 0.75});
        result.details["evidence_items_version"] = json!(1);
        result.details["causal_findings"] = json!([valid.clone()]);
        assert_eq!(
            attributed_findings(None, &result, "encoded_protocol_param").len(),
            1
        );
        for (field, value) in [
            ("score", json!(null)),
            ("score", json!(-0.1)),
            ("score", json!(1.1)),
            ("confidence", json!(null)),
            ("confidence", json!(2.0)),
            ("causal_key", json!("")),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            result.details["causal_findings"] = json!([bad]);
            assert!(attributed_findings(None, &result, "encoded_protocol_param").is_empty());
            assert!(!admitted_classification_signal(
                &result,
                "encoded_protocol_param",
                &VerdictConfig::default(),
                None
            ));
        }
        result.details["causal_findings"] = json!([valid]);
        result.details["evidence_items_version"] = json!(99);
        assert!(attributed_findings(None, &result, "encoded_protocol_param").is_empty());
    }

    #[test]
    fn suspicious_reputation_admits_only_the_item_with_independent_provenance() {
        let mut result = make_result(
            "link_reputation",
            Pillar::Link,
            ThreatLevel::High,
            &["url_intel_suspicious"],
        );
        result.details = json!({"score": 1.0, "evidence_items_version": 1,
        "source": "trusted_module_summary_must_not_authorize_items",
        "causal_findings": [
            {"causal_key": "host:observed.example", "categories": ["url_intel_suspicious"],
                "score": 0.20, "confidence": 0.80, "source": "otx"},
            {"causal_key": "host:reference.example", "categories": ["url_intel_suspicious"],
                "score": 1.0, "confidence": 1.0, "source": "auto_reference"},
            {"causal_key": "host:unknown.example", "categories": ["url_intel_suspicious"],
                "score": 1.0, "confidence": 1.0}
        ]});
        assert!(!builtin_observation_only(&result, "url_intel_suspicious"));
        let items = attributed_findings(None, &result, "url_intel_suspicious");
        assert_eq!(items.len(), 1);
        assert_eq!(
            items[0].causal_key.as_deref(),
            Some("host:observed.example")
        );
        assert_eq!(items[0].score, 0.20);
        result.details["causal_findings"][0]["source"] = json!("auto_reference+reference");
        assert!(builtin_observation_only(&result, "url_intel_suspicious"));
    }

    #[test]
    fn valid_semantic_sibling_cannot_authorize_an_unrelated_quoted_item() {
        let mut result = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["credential_link_lure"],
        );
        result.details["evidence_items_version"] = json!(1);
        let valid = &mut result.details["qualified_link_compounds"][0];
        valid["score"] = json!(0.40);
        valid["confidence"] = json!(0.75);
        let mut quoted = valid.clone();
        quoted["causal_key"] = json!("host:quoted.example");
        quoted["score"] = json!(1.0);
        quoted["claim"]["quote_or_forward_status"] = json!("quoted");
        result.details["qualified_link_compounds"]
            .as_array_mut()
            .unwrap()
            .push(quoted);
        let items = attributed_findings(None, &result, "credential_link_lure");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].score, 0.40);
        assert_eq!(
            items[0].causal_key.as_deref(),
            Some("host:capture.attacker.example")
        );
    }

    #[test]
    fn form_action_source_keeps_current_request_admission_gates() {
        let mut link = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["credential_link_lure"],
        );
        link.details["qualified_link_compounds"][0]["link_extraction_source"] =
            json!("form_action");
        assert!(!qualified_link_claim_keys(&link, "credential_link_lure").is_empty());
        let original = link.details["qualified_link_compounds"][0]["claim"].clone();
        for (field, value) in [
            ("polarity", "anti_action"),
            ("quote_or_forward_status", "quoted"),
            ("actor_role", "unknown"),
        ] {
            link.details["qualified_link_compounds"][0]["claim"] = original.clone();
            link.details["qualified_link_compounds"][0]["claim"][field] = json!(value);
            assert!(qualified_link_claim_keys(&link, "credential_link_lure").is_empty());
        }
        let mut content = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &["external_action_link_lure"],
        );
        let mut record = qualified_lure_record("external_action_link_lure");
        record["link_extraction_source"] = json!("form_action");
        content.details["qualified_compounds"] = json!([record]);
        assert!(qualified_content_compound(
            &content,
            "external_action_link_lure"
        ));
        content.details["qualified_compounds"][0]["quote_or_forward_status"] = json!("quoted");
        assert!(!qualified_content_compound(
            &content,
            "external_action_link_lure"
        ));
    }

    #[test]
    fn legacy_link_labels_require_native_claim_proof() {
        let mut result = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["targeted_credential_phishing"],
        );
        let valid = normalize_results(
            None,
            &HashMap::from([("link_content".to_string(), result.clone())]),
            &VerdictConfig::default(),
        );
        assert!(!valid.clusters.is_empty());
        for field in [
            "actor_role",
            "target_role",
            "polarity",
            "quote_or_forward_status",
        ] {
            let original = result.details.clone();
            result.details["qualified_link_compounds"][0]["claim"][field] = json!(match field {
                "actor_role" => "quoted_author",
                "target_role" => "named_third_party",
                "polarity" => "anti_action",
                _ => "quoted",
            });
            let rejected = normalize_results(
                None,
                &HashMap::from([("link_content".to_string(), result.clone())]),
                &VerdictConfig::default(),
            );
            assert!(rejected.clusters.is_empty(), "{field}: {rejected:?}");
            result.details = original;
        }
        result.details["qualified_link_compounds"] = json!([]);
        let legacy = normalize_results(
            None,
            &HashMap::from([("link_content".to_string(), result)]),
            &VerdictConfig::default(),
        );
        assert!(legacy.clusters.is_empty());
        assert!(
            legacy
                .categories
                .iter()
                .any(|category| category == "targeted_credential_phishing")
        );
    }

    #[test]
    fn brand_relation_cannot_borrow_a_valid_record_from_another_url() {
        let policy = credential_brand_target_scenario_policy().unwrap();
        let mut result = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &[
                &policy.credential_link_category,
                &policy.high_risk_target_category,
                &policy.brand_mismatch_category,
            ],
        );
        assert!(qualified_credential_brand_relation(&result));
        let records = result.details["qualified_link_compounds"]
            .as_array_mut()
            .unwrap();
        let mut other = records[0].clone();
        other["original_url"] = json!("https://other.attacker.example/login");
        other["effective_url"] = json!("https://other.attacker.example/login");
        other["causal_key"] = json!("host:other.attacker.example");
        other["claim"]["source_span_id"] = json!("html:100:190");
        records[0]["claim"]["polarity"] = json!("anti_action");
        records.push(other);
        assert!(!qualified_credential_brand_relation(&result));
    }

    #[test]
    fn unattributed_aliases_keep_max_strength_without_noisy_or() {
        let mut one = make_result(
            "link_scan",
            Pillar::Link,
            ThreatLevel::Low,
            &["javascript_uri"],
        );
        one.details = json!({"score": 0.20});
        one.evidence = vec![Evidence {
            description: "Executable JavaScript URI found in retained HTML".to_string(),
            location: Some("html:href".to_string()),
            snippet: Some("javascript:alert(document.cookie)".to_string()),
        }];
        let baseline = normalize_results(
            None,
            &HashMap::from([("link_scan".to_string(), one.clone())]),
            &VerdictConfig::default(),
        );
        one.categories
            .extend(["javascript_uri".to_string(), "data_uri".to_string()]);
        one.evidence.push(Evidence {
            description: "Executable data URI found in retained HTML".to_string(),
            location: Some("html:href".to_string()),
            snippet: Some("data:text/html,<script>alert(document.cookie)</script>".to_string()),
        });
        let repeated = normalize_results(
            None,
            &HashMap::from([("link_scan".to_string(), one)]),
            &VerdictConfig::default(),
        );
        assert_eq!(baseline.clusters.len(), 1);
        assert_eq!(repeated.clusters.len(), 1);
        assert_eq!(baseline.clusters[0].score, repeated.clusters[0].score);
        assert_eq!(
            baseline.clusters[0].confidence,
            repeated.clusters[0].confidence
        );
        assert_eq!(repeated.clusters[0].causal_atoms.len(), 1);
        assert_eq!(
            baseline.clusters[0].causal_atoms[0].score,
            repeated.clusters[0].causal_atoms[0].score
        );
        assert_eq!(
            baseline.clusters[0].causal_atoms[0].confidence,
            repeated.clusters[0].causal_atoms[0].confidence
        );
        assert!(
            repeated.clusters[0]
                .causal_keys
                .iter()
                .all(|key| key.starts_with("family:"))
        );
    }

    #[test]
    fn only_verified_trust_score_sets_sender_alignment_verified() {
        let mut observed = make_result("domain_verify", Pillar::Package, ThreatLevel::Safe, &[]);
        observed.details = json!({
            "verified": false,
            "alignment_score": 0.75,
            "trust_score": 0.0
        });
        let mut results = HashMap::from([("domain_verify".to_string(), observed)]);
        let scenario = detect_scenarios(None, &BTreeSet::new(), &results);
        assert_eq!(scenario.alignment_score, 0.0);
        assert!(!scenario.sender_alignment_verified);

        results.get_mut("domain_verify").unwrap().details = json!({
            "verified": true,
            "alignment_score": 0.75,
            "trust_score": 0.70
        });
        let scenario = detect_scenarios(None, &BTreeSet::new(), &results);
        assert_eq!(scenario.alignment_score, 0.70);
        assert!(scenario.sender_alignment_verified);
    }

    fn qualified_lure_record(category: &str) -> serde_json::Value {
        json!({
            "category": category,
            "source_span_id": "body:test-request-span",
            "actor_role": "sender",
            "target_role": "recipient",
            "speech_act": "request",
            "polarity": "action",
            "quote_or_forward_status": "original",
            "link_extraction_source": "href",
            "original_url": "https://target.example.invalid/verify",
            "effective_url": "https://target.example.invalid/verify",
            "link_transport_status": "not_attempted",
            "link_content_status": "not_observed",
            "link_ownership_status": "unproven",
            "coverage_reason": "destination_not_fetched",
            "counter_context_ids": [],
            "causal_keys": ["body:test-request-span", "url:test-target"]
        })
    }

    #[test]
    fn unqualified_content_lure_label_cannot_enter_fusion_or_arm_floor() {
        let result = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &[
                "phishing",
                "external_action_link_lure",
                "pii_collection_lure",
            ],
        );
        let results = HashMap::from([("content_scan".to_string(), result)]);
        let config = VerdictConfig::default();
        let normalized = normalize_results(None, &results, &config);
        assert!(normalized.clusters.is_empty());
        assert!(normalized.scenario.qualified_content_compounds.is_empty());
        let verdict = super::super::aggregate_verdict(uuid::Uuid::nil(), &results, &config);
        assert!(verdict.threat_level < ThreatLevel::Medium);
        assert!(verdict.fusion_details.as_ref().unwrap().risk_single < 0.40);
    }

    #[test]
    fn scoped_request_and_target_record_preserves_actionable_lure() {
        let category = "external_action_link_lure";
        let mut result = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &[category],
        );
        result.details["qualified_compounds"] = json!([qualified_lure_record(category)]);
        let results = HashMap::from([("content_scan".to_string(), result)]);
        let config = VerdictConfig::default();
        let normalized = normalize_results(None, &results, &config);
        assert!(!normalized.clusters.is_empty());
        assert!(
            normalized
                .scenario
                .qualified_content_compounds
                .contains(category)
        );
        let verdict = super::super::aggregate_verdict(uuid::Uuid::nil(), &results, &config);
        assert!(verdict.threat_level >= ThreatLevel::Medium);
    }

    #[test]
    fn same_content_claim_shares_one_cause_across_detector_labels() {
        let action = "external_action_link_lure";
        let pii = "pii_collection_lure";
        let mut result = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &[action, pii],
        );
        let action_record = qualified_lure_record(action);
        let mut pii_record = qualified_lure_record(pii);
        // Input ordering and repeated copies do not manufacture new causes.
        pii_record["causal_keys"] = json!(["url:test-target", "body:test-request-span"]);
        result.details["qualified_compounds"] =
            json!([action_record.clone(), action_record, pii_record,]);
        let results = HashMap::from([("content_scan".to_string(), result)]);
        let normalized = normalize_results(None, &results, &VerdictConfig::default());
        assert_eq!(normalized.clusters.len(), 2, "{normalized:?}");
        let keys = normalized
            .clusters
            .iter()
            .flat_map(|cluster| cluster.causal_keys.iter())
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), 1, "{normalized:?}");
        assert!(
            keys.iter()
                .all(|key| key.as_str() == "host:target.example.invalid")
        );
        let verdict =
            super::super::aggregate_verdict(uuid::Uuid::nil(), &results, &VerdictConfig::default());
        assert!(
            verdict
                .fusion_details
                .as_ref()
                .unwrap()
                .convergence_breaker
                .is_none()
        );
    }

    #[test]
    fn content_and_link_request_views_share_the_same_destination_cause() {
        let mut content = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &["pii_collection_lure"],
        );
        let mut record = qualified_lure_record("pii_collection_lure");
        record["original_url"] = json!("https://capture.attacker.example/login");
        record["effective_url"] = record["original_url"].clone();
        content.details["qualified_compounds"] = json!([record]);
        let link = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["credential_link_lure"],
        );
        let normalized = normalize_results(
            None,
            &HashMap::from([
                ("content_scan".to_string(), content.clone()),
                ("link_content".to_string(), link.clone()),
            ]),
            &VerdictConfig::default(),
        );
        let keys = normalized
            .clusters
            .iter()
            .flat_map(|cluster| cluster.causal_atoms.iter())
            .map(|atom| atom.causal_key.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(keys, BTreeSet::from(["host:capture.attacker.example"]));

        let fusion = super::super::clustered_ds_v2::evaluate_model(
            None,
            &HashMap::from([
                ("content_scan".to_string(), content.clone()),
                ("link_content".to_string(), link.clone()),
            ]),
            &VerdictConfig::default(),
        );
        assert_eq!(fusion.artifact_count, 1);
        assert_eq!(fusion.fallback_artifact_count, 0);

        content.details["qualified_compounds"][0]["original_url"] =
            json!("https://independent.example/submit");
        content.details["qualified_compounds"][0]["effective_url"] =
            json!("https://independent.example/submit");
        let independent = normalize_results(
            None,
            &HashMap::from([
                ("content_scan".to_string(), content),
                ("link_content".to_string(), link),
            ]),
            &VerdictConfig::default(),
        );
        assert_eq!(
            independent
                .clusters
                .iter()
                .flat_map(|cluster| cluster.causal_atoms.iter())
                .map(|atom| atom.causal_key.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn family_keeps_one_producer_score_confidence_pair() {
        let mut score_view = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["credential_link_lure"],
        );
        score_view.details["score"] = json!(0.80);
        score_view.confidence = 0.55;
        let mut confidence_view = score_view.clone();
        confidence_view.details["score"] = json!(0.35);
        confidence_view.confidence = 0.95;
        let config = VerdictConfig::default();
        let first = normalize_results(
            None,
            &HashMap::from([("first".to_string(), score_view.clone())]),
            &config,
        );
        let second = normalize_results(
            None,
            &HashMap::from([("second".to_string(), confidence_view.clone())]),
            &config,
        );
        let combined = normalize_results(
            None,
            &HashMap::from([
                ("first".to_string(), score_view),
                ("second".to_string(), confidence_view),
            ]),
            &config,
        );
        let pair = |normalized: &NormalizedEvidence| {
            let atom = &normalized.clusters[0].causal_atoms[0];
            (atom.score, atom.confidence)
        };
        assert!(pair(&combined) == pair(&first) || pair(&combined) == pair(&second));
    }

    #[test]
    fn independent_content_claims_keep_distinct_runtime_causes() {
        let action = "external_action_link_lure";
        let pii = "pii_collection_lure";
        let mut result = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &[action, pii],
        );
        let mut independent = qualified_lure_record(pii);
        independent["source_span_id"] = json!("body:second-request-span");
        independent["original_url"] = json!("https://second.example.invalid/submit");
        independent["effective_url"] = json!("https://second.example.invalid/submit");
        independent["causal_keys"] = json!(["body:second-request-span", "url:second-target"]);
        result.details["qualified_compounds"] = json!([qualified_lure_record(action), independent]);
        let results = HashMap::from([("content_scan".to_string(), result)]);
        let normalized = normalize_results(None, &results, &VerdictConfig::default());
        let keys = normalized
            .clusters
            .iter()
            .flat_map(|cluster| cluster.causal_keys.iter())
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), 2, "{normalized:?}");
    }

    #[test]
    fn subject_only_account_observation_cannot_borrow_a_link_for_its_floor() {
        for link_category in ["href_text_mismatch", "ip_url"] {
            let mut content = make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Medium,
                &["account_security_phishing", "phishing"],
            );
            content.details["score"] = json!(0.30);
            content.evidence = vec![Evidence {
                description: "Synthetic subject observation".to_string(),
                location: Some("subject".to_string()),
                snippet: None,
            }];
            let mut link = make_result(
                "link_scan",
                Pillar::Link,
                ThreatLevel::Low,
                &[link_category],
            );
            link.details["score"] = json!(0.30);
            let mut results = HashMap::from([
                ("content_scan".to_string(), content),
                ("link_scan".to_string(), link),
            ]);
            let config = VerdictConfig::default();
            let normalized = normalize_results(None, &results, &config);
            assert!(!normalized.clusters.is_empty(), "{normalized:?}");
            assert!(!normalized.scenario.has_admitted_content_account_signal);
            let observed = super::super::aggregate_verdict(uuid::Uuid::nil(), &results, &config);
            assert!(observed.threat_level < ThreatLevel::Medium, "{observed:?}");
            assert!(
                !observed
                    .categories
                    .contains(&"account_security_phishing".to_string()),
                "{observed:?}"
            );
            assert!(
                !observed.categories.contains(&"phishing".to_string()),
                "{observed:?}"
            );
            assert_ne!(
                observed.classification,
                Some(EmailClassification::Phishing),
                "{observed:?}"
            );

            let content = results.get_mut("content_scan").unwrap();
            content.details["score"] = json!(0.50);
            content.evidence[0] = Evidence {
                description: "Account expiration threat with a recipient verification request"
                    .to_string(),
                location: Some("body".to_string()),
                snippet: Some(
                    "Your account expires today. Verify your account to retain access.".to_string(),
                ),
            };
            let normalized = normalize_results(None, &results, &config);
            assert!(normalized.scenario.has_admitted_content_account_signal);
            let requested = super::super::aggregate_verdict(uuid::Uuid::nil(), &results, &config);
            assert!(
                requested.threat_level >= ThreatLevel::Medium,
                "{requested:?}"
            );
        }
    }

    #[test]
    fn account_floor_requires_actual_admission_not_a_raw_result_category() {
        for mode in 0..3 {
            let mut content = make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Medium,
                &["account_security_phishing", "phishing"],
            );
            content.evidence = vec![Evidence {
                description: "Synthetic account request".to_string(),
                location: Some("body".to_string()),
                snippet: None,
            }];
            let mut policy = None;
            match mode {
                0 => content.threat_level = ThreatLevel::Safe,
                1 => content.bpa = Some(Bpa::vacuous()),
                _ => {
                    policy = parse_evidence_admission_policy(json!({
                        "enabled": true,
                        "observation_only": {"content_scan": ["account_security_phishing"]},
                    }))
                }
            }
            let results = HashMap::from([("content_scan".to_string(), content)]);
            let normalized = normalize_results_with_admission_policy(
                None,
                &results,
                &VerdictConfig::default(),
                policy.as_ref(),
            );
            assert!(
                !normalized.scenario.has_admitted_content_account_signal,
                "mode {mode}"
            );
        }
    }

    #[test]
    fn content_floor_qualification_requires_positive_weight_score_and_confidence() {
        let action = "external_action_link_lure";
        let pii = "pii_collection_lure";
        for mode in 0..3 {
            let mut content = make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["account_security_phishing", action, pii],
            );
            content.details["qualified_compounds"] =
                json!([qualified_lure_record(action), qualified_lure_record(pii),]);
            content.evidence = vec![Evidence {
                description: "Synthetic body request".to_string(),
                location: Some("body".to_string()),
                snippet: None,
            }];
            let mut config = VerdictConfig::default();
            match mode {
                0 => {
                    config.weights.insert("content_scan".to_string(), 0.0);
                }
                1 => content.details["score"] = json!(0.0),
                _ => content.confidence = 0.0,
            }
            let mut results = HashMap::from([("content_scan".to_string(), content)]);
            let normalized = normalize_results(None, &results, &config);
            assert!(
                !normalized.scenario.has_admitted_content_account_signal,
                "mode {mode}"
            );
            assert!(
                normalized.scenario.qualified_content_compounds.is_empty(),
                "mode {mode}"
            );
            for category in ["account_security_phishing", action, pii] {
                assert!(
                    normalized
                        .categories
                        .iter()
                        .any(|observed| observed == category),
                    "mode {mode}"
                );
            }

            config.weights.insert("content_scan".to_string(), 1.0);
            let content = results.get_mut("content_scan").unwrap();
            content.details["score"] = json!(0.80);
            content.confidence = 0.85;
            let normalized = normalize_results(None, &results, &config);
            assert!(
                normalized.scenario.has_admitted_content_account_signal,
                "mode {mode}"
            );
            assert!(
                normalized
                    .scenario
                    .qualified_content_compounds
                    .contains(action)
            );
            assert!(
                normalized
                    .scenario
                    .qualified_content_compounds
                    .contains(pii)
            );
        }
    }

    #[test]
    fn policy_excluded_identity_anchor_cannot_rescue_display_fusion_or_classification() {
        for anchor in ["authority_display_name_lure", "known_impersonation_domain"] {
            for tier in ["diagnostic_only", "observation_only"] {
                let mut policy_value = json!({"enabled": true});
                policy_value[tier] = json!({"header_scan": [anchor]});
                let policy = parse_evidence_admission_policy(policy_value)
                    .expect("valid scoped identity admission policy");
                let header = make_result(
                    "header_scan",
                    Pillar::Package,
                    ThreatLevel::High,
                    &["display_name_spoof", anchor],
                );
                let results = HashMap::from([("header_scan".to_string(), header)]);
                let config = VerdictConfig::default();
                let normalized =
                    normalize_results_with_admission_policy(None, &results, &config, Some(&policy));
                assert!(
                    normalized.clusters.is_empty(),
                    "{anchor}/{tier}: {normalized:?}"
                );
                assert_eq!(normalized.modules_flagged, 0);
                let mut categories = normalized.categories.clone();
                canonicalize_observed_attack_classification_categories_with_policy(
                    &mut categories,
                    &results,
                    &config,
                    Some(&policy),
                );
                assert_eq!(
                    classify_email_classification(&categories),
                    EmailClassification::Undetermined
                );
                assert!(categories.contains(&"generic_lure_observed".to_string()));
                assert!(!categories.contains(&"display_name_spoof".to_string()));
                assert!(
                    results["header_scan"]
                        .categories
                        .contains(&"display_name_spoof".to_string())
                );
            }

            let header = make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::High,
                &["display_name_spoof", anchor],
            );
            let results = HashMap::from([("header_scan".to_string(), header)]);
            let config = VerdictConfig::default();
            let normalized = normalize_results_with_admission_policy(None, &results, &config, None);
            assert!(!normalized.clusters.is_empty(), "{anchor}: {normalized:?}");
            let mut categories = normalized.categories.clone();
            canonicalize_observed_attack_classification_categories_with_policy(
                &mut categories,
                &results,
                &config,
                None,
            );
            assert_eq!(
                classify_email_classification(&categories),
                EmailClassification::Impersonation
            );
            assert!(categories.contains(&"display_name_spoof".to_string()));
        }
    }

    #[test]
    fn display_classification_cannot_borrow_an_anchor_from_another_producer() {
        let header = make_result(
            "header_scan",
            Pillar::Package,
            ThreatLevel::High,
            &["authority_display_name_lure"],
        );
        let identity = make_result(
            "identity_anomaly",
            Pillar::Semantic,
            ThreatLevel::High,
            &["display_name_spoof"],
        );
        let results = HashMap::from([
            ("header_scan".to_string(), header),
            ("identity_anomaly".to_string(), identity),
        ]);
        let config = VerdictConfig::default();
        let normalized = normalize_results_with_admission_policy(None, &results, &config, None);
        assert!(
            !normalized.clusters.is_empty(),
            "native header anchor must remain: {normalized:?}"
        );
        assert!(
            normalized
                .clusters
                .iter()
                .all(|cluster| !cluster.modules.contains(&"identity_anomaly".to_string()))
        );
        let mut categories = normalized.categories;
        canonicalize_observed_attack_classification_categories_with_policy(
            &mut categories,
            &results,
            &config,
            None,
        );
        assert!(!categories.contains(&"display_name_spoof".to_string()));
        assert!(categories.contains(&"authority_display_name_lure".to_string()));
        assert!(categories.contains(&"generic_lure_observed".to_string()));
    }

    #[test]
    fn malformed_counter_context_or_repeated_cause_cannot_qualify_lure() {
        let category = "external_action_link_lure";
        for mutation in 0..8 {
            let mut record = qualified_lure_record(category);
            match mutation {
                0 => {
                    record["causal_keys"] =
                        json!(["body:test-request-span", "body:test-request-span"])
                }
                1 => record["polarity"] = json!("anti_action"),
                2 => record["quote_or_forward_status"] = json!("quoted"),
                3 => record["counter_context_ids"] = json!(["span:warning"]),
                4 => {
                    record
                        .as_object_mut()
                        .unwrap()
                        .remove("link_content_status");
                }
                5 => record["coverage_reason"] = json!(""),
                6 => record["source_span_id"] = json!("body:"),
                _ => record["original_url"] = json!("not-a-url"),
            }
            let mut result = make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &[category],
            );
            result.details["qualified_compounds"] = json!([record]);
            assert!(
                !qualified_content_compound(&result, category),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn safe_image_only_observation_is_context_not_fusion_evidence() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Safe,
                &["image_only_phishing"],
            ),
        );

        let normalized = normalize_results(None, &results, &VerdictConfig::default());

        assert!(normalized.scenario.image_only_layout_observed);
        assert!(normalized.clusters.is_empty());
        assert!(normalized.categories.is_empty());
        assert_eq!(normalized.modules_flagged, 0);
    }

    #[test]
    fn safe_content_observations_remain_visible_without_fusion_belief() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Safe,
                &[
                    "adult_content_observed",
                    "generic_lure_observed",
                    "empty_body_observed",
                ],
            ),
        );

        let normalized = normalize_results(None, &results, &VerdictConfig::default());

        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "adult_content_observed")
        );
        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "generic_lure_observed")
        );
        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "empty_body_observed")
        );
        assert!(normalized.clusters.is_empty());
        assert_eq!(normalized.modules_flagged, 0);
    }

    #[test]
    fn image_only_layout_observation_is_visible_but_excluded_from_fusion() {
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Low,
                &["image_only_layout_observed"],
            ),
        );

        let normalized = normalize_results(None, &results, &VerdictConfig::default());

        assert!(normalized.scenario.image_only_layout_observed);
        assert!(
            normalized
                .categories
                .contains(&"image_only_layout_observed".to_string())
        );
        assert!(normalized.clusters.is_empty());
        assert_eq!(normalized.modules_flagged, 0);
    }

    #[test]
    fn subject_only_account_security_keyword_is_observation_only() {
        let mut result = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::Low,
            &["account_security_phishing"],
        );
        result.evidence = vec![Evidence {
            description: "subject keyword only".to_string(),
            location: Some("subject".to_string()),
            snippet: None,
        }];

        let normalized = normalize_results(
            None,
            &HashMap::from([("content_scan".to_string(), result)]),
            &VerdictConfig::default(),
        );

        assert!(
            normalized
                .categories
                .contains(&"account_security_phishing".to_string())
        );
        assert!(normalized.clusters.is_empty());
        assert_eq!(normalized.modules_flagged, 0);
    }

    #[test]
    fn detect_scenarios_marks_attachment_phish_and_sensitive_data_flags() {
        let session = make_session(
            "微信聊天记录",
            "附件中包含密码重置提示与卡号信息",
            "fixture-attachment@sender.invalid",
        );
        let mut categories = BTreeSet::new();
        categories.insert("phishing".to_string());
        categories.insert("dlp_credit_card".to_string());
        categories.insert("attachment_phishing_url".to_string());

        let mut results = HashMap::new();
        results.insert(
            "attach_content".to_string(),
            make_result(
                "attach_content",
                Pillar::Attachment,
                ThreatLevel::High,
                &["phishing", "dlp_credit_card", "attachment_phishing_url"],
            ),
        );

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(scenario.has_attachment_phishing_signal);
        assert!(scenario.has_attachment_sensitive_data_signal);
        assert!(scenario.has_high_risk_attachment_content);
        assert!(scenario.has_credential_link_signal);
        assert!(scenario.has_structural_threat_signal);
    }

    #[test]
    fn weak_link_metadata_does_not_create_credential_signal() {
        let session = make_session(
            "August newsletter",
            "Read the latest compliance news.",
            "newsletter@campaign.vendor.example",
        );
        let categories = BTreeSet::from([
            "redirect_url".to_string(),
            "recipient_in_url".to_string(),
            "suspicious_params".to_string(),
            "long_url".to_string(),
        ]);

        let scenario = detect_scenarios(Some(&session), &categories, &HashMap::new());

        assert!(!scenario.has_credential_link_signal);
        assert!(
            !scenario
                .tags
                .iter()
                .any(|tag| tag == "credential_link_signal")
        );
    }

    #[test]
    fn normalization_deduplicates_envelope_alignment_and_caps_weak_links() {
        let session = make_session(
            "August newsletter",
            "Read the latest compliance news.",
            "newsletter@campaign.vendor.example",
        );
        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &["envelope_spoofing"],
            ),
        );
        results.insert(
            "identity_anomaly".to_string(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                ThreatLevel::Low,
                &["envelope_mismatch"],
            ),
        );
        results.insert(
            "link_scan".to_string(),
            make_result(
                "link_scan",
                Pillar::Link,
                ThreatLevel::Critical,
                &["redirect_url", "excessive_links"],
            ),
        );
        results.insert(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::Medium,
                &["recipient_in_url", "long_url", "suspicious_params"],
            ),
        );
        results.insert(
            "aitm_detect".to_string(),
            make_result(
                "aitm_detect",
                Pillar::Link,
                ThreatLevel::Low,
                &["aitm_mfa_bait", "aitm_mfa_urgency"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let links = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception)
            .expect("link cluster");

        assert!(
            normalized
                .categories
                .contains(&"envelope_spoofing".to_string())
        );
        assert!(
            normalized
                .categories
                .contains(&"envelope_mismatch".to_string())
        );
        assert!(
            normalized
                .clusters
                .iter()
                .all(|cluster| cluster.id != EvidenceClusterId::SenderIdentityAuthenticity),
            "routing mismatch observations must not create an identity cluster: {normalized:?}"
        );
        assert!(links.score <= 0.44);
        assert!(!links.breaker_eligible);
        assert!(!normalized.scenario.has_credential_link_signal);
    }

    #[test]
    fn targeted_credential_signal_remains_breaker_eligible() {
        let session = make_session(
            "Verify your account",
            "Please sign in to verify your account.",
            "security@evil.example",
        );
        let mut results = HashMap::new();
        results.insert(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::High,
                &["targeted_credential_phishing"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let links = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception)
            .expect("link cluster");

        assert!(links.breaker_eligible);
        assert!(normalized.scenario.has_credential_link_signal);
        assert!(links.score > 0.44);
    }

    #[test]
    fn yara_hunting_candidate_cannot_trigger_payload_breaker() {
        assert!(!is_breaker_eligible_signal(
            "yara_scan",
            "pe_structural_candidate"
        ));
        assert!(!is_breaker_eligible_signal(
            "yara_scan",
            "malicious_document"
        ));
        assert!(!is_breaker_eligible_signal("yara_scan", "yara_match"));
    }

    #[test]
    fn only_governed_yara_or_structural_payload_can_trigger_breaker() {
        assert!(is_breaker_eligible_signal(
            "yara_scan",
            "verified_yara_signature"
        ));
        assert!(is_breaker_eligible_signal(
            "yara_scan",
            "verified_payload_anchor"
        ));
        assert!(is_breaker_eligible_signal(
            "yara_scan",
            "weaponized_lnk_execution"
        ));
        assert!(map_yara_signal("executable_attachment").is_none());
    }

    #[test]
    fn legacy_yara_categories_are_observation_only_for_ds() {
        for category in [
            "webshell",
            "malware_family",
            "pe_structural_candidate",
            "polyglot_container",
            "yara_match",
        ] {
            assert!(
                map_yara_signal(category).is_none(),
                "legacy YARA category must not enter D-S: {category}"
            );
        }

        assert!(map_yara_signal("verified_yara_signature").is_some());
        assert!(map_yara_signal("verified_payload_anchor").is_some());
        assert!(map_yara_signal("verified_executable_payload").is_some());
        assert!(map_yara_signal("weaponized_lnk_execution").is_some());
    }

    #[test]
    fn detect_scenarios_marks_subsidy_invoice_crypto_and_spoof_flags() {
        let session = make_session(
            "外贸货款对公 平台结算",
            "请尽快处理补贴款，另可加Q 3826878185 办理增值税发票并使用钱包地址支付",
            "fixture-solicitation@sender.invalid",
        );
        let categories = BTreeSet::from([
            "subsidy_fraud".to_string(),
            "invoice_spam".to_string(),
            "crypto_wallet".to_string(),
            "envelope_spoofing".to_string(),
        ]);
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["subsidy_fraud"],
            ),
        );
        results.insert(
            "transaction_correlation".to_string(),
            make_result(
                "transaction_correlation",
                Pillar::Semantic,
                ThreatLevel::Medium,
                &["crypto_wallet"],
            ),
        );
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Medium,
                &["envelope_spoofing"],
            ),
        );

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(scenario.has_subsidy_fraud_signal);
        assert!(scenario.has_invoice_spam_signal);
        assert!(scenario.has_crypto_wallet_signal);
        assert!(scenario.has_header_spoof_signal);
        assert!(scenario.has_payment_change_signal);
    }

    #[test]
    fn detect_scenarios_does_not_treat_encrypted_attachment_as_threat_signal() {
        let session = make_session(
            "请查收",
            "附件为加密压缩包，请按提示打开。",
            "sender@example.com",
        );
        let categories = BTreeSet::from(["encrypted_archive".to_string()]);
        let mut results = HashMap::new();
        results.insert(
            "attach_scan".to_string(),
            make_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::Low,
                &["encrypted_attachment", "encrypted_archive"],
            ),
        );

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(
            !scenario
                .tags
                .iter()
                .any(|tag| tag == "encrypted_attachment_signal")
        );
    }

    #[test]
    fn normalize_results_maps_bec_payment_change_into_business_sensitivity_cluster() {
        // Regression: a pure-text BEC email (no links/attachments/IOCs) from
        // content_scan used to lose both categories at `map_content_signal`'s
        // `_ => None`, producing zero evidence clusters and a Safe verdict.
        let session = make_session(
            "付款账户变更通知",
            "请告知财务，原收款账户已停用，请将货款支付至新账户。",
            "cfo@supplier-example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["bec_payment_change", "bec_no_ioc_social"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        let cluster_ids: Vec<EvidenceClusterId> = normalized
            .clusters
            .iter()
            .map(|cluster| cluster.id)
            .collect();
        assert!(
            cluster_ids.contains(&EvidenceClusterId::BusinessSensitivity),
            "bec_payment_change must produce a BusinessSensitivity cluster, got {cluster_ids:?}"
        );
        assert!(
            !cluster_ids.contains(&EvidenceClusterId::SocialEngineeringIntent),
            "the generic no-IOC BEC label must not duplicate payment-change evidence, got {cluster_ids:?}"
        );
        assert!(
            normalized
                .categories
                .contains(&"bec_no_ioc_social".to_string())
        );
        assert!(
            normalized.scenario.has_payment_change_signal,
            "bec_payment_change must raise the payment-change scenario signal"
        );
    }

    #[test]
    fn normalize_results_maps_subject_contact_lure_into_social_cluster() {
        let session = make_session(
            "VT 发Q-3826878185 加微",
            "",
            "fixture-contact-lure@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Low,
                &["subject_contact_lure"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let social = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SocialEngineeringIntent)
            .expect("subject contact lure should produce a social-engineering cluster");

        assert!(social.score > 0.0);
        assert!(!social.breaker_eligible);
        assert!(!normalized.scenario.has_invoice_spam_signal);
    }

    #[test]
    fn normalize_results_maps_adult_content_lure_into_social_cluster() {
        let session = make_session(
            "Synthetic viewing invitation",
            "Synthetic adult-content lure with an external destination.",
            "promo@sender.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::Low,
                &["adult_content_lure"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let social = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SocialEngineeringIntent)
            .expect("adult-content lure should produce a social-engineering cluster");

        assert!(social.score > 0.0);
        assert!(
            social
                .key_factors
                .iter()
                .any(|factor| factor.contains("Adult-Content") || factor.contains("adult_content"))
        );
    }

    #[test]
    fn normalize_results_maps_known_impersonation_domain_into_sender_identity_cluster() {
        // Regression: header_scan's known_impersonation_domain category was
        // dropped by `map_header_signal`'s `_ => None`, so a previously
        // recorded impersonation domain produced no identity evidence.
        let session = make_session("您好", "请查收附件。", "ceo@c0mpany-example.com");
        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Medium,
                &["known_impersonation_domain"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        let cluster_ids: Vec<EvidenceClusterId> = normalized
            .clusters
            .iter()
            .map(|cluster| cluster.id)
            .collect();
        assert!(
            cluster_ids.contains(&EvidenceClusterId::SenderIdentityAuthenticity),
            "known_impersonation_domain must produce a SenderIdentityAuthenticity cluster, got {cluster_ids:?}"
        );
    }

    #[test]
    fn normalize_results_maps_mailbox_enumeration_probe_into_sender_identity_cluster() {
        let session = make_session("h525266r", "", "h525266r@ccabchina.com.example");
        let results = HashMap::from([(
            "anomaly_detect".to_string(),
            make_result(
                "anomaly_detect",
                Pillar::Package,
                ThreatLevel::Medium,
                &["mailbox_enumeration_probe"],
            ),
        )]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let identity = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SenderIdentityAuthenticity)
            .expect("mailbox enumeration probe should produce an identity cluster");

        assert!(identity.score > 0.0);
        assert!(
            identity
                .key_factors
                .iter()
                .any(|factor| factor.contains("Mailbox Enumeration Probe"))
        );
    }

    #[test]
    fn diagnostic_only_unsafe_result_is_excluded_from_fusion() {
        let session = make_session(
            "Synthetic statement",
            "Your monthly statement is attached.",
            "billing@vendor.example",
        );
        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &[
                    "untrusted_auth_results",
                    "dkim_unverified",
                    "no_auth_results",
                ],
            ),
        );
        results.insert(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::Critical,
                &["long_url"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0);
        assert_eq!(normalized.categories, vec!["long_url".to_string()]);
        assert!(normalized.clusters.is_empty(), "{normalized:?}");
    }

    #[test]
    fn attachment_url_shape_observation_is_excluded_from_fusion() {
        let session = make_session(
            "Synthetic business report",
            "The attachment contains internal service endpoints.",
            "sender@vendor.example",
        );
        let results = HashMap::from([(
            "attach_content".to_string(),
            make_result(
                "attach_content",
                Pillar::Attachment,
                ThreatLevel::Safe,
                &["attachment_url_shape_observation"],
            ),
        )]);

        assert!(map_attach_content_signal("attachment_url_shape_observation").is_none());
        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized
                .categories
                .contains(&"attachment_url_shape_observation".to_string())
        );
        assert!(normalized.clusters.is_empty(), "{normalized:?}");
    }

    #[test]
    fn attachment_type_mismatch_is_observation_but_executable_disguise_stays_actionable() {
        let session = make_session(
            "Synthetic contract delivery",
            "The requested contract documents are attached.",
            "sender@vendor.example",
        );
        let benign_results = HashMap::from([(
            "attach_scan".to_string(),
            make_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::Low,
                &["type_mismatch"],
            ),
        )]);

        // Exercise the built-in fallback as well as the seeded policy: a
        // persisted registry from before this fix must not restore the false
        // positive when the policy is absent or malformed.
        let normalized = normalize_results_with_admission_policy(
            Some(&session),
            &benign_results,
            &VerdictConfig::default(),
            None,
        );
        assert!(
            normalized.categories.contains(&"type_mismatch".to_string()),
            "format observations must remain visible: {normalized:?}"
        );
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized.clusters.is_empty(),
            "a non-executable format mismatch must not create payload belief: {normalized:?}"
        );

        let seeded_normalized =
            normalize_results(Some(&session), &benign_results, &VerdictConfig::default());
        assert_eq!(
            seeded_normalized.modules_flagged, 0,
            "{seeded_normalized:?}"
        );
        assert!(
            seeded_normalized.clusters.is_empty(),
            "the versioned policy must also exclude format mismatch from fusion: {seeded_normalized:?}"
        );

        let malicious_results = HashMap::from([(
            "attach_scan".to_string(),
            make_result(
                "attach_scan",
                Pillar::Attachment,
                ThreatLevel::High,
                &["executable_disguise"],
            ),
        )]);
        let normalized = normalize_results_with_admission_policy(
            Some(&session),
            &malicious_results,
            &VerdictConfig::default(),
            None,
        );
        assert_eq!(normalized.modules_flagged, 1, "{normalized:?}");
        assert!(
            normalized
                .clusters
                .iter()
                .any(|cluster| cluster.id == EvidenceClusterId::PayloadMalware),
            "executable disguises must remain actionable: {normalized:?}"
        );
    }

    #[test]
    fn missing_received_is_retained_as_observation_without_delivery_cluster() {
        let session = make_session(
            "Synthetic statement",
            "Your monthly statement is attached.",
            "billing@vendor.example",
        );
        let results = HashMap::from([(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &["no_received"],
            ),
        )]);

        assert!(map_header_signal("no_received").is_none());
        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized.categories.contains(&"no_received".to_string()),
            "coverage observation should remain analyst-visible: {normalized:?}"
        );
        assert!(normalized.clusters.is_empty(), "{normalized:?}");
    }

    #[test]
    fn envelope_spoof_observations_are_retained_without_identity_fusion() {
        let session = make_session(
            "Routine internal notice",
            "This message is a routine operational notification.",
            "sender@partner.example",
        );
        let result = make_result(
            "header_scan",
            Pillar::Package,
            ThreatLevel::High,
            &["envelope_spoofing", "protected_domain_spoof"],
        );
        let normalized = normalize_results(
            Some(&session),
            &HashMap::from([("header_scan".to_string(), result)]),
            &VerdictConfig::default(),
        );

        assert!(
            normalized
                .categories
                .contains(&"envelope_spoofing".to_string())
        );
        assert!(
            normalized
                .categories
                .contains(&"protected_domain_spoof".to_string())
        );
        assert!(
            normalized
                .clusters
                .iter()
                .all(|cluster| cluster.id != EvidenceClusterId::SenderIdentityAuthenticity),
            "routing mismatch must remain an observation until corroborated: {normalized:?}"
        );
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(!is_breaker_eligible_signal(
            "header_scan",
            "protected_domain_spoof"
        ));
        assert!(map_header_signal("envelope_spoofing").is_none());
        assert!(map_header_signal("protected_domain_spoof").is_none());
    }

    #[test]
    fn suspicious_mailer_observation_is_excluded_from_fusion() {
        let session = make_session(
            "Synthetic document delivery",
            "The requested document is attached.",
            "sender@vendor.example",
        );
        let results = HashMap::from([(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &["suspicious_mailer", "dkim_unverified"],
            ),
        )]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized
                .categories
                .contains(&"suspicious_mailer".to_string()),
            "the client fingerprint remains analyst-visible"
        );
        assert!(
            normalized.clusters.is_empty(),
            "a mail-client fingerprint must not create threat belief: {normalized:?}"
        );
    }

    #[test]
    fn semantic_coverage_and_template_context_cannot_raise_threat() {
        let session = make_session(
            "Synthetic monthly operations report",
            "Repeated report sections are context, not threat evidence.",
            "reports@vendor.example",
        );
        let results = HashMap::from([(
            "semantic_scan".to_string(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                ThreatLevel::Low,
                &["semantic_ai_inspection_limited", "repetitive_template_text"],
            ),
        )]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert_eq!(
            normalized.categories,
            vec!["repetitive_template_text".to_string()],
            "coverage diagnostics must be separated while observations stay visible"
        );
        assert!(
            normalized.clusters.is_empty(),
            "coverage and repetitive-template context must not enter D-S fusion: {normalized:?}"
        );
    }

    #[test]
    fn configured_observations_remain_visible_without_creating_fusion_clusters() {
        let session = make_session(
            "Synthetic business notice",
            "This fixture contains only contextual observations.",
            "notice@vendor.example",
        );
        let results = HashMap::from([
            (
                "identity_anomaly".to_string(),
                make_result(
                    "identity_anomaly",
                    Pillar::Semantic,
                    ThreatLevel::Low,
                    &["first_contact"],
                ),
            ),
            (
                "link_content".to_string(),
                make_result(
                    "link_content",
                    Pillar::Link,
                    ThreatLevel::Low,
                    &["recipient_in_url"],
                ),
            ),
            (
                "link_reputation".to_string(),
                make_result(
                    "link_reputation",
                    Pillar::Link,
                    ThreatLevel::Low,
                    &["long_domain"],
                ),
            ),
            (
                "attach_scan".to_string(),
                make_result(
                    "attach_scan",
                    Pillar::Attachment,
                    ThreatLevel::Low,
                    &["mime_mismatch"],
                ),
            ),
        ]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        for category in [
            "first_contact",
            "recipient_in_url",
            "long_domain",
            "mime_mismatch",
        ] {
            assert!(
                normalized.categories.iter().any(|item| item == category),
                "observation {category} must remain visible: {normalized:?}"
            );
        }
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized.clusters.is_empty(),
            "contextual observations must not become D-S evidence: {normalized:?}"
        );
    }

    #[test]
    fn malformed_evidence_admission_policy_fails_closed() {
        assert!(
            parse_evidence_admission_policy(json!({
                "enabled": true,
                "diagnostic_only": {},
                "observation_only": {
                    "link_content": "recipient_in_url"
                }
            }))
            .is_none()
        );
        assert!(
            parse_evidence_admission_policy(json!({
                "enabled": true,
                "diagnostic_only": {},
                "observation_only": {
                    "": ["recipient_in_url"]
                }
            }))
            .is_none()
        );

        let session = make_session(
            "Synthetic tracking notice",
            "This fixture verifies fail-closed admission behavior.",
            "tracking@sender.example",
        );
        let results = HashMap::from([(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::Low,
                &["recipient_in_url"],
            ),
        )]);
        let normalized = normalize_results_with_admission_policy(
            Some(&session),
            &results,
            &VerdictConfig::default(),
            None,
        );

        assert!(
            normalized.clusters.is_empty(),
            "the compiled admission tiers must keep URL-shape noise out of fusion when the runtime policy is invalid: {normalized:?}"
        );
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized
                .categories
                .contains(&"recipient_in_url".to_string())
        );

        let strong = HashMap::from([(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::High,
                &["targeted_credential_phishing"],
            ),
        )]);
        let strong_normalized = normalize_results_with_admission_policy(
            Some(&session),
            &strong,
            &VerdictConfig::default(),
            None,
        );
        assert!(
            strong_normalized
                .clusters
                .iter()
                .any(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception),
            "a registered credential-target anchor must survive the fallback policy: {strong_normalized:?}"
        );
    }

    #[test]
    fn missing_policy_keeps_known_weak_url_observations_out_of_fusion() {
        let mut typo = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::Medium,
            &["url_typo"],
        );
        typo.details = json!({"score": 0.70});
        let results = HashMap::from([(String::from("link_content"), typo)]);
        let normalized = normalize_results_with_admission_policy(
            None,
            &results,
            &VerdictConfig::default(),
            None,
        );

        assert!(normalized.categories.contains(&"url_typo".to_string()));
        assert!(normalized.clusters.is_empty(), "{normalized:?}");
    }

    #[test]
    fn stage_a_admission_keeps_strong_neighbor_signals_actionable() {
        let session = make_session(
            "Synthetic security alert",
            "Use the supplied security link to review the alert.",
            "security@sender.example",
        );
        let results = HashMap::from([
            (
                "header_scan".to_string(),
                make_result(
                    "header_scan",
                    Pillar::Package,
                    ThreatLevel::High,
                    &["protected_domain_spoof"],
                ),
            ),
            (
                "link_content".to_string(),
                make_result(
                    "link_content",
                    Pillar::Link,
                    ThreatLevel::High,
                    &["dga_random_domain", "targeted_credential_phishing"],
                ),
            ),
            (
                "link_reputation".to_string(),
                make_result(
                    "link_reputation",
                    Pillar::Link,
                    ThreatLevel::High,
                    &["intel_malicious"],
                ),
            ),
            (
                "attach_scan".to_string(),
                make_result(
                    "attach_scan",
                    Pillar::Attachment,
                    ThreatLevel::High,
                    &["type_mismatch", "executable_disguise"],
                ),
            ),
        ]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let cluster_ids = normalized
            .clusters
            .iter()
            .map(|cluster| cluster.id)
            .collect::<BTreeSet<_>>();

        assert!(
            !cluster_ids.contains(&EvidenceClusterId::SenderIdentityAuthenticity),
            "the envelope mismatch observation must not manufacture identity evidence: {normalized:?}"
        );
        assert!(
            cluster_ids.contains(&EvidenceClusterId::LinkAndHtmlDeception),
            "{normalized:?}"
        );
        assert!(
            cluster_ids.contains(&EvidenceClusterId::ExternalReputationIoc),
            "{normalized:?}"
        );
        assert!(
            cluster_ids.contains(&EvidenceClusterId::PayloadMalware),
            "{normalized:?}"
        );
        assert!(
            normalized
                .clusters
                .iter()
                .any(|cluster| cluster.breaker_eligible),
            "strong controls must retain breaker eligibility: {normalized:?}"
        );
    }

    #[test]
    fn random_sender_domain_shape_remains_visible_but_does_not_create_threat_evidence() {
        let session = make_session(
            "Synthetic pending-item notice",
            "A synthetic internal-notice lure with no stronger link anchor.",
            "notice@random-sender.example",
        );
        let results = HashMap::from([(
            "identity_anomaly".to_string(),
            make_result(
                "identity_anomaly",
                Pillar::Semantic,
                ThreatLevel::Low,
                &["first_contact", "random_domain"],
            ),
        )]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        assert!(
            !normalized
                .clusters
                .iter()
                .any(|cluster| cluster.id == EvidenceClusterId::SenderIdentityAuthenticity),
            "random sender-domain shape must not create an identity cluster by itself: {normalized:?}"
        );
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "first_contact"),
            "the demoted first-contact observation remains visible: {normalized:?}"
        );
        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "random_domain")
        );
    }

    #[test]
    fn explicit_zero_belief_result_is_excluded_even_with_actionable_label() {
        let session = make_session(
            "Synthetic notice",
            "This fixture exercises stale result normalization.",
            "notice@vendor.example",
        );
        let mut result = make_result(
            "link_reputation",
            Pillar::Link,
            ThreatLevel::Low,
            &["intel_suspicious"],
        );
        result.bpa = Some(Bpa::safe_analyzed());
        let results = HashMap::from([("link_reputation".to_string(), result)]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0);
        assert!(normalized.categories.is_empty(), "{normalized:?}");
        assert!(normalized.clusters.is_empty(), "{normalized:?}");
    }

    #[test]
    fn lone_reply_domain_mismatch_is_visible_without_standalone_cluster() {
        let session = make_session(
            "Electronic invoice",
            "Your invoice is ready.",
            "notify@travel-service.invalid",
        );
        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &["domain_mismatch", "dkim_unverified"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert!(
            normalized
                .categories
                .contains(&"domain_mismatch".to_string()),
            "the analyst-visible header observation must be retained"
        );
        assert!(
            !normalized
                .categories
                .contains(&"dkim_unverified".to_string()),
            "verification gaps stay diagnostic instead of becoming verdict headlines"
        );
        assert!(
            normalized.clusters.is_empty(),
            "a bare Reply-To routing mismatch must not create threat evidence: {:?}",
            normalized.clusters
        );
        assert!(
            !normalized.scenario.has_header_spoof_signal,
            "an observation cannot lend native spoof authority"
        );
        assert!(!normalized.scenario.has_structural_threat_signal);
    }

    #[test]
    fn reply_domain_mismatch_still_qualifies_compound_credential_scenario() {
        let session = make_session(
            "Verify your account",
            "Use the link to verify your account immediately.",
            "security@example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "header_scan".to_string(),
            make_result(
                "header_scan",
                Pillar::Package,
                ThreatLevel::Low,
                &["domain_mismatch"],
            ),
        );
        results.insert(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::High,
                &["targeted_credential_phishing"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert!(
            !normalized.scenario.has_header_spoof_signal,
            "an observation cannot lend native spoof authority"
        );
        assert!(normalized.scenario.has_credential_link_signal);
        assert!(normalized.clusters.iter().any(|cluster| {
            cluster.id == EvidenceClusterId::LinkAndHtmlDeception && cluster.breaker_eligible
        }));
    }

    #[test]
    fn detect_scenarios_lone_auto_submitted_header_does_not_suppress() {
        // Attack: one forged header line used to trigger both
        // dsn_like_system_mail and auto_reply_like, which downgrade clusters
        // and cap the final risk at 0.30/0.12. A bare header with no
        // corroborating system-mail trait must not suppress anything.
        let mut session = make_session(
            "请尽快安排付款",
            "王总要求今天内把货款打到新账户，不要声张。",
            "attacker@evil-example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));
        let categories = BTreeSet::new();
        let results = HashMap::new();

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(
            !scenario.dsn_like_system_mail,
            "a lone forged Auto-Submitted header must not mark dsn_like_system_mail"
        );
        assert!(
            !scenario.auto_reply_like,
            "a lone forged Auto-Submitted header must not mark auto_reply_like"
        );
    }

    #[test]
    fn detect_scenarios_auto_submitted_with_system_sender_still_suppresses() {
        let mut session = make_session(
            "Undelivered Mail Returned to Sender",
            "This message was generated by the mail system.",
            "MAILER-DAEMON@mail.example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));
        let categories = BTreeSet::new();
        let results = HashMap::new();

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(
            scenario.dsn_like_system_mail,
            "Auto-Submitted + system sender is a genuine system mail"
        );
        assert!(
            scenario.auto_reply_like,
            "Auto-Submitted + system sender is a genuine auto reply"
        );
    }

    #[test]
    fn detect_scenarios_auto_submitted_with_multipart_report_still_suppresses() {
        let mut session = make_session(
            "Delivery report",
            "Your message could not be delivered.",
            "alice@example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-replied".to_string()));
        session.content.headers.push((
            "Content-Type".to_string(),
            "multipart/report; report-type=delivery-status; boundary=x".to_string(),
        ));
        let categories = BTreeSet::new();
        let results = HashMap::new();

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(
            scenario.dsn_like_system_mail,
            "Auto-Submitted + multipart/report is a genuine delivery report"
        );
        assert!(
            scenario.auto_reply_like,
            "Auto-Submitted + multipart/report is a genuine auto reply"
        );
    }

    #[test]
    fn detect_scenarios_auto_submitted_with_empty_return_path_still_suppresses() {
        // DSNs use an empty reverse-path (MAIL FROM:<>).
        let mut session =
            make_session("Mail delivery failed", "Returning message to sender.", "<>");
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-generated".to_string()));
        let categories = BTreeSet::new();
        let results = HashMap::new();

        let scenario = detect_scenarios(Some(&session), &categories, &results);

        assert!(
            scenario.dsn_like_system_mail,
            "Auto-Submitted + empty return path is a genuine DSN"
        );
        assert!(
            scenario.auto_reply_like,
            "Auto-Submitted + empty return path is a genuine auto reply"
        );
    }

    // ─── Round-2 PoC regressions: multi-trait scenario suppression ────────

    fn attack_poc_patterns() -> ScenarioPatternLists {
        ScenarioPatternLists {
            gateway_banner_patterns: vec![
                "[外部邮件]".to_string(),
                "该邮件可能存在恶意内容，请谨慎甄别邮件".to_string(),
            ],
            notice_banner_patterns: vec![],
            dsn_patterns: vec![
                "delivery status notification".to_string(),
                "undelivered mail".to_string(),
            ],
            auto_reply_patterns: vec!["自动回复".to_string(), "out of office".to_string()],
        }
    }

    #[test]
    fn detect_scenarios_lone_mailer_daemon_sender_does_not_suppress() {
        // Attack: a plain-text BEC mail with a forged MAILER-DAEMON envelope.
        // Before the fix, the system-sender trait alone marked
        // dsn_like_system_mail and Phase 4 capped the verdict below Medium.
        let session = make_session(
            "付款账户变更通知",
            "王总要求今天内把货款打到新账户，不要声张。",
            "MAILER-DAEMON@evil-example.com",
        );

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            !scenario.dsn_like_system_mail,
            "a lone forged MAILER-DAEMON envelope must not mark dsn_like_system_mail"
        );
        assert!(
            !scenario.auto_reply_like,
            "a lone forged MAILER-DAEMON envelope must not mark auto_reply_like"
        );
    }

    #[test]
    fn detect_scenarios_lone_dsn_subject_does_not_suppress() {
        // Attack: one forged subject line impersonating a DSN.
        let session = make_session(
            "Delivery Status Notification (failure)",
            "您的账户已冻结，请立即转账至新账户完成验证。",
            "cfo@supplier-example.com",
        );

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            !scenario.dsn_like_system_mail,
            "a lone DSN-pattern subject must not mark dsn_like_system_mail"
        );
    }

    #[test]
    fn detect_scenarios_mailer_daemon_with_dsn_subject_still_suppresses() {
        // Regression protection: a genuine DSN shows two independent traits
        // (system sender + DSN subject) and must stay suppressed.
        let session = make_session(
            "Delivery Status Notification (failure)",
            "This message was generated by the mail system.",
            "MAILER-DAEMON@mail.example.com",
        );

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            scenario.dsn_like_system_mail,
            "system sender + DSN subject is a genuine DSN"
        );
    }

    #[test]
    fn detect_scenarios_mailer_daemon_with_multipart_report_still_suppresses() {
        // Regression protection: system sender + multipart/report body.
        let mut session = make_session(
            "邮件投递失败通知",
            "Your message could not be delivered.",
            "MAILER-DAEMON@mail.example.com",
        );
        session.content.headers.push((
            "Content-Type".to_string(),
            "multipart/report; report-type=delivery-status; boundary=x".to_string(),
        ));

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            scenario.dsn_like_system_mail,
            "system sender + multipart/report is a genuine delivery report"
        );
    }

    #[test]
    fn detect_scenarios_empty_return_path_with_dsn_subject_still_suppresses() {
        // Regression protection: empty reverse-path + DSN subject (no
        // Auto-Submitted header, as some MTAs omit it).
        let session = make_session(
            "Undelivered Mail Returned to Sender",
            "Returning message to sender.",
            "<>",
        );

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            scenario.dsn_like_system_mail,
            "empty return path + DSN subject is a genuine DSN"
        );
    }

    #[test]
    fn detect_scenarios_lone_auto_reply_subject_does_not_suppress() {
        // Attack: one forged "自动回复" subject line on a phishing mail.
        let session = make_session(
            "自动回复：您的账户存在异常",
            "您的账户已冻结，请立即点击链接转账验证，否则将扣款。",
            "attacker@evil-example.com",
        );

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            !scenario.auto_reply_like,
            "a lone auto-reply subject must not mark auto_reply_like"
        );
        assert!(
            !scenario.dsn_like_system_mail,
            "a lone auto-reply subject must not mark dsn_like_system_mail"
        );
    }

    #[test]
    fn detect_scenarios_auto_reply_subject_with_auto_submitted_still_suppresses() {
        // Regression protection: a genuine vacation reply carries both an
        // Auto-Submitted header and an auto-reply subject.
        let mut session = make_session(
            "自动回复：出差中",
            "谢谢来信，我已收到。",
            "alice@example.com",
        );
        session
            .content
            .headers
            .push(("Auto-Submitted".to_string(), "auto-replied".to_string()));

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &BTreeSet::new(),
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            scenario.auto_reply_like,
            "Auto-Submitted + auto-reply subject is a genuine auto reply"
        );
    }

    #[test]
    fn detect_scenarios_subject_only_gateway_tag_does_not_pollute() {
        // Attack: the attacker prepends "[外部邮件]" to their own phishing
        // subject. content_scan emits gateway_pre_classified from the subject
        // tag, but the body carries no gateway banner text — before the fix
        // the subject tag alone marked gateway_banner_polluted and Phase 4
        // capped the verdict at 0.35.
        let session = make_session(
            "[外部邮件] 账户异常登录提醒",
            "您的账户存在异常登录，请立即点击链接验证身份，否则账户将被冻结。",
            "attacker@evil-example.com",
        );
        let categories = BTreeSet::from([
            "gateway_pre_classified".to_string(),
            "account_security_phishing".to_string(),
        ]);

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &categories,
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            !scenario.gateway_banner_polluted,
            "a subject-only gateway tag must not mark gateway_banner_polluted"
        );
    }

    #[test]
    fn detect_scenarios_gateway_banner_in_body_still_pollutes() {
        // Regression protection: a real gateway inserts its banner into the
        // body (and usually tags the subject too) — that still pollutes.
        let session = make_session(
            "[外部邮件] 工资清单",
            "该邮件可能存在恶意内容，请谨慎甄别邮件。\n\n请查收本月工资清单。",
            "hr@example.com",
        );
        let categories = BTreeSet::from(["gateway_pre_classified".to_string()]);

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &categories,
            &HashMap::new(),
            &attack_poc_patterns(),
        );

        assert!(
            scenario.gateway_banner_polluted,
            "a gateway banner in the body must still mark gateway_banner_polluted"
        );
    }

    #[test]
    fn detect_scenarios_subject_only_notice_tag_does_not_pollute() {
        // Attack (round 4): the attacker prepends a forged notice tag to their
        // own BEC subject. NLP flags the body, but the body carries no notice
        // banner text — before the fix the subject tag alone marked
        // notice_banner_polluted and Phase 4 capped the verdict at 0.12.
        let patterns = ScenarioPatternLists {
            notice_banner_patterns: vec![
                "无法扫描邮件附件".to_string(),
                "请确认邮件来源以及真实性".to_string(),
            ],
            ..attack_poc_patterns()
        };
        let session = make_session(
            "[警告：无法扫描邮件附件 - 请确认邮件来源以及真实性]付款账户变更通知",
            "王总要求今天内把货款打到新账户，原收款账户已停用，请勿声张。",
            "cfo@supplier-example.com",
        );
        let categories = BTreeSet::from(["nlp_bec".to_string()]);

        let scenario =
            detect_scenarios_with_patterns(Some(&session), &categories, &HashMap::new(), &patterns);

        assert!(
            !scenario.notice_banner_polluted,
            "a subject-only notice tag must not mark notice_banner_polluted"
        );
    }

    #[test]
    fn detect_scenarios_notice_banner_in_body_still_pollutes() {
        // Regression protection: a real security gateway injects its notice
        // into the body — that still pollutes (aligned with gateway_banner).
        let patterns = ScenarioPatternLists {
            notice_banner_patterns: vec![
                "无法扫描邮件附件".to_string(),
                "请确认邮件来源以及真实性".to_string(),
            ],
            ..attack_poc_patterns()
        };
        let session = make_session(
            "5c2c3f14d027a237283ad8d35936ca5b",
            "发自我的iPhone\n\n警告：无法扫描邮件附件 - 请确认邮件来源以及真实性",
            "fixture-notice@sender.invalid",
        );
        let categories = BTreeSet::from(["nlp_phishing".to_string()]);

        let scenario =
            detect_scenarios_with_patterns(Some(&session), &categories, &HashMap::new(), &patterns);

        assert!(
            scenario.notice_banner_polluted,
            "a notice banner in the body must still mark notice_banner_polluted"
        );
    }

    #[test]
    fn detect_scenarios_statistical_nonsensical_spam_is_not_an_nlp_echo() {
        // Attack: self-induce the statistical CJK detector (random rare
        // characters) and paste a gateway notice banner into the body. The
        // statistical observation must not stand in for an NLP echo, otherwise
        // the social cluster is scaled by 0.28 and risk capped at 0.12.
        let patterns = ScenarioPatternLists {
            notice_banner_patterns: vec![
                "无法扫描邮件附件".to_string(),
                "请确认邮件来源以及真实性".to_string(),
            ],
            ..attack_poc_patterns()
        };
        let session = make_session(
            "付款账户变更通知",
            "王总要求今天内把货款打到新账户。\n\n警告：无法扫描邮件附件 - 请确认邮件来源以及真实性",
            "cfo@supplier-example.com",
        );
        let categories = BTreeSet::from(["nonsensical_spam".to_string()]);

        let scenario =
            detect_scenarios_with_patterns(Some(&session), &categories, &HashMap::new(), &patterns);

        assert!(
            !scenario.notice_banner_polluted,
            "statistical nonsensical_spam must not qualify as an NLP echo"
        );

        let categories = BTreeSet::from(["nonsensical_spam".to_string(), "nlp_spam".to_string()]);
        let scenario =
            detect_scenarios_with_patterns(Some(&session), &categories, &HashMap::new(), &patterns);
        assert!(
            scenario.notice_banner_polluted,
            "a genuine NLP echo next to a body notice banner still pollutes"
        );
    }

    #[test]
    fn semantic_coverage_categories_never_map_to_threat_signals() {
        for category in [
            "semantic_inspection_limited",
            "semantic_ai_inspection_limited",
            "semantic_ocr_inspection_limited",
            "semantic_review_required",
            "repetitive_template_text",
            crate::semantic::TEXT_CLASSIFIER_CATEGORY,
        ] {
            assert!(
                map_semantic_signal(category).is_none(),
                "{category} is coverage/context, not threat evidence"
            );
            assert!(
                map_signal("semantic_scan", category).is_none(),
                "{category} must not enter fusion via semantic_scan"
            );
        }
        assert!(
            map_semantic_signal("nlp_phishing").is_some(),
            "genuine semantic threat categories still map"
        );
    }

    #[test]
    fn non_safe_semantic_inspection_limited_cannot_raise_threat() {
        let session = make_session(
            "Synthetic quarterly notice",
            "The semantic budget was exhausted; this is coverage state only.",
            "notice@vendor.example",
        );
        let results = HashMap::from([(
            "semantic_scan".to_string(),
            make_result(
                "semantic_scan",
                Pillar::Semantic,
                ThreatLevel::Low,
                &["semantic_inspection_limited"],
            ),
        )]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        assert!(
            normalized.clusters.is_empty(),
            "semantic_inspection_limited must not enter D-S fusion: {normalized:?}"
        );
    }

    /// PoC (A6): a planted prompt injection that makes the LLM second opinion
    /// emit an off-whitelist verdict used to carry cluster scale 0.78 — a
    /// single attacker-self-induced signal inflating an otherwise harmless
    /// mail (availability/alert-storm attack). It is now inspection-note
    /// weight (0.15): alone it stays far below the Low band.
    #[test]
    fn llm_injection_suspected_alone_is_inspection_note_weight() {
        let mapped = map_signal("semantic_scan", "llm_injection_suspected")
            .expect("llm_injection_suspected must map into a cluster");
        assert_eq!(mapped.cluster, EvidenceClusterId::SocialEngineeringIntent);
        assert!(
            mapped.scale <= 0.15,
            "attacker-self-induced signal must stay at inspection-note weight: {}",
            mapped.scale
        );

        let session = make_session(
            "季度会议安排",
            "请各位同事于周五前确认参会时间，会议室预订详情见内网。",
            "colleague@corp-example.com",
        );
        let mut result = make_result(
            "semantic_scan",
            Pillar::Semantic,
            ThreatLevel::Low,
            &["llm_injection_suspected"],
        );
        // The semantic module emits exactly 0.15 for a lone injection signal.
        result.details = json!({ "score": 0.15 });
        let mut results = HashMap::new();
        results.insert("semantic_scan".to_string(), result);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let social = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SocialEngineeringIntent)
            .expect("injection signal must still surface as cluster evidence");
        assert!(
            social.score < 0.05,
            "a lone llm_injection_suspected must not lift the verdict, cluster score {}",
            social.score
        );
        assert!(
            !social.breaker_eligible,
            "injection signal must never arm the hard risk-floor breaker"
        );
    }

    #[test]
    fn map_signal_maps_new_link_content_categories_into_link_cluster() {
        // Round-2 link_content categories must keep landing in the
        // LinkAndHtmlDeception cluster with a deliberate family/scale, not
        // fall through to the generic catch-all.
        for (category, family, scale) in [
            ("oss_content_override", "link_obfuscation", 0.72),
            ("encoded_protocol_param", "active_link_payload", 0.82),
            ("double_encoded_payload", "active_link_payload", 0.72),
            ("suspicious_param_value", "weak_link_context", 0.66),
        ] {
            let mapped = map_signal("link_content", category)
                .unwrap_or_else(|| panic!("{category} must map into an evidence cluster"));
            assert_eq!(
                mapped.cluster,
                EvidenceClusterId::LinkAndHtmlDeception,
                "{category} cluster"
            );
            assert_eq!(mapped.family, family, "{category} family");
            assert!((mapped.scale - scale).abs() < 1e-9, "{category} scale");
        }
    }

    #[test]
    fn normalize_results_keeps_new_link_content_categories_in_cluster_evidence() {
        let session = make_session(
            "登录验证",
            "请点击链接完成验证。",
            "attacker@evil-example.com",
        );
        let mut results = HashMap::new();
        results.insert(
            "link_content".to_string(),
            make_result(
                "link_content",
                Pillar::Link,
                ThreatLevel::Medium,
                &[
                    "oss_content_override",
                    "encoded_protocol_param",
                    "double_encoded_payload",
                    "suspicious_param_value",
                ],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        let links = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception)
            .expect("link cluster must exist for the new link_content categories");

        for expected in [
            "Oss Content Override",
            "Encoded Protocol Param",
            "Double Encoded Payload",
        ] {
            assert!(
                links.key_factors.iter().any(|factor| factor == expected),
                "link cluster evidence must contain {expected}, got {:?}",
                links.key_factors
            );
        }
    }

    #[test]
    fn weak_url_observations_are_visible_but_not_actionable_without_a_qualifier() {
        let session = make_session(
            "Invoice notification",
            "Download the invoice.",
            "notice@sender.invalid",
        );
        let mut link_content = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::Medium,
            &["dga_random_domain", "gateway_unwrapped_risky_target"],
        );
        link_content.details = json!({
            "score": 0.43,
            "causal_findings": [{
                "causal_key": "host:bucket.s3.region.object-storage.example.invalid",
                "categories": ["dga_random_domain", "gateway_unwrapped_risky_target"]
            }]
        });
        let mut link_reputation = make_result(
            "link_reputation",
            Pillar::Link,
            ThreatLevel::Low,
            &["long_domain", "deep_subdomain", "random_domain"],
        );
        link_reputation.details = json!({
            "score": 0.20,
            "causal_findings": [{
                "causal_key": "host:bucket.s3.region.object-storage.example.invalid",
                "categories": ["long_domain", "deep_subdomain", "random_domain"]
            }]
        });

        let results = HashMap::from([
            ("link_content".to_string(), link_content),
            ("link_reputation".to_string(), link_reputation),
        ]);
        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        assert!(
            normalized
                .clusters
                .iter()
                .all(|cluster| { cluster.id != EvidenceClusterId::LinkAndHtmlDeception }),
            "same-host weak URL observations must not create a standalone link cluster: {normalized:?}"
        );
        assert!(
            normalized
                .categories
                .contains(&"dga_random_domain".to_string())
        );
        assert!(
            normalized
                .categories
                .contains(&"gateway_unwrapped_risky_target".to_string())
        );
        assert!(!normalized.scenario.has_structural_threat_signal);
        assert!(
            !normalized
                .scenario
                .has_gateway_unwrapped_risky_target_signal
        );
    }

    #[test]
    fn one_effective_target_with_only_shape_signals_stays_out_of_threat_fusion() {
        let session = make_session(
            "Invoice notification",
            "Download the invoice.",
            "notice@sender.invalid",
        );
        let mut link_content = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["idn_homograph", "suspicious_params"],
        );
        link_content.details = json!({
            "score": 0.70,
            "causal_findings": [{
                "causal_key": "host:target.example.invalid",
                "categories": ["idn_homograph", "suspicious_params"]
            }]
        });
        let mut link_reputation = make_result(
            "link_reputation",
            Pillar::Link,
            ThreatLevel::High,
            &["brand_impersonation"],
        );
        link_reputation.details = json!({
            "score": 0.60,
            "causal_findings": [{
                "causal_key": "host:target.example.invalid",
                "categories": ["brand_impersonation"]
            }]
        });

        let results = HashMap::from([
            ("link_content".to_string(), link_content),
            ("link_reputation".to_string(), link_reputation),
        ]);
        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());
        assert!(
            normalized.clusters.is_empty(),
            "homograph, parameter, and brand-shape findings from one target are observations until independently corroborated: {normalized:?}"
        );
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        for category in ["idn_homograph", "suspicious_params", "brand_impersonation"] {
            assert!(normalized.categories.iter().any(|item| item == category));
        }
    }

    #[test]
    fn credential_brand_target_policy_maps_into_distinct_link_and_identity_clusters() {
        let policy = credential_brand_target_scenario_policy()
            .expect("embedded credential-brand-target policy must be valid");
        let session = make_session(
            "Synthetic account security review",
            "A new device was detected. Complete the requested security review.",
            "notice@sender.invalid",
        );
        let mut link_result = make_result("link_content", Pillar::Link, ThreatLevel::High, &[]);
        link_result.categories = vec![
            policy.credential_link_category.clone(),
            policy.high_risk_target_category.clone(),
            policy.brand_mismatch_category.clone(),
            policy.redirect_target_category.clone(),
            "dga_random_domain".to_string(),
        ];
        qualify_link_fixture(&mut link_result);
        let gateway_url =
            "https://gateway.example/redirect?url=https%3A%2F%2Fcapture.attacker.example%2Flogin";
        for record in link_result.details["qualified_link_compounds"]
            .as_array_mut()
            .unwrap()
        {
            record["original_url"] = json!(gateway_url);
        }
        link_result.details["credential_target_observations"] = json!([{
            "original_url": gateway_url,
            "effective_url": "https://capture.attacker.example/login",
            "gateway_unwrapped": true,
        }]);
        let mut results = HashMap::new();
        results.insert("link_content".to_string(), link_result);
        results.insert(
            "content_scan".to_string(),
            make_result(
                "content_scan",
                Pillar::Content,
                ThreatLevel::High,
                &["account_security_phishing"],
            ),
        );

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert!(normalized.scenario.has_account_security_signal);
        assert!(normalized.scenario.has_credential_link_signal);
        assert!(normalized.scenario.has_high_risk_credential_target_signal);
        assert!(normalized.scenario.has_brand_sender_target_mismatch_signal);
        assert!(
            normalized
                .scenario
                .has_gateway_unwrapped_risky_target_signal
        );
        let link_cluster = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception)
            .expect("the risky target category must map into the link cluster");
        let identity_cluster = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SenderIdentityAuthenticity)
            .expect("the brand triad category must map into the identity cluster");
        assert!(link_cluster.score > 0.0);
        assert!(identity_cluster.score > 0.0);
        assert!(
            normalized
                .categories
                .contains(&policy.high_risk_target_category)
        );
        assert!(
            normalized
                .categories
                .contains(&policy.brand_mismatch_category)
        );
        assert!(
            !normalized
                .scenario
                .admitted_categories
                .contains(&policy.redirect_target_category)
        );

        results.get_mut("link_content").unwrap().details["credential_target_observations"][0]["effective_url"] =
            json!("https://unrelated.example/login");
        let unrelated = normalize_results(Some(&session), &results, &VerdictConfig::default());
        assert!(!unrelated.scenario.has_gateway_unwrapped_risky_target_signal);
        assert!(unrelated.scenario.has_credential_link_signal);
        assert!(unrelated.scenario.qualified_credential_brand_target);
    }

    #[test]
    fn malformed_credential_scenario_policy_cannot_arm_a_floor() {
        let mut invalid = crate::module_data::module_data()
            .get_structured("credential_brand_target_policy_v1")
            .expect("embedded policy")
            .clone();
        invalid["verdict_floor"] = serde_json::json!(2.0);

        assert!(
            parse_credential_brand_target_scenario_policy(invalid).is_none(),
            "an invalid floor must disable the scenario policy without panicking"
        );
    }

    #[test]
    fn malformed_image_only_phishing_policy_fails_closed() {
        assert!(
            parse_image_only_phishing_medium_policy(json!({
                "enabled": true,
                "trigger_category": "image_only_phishing",
                "minimum_social_score": 0.08,
                "verdict_floor": 0.35,
                "require_unverified_sender": true
            }))
            .is_none()
        );
        assert!(
            parse_image_only_phishing_medium_policy(json!({
                "enabled": true,
                "trigger_category": "",
                "minimum_social_score": 0.08,
                "verdict_floor": 0.40,
                "require_unverified_sender": true
            }))
            .is_none()
        );
    }

    #[test]
    fn malformed_obfuscated_domain_lure_verdict_policy_fails_closed() {
        assert!(
            parse_obfuscated_domain_lure_verdict_policy(json!({
                "enabled": true,
                "result_category": "obfuscated_domain_lure",
                "minimum_social_score": 0.30,
                "verdict_floor": 0.39
            }))
            .is_none()
        );
        assert!(
            parse_obfuscated_domain_lure_verdict_policy(json!({
                "enabled": true,
                "result_category": "",
                "minimum_social_score": 0.30,
                "verdict_floor": 0.40
            }))
            .is_none()
        );
    }

    #[test]
    fn mailto_credential_form_is_native_actionable_html_evidence() {
        let data = crate::module_data::module_data();
        let category = data
            .get_structured("html_mailto_credential_form_policy_v1")
            .and_then(|policy| policy.get("result_category"))
            .and_then(serde_json::Value::as_str)
            .expect("embedded mailto credential-form category");
        let mapped = map_signal("html_scan", category).expect("mapped HTML signal");

        assert_eq!(mapped.cluster, EvidenceClusterId::LinkAndHtmlDeception);
        assert_eq!(mapped.family, "credential_exfiltration");
        assert!(mapped.scale >= 0.90);
        assert!(is_breaker_eligible_signal("html_scan", category));
    }

    #[test]
    fn stage_a_weak_fp_observations_do_not_create_threat_clusters() {
        let session = make_session(
            "Synthetic business notice",
            "A routine statement contains account fields and a long vendor URL.",
            "notice@vendor.example",
        );

        let mut identity = make_result(
            "identity_anomaly",
            Pillar::Semantic,
            ThreatLevel::High,
            &[
                "display_name_spoof",
                "first_contact",
                "random_domain",
                "suspicious_client",
            ],
        );
        identity.details = json!({ "score": 0.35 });

        let mut content = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &[
                "phishing",
                "bec",
                "bec_no_ioc_social",
                "phishing_subject",
                "multilingual_gibberish",
            ],
        );
        content.details = json!({ "score": 0.55 });

        let mut links = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &[
                "suspicious_params",
                "suspicious_path",
                "long_domain",
                "deep_subdomain",
            ],
        );
        links.details = json!({ "score": 0.80 });

        let mut attachment = make_result(
            "attach_scan",
            Pillar::Attachment,
            ThreatLevel::High,
            &["mime_mismatch"],
        );
        attachment.details = json!({ "score": 0.40 });

        let results = HashMap::from([
            ("identity_anomaly".to_string(), identity),
            ("content_scan".to_string(), content),
            ("link_content".to_string(), links),
            ("attach_scan".to_string(), attachment),
        ]);

        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert!(normalized.clusters.is_empty(), "{normalized:?}");
        assert_eq!(normalized.modules_flagged, 0, "{normalized:?}");
        for category in [
            "display_name_spoof",
            "phishing",
            "bec",
            "suspicious_params",
            "mime_mismatch",
        ] {
            assert!(
                normalized.categories.iter().any(|item| item == category),
                "weak observation {category} must remain analyst-visible: {normalized:?}"
            );
        }
    }

    #[test]
    fn stage_a_pii_reply_harvest_anchor_remains_actionable() {
        let mapped = map_content_signal("pii_reply_harvest_lure")
            .expect("qualified PII-harvest anchor must be registered");
        assert_eq!(mapped.cluster, EvidenceClusterId::SocialEngineeringIntent);
        assert_eq!(mapped.family, "pii_collection_lure");
        assert!(mapped.scale >= 0.86);
    }

    #[test]
    fn stage_a_generic_phishing_demotion_keeps_named_link_anchor_actionable() {
        let session = make_session(
            "Synthetic account verification",
            "Use the supplied link to review the security alert.",
            "security@sender.example",
        );
        let mut content = make_result(
            "content_scan",
            Pillar::Content,
            ThreatLevel::High,
            &["phishing", "external_action_link_lure"],
        );
        content.details = json!({ "score": 0.56 });

        let mut links = make_result(
            "link_content",
            Pillar::Link,
            ThreatLevel::High,
            &["suspicious_params", "targeted_credential_phishing"],
        );
        links.details = json!({ "score": 0.82 });
        qualify_link_fixture(&mut links);

        let results = HashMap::from([
            ("content_scan".to_string(), content),
            ("link_content".to_string(), links),
        ]);
        let normalized = normalize_results(Some(&session), &results, &VerdictConfig::default());

        assert!(
            normalized
                .clusters
                .iter()
                .any(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception),
            "the named action-link and targeted credential anchors must remain actionable: {normalized:?}"
        );
        assert!(
            !normalized
                .clusters
                .iter()
                .any(|cluster| cluster.id == EvidenceClusterId::SocialEngineeringIntent)
        );
        assert!(
            normalized
                .categories
                .iter()
                .any(|category| category == "phishing")
        );
    }
}
