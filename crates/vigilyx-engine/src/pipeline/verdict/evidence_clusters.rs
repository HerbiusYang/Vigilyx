use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock, RwLock};

use vigilyx_core::models::EmailSession;
use vigilyx_core::security::ModuleResult;

use crate::config::VerdictConfig;
use crate::modules::content_scan::{EffectiveKeywordLists, normalize_keyword_list};

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

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::InheritedGatewayPrior => "Inherited Gateway Prior",
            Self::DeliveryIntegrity => "Delivery Integrity",
            Self::SenderIdentityAuthenticity => "Sender Identity Authenticity",
            Self::LinkAndHtmlDeception => "Link and HTML Deception",
            Self::PayloadMalware => "Payload Malware",
            Self::ExternalReputationIoc => "External Reputation and IOC",
            Self::SocialEngineeringIntent => "Social Engineering Intent",
            Self::BusinessSensitivity => "Business Sensitivity",
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

#[derive(Debug, Clone)]
pub struct ClusterEvidence {
    pub id: EvidenceClusterId,
    pub score: f64,
    pub confidence: f64,
    /// Whether this cluster contains an independently strong signal allowed
    /// to activate the generic hard risk-floor circuit breaker.
    pub breaker_eligible: bool,
    pub modules: Vec<String>,
    pub key_factors: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ScenarioContext {
    pub tags: Vec<String>,
    pub gateway_banner_polluted: bool,
    pub notice_banner_polluted: bool,
    pub dsn_like_system_mail: bool,
    pub auto_reply_like: bool,
    pub semantic_nlp_only_signal: bool,
    pub transcript_like_structure: bool,
    pub sender_alignment_verified: bool,
    pub has_header_spoof_signal: bool,
    pub has_payment_change_signal: bool,
    pub has_account_security_signal: bool,
    pub has_credential_link_signal: bool,
    pub has_malicious_ioc_signal: bool,
    pub has_subsidy_fraud_signal: bool,
    pub has_invoice_spam_signal: bool,
    pub has_crypto_wallet_signal: bool,
    pub has_attachment_phishing_signal: bool,
    pub has_attachment_sensitive_data_signal: bool,
    pub has_high_risk_attachment_content: bool,
    /// Structural threat signals independent of NLP/banner text pollution.
    /// Includes: DGA domains, brand impersonation, domain mismatches,
    /// suspicious TLDs, language inconsistency, attachment type mismatches.
    pub has_structural_threat_signal: bool,
    pub alignment_score: f64,
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
    categories: BTreeSet<String>,
    modules: BTreeSet<String>,
    factors: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct ClusterAccumulator {
    families: HashMap<&'static str, FamilyAccumulator>,
    categories: BTreeSet<String>,
    modules: BTreeSet<String>,
    breaker_eligible: bool,
}

pub fn normalize_results(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> NormalizedEvidence {
    let mut accumulators: HashMap<EvidenceClusterId, ClusterAccumulator> = HashMap::new();
    let mut categories = BTreeSet::new();
    let mut modules_run = 0u32;
    let mut modules_flagged = 0u32;
    let mut total_duration_ms = 0u64;

    for result in results
        .values()
        .filter(|result| result.module_id != "verdict")
    {
        modules_run += 1;
        total_duration_ms += result.duration_ms;

        if result.threat_level <= vigilyx_core::security::ThreatLevel::Safe {
            continue;
        }

        modules_flagged += 1;
        let module_weight = config
            .weights
            .get(&result.module_id)
            .copied()
            .unwrap_or(1.0);
        let base_score = (result.raw_score() * module_weight).clamp(0.0, 1.0);
        let confidence = result.confidence.clamp(0.0, 1.0);
        for category in &result.categories {
            categories.insert(category.clone());
            if let Some(mapped) = map_signal(&result.module_id, category) {
                let cluster = accumulators.entry(mapped.cluster).or_default();
                cluster.categories.insert(category.clone());
                cluster.modules.insert(result.module_id.clone());
                cluster.breaker_eligible |= is_breaker_eligible_signal(&result.module_id, category);

                let family = cluster.families.entry(mapped.family).or_default();
                family.score = family
                    .score
                    .max((base_score * mapped.scale).clamp(0.0, 1.0));
                family.confidence = family.confidence.max(confidence);
                family.categories.insert(category.clone());
                family.modules.insert(result.module_id.clone());
                family
                    .factors
                    .insert(key_factor_for_signal(result, category));
            }
        }
    }

    let scenario = detect_scenarios(session, &categories, results);
    let mut clusters = Vec::new();

    for cluster_id in EvidenceClusterId::ALL {
        let Some(cluster) = accumulators.remove(&cluster_id) else {
            continue;
        };
        if cluster.families.is_empty() {
            continue;
        }

        let mut family_scores: Vec<f64> = cluster.families.values().map(|f| f.score).collect();
        family_scores.sort_by(|a, b| b.total_cmp(a));

        let base_score = 1.0
            - family_scores
                .iter()
                .fold(1.0, |acc, score| acc * (1.0 - score));
        let synergy = (cluster.families.len().saturating_sub(1).min(3) as f64) * 0.04;
        let mut score = (base_score + synergy).min(cluster_id.score_cap());
        // Structural URL heuristics can be numerous but are not independent
        // proof of credential theft. Keep a weak-only link cluster below High
        // until a breaker-eligible anchor is present.
        if cluster_id == EvidenceClusterId::LinkAndHtmlDeception && !cluster.breaker_eligible {
            score = score.min(0.44);
        }

        let mut max_confidence: f64 = 0.0;
        let mut key_factors = BTreeSet::new();
        for family in cluster.families.values() {
            max_confidence = max_confidence.max(family.confidence);
            for factor in family.factors.iter().take(2) {
                key_factors.insert(factor.clone());
            }
        }
        let confidence = ((max_confidence * cluster_id.confidence_scale())
            + 0.03 * (cluster.modules.len().saturating_sub(1).min(3) as f64))
            .clamp(0.20, 0.95);

        clusters.push(ClusterEvidence {
            id: cluster_id,
            score,
            confidence,
            breaker_eligible: cluster.breaker_eligible,
            modules: cluster.modules.into_iter().collect(),
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
    let has_nlp_echo = categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "nlp_phishing" | "nlp_scam" | "nlp_bec" | "nlp_spam" | "nonsensical_spam"
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

    let auto_reply_corroborated = is_auto_reply_subject
        && (is_system_sender || has_empty_return_path || is_multipart_report);
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
                | "credential_link_lure"
                | "targeted_credential_phishing"
        )
    }) {
        context.has_account_security_signal = true;
        context.tags.push("account_security_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "credential_link_lure"
                | "targeted_credential_phishing"
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
    }) {
        context.has_credential_link_signal = true;
        context.tags.push("credential_link_signal".to_string());
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

    if categories.contains("invoice_spam") {
        context.has_invoice_spam_signal = true;
        context.tags.push("invoice_spam_signal".to_string());
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
            "dga_random_domain"
                | "external_impersonation"
                | "domain_mismatch"
                | "suspicious_tld"
                | "lang_inconsistency"
                | "type_mismatch"
                | "idn_homograph"
                | "mixed_script_domain"
                | "attachment_phishing_url"
        )
    }) {
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
        "targeted_credential_phishing" => return "Targeted Credential Phishing".to_string(),
        "bec" => return "Business Email Compromise".to_string(),
        "gateway_pre_classified" => return "Upstream Gateway Prior".to_string(),
        "subject_contact_lure" => return "Subject Contact Lure".to_string(),
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
        .and_then(|result| {
            result
                .details
                .get("alignment_score")
                .or_else(|| result.details.get("trust_score"))
        })
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
            // These categories describe inspection coverage only.  They are
            // retained in the module result and verdict metadata, but must
            // never enter the Payload Malware evidence cluster.
            "attachment_inspection_limited"
            | "unsupported_container"
            | "encrypted_attachment"
            | "encrypted_archive"
            | "encrypted_pdf"
            | "ocr_unavailable" => None,
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
        "html_scan" | "html_pixel_art" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "html_obfuscation",
            scale: 0.74,
        }),
        "link_scan" => map_link_scan_signal(category),
        "link_content" => map_link_content_signal(category),
        "link_reputation" => map_link_reputation_signal(category),
        "semantic_scan" => map_semantic_signal(category),
        "anomaly_detect" => match category {
            "no_recipients" | "recipient_metadata_incomplete" => None,
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
        // Payment-account-change BEC from an external sender (detectors.rs
        // emits this with a score of up to 0.78) is concrete business
        // sensitivity evidence — it must not be dropped on the floor.
        "bec_payment_change" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: transaction_family(category),
            scale: transaction_scale(category),
        }),
        "subject_contact_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: "off_platform_contact_lure",
            scale: 0.50,
        }),
        // The structural combination is a link deception signal. It is not a
        // generic breaker anchor by itself; clustered DS applies the scenario
        // floor only after both the credential instruction and auth-link facts
        // are present.
        "credential_link_lure" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "credential_lure",
            scale: 0.86,
        }),
        "phishing"
        | "bec"
        | "bec_no_ioc_social"
        | "phishing_subject"
        | "phone_in_subject"
        | "image_only_phishing"
        | "account_security_phishing"
        | "subsidy_fraud"
        | "invoice_spam"
        | "phone_in_body"
        | "lang_inconsistency" => Some(MappedSignal {
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
        "dlp_credit_card" | "dlp_id_number" => None,
        "attachment_phishing_url" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_embedded_url",
            scale: 0.74,
        }),
        // A meta-refresh target inside an HTML attachment is the same kind of
        // embedded-URL evidence as a phishing URL — one family, one signal.
        "attachment_meta_refresh" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_embedded_url",
            scale: 0.70,
        }),
        "attachment_credential_form" | "nested_message_phishing" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "attachment_embedded_phishing",
            scale: 0.86,
        }),
        "ics_embedded_executable" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "attachment_embedded_payload",
            scale: 0.80,
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
        "envelope_spoofing" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "envelope_alignment",
            scale: 0.80,
        }),
        // Outsourced reply handling is common in legitimate marketing and
        // transactional mail. Preserve the mismatch in verdict categories
        // and scenario context, but do not manufacture an identity cluster
        // from this routing observation alone. Compound spoof/lure scenarios
        // still consume `has_header_spoof_signal` below.
        "domain_mismatch" => None,
        "brand_spoof_reply_to" | "protected_domain_spoof" | "known_impersonation_domain" => {
            Some(MappedSignal {
                cluster: EvidenceClusterId::SenderIdentityAuthenticity,
                family: "protected_identity",
                scale: 0.80,
            })
        }
        "auth_spf_dmarc_fail"
        | "auth_spf_fail"
        | "auth_dmarc_fail"
        | "no_auth_results"
        | "future_date"
        | "stale_date"
        | "missing_date"
        | "missing_message_id"
        | "suspicious_mailer"
        | "no_received"
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
        // These categories can only be emitted after exact-signature opt-in
        // or format-aware payload validation.
        "verified_yara_signature" | "verified_payload_anchor" => 0.98,
        "verified_executable_payload" => 0.94,
        // Candidate rules are hunting leads. They must not inherit the same
        // fusion scale as AV verdicts or structurally verified executables.
        "pe_structural_candidate" => 0.48,
        // A container polyglot (image with an appended ZIP) is strong
        // evasion evidence, but it is not proof of a malicious payload.
        "polyglot_container" => 0.60,
        _ => 0.78,
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
    let family = match category {
        "redirect_url" | "suspicious_params" | "excessive_links" | "url_shortener"
        | "unparseable_url" => "weak_link_context",
        "href_text_mismatch" | "userinfo_in_url" => "link_impersonation",
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

fn is_breaker_eligible_signal(module_id: &str, category: &str) -> bool {
    if matches!(module_id, "av_eml_scan" | "av_attach_scan" | "sandbox_scan") {
        return true;
    }

    // A generic/custom YARA match is not automatically equivalent to an AV
    // conviction. Only an explicitly exact signature or the structural
    // validator's active-payload anchor may impose a hard risk floor.
    if module_id == "yara_scan" {
        return matches!(
            category,
            "verified_yara_signature" | "verified_payload_anchor"
        );
    }

    matches!(
        category,
        "malware_hash"
            | "virus_detected"
            | "sandbox_malicious"
            | "sandbox_c2_detected"
            | "malicious_document"
            | "webshell"
            | "hash_intel_malicious"
            | "intel_malicious"
            | "url_intel_malicious"
            | "sender_ip_malicious"
            | "ioc_ip_hit"
            | "blacklisted_domain"
            | "blacklisted_parent_domain"
            | "protected_domain_spoof"
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

fn map_semantic_signal(category: &str) -> Option<MappedSignal> {
    Some(MappedSignal {
        cluster: EvidenceClusterId::SocialEngineeringIntent,
        family: social_family(category),
        scale: social_scale(category),
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
        "no_received" | "excessive_hops" => "received_chain",
        "suspicious_mailer" => "mailer_identity",
        _ => "delivery_other",
    }
}

fn delivery_scale(category: &str) -> f64 {
    match category {
        "auth_spf_dmarc_fail" => 0.72,
        "auth_spf_fail" | "auth_dmarc_fail" => 0.65,
        "no_auth_results" | "no_received" => 0.50,
        "header_injection" => 0.75,
        _ => 0.55,
    }
}

fn social_family(category: &str) -> &'static str {
    match category {
        "phishing"
        | "phishing_subject"
        | "account_security_phishing"
        | "credential_link_lure"
        | "image_only_phishing"
        | "targeted_credential_phishing" => "credential_theft_intent",
        "bec" | "bec_no_ioc_social" | "nlp_bec" => "bec_intent",
        "subsidy_fraud" | "invoice_spam" | "nlp_scam" => "financial_fraud_intent",
        "sextortion" | "extortion_threat" => "extortion_intent",
        "nlp_spam" | "nonsensical_spam" | "mass_mailing" | "spam_cannon" => "bulk_spam_intent",
        "foreign_to_cn_corp" | "japanese_to_cn_corp" | "japanese_unexpected" => "language_context",
        "phone_in_subject" | "phone_in_body" => "contact_urgency",
        "subject_contact_lure" => "off_platform_contact_lure",
        "llm_injection_suspected" => "ai_integrity",
        "lang_inconsistency" | "multilingual_gibberish" => "language_anomaly",
        _ => "social_other",
    }
}

fn social_scale(category: &str) -> f64 {
    match category {
        "account_security_phishing" => 0.88,
        "credential_link_lure" => 0.82,
        "phishing" | "phishing_subject" | "nlp_phishing" => 0.76,
        "bec" | "bec_no_ioc_social" | "nlp_bec" => 0.72,
        "subsidy_fraud" | "invoice_spam" | "nlp_scam" => 0.66,
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
        "recipient_in_url" | "long_url" | "suspicious_params" | "suspicious_param_value"
        | "double_encoding" | "multiple_redirects" => "weak_link_context",
        "at_sign_obfuscation" | "idn_homograph" | "org_domain_mimicry" | "url_typo" => {
            "link_impersonation"
        }
        "dga_random_domain" | "hex_subdomain" | "encoded_separator" | "unusual_port"
        | "oss_content_override" => "link_obfuscation",
        // Percent-decoded layers that resolve to a dangerous protocol are
        // active payloads, not context — same family link_scan uses for
        // javascript:/data: URIs so one underlying signal is not double-counted.
        "encoded_protocol_param" | "double_encoded_payload" => "active_link_payload",
        "deep_fragment_route" | "suspicious_fragment" | "mobile_redirect" => "fragment_obfuscation",
        "suspicious_path" => "credential_pathing",
        _ => "link_content_other",
    }
}

fn link_content_scale(category: &str) -> f64 {
    match category {
        "targeted_credential_phishing" => 0.92,
        "recipient_in_url" | "at_sign_obfuscation" | "idn_homograph" | "org_domain_mimicry"
        | "encoded_protocol_param" => 0.82,
        "dga_random_domain" | "double_encoded_payload" | "oss_content_override" => 0.72,
        "mobile_redirect" => 0.60,
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
    use vigilyx_core::security::{ModuleResult, Pillar, ThreatLevel};

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
        ModuleResult {
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
        }
    }

    #[test]
    fn detect_scenarios_marks_attachment_phish_and_sensitive_data_flags() {
        let session = make_session(
            "微信聊天记录",
            "附件中包含密码重置提示与卡号信息",
            "799422752@qq.com",
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
            "info@contact.acams.org",
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
            "info@contact.acams.org",
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
        let identity = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::SenderIdentityAuthenticity)
            .expect("identity cluster");
        let links = normalized
            .clusters
            .iter()
            .find(|cluster| cluster.id == EvidenceClusterId::LinkAndHtmlDeception)
            .expect("link cluster");

        assert!((identity.score - 0.64).abs() < 1e-9);
        assert!(!identity.breaker_eligible);
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
    fn only_verified_yara_or_structural_payload_can_trigger_breaker() {
        assert!(is_breaker_eligible_signal(
            "yara_scan",
            "verified_yara_signature"
        ));
        assert!(is_breaker_eligible_signal(
            "yara_scan",
            "verified_payload_anchor"
        ));
    }

    #[test]
    fn detect_scenarios_marks_subsidy_invoice_crypto_and_spoof_flags() {
        let session = make_session(
            "外贸货款对公 平台结算",
            "请尽快处理补贴款，另可加Q 3826878185 办理增值税发票并使用钱包地址支付",
            "yleqte@qq.com",
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
            cluster_ids.contains(&EvidenceClusterId::SocialEngineeringIntent),
            "bec_no_ioc_social must produce a SocialEngineeringIntent cluster, got {cluster_ids:?}"
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
            "fjlmodtf@diic.com",
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
    fn lone_reply_domain_mismatch_is_visible_without_standalone_cluster() {
        let session = make_session(
            "Electronic invoice",
            "Your invoice is ready.",
            "notify@supports.ly.com",
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
            normalized.clusters.is_empty(),
            "a bare Reply-To routing mismatch must not create threat evidence: {:?}",
            normalized.clusters
        );
        assert!(normalized.scenario.has_header_spoof_signal);
        assert!(normalized.scenario.has_structural_threat_signal);
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

        assert!(normalized.scenario.has_header_spoof_signal);
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

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &categories,
            &HashMap::new(),
            &patterns,
        );

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
            "1738338551@qq.com",
        );
        let categories = BTreeSet::from(["nlp_phishing".to_string()]);

        let scenario = detect_scenarios_with_patterns(
            Some(&session),
            &categories,
            &HashMap::new(),
            &patterns,
        );

        assert!(
            scenario.notice_banner_polluted,
            "a notice banner in the body must still mark notice_banner_polluted"
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
            "Suspicious Param Value",
        ] {
            assert!(
                links.key_factors.iter().any(|factor| factor == expected),
                "link cluster evidence must contain {expected}, got {:?}",
                links.key_factors
            );
        }
    }
}
