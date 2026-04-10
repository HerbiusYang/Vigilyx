use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, OnceLock, RwLock};

use vigilyx_core::models::EmailSession;
use vigilyx_core::security::ModuleResult;

use crate::config::VerdictConfig;
use crate::modules::content_scan::EffectiveKeywordLists;

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
    pub has_payment_change_signal: bool,
    pub has_account_security_signal: bool,
    pub has_credential_link_signal: bool,
    pub has_malicious_ioc_signal: bool,
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
    GLOBAL_SCENARIO_PATTERNS
        .get_or_init(|| Arc::new(RwLock::new(ScenarioPatternLists::default())))
}

pub fn set_runtime_scenario_patterns(patterns: ScenarioPatternLists) {
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

    for result in results.values().filter(|result| result.module_id != "verdict") {
        modules_run += 1;
        total_duration_ms += result.duration_ms;

        if result.threat_level <= vigilyx_core::security::ThreatLevel::Safe {
            continue;
        }

        modules_flagged += 1;
        let module_weight = config.weights.get(&result.module_id).copied().unwrap_or(1.0);
        let base_score = (result.raw_score() * module_weight).clamp(0.0, 1.0);
        let confidence = result.confidence.clamp(0.0, 1.0);
        for category in &result.categories {
            categories.insert(category.clone());
            if let Some(mapped) = map_signal(&result.module_id, category) {
                let cluster = accumulators.entry(mapped.cluster).or_default();
                cluster.categories.insert(category.clone());
                cluster.modules.insert(result.module_id.clone());

                let family = cluster.families.entry(mapped.family).or_default();
                family.score = family.score.max((base_score * mapped.scale).clamp(0.0, 1.0));
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

        let base_score = 1.0 - family_scores.iter().fold(1.0, |acc, score| acc * (1.0 - score));
        let synergy = (cluster.families.len().saturating_sub(1).min(3) as f64) * 0.04;
        let score = (base_score + synergy).min(cluster_id.score_cap());

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
    let mut context = ScenarioContext {
        alignment_score: extract_alignment_score(results),
        ..ScenarioContext::default()
    };
    let scenario_patterns = current_scenario_patterns();

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
    if has_gateway_prior
        && scenario_patterns
            .gateway_banner_patterns
            .iter()
            .any(|pattern| subject_lower.contains(pattern) || body_lower.contains(pattern))
    {
        context.gateway_banner_polluted = true;
        context.tags.push("gateway_banner_polluted".to_string());
    }

    if has_nlp_echo
        && scenario_patterns
            .notice_banner_patterns
            .iter()
            .any(|pattern| subject_lower.contains(pattern) || body_lower.contains(pattern))
    {
        context.notice_banner_polluted = true;
        context.tags.push("notice_banner_polluted".to_string());
    }

    let is_auto_submitted = session.is_some_and(|session| {
        session.content.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("auto-submitted")
                && value.to_ascii_lowercase().contains("auto-")
        })
    });
    let is_system_sender = sender_lower.contains("mailer-daemon")
        || sender_lower.contains("postmaster")
        || sender_lower.contains("mail delivery system");
    let is_dsn_subject = scenario_patterns
        .dsn_patterns
        .iter()
        .any(|pattern| subject_lower.contains(pattern));
    if is_auto_submitted || is_system_sender || is_dsn_subject {
        context.dsn_like_system_mail = true;
        context.tags.push("dsn_like_system_mail".to_string());
    }

    let is_auto_reply_subject = scenario_patterns
        .auto_reply_patterns
        .iter()
        .any(|pattern| subject_lower.contains(pattern));
    if is_auto_submitted || is_auto_reply_subject {
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
                | "wire_transfer"
                | "bank_account_detected"
                | "iban_detected"
                | "swift_code_detected"
        )
    }) {
        context.has_payment_change_signal = true;
        context.tags.push("payment_change_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "account_security_phishing" | "targeted_credential_phishing"
        )
    }) {
        context.has_account_security_signal = true;
        context.tags.push("account_security_signal".to_string());
    }

    if categories.iter().any(|category| {
        matches!(
            category.as_str(),
            "suspicious_params"
                | "recipient_in_url"
                | "at_sign_obfuscation"
                | "targeted_credential_phishing"
                | "redirect_target"
                | "redirect_url"
                | "href_text_mismatch"
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

    let short_lines = lines.iter().filter(|line| line.chars().count() <= 48).count();
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
                    Some(first) => {
                        first.to_uppercase().collect::<String>() + chars.as_str()
                    }
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
        "attach_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "attachment_anomaly",
            scale: 0.72,
        }),
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
        "av_eml_scan" | "av_attach_scan" | "sandbox_scan" | "yara_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::PayloadMalware,
            family: "malware_signature",
            scale: 0.95,
        }),
        "header_scan" => map_header_signal(category),
        "mime_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::DeliveryIntegrity,
            family: "mime_integrity",
            scale: 0.58,
        }),
        "identity_anomaly" => map_identity_signal(category),
        "html_scan" | "html_pixel_art" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "html_obfuscation",
            scale: 0.74,
        }),
        "link_scan" => Some(MappedSignal {
            cluster: EvidenceClusterId::LinkAndHtmlDeception,
            family: "link_structure",
            scale: 0.78,
        }),
        "link_content" => map_link_content_signal(category),
        "link_reputation" => map_link_reputation_signal(category),
        "semantic_scan" => map_semantic_signal(category),
        "anomaly_detect" => match category {
            "no_recipients" => Some(MappedSignal {
                cluster: EvidenceClusterId::DeliveryIntegrity,
                family: "recipient_integrity",
                scale: 0.55,
            }),
            _ => Some(MappedSignal {
                cluster: EvidenceClusterId::SocialEngineeringIntent,
                family: "behavioral_pattern",
                scale: 0.52,
            }),
        },
        "transaction_correlation" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: transaction_family(category),
            scale: transaction_scale(category),
        }),
        _ => map_fallback_signal(category),
    }
}

fn map_content_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "gateway_pre_classified" => Some(MappedSignal {
            cluster: EvidenceClusterId::InheritedGatewayPrior,
            family: "gateway_banner",
            scale: 0.60,
        }),
        "dlp_credit_card" | "dlp_id_number" | "dlp_api_key" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: "sensitive_content",
            scale: if category == "dlp_api_key" { 0.58 } else { 0.66 },
        }),
        "external_impersonation" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "external_impersonation",
            scale: 0.78,
        }),
        "phishing"
        | "bec"
        | "phishing_subject"
        | "phone_in_subject"
        | "image_only_phishing"
        | "account_security_phishing"
        | "subsidy_fraud"
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
        "dlp_credit_card" | "dlp_id_number" => Some(MappedSignal {
            cluster: EvidenceClusterId::BusinessSensitivity,
            family: "attachment_dlp",
            scale: 0.64,
        }),
        "phishing" | "bec" => Some(MappedSignal {
            cluster: EvidenceClusterId::SocialEngineeringIntent,
            family: social_family(category),
            scale: 0.74,
        }),
        _ => None,
    }
}

fn map_header_signal(category: &str) -> Option<MappedSignal> {
    match category {
        "ioc_ip_hit" | "sender_ip_malicious" | "sender_ip_suspicious" => Some(MappedSignal {
            cluster: EvidenceClusterId::ExternalReputationIoc,
            family: "sender_ip_reputation",
            scale: if category == "sender_ip_malicious" { 0.88 } else { 0.72 },
        }),
        "domain_mismatch" | "brand_spoof_reply_to" | "envelope_spoofing" | "protected_domain_spoof" => {
            Some(MappedSignal {
                cluster: EvidenceClusterId::SenderIdentityAuthenticity,
                family: "header_identity",
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
        "reply_chain_anomaly" | "suspicious_client" | "envelope_mismatch" => Some(MappedSignal {
            cluster: EvidenceClusterId::SenderIdentityAuthenticity,
            family: "mail_client_envelope",
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
            scale: 0.66,
        }),
        _ => None,
    }
}

fn map_link_content_signal(category: &str) -> Option<MappedSignal> {
    Some(MappedSignal {
        cluster: EvidenceClusterId::LinkAndHtmlDeception,
        family: link_content_family(category),
        scale: link_content_scale(category),
    })
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
        | "image_only_phishing"
        | "targeted_credential_phishing" => "credential_theft_intent",
        "bec" | "nlp_bec" => "bec_intent",
        "subsidy_fraud" | "nlp_scam" => "financial_fraud_intent",
        "sextortion" | "extortion_threat" => "extortion_intent",
        "nlp_spam" | "nonsensical_spam" | "mass_mailing" | "spam_cannon" => "bulk_spam_intent",
        "foreign_to_cn_corp" | "japanese_to_cn_corp" | "japanese_unexpected" => "language_context",
        "phone_in_subject" | "phone_in_body" => "contact_urgency",
        "lang_inconsistency" | "multilingual_gibberish" => "language_anomaly",
        _ => "social_other",
    }
}

fn social_scale(category: &str) -> f64 {
    match category {
        "account_security_phishing" => 0.88,
        "phishing" | "phishing_subject" | "nlp_phishing" => 0.76,
        "bec" | "nlp_bec" => 0.72,
        "subsidy_fraud" | "nlp_scam" => 0.66,
        "sextortion" | "extortion_threat" => 0.82,
        "gateway_pre_classified" => 0.30,
        "foreign_to_cn_corp" | "japanese_to_cn_corp" | "japanese_unexpected" => 0.42,
        "nlp_spam" | "nonsensical_spam" => 0.46,
        _ => 0.56,
    }
}

fn transaction_family(category: &str) -> &'static str {
    match category {
        "iban_detected" | "swift_code_detected" | "bank_account_detected" => {
            "banking_identifier"
        }
        "wire_transfer" | "crypto_wallet" => "payment_rail",
        "payment_change" => "payment_change",
        "urgency_financial_combo" => "financial_urgency",
        "multi_financial_entities" => "financial_density",
        _ => "business_other",
    }
}

fn transaction_scale(category: &str) -> f64 {
    match category {
        "payment_change" => 0.76,
        "wire_transfer" | "crypto_wallet" => 0.70,
        "multi_financial_entities" => 0.52,
        "urgency_financial_combo" => 0.60,
        _ => 0.62,
    }
}

fn link_content_family(category: &str) -> &'static str {
    match category {
        "recipient_in_url" | "targeted_credential_phishing" => "targeted_link",
        "at_sign_obfuscation" | "idn_homograph" | "org_domain_mimicry" | "url_typo" => {
            "link_impersonation"
        }
        "dga_random_domain" | "hex_subdomain" | "long_url" | "double_encoding"
        | "encoded_separator" | "multiple_redirects" | "unusual_port" => "link_obfuscation",
        "deep_fragment_route" | "suspicious_fragment" | "mobile_redirect" => "fragment_obfuscation",
        "suspicious_path" | "suspicious_params" => "credential_pathing",
        _ => "link_content_other",
    }
}

fn link_content_scale(category: &str) -> f64 {
    match category {
        "targeted_credential_phishing" => 0.92,
        "recipient_in_url" | "at_sign_obfuscation" | "idn_homograph" | "org_domain_mimicry" => {
            0.82
        }
        "dga_random_domain" => 0.72,
        "mobile_redirect" => 0.60,
        _ => 0.66,
    }
}

fn link_reputation_family(category: &str) -> &'static str {
    match category {
        "redirect_target" | "redirect_url" => "redirect_chain",
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
        "intel_malicious" | "url_intel_malicious" | "hash_intel_malicious" => {
            "malicious_intel"
        }
        "intel_suspicious" | "url_intel_suspicious" | "hash_intel_suspicious" => {
            "suspicious_intel"
        }
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
