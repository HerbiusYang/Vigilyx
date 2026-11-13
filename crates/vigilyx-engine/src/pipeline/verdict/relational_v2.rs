//! Non-additive relational V2 shadow model.
//!
//! This path is intentionally independent from `clustered_ds_v2`. It retains
//! every module result, then evaluates named hypotheses against scoped facts.
//! No detector score, BPA, module count, max, or previous verdict is a
//! decision input. The result is diagnostic only.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use vigilyx_core::models::EmailSession;
use vigilyx_core::security::relational::{
    LegacyAlertReference, ObservationSnapshot, RelationDecision, RelationState,
    RelationalAssessment, RelationalEvidenceRef, RetainedModuleEvidence,
};
use vigilyx_core::security::{
    ModuleResult, SemanticActorRole, SemanticClaim, SemanticCoverageStatus,
    SemanticLinkObservation, SemanticLinkOwnershipStatus, SemanticMessageContext, SemanticPolarity,
    SemanticQuoteStatus, SemanticScenarioId, SemanticSpeechAct, SemanticTargetRole, ThreatLevel,
};

use crate::module_data::ModuleDataRegistry;
use crate::modules::common::extract_domain_from_email;
use crate::semantic::semantic_counter_context_qualifies;

const POLICY_JSON: &str = include_str!("../../../../../shared/schemas/relational_v2_policy.json");
const MAX_CONTEXTS: usize = 16;
const MAX_CLAIMS: usize = 256;
const MAX_LINKS: usize = 512;
const MAX_TARGETS: usize = 512;
const MAX_RELATIONS: usize = 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u32,
    policy_version: u32,
    enabled: bool,
    /// This is an evidence-admission floor for the current extractor, not a
    /// calibrated probability or a confidence estimate for the email.
    semantic_admission_floor: f64,
    semantic_module: String,
    target_module: String,
    scenario_list: String,
    brand_profile_list: String,
    relations: Vec<RelationRule>,
    native_sources: Vec<NativeRule>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RelationId {
    CredentialBrandTargetContradiction,
}

impl RelationId {
    fn label(self) -> &'static str {
        match self {
            Self::CredentialBrandTargetContradiction => "credential_brand_target_contradiction",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationRule {
    id: RelationId,
    scenarios: Vec<SemanticScenarioId>,
    deceptive_target_categories: Vec<String>,
    severity: ThreatLevel,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NativeGuard {
    InfectedAttachmentScan,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRule {
    id: String,
    module_id: String,
    category: String,
    guard: NativeGuard,
    severity: ThreatLevel,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    scenario_id: SemanticScenarioId,
    variants: Vec<Variant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Variant {
    actions_any: Vec<String>,
    objects_any: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrandProfile {
    brand: String,
    #[serde(default)]
    aliases: Vec<String>,
    sender_domains: Vec<String>,
    landing_domains: Vec<String>,
}

/// Same-link target facts emitted before the legacy link detector applies its
/// CTA/score gates. Raw values stay in the owning module result; this adapter
/// only reads them through pointers.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetObservation {
    original_url: String,
    effective_url: String,
    #[serde(default)]
    anchor_text: Option<String>,
    #[serde(default)]
    risky_target_categories: Vec<String>,
    claimed_brand: Option<String>,
    from_domain: Option<String>,
    target_domain: Option<String>,
    sender_brand_aligned: Option<bool>,
    target_brand_aligned: Option<bool>,
    brand_sender_target_mismatch: Option<bool>,
    #[serde(default)]
    ownership_status: Option<SemanticLinkOwnershipStatus>,
    #[serde(default)]
    observation_complete: Option<bool>,
}

fn valid_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256
}

fn parse_policy(value: &Value) -> Option<Policy> {
    let policy: Policy = serde_json::from_value(value.clone()).ok()?;
    if policy.schema_version != 1
        || policy.policy_version == 0
        || !policy.enabled
        || !policy.semantic_admission_floor.is_finite()
        || !(0.5..=1.0).contains(&policy.semantic_admission_floor)
        || !valid_id(&policy.semantic_module)
        || !valid_id(&policy.target_module)
        || policy.semantic_module == policy.target_module
        || !valid_id(&policy.scenario_list)
        || !valid_id(&policy.brand_profile_list)
        || policy.relations.is_empty()
        || policy.relations.len() > 16
        || policy.native_sources.len() > 32
    {
        return None;
    }

    let mut ids = BTreeSet::new();
    for rule in &policy.relations {
        if !ids.insert(rule.id.label().to_owned())
            || rule.scenarios.is_empty()
            || rule.scenarios.iter().any(|scenario| {
                !matches!(
                    scenario,
                    SemanticScenarioId::CredentialRequest
                        | SemanticScenarioId::AccountAccessRequest
                )
            })
            || rule.deceptive_target_categories.is_empty()
            || rule
                .deceptive_target_categories
                .iter()
                .any(|category| !valid_id(category))
            || rule.severity != ThreatLevel::High
        {
            return None;
        }
    }
    for rule in &policy.native_sources {
        if !valid_id(&rule.id)
            || !ids.insert(rule.id.clone())
            || !valid_id(&rule.module_id)
            || !valid_id(&rule.category)
            || rule.severity != ThreatLevel::Critical
        {
            return None;
        }
    }
    Some(policy)
}

fn evidence_ref(module_id: &str, pointer: impl Into<String>) -> RelationalEvidenceRef {
    RelationalEvidenceRef {
        module_id: module_id.to_owned(),
        pointer: pointer.into(),
    }
}

fn pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn bounded_categories(categories: &[String]) -> (Vec<String>, bool) {
    let snapshot = ObservationSnapshot::capture(categories, 0);
    (snapshot.categories, snapshot.truncated)
}

fn inventory(results: &HashMap<String, ModuleResult>) -> Vec<RetainedModuleEvidence> {
    let mut ordered = results.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|(key, _)| *key);
    ordered
        .into_iter()
        .map(|(key, result)| {
            let snapshot = result
                .details
                .get("observation_snapshot")
                .and_then(|value| serde_json::from_value::<ObservationSnapshot>(value.clone()).ok())
                .filter(|snapshot| snapshot.schema_version == 1);
            let (categories, category_truncated) = bounded_categories(&result.categories);
            let (snapshot_categories, snapshot_truncated) = snapshot
                .as_ref()
                .map(|snapshot| bounded_categories(&snapshot.categories))
                .unwrap_or_default();
            let mut observations = vec![
                evidence_ref(&result.module_id, "/categories"),
                evidence_ref(&result.module_id, "/evidence"),
            ];
            let mut detail_truncated = false;
            if let Some(details) = result.details.as_object() {
                for (index, field) in details.keys().enumerate() {
                    if index >= 64 || !valid_id(field) {
                        detail_truncated = true;
                        continue;
                    }
                    observations.push(evidence_ref(
                        &result.module_id,
                        format!("/details/{}", pointer_escape(field)),
                    ));
                }
            }
            RetainedModuleEvidence {
                result_key: key.clone(),
                module_id: result.module_id.clone(),
                original_level: result.threat_level,
                categories,
                snapshot_categories,
                evidence_count: result.evidence.len(),
                snapshot_evidence_count: snapshot.as_ref().map(|snapshot| snapshot.evidence_count),
                observations,
                incomplete: category_truncated
                    || snapshot_truncated
                    || detail_truncated
                    || snapshot.is_some_and(|snapshot| snapshot.truncated),
            }
        })
        .collect()
}

fn legacy_alerts(modules: &[RetainedModuleEvidence]) -> Vec<LegacyAlertReference> {
    modules
        .iter()
        .filter(|module| module.original_level >= ThreatLevel::High)
        .map(|module| LegacyAlertReference {
            result_key: module.result_key.clone(),
            module_id: module.module_id.clone(),
            original_level: module.original_level,
            categories: module.categories.clone(),
            evidence_refs: module.observations.clone(),
        })
        .collect()
}

fn decision(id: &str, key: &str, refs: Vec<RelationalEvidenceRef>) -> RelationDecision {
    RelationDecision {
        relation_id: id.to_owned(),
        candidate_key: key.to_owned(),
        state: RelationState::Unresolved,
        candidate_severity: None,
        evidence_refs: refs,
        reasons: Vec::new(),
    }
}

fn stop(mut outcome: RelationDecision, state: RelationState, reason: &str) -> RelationDecision {
    outcome.state = state;
    outcome.candidate_severity = None;
    outcome.reasons.push(reason.to_owned());
    outcome
}

fn canonical_url(value: &str) -> Option<Url> {
    if value.len() > 16_384 {
        return None;
    }
    let url = Url::parse(value).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then_some(url)
}

fn opaque_key(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    format!("relation:{}", hex::encode(digest.finalize()))
}

fn domains_match(domain: &str, allowed: &[String]) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|item| {
        let item = item.trim().trim_start_matches('.').to_ascii_lowercase();
        !item.is_empty() && (domain == item || domain.ends_with(&format!(".{item}")))
    })
}

fn phrase_present(text: &str, phrase: &str) -> bool {
    if phrase.trim().is_empty() {
        return false;
    }
    let text = text.to_lowercase();
    let phrase = phrase.to_lowercase();
    text.match_indices(&phrase).any(|(offset, _)| {
        if !phrase.is_ascii() {
            return true;
        }
        let before = text
            .get(..offset)
            .and_then(|value| value.chars().next_back());
        let after = text
            .get(offset + phrase.len()..)
            .and_then(|value| value.chars().next());
        !before.is_some_and(|character| character.is_alphanumeric())
            && !after.is_some_and(|character| character.is_alphanumeric())
    })
}

fn scenario_matches(claim: &SemanticClaim, scenario: &Scenario) -> bool {
    let has_action = |candidate: &str| {
        claim
            .action
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(candidate))
            || claim
                .actions
                .iter()
                .any(|value| value.eq_ignore_ascii_case(candidate))
    };
    let has_object = |candidate: &str| {
        claim
            .object
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(candidate))
            || claim
                .objects
                .iter()
                .any(|value| value.eq_ignore_ascii_case(candidate))
    };
    scenario.variants.iter().any(|variant| {
        variant.actions_any.iter().any(|action| has_action(action))
            && variant.objects_any.iter().any(|object| has_object(object))
    })
}

fn scenario_label(scenario: SemanticScenarioId) -> &'static str {
    match scenario {
        SemanticScenarioId::CredentialRequest => "credential_request",
        SemanticScenarioId::AccountAccessRequest => "account_access_request",
        SemanticScenarioId::PaymentAccountChangeRequest => "payment_account_change_request",
        SemanticScenarioId::SensitiveDataRequest => "sensitive_data_request",
        SemanticScenarioId::OffPlatformContactRequest => "off_platform_contact_request",
        SemanticScenarioId::AccountSecurityVerification => "account_security_verification",
        SemanticScenarioId::StorageQuotaReward => "storage_quota_reward",
    }
}

fn semantic_gate(
    context: &SemanticMessageContext,
    claim: &SemanticClaim,
    admission_floor: f64,
    mut outcome: RelationDecision,
) -> Result<RelationDecision, RelationDecision> {
    if !valid_id(&claim.source_span_id)
        || !valid_id(&claim.causal_key)
        || claim.span.start_byte >= claim.span.end_byte
        || !claim.confidence.is_finite()
        || !(0.0..=1.0).contains(&claim.confidence)
    {
        return Err(stop(
            outcome,
            RelationState::Unresolved,
            "invalid_claim_provenance",
        ));
    }
    if claim.confidence < admission_floor {
        return Err(stop(
            outcome,
            RelationState::Unresolved,
            "semantic_attribution_requires_confirmation",
        ));
    }
    if claim.polarity == SemanticPolarity::AntiAction {
        return Err(stop(
            outcome,
            RelationState::Refuted,
            "same_claim_is_anti_action",
        ));
    }
    if matches!(
        claim.quote_or_forward_status,
        SemanticQuoteStatus::Quoted
            | SemanticQuoteStatus::Forwarded
            | SemanticQuoteStatus::Reported
    ) {
        return Err(stop(
            outcome,
            RelationState::Refuted,
            "reported_text_not_current_instruction",
        ));
    }
    if !matches!(
        claim.actor_role,
        SemanticActorRole::Sender | SemanticActorRole::AuthenticatedSender
    ) || claim.target_role != SemanticTargetRole::Recipient
        || !matches!(
            claim.speech_act,
            SemanticSpeechAct::Request | SemanticSpeechAct::Instruction
        )
        || claim.polarity != SemanticPolarity::Action
        || claim.quote_or_forward_status != SemanticQuoteStatus::Original
    {
        return Err(stop(
            outcome,
            RelationState::Unresolved,
            "current_recipient_action_not_established",
        ));
    }

    let mut anti_action = false;
    for counter_id in &claim.counter_context_ids {
        let Some(counter) = context
            .claims
            .iter()
            .find(|other| &other.source_span_id == counter_id)
        else {
            return Err(stop(
                outcome,
                RelationState::Unresolved,
                "counter_context_reference_missing",
            ));
        };
        if counter.source_span_id == claim.source_span_id {
            return Err(stop(
                outcome,
                RelationState::Unresolved,
                "counter_context_self_reference",
            ));
        }
        if !valid_id(&counter.source_span_id)
            || !valid_id(&counter.causal_key)
            || counter.span.start_byte >= counter.span.end_byte
            || !counter.confidence.is_finite()
            || counter.confidence < admission_floor
            || counter.confidence > 1.0
            || counter.source_part != claim.source_part
            || !matches!(
                counter.actor_role,
                SemanticActorRole::Sender | SemanticActorRole::AuthenticatedSender
            )
            || counter.target_role != SemanticTargetRole::Recipient
            || !matches!(
                counter.speech_act,
                SemanticSpeechAct::Request
                    | SemanticSpeechAct::Instruction
                    | SemanticSpeechAct::Warning
            )
            || counter.quote_or_forward_status != SemanticQuoteStatus::Original
        {
            return Err(stop(
                outcome,
                RelationState::Unresolved,
                "counter_context_attribution_unreliable",
            ));
        }
        if !semantic_counter_context_qualifies(claim, counter) {
            return Err(stop(
                outcome,
                RelationState::Unresolved,
                "counter_context_scope_inconsistent",
            ));
        }
        anti_action |= counter.polarity == SemanticPolarity::AntiAction;
    }
    if !claim.counter_context_ids.is_empty() {
        outcome
            .reasons
            .push("scoped_counter_context_observed".to_owned());
        return Err(if anti_action {
            stop(outcome, RelationState::Refuted, "scoped_anti_action")
        } else {
            stop(
                outcome,
                RelationState::Unresolved,
                "counter_context_requires_adjudication",
            )
        });
    }
    Ok(outcome)
}

fn evaluate_target(
    mut outcome: RelationDecision,
    context: &SemanticMessageContext,
    link: &SemanticLinkObservation,
    target: &TargetObservation,
    profiles: &[BrandProfile],
    rule: &RelationRule,
) -> RelationDecision {
    let Some(effective) = canonical_url(&target.effective_url) else {
        return stop(outcome, RelationState::Unresolved, "effective_url_invalid");
    };
    if let Some(observed) = &link.effective_url
        && canonical_url(observed).as_ref() != Some(&effective)
    {
        return stop(
            outcome,
            RelationState::Conflicted,
            "effective_target_disagreement",
        );
    }
    let Some(brand) = target
        .claimed_brand
        .as_deref()
        .filter(|value| valid_id(value))
    else {
        return stop(outcome, RelationState::Unresolved, "claimed_brand_missing");
    };
    let Some(profile) = profiles
        .iter()
        .find(|profile| profile.brand.eq_ignore_ascii_case(brand))
    else {
        return stop(outcome, RelationState::Unresolved, "brand_profile_missing");
    };
    let Some(anchor) = target
        .anchor_text
        .as_deref()
        .filter(|value| value.len() <= 8192)
    else {
        return stop(outcome, RelationState::Unresolved, "local_anchor_missing");
    };
    if !std::iter::once(&profile.brand)
        .chain(profile.aliases.iter())
        .any(|alias| phrase_present(anchor, alias))
    {
        return stop(
            outcome,
            RelationState::Unresolved,
            "brand_not_bound_to_same_anchor",
        );
    }
    if target.observation_complete == Some(false) {
        return stop(
            outcome,
            RelationState::Unresolved,
            "same_link_observation_incomplete",
        );
    }

    let Some(sender) = context
        .header_sender
        .as_deref()
        .and_then(extract_domain_from_email)
    else {
        return stop(outcome, RelationState::Unresolved, "header_sender_missing");
    };
    let sender = sender.trim_end_matches('.').to_ascii_lowercase();
    let target_domain = effective
        .host_str()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if target.from_domain.as_deref().map(str::to_ascii_lowercase) != Some(sender.clone())
        || target.target_domain.as_deref().map(str::to_ascii_lowercase)
            != Some(target_domain.clone())
    {
        return stop(
            outcome,
            RelationState::Conflicted,
            "identity_target_record_disagreement",
        );
    }
    let sender_aligned = domains_match(&sender, &profile.sender_domains);
    let target_aligned = domains_match(&target_domain, &profile.landing_domains);
    if target.sender_brand_aligned != Some(sender_aligned)
        || target.target_brand_aligned != Some(target_aligned)
    {
        return stop(
            outcome,
            RelationState::Conflicted,
            "brand_profile_record_disagreement",
        );
    }
    if sender_aligned || target_aligned {
        return stop(
            outcome,
            RelationState::Unresolved,
            "identity_contradiction_not_established",
        );
    }
    if target.brand_sender_target_mismatch != Some(true) {
        return stop(
            outcome,
            RelationState::Unresolved,
            "identity_contradiction_not_recorded",
        );
    }
    if target.ownership_status == Some(SemanticLinkOwnershipStatus::Proven)
        || link.ownership_status == SemanticLinkOwnershipStatus::Proven
    {
        return stop(
            outcome,
            RelationState::Conflicted,
            "ownership_and_impersonation_need_reconciliation",
        );
    }
    if !target
        .risky_target_categories
        .iter()
        .any(|category| rule.deceptive_target_categories.contains(category))
    {
        return stop(
            outcome,
            RelationState::Unresolved,
            "shape_only_not_deceptive_relation",
        );
    }
    outcome.state = RelationState::Supported;
    outcome.candidate_severity = Some(rule.severity);
    outcome
        .reasons
        .push("current_action_same_anchor_brand_and_deceptive_target_contradiction".to_owned());
    outcome.reasons.push(
        if link.transport_status != vigilyx_core::security::SemanticLinkTransportStatus::Reachable
            || link.content_status != vigilyx_core::security::SemanticLinkContentStatus::Observed
        {
            "link_content_not_verified".to_owned()
        } else {
            "link_content_observed_with_unresolved_ownership".to_owned()
        },
    );
    outcome
}

fn native_findings(
    policy: &Policy,
    results: &HashMap<String, ModuleResult>,
) -> Vec<RelationDecision> {
    let mut findings = Vec::new();
    for rule in &policy.native_sources {
        let Some(result) = results
            .get(&rule.module_id)
            .filter(|result| result.module_id == rule.module_id)
        else {
            continue;
        };
        if !result.categories.contains(&rule.category) {
            continue;
        }
        let mut outcome = decision(
            &rule.id,
            &opaque_key(&[&rule.id, &rule.module_id]),
            vec![
                evidence_ref(&rule.module_id, "/details/infected_files"),
                evidence_ref(&rule.module_id, "/details/scanned_count"),
            ],
        );
        let valid = match rule.guard {
            NativeGuard::InfectedAttachmentScan => {
                let infected = result
                    .details
                    .get("infected_files")
                    .and_then(Value::as_array);
                let scanned = result.details.get("scanned_count").and_then(Value::as_u64);
                infected.is_some_and(|files| {
                    !files.is_empty()
                        && files
                            .iter()
                            .all(|file| file.as_str().is_some_and(|value| !value.is_empty()))
                        && scanned.is_some_and(|count| count >= files.len() as u64)
                })
            }
        };
        if valid {
            outcome.state = RelationState::Supported;
            outcome.candidate_severity = Some(rule.severity);
            outcome
                .reasons
                .push("native_scan_positive_retained_independently".to_owned());
        } else {
            outcome
                .reasons
                .push("native_category_without_required_scan_provenance".to_owned());
        }
        findings.push(outcome);
    }
    findings
}

pub(super) fn assess(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
) -> RelationalAssessment {
    let data = crate::module_data::module_data();
    let policy = serde_json::from_str(POLICY_JSON).unwrap_or(Value::Null);
    assess_with_policy(session, results, &data, &policy)
}

fn assess_with_policy(
    session: Option<&EmailSession>,
    results: &HashMap<String, ModuleResult>,
    data: &ModuleDataRegistry,
    policy_value: &Value,
) -> RelationalAssessment {
    let modules = inventory(results);
    let mut assessment = RelationalAssessment {
        model: "relational_v2".to_owned(),
        model_version: 1,
        policy_version: None,
        policy_sha256: None,
        calibrated: false,
        legacy_alerts: legacy_alerts(&modules),
        modules,
        relations: Vec::new(),
        gaps: Vec::new(),
    };
    if session.is_none_or(|session| session.content.has_inspection_coverage_gap()) {
        assessment
            .gaps
            .push("session_coverage_unknown_or_incomplete".to_owned());
    }
    if assessment.modules.iter().any(|module| module.incomplete) {
        assessment
            .gaps
            .push("observation_inventory_truncated".to_owned());
    }
    for alert in &assessment.legacy_alerts {
        assessment
            .gaps
            .push(format!("unadapted_legacy_alert:{}", alert.module_id));
    }

    let Some(policy) = parse_policy(policy_value) else {
        assessment
            .gaps
            .push("relation_policy_invalid_or_disabled".to_owned());
        return assessment;
    };
    assessment.policy_version = Some(policy.policy_version);
    let scenario_value = data
        .get_structured(&policy.scenario_list)
        .cloned()
        .unwrap_or(Value::Null);
    let profile_value = data
        .get_structured(&policy.brand_profile_list)
        .cloned()
        .unwrap_or(Value::Null);
    let policy_bytes =
        serde_json::to_vec(&(policy_value, &scenario_value, &profile_value)).unwrap_or_default();
    assessment.policy_sha256 = Some(hex::encode(Sha256::digest(policy_bytes)));
    assessment.relations = native_findings(&policy, results);

    let scenarios = serde_json::from_value::<Vec<Scenario>>(scenario_value)
        .ok()
        .filter(|items| {
            !items.is_empty()
                && items.len() <= 32
                && items.iter().all(|item| {
                    !item.variants.is_empty()
                        && item.variants.iter().all(|variant| {
                            !variant.actions_any.is_empty()
                                && !variant.objects_any.is_empty()
                                && variant
                                    .actions_any
                                    .iter()
                                    .chain(&variant.objects_any)
                                    .all(|value| valid_id(value))
                        })
                })
        });
    let profiles = serde_json::from_value::<Vec<BrandProfile>>(profile_value)
        .ok()
        .filter(|items| {
            !items.is_empty()
                && items.len() <= 256
                && items.iter().all(|item| {
                    valid_id(&item.brand)
                        && !item.sender_domains.is_empty()
                        && !item.landing_domains.is_empty()
                        && item
                            .aliases
                            .iter()
                            .chain(&item.sender_domains)
                            .chain(&item.landing_domains)
                            .all(|value| valid_id(value))
                })
        });
    let (Some(scenarios), Some(profiles)) = (scenarios, profiles) else {
        assessment
            .gaps
            .push("semantic_or_brand_policy_missing_or_invalid".to_owned());
        return assessment;
    };

    let Some(semantic) = results
        .get(&policy.semantic_module)
        .filter(|result| result.module_id == policy.semantic_module)
    else {
        assessment
            .gaps
            .push("semantic_module_unavailable".to_owned());
        return assessment;
    };
    let mut projections = Vec::new();
    if let Some(value) = semantic.details.get("semantic_context") {
        projections.push(("/details/semantic_context".to_owned(), value));
    }
    if let Some(alternatives) = semantic
        .details
        .get("semantic_alternative_contexts")
        .and_then(Value::as_array)
    {
        for (index, alternative) in alternatives.iter().enumerate() {
            if let Some(value) = alternative.get("semantic_context") {
                projections.push((
                    format!("/details/semantic_alternative_contexts/{index}/semantic_context"),
                    value,
                ));
            }
        }
    }
    if let Some(sources) = semantic
        .details
        .get("visual_ocr_semantic_context")
        .and_then(Value::as_array)
    {
        for (index, source) in sources.iter().enumerate().take(MAX_CONTEXTS) {
            if let Some(value) = source.get("semantic_context") {
                projections.push((
                    format!("/details/visual_ocr_semantic_context/{index}/semantic_context"),
                    value,
                ));
            }
        }
        if sources.len() > MAX_CONTEXTS {
            assessment
                .gaps
                .push("semantic_projection_budget".to_owned());
        }
    }
    if projections.is_empty() {
        assessment.gaps.push("semantic_context_missing".to_owned());
    }

    let mut targets: BTreeMap<String, Vec<(String, TargetObservation)>> = BTreeMap::new();
    if let Some(result) = results
        .get(&policy.target_module)
        .filter(|result| result.module_id == policy.target_module)
    {
        if result
            .details
            .get("relational_targets_truncated")
            .and_then(Value::as_bool)
            == Some(true)
        {
            assessment.gaps.push("target_observation_budget".to_owned());
        }
        let field = if result
            .details
            .get("relational_target_observations")
            .is_some()
        {
            "relational_target_observations"
        } else {
            "credential_target_observations"
        };
        let items = result.details.get(field).and_then(Value::as_array);
        if items.is_none() {
            assessment
                .gaps
                .push("target_observations_missing_or_invalid".to_owned());
        }
        let empty = Vec::new();
        let items = items.unwrap_or(&empty);
        if items.len() > MAX_TARGETS {
            assessment.gaps.push("target_observation_budget".to_owned());
        }
        for (index, item) in items.iter().take(MAX_TARGETS).enumerate() {
            if let Ok(target) = serde_json::from_value::<TargetObservation>(item.clone())
                && let Some(url) = canonical_url(&target.original_url)
            {
                targets
                    .entry(url.to_string())
                    .or_default()
                    .push((format!("/details/{field}/{index}"), target));
            } else {
                assessment
                    .gaps
                    .push("target_observation_invalid".to_owned());
            }
        }
    } else {
        assessment.gaps.push("target_module_unavailable".to_owned());
    }

    for (projection, value) in projections {
        let bounded = value
            .get("claims")
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() <= MAX_CLAIMS)
            && value
                .get("links")
                .and_then(Value::as_array)
                .is_some_and(|items| items.len() <= MAX_LINKS);
        if !bounded {
            assessment
                .gaps
                .push("semantic_context_missing_or_over_budget".to_owned());
            continue;
        }
        let Ok(context) = serde_json::from_value::<SemanticMessageContext>(value.clone()) else {
            assessment.gaps.push("semantic_context_invalid".to_owned());
            continue;
        };
        if context.schema_version != 2 {
            assessment
                .gaps
                .push("semantic_schema_unsupported".to_owned());
            continue;
        }
        evaluate_context(
            &context,
            &projection,
            &policy,
            &scenarios,
            &profiles,
            &targets,
            &mut assessment,
        );
    }
    assessment.relations.sort_by(|left, right| {
        (&left.relation_id, &left.candidate_key).cmp(&(&right.relation_id, &right.candidate_key))
    });
    assessment.gaps.sort();
    assessment.gaps.dedup();
    assessment
}

fn evaluate_context(
    context: &SemanticMessageContext,
    projection: &str,
    policy: &Policy,
    scenarios: &[Scenario],
    profiles: &[BrandProfile],
    targets: &BTreeMap<String, Vec<(String, TargetObservation)>>,
    assessment: &mut RelationalAssessment,
) {
    if context.coverage != SemanticCoverageStatus::Complete {
        assessment
            .gaps
            .push(format!("semantic_projection_incomplete:{projection}"));
    }
    if context
        .links
        .iter()
        .any(|link| link.coverage_reason.is_some() || link.failure_reason.is_some())
    {
        assessment
            .gaps
            .push(format!("link_verification_limited:{projection}"));
    }

    let mut seen = BTreeSet::new();
    for claim in &context.claims {
        if !seen.insert(claim.source_span_id.clone()) {
            continue;
        }
        let claim_indices = context
            .claims
            .iter()
            .enumerate()
            .filter_map(|(index, other)| {
                (other.source_span_id == claim.source_span_id).then_some(index)
            })
            .collect::<Vec<_>>();
        let claim_evidence_refs = claim_indices
            .iter()
            .map(|index| {
                evidence_ref(
                    &policy.semantic_module,
                    format!("{projection}/claims/{index}"),
                )
            })
            .collect::<Vec<_>>();
        let conflicting_claim_id = context
            .claims
            .iter()
            .filter(|other| other.source_span_id == claim.source_span_id)
            .any(|other| other != claim);
        let mut seen_hypotheses = BTreeSet::new();
        for scenario in scenarios
            .iter()
            .filter(|scenario| scenario_matches(claim, scenario))
        {
            if assessment.relations.len() >= MAX_RELATIONS {
                assessment.gaps.push("relation_budget_exhausted".to_owned());
                return;
            }
            let rule = policy
                .relations
                .iter()
                .find(|rule| rule.scenarios.contains(&scenario.scenario_id));
            let id = rule
                .map(|rule| rule.id.label())
                .unwrap_or_else(|| scenario_label(scenario.scenario_id));
            let base_key = opaque_key(&[projection, &claim.source_span_id, id]);
            if !seen_hypotheses.insert(base_key.clone()) {
                continue;
            }
            let mut base = decision(id, &base_key, claim_evidence_refs.clone());
            if conflicting_claim_id {
                assessment.relations.push(stop(
                    base,
                    RelationState::Conflicted,
                    "duplicate_claim_id_disagreement",
                ));
                continue;
            }
            base = match semantic_gate(context, claim, policy.semantic_admission_floor, base) {
                Ok(value) => value,
                Err(value) => {
                    assessment.relations.push(value);
                    continue;
                }
            };
            let Some(rule) = rule else {
                assessment.relations.push(stop(
                    base,
                    RelationState::Unresolved,
                    "scenario_relation_adapter_pending",
                ));
                continue;
            };

            let mut by_target: BTreeMap<String, Vec<RelationDecision>> = BTreeMap::new();
            for (link_index, link) in context.links.iter().enumerate() {
                if !claim.link_ids.contains(&link.link_id)
                    || link.source_span_id.as_deref() != Some(claim.source_span_id.as_str())
                {
                    continue;
                }
                if context
                    .links
                    .iter()
                    .any(|other| other.link_id == link.link_id && other != link)
                {
                    by_target
                        .entry(link.link_id.clone())
                        .or_default()
                        .push(stop(
                            base.clone(),
                            RelationState::Conflicted,
                            "duplicate_link_id_disagreement",
                        ));
                    continue;
                }
                let Some(url) = canonical_url(&link.original_url) else {
                    continue;
                };
                let Some(observations) = targets.get(url.as_str()) else {
                    continue;
                };
                for (pointer, target) in observations {
                    let mut local = base.clone();
                    local.evidence_refs.push(evidence_ref(
                        &policy.semantic_module,
                        format!("{projection}/links/{link_index}"),
                    ));
                    local
                        .evidence_refs
                        .push(evidence_ref(&policy.target_module, pointer.clone()));
                    // `TargetObservation` contains only same-link values; the
                    // anchor binding is checked by requiring the target
                    // collector to emit a local brand claim. The value is
                    // intentionally not copied into relation output.
                    by_target
                        .entry(url.to_string())
                        .or_default()
                        .push(evaluate_target(
                            local, context, link, target, profiles, rule,
                        ));
                }
            }

            if by_target.is_empty() {
                assessment.relations.push(stop(
                    base,
                    RelationState::Unresolved,
                    "same_link_target_evidence_missing",
                ));
            } else {
                for (target_key, candidates) in by_target {
                    if assessment.relations.len() >= MAX_RELATIONS {
                        assessment.gaps.push("relation_budget_exhausted".to_owned());
                        return;
                    }
                    let mut outcome = base.clone();
                    outcome.candidate_key = opaque_key(&[&base_key, &target_key]);
                    let supported = candidates
                        .iter()
                        .any(|candidate| candidate.state == RelationState::Supported);
                    let countered = candidates.iter().any(|candidate| {
                        matches!(
                            candidate.state,
                            RelationState::Refuted | RelationState::Conflicted
                        )
                    });
                    outcome.state = if countered {
                        RelationState::Conflicted
                    } else if supported {
                        RelationState::Supported
                    } else {
                        RelationState::Unresolved
                    };
                    outcome.candidate_severity =
                        (outcome.state == RelationState::Supported).then_some(rule.severity);
                    for candidate in candidates {
                        outcome.evidence_refs.extend(candidate.evidence_refs);
                        outcome.reasons.extend(candidate.reasons);
                    }
                    outcome.evidence_refs.sort();
                    outcome.evidence_refs.dedup();
                    outcome.reasons.sort();
                    outcome.reasons.dedup();
                    assessment.relations.push(outcome);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_data::ModuleDataOverrides;
    use serde_json::json;
    use vigilyx_core::security::{Bpa, Pillar};

    fn data() -> ModuleDataRegistry {
        let seed = json!({"lists": {
            "semantic_scenario_policy_v1": {"items": [
                {"scenario_id": "account_access_request", "variants": [
                    {"actions_any": ["verify", "click"], "objects_any": ["account"]}]},
                {"scenario_id": "credential_request", "variants": [
                    {"actions_any": ["verify"], "objects_any": ["password"]}]},
                {"scenario_id": "payment_account_change_request", "variants": [
                    {"actions_any": ["pay"], "objects_any": ["bank account"]}]}
            ]},
            "account_action_brand_profiles_v1": {"items": [
                {"brand": "Acme", "aliases": ["Acme"],
                 "sender_domains": ["acme.example"], "landing_domains": ["acme.example"]}
            ]}
        }});
        ModuleDataRegistry::from_seed_and_overrides(
            &seed.to_string(),
            &ModuleDataOverrides::default(),
        )
        .unwrap()
    }

    fn policy() -> Value {
        serde_json::from_str(POLICY_JSON).unwrap()
    }

    fn module(id: &str) -> ModuleResult {
        ModuleResult::safe_analyzed(id, id, Pillar::Content, "fixture", 0)
    }

    fn fixture() -> HashMap<String, ModuleResult> {
        let url = "https://acme.example@capture.attacker.example/login";
        let mut semantic = module("semantic_scan");
        semantic.details = json!({"semantic_context": {
            "schema_version": 2, "coverage": "complete", "header_sender": "help@attacker.example",
            "claims": [{
                "source_span_id": "html:0:80", "source_part": "html",
                "span": {"start_byte": 0, "end_byte": 80},
                "actor_role": "sender", "target_role": "recipient", "speech_act": "request",
                "polarity": "action", "quote_or_forward_status": "original",
                "actions": ["verify"], "objects": ["account"], "link_ids": ["link:a"],
                "counter_context_ids": [], "confidence": 0.75, "causal_key": "claim:a"
            }],
            "links": [{
                "link_id": "link:a", "source_span_id": "html:0:80", "extraction_source": "href",
                "original_url": url, "transport_status": "not_attempted", "content_status": "not_observed",
                "ownership_status": "unknown", "causal_key": "url:a"
            }]
        }});
        let mut target = module("link_content");
        target.details = json!({"score": 0.0, "relational_target_observations": [{
            "original_url": url, "effective_url": url, "anchor_text": "Acme verify account",
            "claimed_brand": "Acme", "from_domain": "attacker.example", "target_domain": "capture.attacker.example",
            "sender_brand_aligned": false, "target_brand_aligned": false,
            "brand_sender_target_mismatch": true, "risky_target_categories": ["at_sign_obfuscation"]
        }]});
        HashMap::from([
            ("semantic_scan".into(), semantic),
            ("link_content".into(), target),
        ])
    }

    fn assess_fixture(results: &HashMap<String, ModuleResult>) -> RelationalAssessment {
        assess_with_policy(None, results, &data(), &policy())
    }

    fn semantic_details_mut(results: &mut HashMap<String, ModuleResult>) -> &mut Value {
        &mut results.get_mut("semantic_scan").unwrap().details
    }

    #[test]
    fn complete_relation_can_be_high_when_legacy_modules_are_safe() {
        let results = fixture();
        let assessment = assess_fixture(&results);
        assert_eq!(assessment.relations[0].state, RelationState::Supported);
        assert_eq!(
            assessment.relations[0].candidate_severity,
            Some(ThreatLevel::High)
        );
        assert!(!assessment.calibrated);
        assert!(
            assessment
                .modules
                .iter()
                .all(|module| module.original_level == ThreatLevel::Safe)
        );
        let json = serde_json::to_string(&assessment).unwrap();
        assert!(!json.contains("capture.attacker.example"));
        assert!(!json.contains("Acme verify account"));
        assert!(!json.contains("raw_score"));
    }

    #[test]
    fn repeated_weak_facts_do_not_manufacture_a_relation() {
        let mut results = HashMap::new();
        for index in 0..100 {
            let id = format!("weak_{index}");
            let mut result = module(&id);
            result.threat_level = ThreatLevel::Low;
            result.categories = vec!["unknown_shape".into()];
            result.details = json!({"score": 0.99});
            results.insert(id, result);
        }
        let assessment = assess_fixture(&results);
        assert_eq!(assessment.modules.len(), 100);
        assert!(assessment.relations.is_empty());
    }

    #[test]
    fn scores_and_bpa_are_not_inputs_to_relation_state() {
        let original = fixture();
        let mut changed = original.clone();
        for result in changed.values_mut() {
            result.threat_level = ThreatLevel::Critical;
            result.confidence = 1.0;
            result.bpa = Some(Bpa::new(1.0, 0.0, 0.0));
            result.details["score"] = json!(1.0);
        }
        let left = assess_fixture(&original);
        let right = assess_fixture(&changed);
        assert_eq!(left.relations, right.relations);
        assert_eq!(right.legacy_alerts.len(), 2);
    }

    #[test]
    fn removing_same_link_edge_leaves_the_candidate_unknown() {
        let mut results = fixture();
        semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["link_ids"] =
            json!(["other-link"]);
        let assessment = assess_fixture(&results);
        assert_eq!(assessment.relations[0].state, RelationState::Unresolved);
    }

    #[test]
    fn weak_semantic_attribution_is_unknown_even_with_structural_target_facts() {
        let mut results = fixture();
        semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["confidence"] =
            json!(0.01);
        let assessment = assess_fixture(&results);
        assert_eq!(assessment.relations[0].state, RelationState::Unresolved);
        assert!(
            assessment.relations[0]
                .reasons
                .contains(&"semantic_attribution_requires_confirmation".to_owned())
        );
    }

    #[test]
    fn quotes_negation_and_unknown_roles_do_not_become_current_requests() {
        for (field, value, expected) in [
            ("quote_or_forward_status", "quoted", RelationState::Refuted),
            (
                "quote_or_forward_status",
                "forwarded",
                RelationState::Refuted,
            ),
            ("polarity", "anti_action", RelationState::Refuted),
            ("actor_role", "unknown", RelationState::Unresolved),
            (
                "target_role",
                "named_third_party",
                RelationState::Unresolved,
            ),
            (
                "quote_or_forward_status",
                "unknown",
                RelationState::Unresolved,
            ),
        ] {
            let mut results = fixture();
            semantic_details_mut(&mut results)["semantic_context"]["claims"][0][field] =
                json!(value);
            assert_eq!(
                assess_fixture(&results).relations[0].state,
                expected,
                "{field}={value}"
            );
        }
    }

    #[test]
    fn conflicting_claim_id_is_conflicted_and_order_invariant() {
        let mut results = fixture();
        let mut conflicting =
            results["semantic_scan"].details["semantic_context"]["claims"][0].clone();
        conflicting["polarity"] = json!("anti_action");
        semantic_details_mut(&mut results)["semantic_context"]["claims"]
            .as_array_mut()
            .unwrap()
            .push(conflicting);
        let first = assess_fixture(&results);
        results.get_mut("semantic_scan").unwrap().details["semantic_context"]["claims"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let second = assess_fixture(&results);
        assert_eq!(first.relations, second.relations);
        assert_eq!(first.relations[0].state, RelationState::Conflicted);
        assert!(
            first.relations[0]
                .reasons
                .contains(&"duplicate_claim_id_disagreement".to_owned())
        );
    }

    #[test]
    fn unrelated_counter_context_does_not_refute_the_request() {
        let mut results = fixture();
        let mut counter = results["semantic_scan"].details["semantic_context"]["claims"][0].clone();
        counter["source_span_id"] = json!("html:200:250");
        counter["span"] = json!({"start_byte": 200, "end_byte": 250});
        counter["polarity"] = json!("anti_action");
        counter["speech_act"] = json!("warning");
        counter["objects"] = json!(["invoice"]);
        semantic_details_mut(&mut results)["semantic_context"]["claims"]
            .as_array_mut()
            .unwrap()
            .push(counter);
        assert_eq!(
            assess_fixture(&results).relations[0].state,
            RelationState::Supported
        );
    }

    #[test]
    fn scoped_anti_action_refutes_only_the_local_candidate() {
        let mut results = fixture();
        let mut counter = results["semantic_scan"].details["semantic_context"]["claims"][0].clone();
        counter["source_span_id"] = json!("html:81:100");
        counter["span"] = json!({"start_byte": 81, "end_byte": 100});
        counter["polarity"] = json!("anti_action");
        counter["speech_act"] = json!("warning");
        semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["counter_context_ids"] =
            json!(["html:81:100"]);
        semantic_details_mut(&mut results)["semantic_context"]["claims"]
            .as_array_mut()
            .unwrap()
            .push(counter);
        assert!(
            assess_fixture(&results)
                .relations
                .iter()
                .all(|relation| relation.state == RelationState::Refuted)
        );
    }

    #[test]
    fn quoted_or_unattributed_counter_context_stays_unknown() {
        for (field, value) in [
            ("quote_or_forward_status", "quoted"),
            ("actor_role", "quoted_author"),
            ("speech_act", "report"),
        ] {
            let mut results = fixture();
            let mut counter =
                results["semantic_scan"].details["semantic_context"]["claims"][0].clone();
            counter["source_span_id"] = json!("html:81:100");
            counter["span"] = json!({"start_byte": 81, "end_byte": 100});
            counter["polarity"] = json!("anti_action");
            counter["speech_act"] = json!("warning");
            counter[field] = json!(value);
            semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["counter_context_ids"] =
                json!(["html:81:100"]);
            semantic_details_mut(&mut results)["semantic_context"]["claims"]
                .as_array_mut()
                .unwrap()
                .push(counter);
            let assessment = assess_fixture(&results);
            let request = assessment
                .relations
                .iter()
                .find(|relation| {
                    relation
                        .evidence_refs
                        .iter()
                        .any(|reference| reference.pointer == "/details/semantic_context/claims/0")
                })
                .expect("original request relation");
            assert_eq!(request.state, RelationState::Unresolved, "{field}={value}");
        }
    }

    #[test]
    fn referenced_counter_requires_both_action_and_object() {
        for (actions, objects) in [
            (json!(["verify"]), json!(["invoice"])),
            (json!(["pay"]), json!(["account"])),
        ] {
            let mut results = fixture();
            let mut counter =
                results["semantic_scan"].details["semantic_context"]["claims"][0].clone();
            counter["source_span_id"] = json!("html:81:100");
            counter["span"] = json!({"start_byte": 81, "end_byte": 100});
            counter["polarity"] = json!("anti_action");
            counter["speech_act"] = json!("warning");
            counter["actions"] = actions;
            counter["objects"] = objects;
            semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["counter_context_ids"] =
                json!(["html:81:100"]);
            semantic_details_mut(&mut results)["semantic_context"]["claims"]
                .as_array_mut()
                .unwrap()
                .push(counter);
            let assessment = assess_fixture(&results);
            let request = assessment
                .relations
                .iter()
                .find(|relation| {
                    relation
                        .evidence_refs
                        .iter()
                        .any(|reference| reference.pointer == "/details/semantic_context/claims/0")
                })
                .unwrap();
            assert_eq!(request.state, RelationState::Unresolved, "{assessment:?}");
        }
    }

    #[test]
    fn independently_qualified_html_alternative_is_assessed() {
        let mut results = fixture();
        let alternate = results["semantic_scan"].details["semantic_context"].clone();
        semantic_details_mut(&mut results)["semantic_context"]["claims"] = json!([]);
        semantic_details_mut(&mut results)["semantic_alternative_contexts"] = json!([{"source_part": "html", "semantic_context": alternate, "semantic_scenarios": []}]);
        let assessment = assess_fixture(&results);
        assert!(
            assessment
                .relations
                .iter()
                .any(|relation| relation.state == RelationState::Supported),
            "{assessment:?}"
        );
        assert!(
            assessment
                .relations
                .iter()
                .any(
                    |relation| relation.evidence_refs.iter().any(|reference| reference
                        .pointer
                        .starts_with(
                            "/details/semantic_alternative_contexts/0/semantic_context/claims/"
                        ))
                )
        );
    }

    #[test]
    fn normal_brand_alignment_is_unknown_and_not_a_false_attack() {
        let mut results = fixture();
        semantic_details_mut(&mut results)["semantic_context"]["header_sender"] =
            json!("help@acme.example");
        let target = &mut results.get_mut("link_content").unwrap().details["relational_target_observations"]
            [0];
        target["from_domain"] = json!("acme.example");
        target["sender_brand_aligned"] = json!(true);
        target["brand_sender_target_mismatch"] = json!(false);
        assert_eq!(
            assess_fixture(&results).relations[0].state,
            RelationState::Unresolved
        );
    }

    #[test]
    fn malformed_policy_fails_closed_without_dropping_module_inventory() {
        for mutation in [
            json!({}),
            {
                let mut value = policy();
                value["enabled"] = json!(false);
                value
            },
            {
                let mut value = policy();
                let relation = value["relations"][0].clone();
                value["relations"].as_array_mut().unwrap().push(relation);
                value
            },
            {
                let mut value = policy();
                value["relations"][0]["severity"] = json!("critical");
                value
            },
        ] {
            let results = fixture();
            let report = assess_with_policy(None, &results, &data(), &mutation);
            assert_eq!(report.modules.len(), results.len());
            assert!(report.relations.is_empty());
            assert!(
                report
                    .gaps
                    .iter()
                    .any(|gap| gap == "relation_policy_invalid_or_disabled")
            );
        }
    }

    #[test]
    fn native_malware_requires_provenance_and_survives_unrelated_refutation() {
        let mut results = fixture();
        let mut av = module("av_attach_scan");
        av.categories = vec!["virus_detected".into()];
        av.threat_level = ThreatLevel::Critical;
        av.details = json!({"infected_files": ["sample.bin"], "scanned_count": 1});
        results.insert("av_attach_scan".into(), av);
        semantic_details_mut(&mut results)["semantic_context"]["claims"][0]["polarity"] =
            json!("anti_action");
        let report = assess_fixture(&results);
        assert!(
            report
                .relations
                .iter()
                .any(|relation| relation.candidate_severity == Some(ThreatLevel::Critical))
        );
        assert!(
            report
                .relations
                .iter()
                .any(|relation| relation.state == RelationState::Refuted)
        );
        assert!(
            report
                .legacy_alerts
                .iter()
                .any(|alert| alert.module_id == "av_attach_scan")
        );
    }

    #[test]
    fn category_name_without_native_provenance_stays_unresolved() {
        let mut results = fixture();
        let mut av = module("av_attach_scan");
        av.categories = vec!["virus_detected".into()];
        av.threat_level = ThreatLevel::Critical;
        results.insert("av_attach_scan".into(), av);
        let report = assess_fixture(&results);
        let native = report
            .relations
            .iter()
            .find(|relation| relation.relation_id == "attachment_antivirus_detection")
            .unwrap();
        assert_eq!(native.state, RelationState::Unresolved);
        assert!(
            report
                .modules
                .iter()
                .any(|module| module.original_level == ThreatLevel::Critical)
        );
    }

    #[test]
    fn payment_candidate_is_retained_as_unresolved_without_bec_adapter() {
        let mut results = fixture();
        let claim = &mut semantic_details_mut(&mut results)["semantic_context"]["claims"][0];
        claim["actions"] = json!(["pay"]);
        claim["objects"] = json!(["bank account"]);
        let report = assess_fixture(&results);
        assert_eq!(report.relations.len(), 1);
        assert_eq!(report.relations[0].state, RelationState::Unresolved);
        assert!(
            report.relations[0]
                .reasons
                .contains(&"scenario_relation_adapter_pending".to_owned())
        );
    }

    #[test]
    fn target_record_conflict_is_order_invariant() {
        let mut results = fixture();
        let duplicate =
            results["link_content"].details["relational_target_observations"][0].clone();
        let mut conflicting = duplicate.clone();
        conflicting["target_domain"] = json!("different.example");
        results.get_mut("link_content").unwrap().details["relational_target_observations"] =
            json!([duplicate.clone(), conflicting]);
        let first = assess_fixture(&results);
        results.get_mut("link_content").unwrap().details["relational_target_observations"]
            .as_array_mut()
            .unwrap()
            .reverse();
        let second = assess_fixture(&results);
        assert_eq!(first.relations, second.relations);
        assert_eq!(first.relations[0].state, RelationState::Conflicted);
    }

    #[tokio::test]
    async fn parser_and_real_detectors_keep_v3_semantics_out_of_relational_v2() {
        use std::sync::Arc;

        use crate::context::SecurityContext;
        use crate::module::SecurityModule;
        use crate::modules::link_content::LinkContentModule;
        use crate::semantic::SemanticScanModule;
        use vigilyx_core::models::{EmailSession, Protocol};

        let raw = concat!(
            "From: help@attacker.invalid\r\n",
            "To: employee@corp.invalid\r\n",
            "Subject: Account notification\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
            "<html><body><p>Account notification.</p>",
            "<a href=\"https://login.microsoftonline.com@capture.attacker.invalid/login\">",
            "Microsoft: please verify your login page</a></body></html>"
        );
        let mut session = EmailSession::new(
            Protocol::Smtp,
            "203.0.113.10".into(),
            25_000,
            "192.0.2.10".into(),
            25,
        );
        session.mail_from = Some("help@attacker.invalid".into());
        session.rcpt_to = vec!["employee@corp.invalid".into()];
        session.content = vigilyx_parser::MimeParser::new()
            .parse(raw.as_bytes())
            .unwrap();
        let context = SecurityContext::new(Arc::new(session.clone()));
        let semantic = SemanticScanModule::new(None)
            .analyze(&context)
            .await
            .unwrap();
        let target = LinkContentModule::new().analyze(&context).await.unwrap();
        let results = HashMap::from([
            ("semantic_scan".to_owned(), semantic),
            ("link_content".to_owned(), target),
        ]);
        let report = assess(Some(&session), &results);
        assert!(
            report
                .relations
                .iter()
                .all(|relation| relation.state != RelationState::Supported),
            "schema v3 observations must stay out of relational_v2: {report:?}"
        );
        assert!(
            report
                .gaps
                .iter()
                .any(|gap| gap == "semantic_schema_unsupported"),
            "the unsupported schema must be surfaced as a coverage gap: {report:?}"
        );
    }
}
