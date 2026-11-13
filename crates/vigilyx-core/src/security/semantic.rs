//! Shared semantic facts used by email detectors.
//!
//! These types describe what an extractor observed.  They are intentionally
//! not a verdict and contain no threat score.  A missing fact is represented by
//! `unknown` instead of being inferred from a different message role.

use serde::{Deserialize, Serialize};

/// Where a semantic claim was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSourcePart {
    Header,
    PlainText,
    Html,
    Attachment,
    Ocr,
    Qr,
    LandingPage,
}

/// The best-supported speaker role for a bounded claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticActorRole {
    Sender,
    AuthenticatedSender,
    QuotedAuthor,
    System,
    Reporter,
    #[default]
    Unknown,
}

/// The best-supported target role for a bounded claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTargetRole {
    Recipient,
    NamedThirdParty,
    /// The original sender is explicitly the affected party or owns the
    /// affected object. First-person speaker identity alone is insufficient.
    SenderSelf,
    /// Retained for compatibility with previously stored generic user roles.
    User,
    System,
    Attachment,
    #[default]
    Unknown,
}

/// Where an action asks information or value to go. This is distinct from
/// `target_role`, which describes who is being asked to perform the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticActionDestination {
    Sender,
    Recipient,
    Other,
    Mixed,
    #[default]
    Unknown,
}

/// What the sentence is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticSpeechAct {
    Request,
    Instruction,
    Warning,
    Report,
    Quotation,
    Notice,
    None,
    #[default]
    Unknown,
}

/// Whether the sentence asks for an action or rejects one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticPolarity {
    Action,
    AntiAction,
    Neutral,
    #[default]
    Unknown,
}

/// Whether the span is original message text or reported/quoted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticQuoteStatus {
    Original,
    Quoted,
    Forwarded,
    Reported,
    Mixed,
    #[default]
    Unknown,
}

/// Where a URL associated with a semantic claim was extracted from.
///
/// This is intentionally independent from transport/content verification: an
/// extracted href is not proof that the target was fetched or belongs to the
/// claimed sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLinkExtractionSource {
    Href,
    /// A submit control and its actual form action or formaction target.
    FormAction,
    PlainText,
    HtmlText,
    Qr,
    Attachment,
    LandingPage,
    None,
    #[default]
    Unknown,
}

/// Network-level observation for a semantic link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLinkTransportStatus {
    NotAttempted,
    Reachable,
    Blocked,
    Failed,
    #[default]
    Unknown,
}

/// Whether landing-page content was actually retained and inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLinkContentStatus {
    NotObserved,
    Partial,
    Observed,
    #[default]
    Unknown,
}

/// Whether ownership of a link target was established independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLinkOwnershipStatus {
    Proven,
    Unproven,
    Contradicted,
    #[default]
    Unknown,
}

/// UTF-8 byte offsets into the bounded source projection supplied to the
/// extractor.  The offsets are not offsets into raw MIME unless the caller
/// explicitly supplies raw MIME as the source projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSpan {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// A bounded, explainable semantic claim.  This is an observation layer; it
/// becomes actionable only after a named scenario policy validates it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticClaim {
    pub source_span_id: String,
    pub source_part: SemanticSourcePart,
    pub span: SemanticSpan,
    /// The bounded visible-text block containing this claim. Claims from
    /// separate HTML paragraphs/list items must not borrow semantic context
    /// merely because their byte offsets are close.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_block_id: Option<String>,
    #[serde(default)]
    pub actor_role: SemanticActorRole,
    #[serde(default)]
    pub target_role: SemanticTargetRole,
    #[serde(default)]
    pub action_destination: SemanticActionDestination,
    #[serde(default)]
    pub speech_act: SemanticSpeechAct,
    #[serde(default)]
    pub polarity: SemanticPolarity,
    #[serde(default)]
    pub quote_or_forward_status: SemanticQuoteStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// All recognized action predicates in this bounded span, ordered from
    /// most specific to least specific. `action` remains the primary value for
    /// consumers that have not migrated to multi-fact semantics yet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    /// All recognized objects in this bounded span. Keeping the set prevents
    /// a phrase such as "click the link to verify the account" from losing
    /// either side of the relation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub objects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter_context_ids: Vec<String>,
    /// Links that were locally associated with this span. Message-level links
    /// that cannot be bound without borrowing unrelated context remain in
    /// `SemanticMessageContext::links` and are not copied here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub link_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<String>,
    pub confidence: f64,
    pub causal_key: String,
}

/// Audit-grade link observation referenced by semantic claims.
///
/// The semantic extractor records parser provenance only. Until another
/// module supplies fetch/content/ownership results, those states stay
/// explicitly `not_attempted`, `not_observed`, and `unknown`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticLinkObservation {
    pub link_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span_id: Option<String>,
    pub extraction_source: SemanticLinkExtractionSource,
    pub original_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_chain: Vec<String>,
    #[serde(default)]
    pub transport_status: SemanticLinkTransportStatus,
    #[serde(default)]
    pub content_status: SemanticLinkContentStatus,
    #[serde(default)]
    pub ownership_status: SemanticLinkOwnershipStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_reason: Option<String>,
    pub causal_key: String,
}

/// Reusable semantic scenario families.  These are observations until a
/// separately validated policy admits them into threat fusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScenarioId {
    CredentialRequest,
    AccountAccessRequest,
    PaymentAccountChangeRequest,
    SensitiveDataRequest,
    OffPlatformContactRequest,
    AccountSecurityVerification,
    StorageQuotaReward,
}

/// How far a semantic relation is supported. This describes only the
/// observation relationship, never whether the message is malicious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScenarioResolution {
    #[default]
    Candidate,
    Ambiguous,
    Countered,
}

/// A scenario candidate linked to the exact semantic claims that support it.
/// It carries no threat score and cannot by itself produce a disposition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticScenarioFinding {
    pub scenario_id: SemanticScenarioId,
    #[serde(default)]
    pub resolution: SemanticScenarioResolution,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_reason: Option<String>,
    pub claim_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub link_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter_context_ids: Vec<String>,
    pub coverage: SemanticCoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_reason: Option<String>,
    pub provenance: Vec<String>,
    pub confidence: f64,
    pub causal_key: String,
}

/// Coverage status for the source projection used by semantic extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCoverageStatus {
    Complete,
    Incomplete,
    #[default]
    Unknown,
}

/// Message-level semantic extraction result.  Actual envelope identity is
/// deliberately kept beside, not inside, body claims.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SemanticMessageContext {
    pub schema_version: u8,
    #[serde(default)]
    pub actual_recipients: Vec<String>,
    /// Recipients claimed by message headers.  They are not equivalent to
    /// SMTP envelope recipients and may be forged or omitted (for Bcc).
    #[serde(default)]
    pub header_recipients: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_sender: Option<String>,
    /// Sender claimed by the message headers, kept separate from MAIL FROM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_sender: Option<String>,
    #[serde(default)]
    pub coverage: SemanticCoverageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_reason: Option<String>,
    #[serde(default)]
    pub claims: Vec<SemanticClaim>,
    #[serde(default)]
    pub links: Vec<SemanticLinkObservation>,
}
