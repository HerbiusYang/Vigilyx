//! Resolve roles from the existing registry-backed clause cues.

use vigilyx_core::security::{
    SemanticActorRole, SemanticPolarity, SemanticQuoteStatus, SemanticSpeechAct, SemanticTargetRole,
};

pub(super) struct ClauseCues {
    pub(super) quote_status: SemanticQuoteStatus,
    pub(super) reported: bool,
    pub(super) request: bool,
    pub(super) instruction: bool,
    pub(super) self_subject: bool,
    pub(super) third_party_subject: bool,
    pub(super) description: bool,
    pub(super) anti_action: bool,
    pub(super) inherited_request: bool,
    pub(super) directed_command: bool,
    pub(super) nominal_html_command: bool,
    pub(super) recipient_directed: bool,
    pub(super) has_action: bool,
}

pub(super) struct ClauseAttribution {
    pub(super) speech_act: SemanticSpeechAct,
    pub(super) polarity: SemanticPolarity,
    pub(super) quote_status: SemanticQuoteStatus,
    pub(super) actor_role: SemanticActorRole,
    pub(super) target_role: SemanticTargetRole,
}

/// Resolve quotation and report first, then scoped anti-action, described
/// subjects and current recipient requests. Identity is never inferred
/// from MAIL FROM or a display name here.
pub(super) fn attribute_clause(
    cues: ClauseCues,
    self_target: impl FnOnce() -> SemanticTargetRole,
) -> ClauseAttribution {
    let (speech_act, polarity, quote_status, actor_role, target_role) = if matches!(
        cues.quote_status,
        SemanticQuoteStatus::Quoted | SemanticQuoteStatus::Forwarded
    ) {
        (
            SemanticSpeechAct::Quotation,
            if cues.anti_action {
                SemanticPolarity::AntiAction
            } else {
                SemanticPolarity::Neutral
            },
            cues.quote_status,
            SemanticActorRole::QuotedAuthor,
            SemanticTargetRole::Unknown,
        )
    } else if cues.reported {
        (
            SemanticSpeechAct::Report,
            SemanticPolarity::Neutral,
            if cues.request {
                SemanticQuoteStatus::Mixed
            } else {
                SemanticQuoteStatus::Reported
            },
            SemanticActorRole::Reporter,
            SemanticTargetRole::Unknown,
        )
    } else if cues.anti_action {
        // A bank's own prohibition remains an anti-action fact even though
        // its grammatical subject is a third party or the sender itself.
        (
            SemanticSpeechAct::Warning,
            SemanticPolarity::AntiAction,
            SemanticQuoteStatus::Original,
            SemanticActorRole::Sender,
            if cues.self_subject {
                self_target()
            } else if cues.third_party_subject {
                SemanticTargetRole::NamedThirdParty
            } else {
                SemanticTargetRole::Recipient
            },
        )
    } else if cues.self_subject || cues.third_party_subject || cues.description {
        (
            SemanticSpeechAct::Notice,
            SemanticPolarity::Neutral,
            SemanticQuoteStatus::Original,
            if cues.self_subject {
                SemanticActorRole::Sender
            } else {
                SemanticActorRole::Unknown
            },
            if cues.self_subject {
                self_target()
            } else if cues.third_party_subject {
                SemanticTargetRole::NamedThirdParty
            } else {
                SemanticTargetRole::Unknown
            },
        )
    } else if (cues.request
        || cues.instruction
        || cues.inherited_request
        || cues.directed_command
        || cues.nominal_html_command
        || cues.recipient_directed)
        && cues.has_action
    {
        (
            if cues.instruction || cues.directed_command || cues.nominal_html_command {
                SemanticSpeechAct::Instruction
            } else {
                SemanticSpeechAct::Request
            },
            SemanticPolarity::Action,
            SemanticQuoteStatus::Original,
            SemanticActorRole::Sender,
            SemanticTargetRole::Recipient,
        )
    } else {
        (
            SemanticSpeechAct::Unknown,
            SemanticPolarity::Unknown,
            SemanticQuoteStatus::Original,
            SemanticActorRole::Unknown,
            SemanticTargetRole::Unknown,
        )
    };
    ClauseAttribution {
        speech_act,
        polarity,
        quote_status,
        actor_role,
        target_role,
    }
}
