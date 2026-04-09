//! SMTP multi-hop relay correlation diagnostics.

use super::*;
use tracing::warn;
use vigilyx_core::{EmailSession, Protocol, SessionStatus};

/// Targeted relay-hop correlation diagnostics for the current mirror deployment.
pub(super) const SMTP_RELAY_CORRELATION_WINDOW_SECS: i64 = 30;
pub(super) const SMTP_RELAY_CORRELATION_MAX_CANDIDATES_LOGGED: usize = 4;
pub(super) const SMTP_FIRST_HOP_CLIENT_IP: &str = "10.1.246.40";
pub(super) const SMTP_FIRST_HOP_SERVER_IP: &str = "10.1.246.41";
pub(super) const SMTP_SECOND_HOP_CLIENT_IP: &str = "10.1.246.41";
pub(super) const SMTP_SECOND_HOP_SERVER_IP: &str = "10.7.126.68";

#[derive(Debug, Clone)]
pub(crate) struct SmtpRelayCorrelationProbe {
    pub(super) session_id: String,
    pub(super) started_at: chrono::DateTime<chrono::Utc>,
    pub(super) client_ip: String,
    pub(super) server_ip: String,
    pub(super) message_id: String,
    pub(super) mail_from: Option<String>,
    pub(super) rcpt_to: Vec<String>,
    pub(super) subject: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(super) struct SmtpRelayCandidateSummary {
    pub(super) session_id: String,
    pub(super) started_at: chrono::DateTime<chrono::Utc>,
    pub(super) last_packet_at: chrono::DateTime<chrono::Utc>,
    pub(super) status: SessionStatus,
    pub(super) mail_from: Option<String>,
    pub(super) rcpt_to: Vec<String>,
    pub(super) subject: Option<String>,
    pub(super) message_id: Option<String>,
    pub(super) email_count: u32,
    pub(super) has_restored_payload: bool,
    pub(super) is_complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SmtpRelayCorrelationIssueKind {
    NoMatchingFirstHopSession,
    SameEnvelopeFirstHopWithoutMatchingMessageId,
}

impl SmtpRelayCorrelationIssueKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::NoMatchingFirstHopSession => "no_matching_first_hop_session",
            Self::SameEnvelopeFirstHopWithoutMatchingMessageId => {
                "same_envelope_first_hop_without_matching_message_id"
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct SmtpRelayCorrelationIssue {
    pub(super) kind: SmtpRelayCorrelationIssueKind,
    pub(super) window_candidate_count: usize,
    pub(super) same_envelope_candidate_count: usize,
    pub(super) window_candidates: Vec<SmtpRelayCandidateSummary>,
    pub(super) same_envelope_candidates: Vec<SmtpRelayCandidateSummary>,
}

impl ShardedSessionManager {
    #[inline]
    pub(super) fn is_smtp_first_hop(session: &EmailSession) -> bool {
        session.protocol == Protocol::Smtp
            && session.client_ip == SMTP_FIRST_HOP_CLIENT_IP
            && session.server_ip == SMTP_FIRST_HOP_SERVER_IP
    }

    #[inline]
    pub(super) fn is_smtp_second_hop(session: &EmailSession) -> bool {
        session.protocol == Protocol::Smtp
            && session.client_ip == SMTP_SECOND_HOP_CLIENT_IP
            && session.server_ip == SMTP_SECOND_HOP_SERVER_IP
    }

    pub(super) fn normalized_rcpt_list(rcpt_to: &[String]) -> Vec<String> {
        let mut normalized = rcpt_to
            .iter()
            .map(|addr| addr.trim().to_ascii_lowercase())
            .filter(|addr| !addr.is_empty())
            .collect::<Vec<_>>();
        normalized.sort();
        normalized
    }

    pub(super) fn same_envelope(
        probe_mail_from: Option<&str>,
        probe_rcpt_to: &[String],
        candidate: &EmailSession,
    ) -> bool {
        let (Some(probe_mail_from), Some(candidate_mail_from)) =
            (probe_mail_from, candidate.mail_from.as_deref())
        else {
            return false;
        };

        if !probe_mail_from.eq_ignore_ascii_case(candidate_mail_from) {
            return false;
        }

        Self::normalized_rcpt_list(probe_rcpt_to) == Self::normalized_rcpt_list(&candidate.rcpt_to)
    }

    pub(super) fn summarize_relay_candidate(session_data: &Sessiondata) -> SmtpRelayCandidateSummary {
        SmtpRelayCandidateSummary {
            session_id: session_data.session.id.to_string(),
            started_at: session_data.session.started_at,
            last_packet_at: session_data.last_packet_at,
            status: session_data.session.status,
            mail_from: session_data.session.mail_from.clone(),
            rcpt_to: session_data.session.rcpt_to.clone(),
            subject: session_data.session.subject.clone(),
            message_id: Self::session_message_id(&session_data.session)
                .map(|value| value.to_string()),
            email_count: session_data.session.email_count,
            has_restored_payload: Self::smtp_session_has_restored_payload(&session_data.session),
            is_complete: session_data.session.content.is_complete,
        }
    }

    pub(super) fn enqueue_smtp_relay_probe(&self, session_data: &Sessiondata, message_id: String) {
        if !Self::is_smtp_second_hop(&session_data.session) {
            return;
        }

        self.smtp_relay_diag_queue.push(SmtpRelayCorrelationProbe {
            session_id: session_data.session.id.to_string(),
            started_at: session_data.session.started_at,
            client_ip: session_data.session.client_ip.clone(),
            server_ip: session_data.session.server_ip.clone(),
            message_id,
            mail_from: session_data.session.mail_from.clone(),
            rcpt_to: session_data.session.rcpt_to.clone(),
            subject: session_data.session.subject.clone(),
        });
    }

    pub(super) fn find_smtp_first_hop_correlation_issue(
        &self,
        probe: &SmtpRelayCorrelationProbe,
    ) -> Option<SmtpRelayCorrelationIssue> {
        let window_start =
            probe.started_at - chrono::Duration::seconds(SMTP_RELAY_CORRELATION_WINDOW_SECS);
        let mut window_candidate_count = 0usize;
        let mut same_envelope_candidate_count = 0usize;
        let mut window_candidates = Vec::new();
        let mut same_envelope_candidates = Vec::new();

        for entry in self.sessions.iter() {
            let session_data = entry.value();
            if !Self::is_smtp_first_hop(&session_data.session)
                || session_data.session.started_at > probe.started_at
                || session_data.last_packet_at < window_start
            {
                continue;
            }

            let summary = Self::summarize_relay_candidate(session_data);
            window_candidate_count += 1;
            if window_candidates.len() < SMTP_RELAY_CORRELATION_MAX_CANDIDATES_LOGGED {
                window_candidates.push(summary.clone());
            }

            if summary.message_id.as_deref() == Some(probe.message_id.as_str()) {
                return None;
            }

            let same_envelope = Self::same_envelope(
                probe.mail_from.as_deref(),
                &probe.rcpt_to,
                &session_data.session,
            );
            let candidate_is_unidentified = summary.message_id.is_none()
                || !summary.has_restored_payload
                || !summary.is_complete;

            if same_envelope && candidate_is_unidentified {
                same_envelope_candidate_count += 1;
                if same_envelope_candidates.len() < SMTP_RELAY_CORRELATION_MAX_CANDIDATES_LOGGED {
                    same_envelope_candidates.push(summary);
                }
            }
        }

        let kind = if same_envelope_candidate_count > 0 {
            SmtpRelayCorrelationIssueKind::SameEnvelopeFirstHopWithoutMatchingMessageId
        } else {
            SmtpRelayCorrelationIssueKind::NoMatchingFirstHopSession
        };

        Some(SmtpRelayCorrelationIssue {
            kind,
            window_candidate_count,
            same_envelope_candidate_count,
            window_candidates,
            same_envelope_candidates,
        })
    }

    pub(super) fn process_smtp_relay_diag_queue(&self) {
        while let Some(probe) = self.smtp_relay_diag_queue.pop() {
            let Some(issue) = self.find_smtp_first_hop_correlation_issue(&probe) else {
                continue;
            };

            warn!(
                second_hop_session_id = %probe.session_id,
                second_hop_started_at = %probe.started_at,
                second_hop_client_ip = %probe.client_ip,
                second_hop_server_ip = %probe.server_ip,
                message_id = %probe.message_id,
                mail_from = ?probe.mail_from,
                rcpt_to = ?probe.rcpt_to,
                subject = ?probe.subject,
                first_hop_window_secs = SMTP_RELAY_CORRELATION_WINDOW_SECS,
                reason = issue.kind.as_str(),
                first_hop_window_candidate_count = issue.window_candidate_count,
                first_hop_same_envelope_candidate_count = issue.same_envelope_candidate_count,
                first_hop_window_candidates = ?issue.window_candidates,
                first_hop_same_envelope_candidates = ?issue.same_envelope_candidates,
                "SMTP relay correlation miss after second-hop restore"
            );
        }
    }
}
