//! Reported delivery failures are analyst observations, never sender trust or
//! native threat evidence. Correlate bounded reports without counting retries.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use uuid::Uuid;
use vigilyx_core::security::BounceHarvestConfig;
use vigilyx_db::security::threat_scene::{BounceHarvestAlertRow, BounceHarvestRow};

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")
        .expect("reported alert email regex")
});

#[derive(Default)]
struct Record {
    recipients: Vec<String>,
    sender: Option<String>,
    subject: Option<String>,
    message_id: String,
    detected_at: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Default)]
struct Template {
    sender_domains: BTreeSet<String>,
    targets: BTreeSet<String>,
}

#[derive(Default)]
struct Aggregate {
    events: BTreeSet<(String, String, String)>,
    targets: BTreeSet<String>,
    sender_domains: BTreeSet<String>,
    subjects: BTreeSet<String>,
    sessions: BTreeSet<Uuid>,
    spans: BTreeSet<(Uuid, usize, usize)>,
    templates: BTreeMap<String, Template>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

fn records(body: &str) -> Vec<Record> {
    let mut result = Vec::new();
    let mut current = Record::default();
    for (line_number, line) in body.lines().enumerate() {
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        current.end_line = line_number;
        match key.trim().to_ascii_lowercase().as_str() {
            "message id" | "message-id" => {
                if !current.recipients.is_empty() {
                    current.end_line = line_number.saturating_sub(1);
                    result.push(std::mem::take(&mut current));
                }
                // An explicit message boundary also discards incomplete records.
                // Unknown fields must never be supplied by the preceding message.
                current = Record::default();
                current.start_line = line_number;
                current.message_id = value.chars().take(256).collect();
            }
            "recipients" => {
                if !current.recipients.is_empty() {
                    current.end_line = line_number.saturating_sub(1);
                    result.push(std::mem::take(&mut current));
                }
                if current.message_id.is_empty() {
                    current.start_line = line_number;
                }
                current.end_line = line_number;
                current.recipients = EMAIL_RE
                    .find_iter(value)
                    .map(|m| m.as_str().to_ascii_lowercase())
                    .collect();
            }
            "sender" => {
                current.sender = EMAIL_RE
                    .find(value)
                    .map(|m| m.as_str().to_ascii_lowercase());
            }
            "subject" => current.subject = Some(value.chars().take(1024).collect()),
            "detected" => current.detected_at = value.chars().take(128).collect(),
            _ => {}
        }
    }
    if !current.recipients.is_empty() {
        result.push(current);
    }
    result
}

fn internal(domain: &str, configured: &[String]) -> bool {
    configured.iter().any(|value| {
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        !value.is_empty() && (domain == value || domain.ends_with(&format!(".{value}")))
    })
}

pub(super) fn parse_reported_bounce_harvest(
    alerts: &[BounceHarvestAlertRow],
    internal_domains: &[String],
    config: &BounceHarvestConfig,
) -> Vec<BounceHarvestRow> {
    let data = crate::module_data::module_data();
    let mut aggregates: BTreeMap<String, Aggregate> = BTreeMap::new();
    for alert in alerts {
        // Recognizing reported content is independent of granting a sender
        // operational context in the per-message threat modules.
        let report = format!(
            "{}\n{}",
            alert.subject.as_deref().unwrap_or_default(),
            alert.body_text
        )
        .to_lowercase();
        if data
            .get_list("operational_alert_markers")
            .iter()
            .filter(|marker| report.contains(&marker.to_lowercase()))
            .count()
            < 2
        {
            continue;
        }
        let Ok(at) = DateTime::parse_from_rfc3339(&alert.started_at) else {
            continue;
        };
        let at = at.with_timezone(&Utc);
        for record in records(&alert.body_text) {
            let Some(sender) = record.sender else {
                continue;
            };
            let Some((_, domain)) = sender.rsplit_once('@') else {
                continue;
            };
            let sender_domain = domain.trim_end_matches('.');
            if internal(sender_domain, internal_domains) {
                continue;
            }
            // Missing IDs cannot turn identical report lines into independent
            // events. The fallback deliberately undercounts ambiguous retries.
            let identity = if record.message_id.is_empty() {
                format!(
                    "{}\n{}",
                    record.subject.as_deref().unwrap_or_default(),
                    record.detected_at
                )
            } else {
                record.message_id
            };
            for recipient in record.recipients {
                let Some((_, domain)) = recipient.rsplit_once('@') else {
                    continue;
                };
                let domain = domain.trim_end_matches('.');
                if !internal(domain, internal_domains) {
                    continue;
                }
                let aggregate = aggregates.entry(domain.to_string()).or_default();
                aggregate.sessions.insert(alert.session_id);
                aggregate
                    .spans
                    .insert((alert.session_id, record.start_line, record.end_line));
                aggregate.start = Some(aggregate.start.map_or(at, |old| old.min(at)));
                aggregate.end = Some(aggregate.end.map_or(at, |old| old.max(at)));
                if !aggregate
                    .events
                    .insert((sender.clone(), identity.clone(), recipient.clone()))
                {
                    continue;
                }
                aggregate.targets.insert(recipient.clone());
                aggregate.sender_domains.insert(sender_domain.to_string());
                if let Some(subject) = &record.subject {
                    aggregate.subjects.insert(subject.clone());
                    let lower = subject.to_lowercase();
                    // A shared generic template or domain shape alone cannot
                    // create this low-volume observation. Require an explicit
                    // target address and a policy-listed account action.
                    if EMAIL_RE.find_iter(&lower).any(|m| m.as_str() == recipient)
                        && data
                            .get_list("bounce_harvest_subject_markers")
                            .iter()
                            .any(|marker| lower.contains(&marker.to_lowercase()))
                    {
                        let key = lower.replace(&recipient, "{recipient}");
                        let template = aggregate.templates.entry(key).or_default();
                        template.targets.insert(recipient);
                        template.sender_domains.insert(sender_domain.to_string());
                    }
                }
            }
        }
    }

    aggregates
        .into_iter()
        .filter_map(|(target_domain, aggregate)| {
            let bounce_count = aggregate.events.len() as i64;
            let unique_targets = aggregate.targets.len() as i64;
            let volume =
                bounce_count >= config.min_bounces && unique_targets >= config.min_unique_targets;
            let sparse = config.sparse_report_enabled
                && aggregate.templates.values().any(|template| {
                    template.targets.len() >= 2 && template.sender_domains.len() >= 2
                });
            if !volume && !sparse {
                return None;
            }
            let sender_domains: Vec<_> = aggregate.sender_domains.into_iter().collect();
            let source_session_ids: Vec<_> = aggregate.sessions.into_iter().collect();
            Some(BounceHarvestRow {
                sender: if sender_domains.len() == 1 {
                    sender_domains[0].clone()
                } else {
                    "multiple_senders".to_string()
                },
                target_domain,
                bounce_count,
                unique_targets,
                window_start: aggregate.start?.to_rfc3339(),
                window_end: aggregate.end?.to_rfc3339(),
                sample_subjects: aggregate.subjects.into_iter().take(5).collect(),
                sample_recipients: aggregate.targets.into_iter().take(10).collect(),
                sender_domains,
                source: "reported_alert".to_string(),
                source_session_id: source_session_ids.first().copied(),
                source_session_ids,
                source_spans: aggregate
                    .spans
                    .into_iter()
                    .take(50)
                    .map(|(session_id, start, end)| {
                        serde_json::json!({"session_id": session_id, "source_part": "report_body",
                    "start_line": start, "end_line": end, "actor_role": "reporter",
                    "target_role": "reported_internal_recipient", "speech_act": "report",
                    "polarity": "neutral", "quote_or_forward_status": "reported",
                    "link_extraction_source": "none"})
                    })
                    .collect(),
                detection_basis: if volume {
                    "volume_threshold"
                } else {
                    "rotating_sender_template"
                }
                .to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(index: u32, entries: &[(usize, &str, &str, &str)]) -> BounceHarvestAlertRow {
        let mut body = String::from(
            "Deep Discovery Email Inspector\nThe following relay MTA servers are unreachable\n",
        );
        for (id, sender, recipient, subject) in entries {
            body.push_str(&format!("Message ID: <{id}@message.example>\nRecipients: {recipient}\nSender: {sender}\nSubject: {subject}\nDetected: 2026-11-01 12:00:00\n"));
        }
        BounceHarvestAlertRow {
            session_id: Uuid::from_u128(index as u128),
            // Unconfigured report identity must neither hide evidence nor be
            // assigned as the attacker. No actual appliance identity in tests.
            mail_from: Some("notifier@unconfigured.example".into()),
            client_ip: "192.0.2.41".into(),
            started_at: format!("2026-11-01T12:00:{index:02}Z"),
            subject: Some("Relay MTA delivery alert".into()),
            body_text: body,
        }
    }

    fn parse(alerts: &[BounceHarvestAlertRow], sparse: bool) -> Vec<BounceHarvestRow> {
        parse_reported_bounce_harvest(
            alerts,
            &["corp.example".into()],
            &BounceHarvestConfig {
                sparse_report_enabled: sparse,
                ..Default::default()
            },
        )
    }

    #[test]
    fn unconfigured_reporter_does_not_hide_volume_evidence() {
        let mut alert = report(1, &[]);
        for id in 0..13 {
            alert.body_text.push_str(&format!("Message ID: <{id}@message.example>\nRecipients: user{}@corp.example\nSender: source@rotating{id}.example\nSubject: user{}@corp.example验证通知\n", id % 9, id % 9));
        }
        let rows = parse(&[alert], false);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].bounce_count, rows[0].unique_targets), (13, 9));
        assert_eq!(rows[0].detection_basis, "volume_threshold");
        assert!(
            !rows[0]
                .sender_domains
                .contains(&"unconfigured.example".into())
        );
        assert!(!super::super::bounce_auto_block_eligible(&rows[0]));
        let details = super::super::bounce_scene_details(&rows[0]);
        assert_eq!(details["evidence_class"], "observation");
        assert_eq!(details["sender_identity"], "reported_unverified");
        assert_eq!(details["source_spans"][0]["speech_act"], "report");
    }

    #[test]
    fn sparse_rotation_is_opt_in_and_preserves_each_report_reference() {
        let alerts = [
            report(
                1,
                &[(
                    1,
                    "a@rotating-one.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                )],
            ),
            report(
                2,
                &[(
                    2,
                    "b@rotating-two.example",
                    "two@corp.example",
                    "two@corp.example验证通知",
                )],
            ),
        ];
        assert!(parse(&alerts, false).is_empty());
        let rows = parse(&alerts, true);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].bounce_count, rows[0].unique_targets), (2, 2));
        assert_eq!(rows[0].detection_basis, "rotating_sender_template");
        assert_eq!(rows[0].source_session_ids.len(), 2);
        assert_eq!(rows[0].window_start, "2026-11-01T12:00:01+00:00");
        assert_eq!(rows[0].window_end, "2026-11-01T12:00:02+00:00");
        assert!(!super::super::bounce_auto_block_eligible(&rows[0]));
    }

    #[test]
    fn retries_copies_and_duplicate_recipient_fields_do_not_inflate_counts() {
        let first = report(
            1,
            &[(
                1,
                "a@one.example",
                "one@corp.example, one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        let copy = report(
            2,
            &[(
                1,
                "a@one.example",
                "one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        assert!(parse(&[first, copy], true).is_empty());
        let config = BounceHarvestConfig {
            min_bounces: 1,
            min_unique_targets: 1,
            ..Default::default()
        };
        let alerts = [
            report(
                1,
                &[(
                    1,
                    "a@one.example",
                    "one@corp.example, one@corp.example",
                    "notice",
                )],
            ),
            report(2, &[(1, "a@one.example", "one@corp.example", "notice")]),
        ];
        let rows = parse_reported_bounce_harvest(&alerts, &["corp.example".into()], &config);
        assert_eq!((rows[0].bounce_count, rows[0].unique_targets), (1, 1));
    }

    #[test]
    fn sparse_controls_require_same_template_personalization_external_rotation_and_distinct_targets()
     {
        for entries in [
            // General outage or ordinary cross-supplier traffic.
            vec![
                (1, "a@one.example", "one@corp.example", "invoice"),
                (2, "b@two.example", "two@corp.example", "invoice"),
            ],
            // A generic account phrase without recipient personalization.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "account verification",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "account verification",
                ),
            ],
            // Normalization must not erase another mailbox's distinct role.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example验证通知 reply@one.example",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example验证通知 reply@two.example",
                ),
            ],
            // A target substring inside another address is not personalization.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example.evil.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example.evil.example验证通知",
                ),
            ],
            // One sender domain is insufficient.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
                (
                    2,
                    "b@one.example",
                    "two@corp.example",
                    "two@corp.example验证通知",
                ),
            ],
            // Independent subjects cannot borrow each other's features.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example账户验证",
                ),
            ],
            // One target is insufficient.
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
            ],
            // Internal senders and suffix lookalikes are not external-to-internal observations.
            vec![
                (
                    1,
                    "a@corp.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example验证通知",
                ),
            ],
            vec![
                (
                    1,
                    "a@one.example",
                    "one@corp.example.evil.example",
                    "one@corp.example.evil.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example验证通知",
                ),
            ],
        ] {
            assert!(
                parse(&[report(1, &entries)], true).is_empty(),
                "unrelated facts must not create a sparse observation"
            );
        }
    }

    #[test]
    fn incomplete_record_cannot_supply_sender_or_subject_to_the_next_message() {
        let mut alert = report(1, &[]);
        alert.body_text.push_str(
            "Message ID: <incomplete@message.example>\n\
             Sender: source@external.example\n\
             Subject: one@corp.example验证通知\n\
             Message ID: <next@message.example>\n\
             Recipients: one@corp.example\n",
        );
        let config = BounceHarvestConfig {
            min_bounces: 1,
            min_unique_targets: 1,
            ..Default::default()
        };
        assert!(
            parse_reported_bounce_harvest(&[alert], &["corp.example".into()], &config).is_empty(),
            "a missing sender must remain unknown across message boundaries"
        );
    }

    #[test]
    fn report_order_and_duplicate_copies_preserve_counts_and_references() {
        let first = report(
            1,
            &[(
                1,
                "a@one.example",
                "one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        let second = report(
            2,
            &[(
                2,
                "b@two.example",
                "two@corp.example",
                "two@corp.example验证通知",
            )],
        );
        let copied = report(
            3,
            &[(
                1,
                "a@one.example",
                "one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        let left = parse(&[first, second, copied], true);
        let first = report(
            1,
            &[(
                1,
                "a@one.example",
                "one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        let second = report(
            2,
            &[(
                2,
                "b@two.example",
                "two@corp.example",
                "two@corp.example验证通知",
            )],
        );
        let copied = report(
            3,
            &[(
                1,
                "a@one.example",
                "one@corp.example",
                "one@corp.example验证通知",
            )],
        );
        let right = parse(&[copied, second, first], true);
        assert_eq!(left.len(), 1);
        assert_eq!((left[0].bounce_count, left[0].unique_targets), (2, 2));
        assert_eq!(
            super::super::bounce_scene_details(&left[0]),
            super::super::bounce_scene_details(&right[0])
        );
        assert_eq!(left[0].source_session_ids.len(), 3);
        assert_eq!(left[0].window_start, right[0].window_start);
        assert_eq!(left[0].window_end, right[0].window_end);
        assert_eq!(left[0].sample_subjects, right[0].sample_subjects);
    }

    #[test]
    fn missing_report_structure_and_generic_direct_requests_are_not_reported_incidents() {
        let mut alert = report(
            1,
            &[
                (
                    1,
                    "a@one.example",
                    "one@corp.example",
                    "one@corp.example验证通知",
                ),
                (
                    2,
                    "b@two.example",
                    "two@corp.example",
                    "two@corp.example验证通知",
                ),
            ],
        );
        alert.body_text = alert
            .body_text
            .lines()
            .skip(2)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse(&[alert], true).is_empty());
        let alert = report(1, &[]);
        assert!(parse(&[alert], true).is_empty());
    }
}
