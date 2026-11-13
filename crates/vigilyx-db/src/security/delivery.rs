//! Persistent delivery-chain correlation for passive SMTP mirror captures.
//!
//! A chain is keyed by a privacy-preserving message fingerprint and a bounded
//! observation window. The first observed hop owns the native verdict; later
//! hops are recorded for coverage and downstream-forwarding measurement.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use vigilyx_core::models::delivery_fingerprint_from_parts;
use vigilyx_core::security::DeliveryRiskDetailItem;

use crate::VigilDb;

const DELIVERY_CHAIN_WINDOW: Duration = Duration::minutes(15);
const DELIVERY_FINGERPRINT_REKEY_MIGRATION: &str = "124_delivery_fingerprint_v3_topology";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRiskDetailKind {
    FirstHop,
    RiskyFirstHop,
    ReusedHop,
    DangerousForwarded,
    NodeSettled,
    NodeRisky,
    NodeRejected,
    NodeForwarded,
    TerminalDelivered,
    Agreement,
    Disagreement,
    BothThreat,
    VigilyxOnly,
    VendorOnly,
    SafePassed,
    Unconfirmed,
}

impl DeliveryRiskDetailKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "first_hop" => Some(Self::FirstHop),
            "risky_first_hop" => Some(Self::RiskyFirstHop),
            "reused_hop" => Some(Self::ReusedHop),
            "dangerous_forwarded" => Some(Self::DangerousForwarded),
            "node_settled" => Some(Self::NodeSettled),
            "node_risky" => Some(Self::NodeRisky),
            "node_rejected" => Some(Self::NodeRejected),
            "node_forwarded" => Some(Self::NodeForwarded),
            "terminal_delivered" => Some(Self::TerminalDelivered),
            "agreement" => Some(Self::Agreement),
            "disagreement" => Some(Self::Disagreement),
            "both_threat" => Some(Self::BothThreat),
            "vigilyx_only" => Some(Self::VigilyxOnly),
            "vendor_only" => Some(Self::VendorOnly),
            "safe_passed" => Some(Self::SafePassed),
            "unconfirmed" => Some(Self::Unconfirmed),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstHop => "first_hop",
            Self::RiskyFirstHop => "risky_first_hop",
            Self::ReusedHop => "reused_hop",
            Self::DangerousForwarded => "dangerous_forwarded",
            Self::NodeSettled => "node_settled",
            Self::NodeRisky => "node_risky",
            Self::NodeRejected => "node_rejected",
            Self::NodeForwarded => "node_forwarded",
            Self::TerminalDelivered => "terminal_delivered",
            Self::Agreement => "agreement",
            Self::Disagreement => "disagreement",
            Self::BothThreat => "both_threat",
            Self::VigilyxOnly => "vigilyx_only",
            Self::VendorOnly => "vendor_only",
            Self::SafePassed => "safe_passed",
            Self::Unconfirmed => "unconfirmed",
        }
    }

    pub fn requires_node(self) -> bool {
        matches!(
            self,
            Self::NodeSettled
                | Self::NodeRisky
                | Self::NodeRejected
                | Self::NodeForwarded
                | Self::TerminalDelivered
                | Self::Agreement
                | Self::Disagreement
                | Self::BothThreat
                | Self::VigilyxOnly
                | Self::VendorOnly
                | Self::SafePassed
                | Self::Unconfirmed
        )
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DeliveryRiskDetailRow {
    chain_id: String,
    session_id: String,
    hop_index: i32,
    server_ip: String,
    observed_at: String,
    threat_level: Option<String>,
    action_evidence: String,
    message_id: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Option<String>,
    subject: Option<String>,
    total_count: i64,
}

impl DeliveryRiskDetailRow {
    fn into_item(self) -> DeliveryRiskDetailItem {
        DeliveryRiskDetailItem {
            chain_id: self.chain_id,
            session_id: self.session_id,
            hop_index: self.hop_index.max(0) as u32,
            server_ip: self.server_ip,
            observed_at: self.observed_at,
            threat_level: self.threat_level,
            action_evidence: self.action_evidence,
            message_id: self.message_id,
            mail_from: self.mail_from,
            rcpt_to: self
                .rcpt_to
                .as_deref()
                .and_then(|value| serde_json::from_str(value).ok())
                .unwrap_or_default(),
            subject: self.subject,
        }
    }
}

fn is_risky_threat_level(level: Option<&str>) -> bool {
    matches!(level, Some("low" | "medium" | "high" | "critical"))
}

#[derive(Debug, sqlx::FromRow)]
struct DeliveryRekeyRow {
    session_id: String,
    old_chain_id: String,
    client_ip: String,
    server_ip: String,
    observed_at: String,
    old_verdict_origin: String,
    old_reused_from_session_id: Option<String>,
    message_id: Option<String>,
    mail_from: Option<String>,
    verdict_id: Option<String>,
    threat_level: Option<String>,
    smtp_security_rejected: bool,
    old_chain_verdict_id: Option<String>,
    old_chain_threat_level: Option<String>,
}

#[derive(Debug)]
struct RebuiltDeliveryHop {
    session_id: String,
    client_ip: String,
    server_ip: String,
    observed_at: DateTime<Utc>,
    old_verdict_origin: String,
    old_reused_from_session_id: Option<String>,
    verdict_id: Option<String>,
    threat_level: Option<String>,
    smtp_security_rejected: bool,
    old_chain_verdict_id: Option<String>,
    old_chain_threat_level: Option<String>,
}

trait DeliveryHopTopology {
    fn session_id(&self) -> &str;
    fn client_ip(&self) -> &str;
    fn server_ip(&self) -> &str;
    fn observed_at(&self) -> DateTime<Utc>;
}

impl DeliveryHopTopology for RebuiltDeliveryHop {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn client_ip(&self) -> &str {
        &self.client_ip
    }

    fn server_ip(&self) -> &str {
        &self.server_ip
    }

    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Debug)]
struct RebuiltDeliveryChain {
    chain_id: String,
    fingerprint: String,
    first_session_id: String,
    first_seen_at: DateTime<Utc>,
    first_server_ip: String,
    first_verdict_id: Option<String>,
    first_threat_level: Option<String>,
    last_seen_at: DateTime<Utc>,
    hops: Vec<RebuiltDeliveryHop>,
}

#[derive(Debug)]
struct LiveDeliveryHop {
    session_id: String,
    client_ip: String,
    server_ip: String,
    observed_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct LiveDeliveryHopRow {
    session_id: String,
    client_ip: String,
    server_ip: String,
    observed_at: String,
}

impl DeliveryHopTopology for LiveDeliveryHop {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn client_ip(&self) -> &str {
        &self.client_ip
    }

    fn server_ip(&self) -> &str {
        &self.server_ip
    }

    fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

/// Order one message's observations by the SMTP relay graph.  Event timestamps
/// remain the deterministic fallback for disconnected observations, but an
/// explicit `upstream.server_ip == downstream.client_ip` edge always wins.
/// This prevents asynchronous Engine processing from producing paths such as
/// terminal-mail-server -> gateway.
fn topology_order_delivery_hops<T: DeliveryHopTopology>(mut remaining: Vec<T>) -> Vec<T> {
    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let roots = (0..remaining.len())
            .filter(|&candidate| {
                !remaining.iter().enumerate().any(|(predecessor, hop)| {
                    predecessor != candidate && hop.server_ip() == remaining[candidate].client_ip()
                })
            })
            .collect::<Vec<_>>();
        let candidates = if roots.is_empty() {
            (0..remaining.len()).collect::<Vec<_>>()
        } else {
            roots
        };
        let next = candidates
            .into_iter()
            .min_by(|&left, &right| {
                remaining[left]
                    .observed_at()
                    .cmp(&remaining[right].observed_at())
                    .then_with(|| {
                        remaining[left]
                            .session_id()
                            .cmp(remaining[right].session_id())
                    })
            })
            .expect("a non-empty delivery hop set has a candidate");
        ordered.push(remaining.remove(next));
    }
    ordered
}

async fn reindex_live_delivery_chain(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    chain_id: &str,
    registered_session_id: &str,
    updated_at: &str,
) -> Result<(String, i32)> {
    let rows = sqlx::query_as::<_, LiveDeliveryHopRow>(
        "SELECT session_id, client_ip, server_ip, observed_at \
         FROM email_delivery_hops WHERE chain_id = $1",
    )
    .bind(chain_id)
    .fetch_all(&mut **tx)
    .await?;
    let rows = rows
        .into_iter()
        .map(|row| {
            Ok(LiveDeliveryHop {
                session_id: row.session_id,
                client_ip: row.client_ip,
                server_ip: row.server_ip,
                observed_at: DateTime::parse_from_rfc3339(&row.observed_at)
                    .with_context(|| {
                        format!("invalid live delivery hop timestamp: {}", row.observed_at)
                    })?
                    .with_timezone(&Utc),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let ordered = topology_order_delivery_hops(rows);
    let first = ordered
        .first()
        .context("live delivery chain must contain a hop")?;
    let old_first = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
        "SELECT first_session_id, first_verdict_id, first_threat_level \
         FROM email_delivery_chains WHERE chain_id = $1 FOR UPDATE",
    )
    .bind(chain_id)
    .fetch_one(&mut **tx)
    .await?;
    let first_verdict = sqlx::query_as::<_, (String, String)>(
        "SELECT id, threat_level FROM security_verdicts WHERE session_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(&first.session_id)
    .fetch_optional(&mut **tx)
    .await?;
    let (first_verdict_id, first_threat_level) = match first_verdict {
        Some((verdict_id, threat_level)) => (Some(verdict_id), Some(threat_level)),
        None if old_first.0 == first.session_id => (old_first.1, old_first.2),
        None => (None, None),
    };

    let mut registered_hop_index = None;
    for (hop_index, hop) in ordered.iter().enumerate() {
        if hop.session_id == registered_session_id {
            registered_hop_index = Some(hop_index as i32);
        }
        sqlx::query(
            "UPDATE email_delivery_hops SET hop_index = $2, first_session_id = $3, \
             first_hop_threat_level = $4, dangerous_forwarded = (\
                 COALESCE($4 IN ('low', 'medium', 'high', 'critical') AND $2 > 0, FALSE)\
             ) WHERE session_id = $1",
        )
        .bind(&hop.session_id)
        .bind(hop_index as i32)
        .bind(&first.session_id)
        .bind(&first_threat_level)
        .execute(&mut **tx)
        .await?;
    }

    let last_seen_at = ordered
        .iter()
        .map(DeliveryHopTopology::observed_at)
        .max()
        .context("live delivery chain must contain an observed timestamp")?
        .to_rfc3339();
    sqlx::query(
        "UPDATE email_delivery_chains SET first_session_id = $2, first_seen_at = $3, \
         first_server_ip = $4, first_verdict_id = $5, first_threat_level = $6, \
         last_seen_at = $7, hop_count = $8, dangerous_forwarded_count = (\
             SELECT COUNT(*) FROM email_delivery_hops h \
             WHERE h.chain_id = $1 AND h.dangerous_forwarded = TRUE\
         ), updated_at = $9 WHERE chain_id = $1",
    )
    .bind(chain_id)
    .bind(&first.session_id)
    .bind(first.observed_at.to_rfc3339())
    .bind(&first.server_ip)
    .bind(&first_verdict_id)
    .bind(&first_threat_level)
    .bind(&last_seen_at)
    .bind(ordered.len() as i32)
    .bind(updated_at)
    .execute(&mut **tx)
    .await?;

    Ok((
        first.session_id.clone(),
        registered_hop_index.context("registered session must remain in its delivery chain")?,
    ))
}

async fn rebuild_delivery_lineage_v3(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<usize> {
    let rows = sqlx::query_as::<_, DeliveryRekeyRow>(
        r#"
        SELECT
            h.session_id,
            h.chain_id AS old_chain_id,
            s.client_ip,
            h.server_ip,
            h.observed_at,
            h.verdict_origin AS old_verdict_origin,
            h.reused_from_session_id AS old_reused_from_session_id,
            s.message_id,
            s.mail_from,
            v.id AS verdict_id,
            v.threat_level,
            h.smtp_security_rejected,
            c.first_verdict_id AS old_chain_verdict_id,
            c.first_threat_level AS old_chain_threat_level
        FROM email_delivery_hops h
        INNER JOIN sessions s ON s.id = h.session_id
        LEFT JOIN LATERAL (
            SELECT id, threat_level
            FROM security_verdicts
            WHERE session_id = h.session_id
            ORDER BY created_at DESC, id DESC
            LIMIT 1
        ) v ON TRUE
        LEFT JOIN email_delivery_chains c ON c.chain_id = h.chain_id
        ORDER BY vigilyx_text_timestamptz(h.observed_at), h.session_id
        "#,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut chains = Vec::<RebuiltDeliveryChain>::new();
    let mut active_by_fingerprint = HashMap::<String, Vec<usize>>::new();
    let mut used_chain_ids = HashSet::<String>::new();

    for row in rows {
        let observed_at = DateTime::parse_from_rfc3339(&row.observed_at)
            .with_context(|| format!("invalid delivery hop timestamp: {}", row.observed_at))?
            .with_timezone(&Utc);
        // Existing rows were created only when a Message-ID was available.
        // Preserve any malformed legacy row under its old chain instead of
        // silently dropping audit evidence during the rebuild.
        let fingerprint =
            delivery_fingerprint_from_parts(row.message_id.as_deref(), row.mail_from.as_deref())
                .unwrap_or_else(|| format!("legacy-v1:{}", row.old_chain_id));

        let chain_index = matching_rebuilt_delivery_chain(
            &chains,
            &active_by_fingerprint,
            &fingerprint,
            observed_at,
            &row.client_ip,
            &row.server_ip,
        );

        if let Some(index) = chain_index {
            let chain = &mut chains[index];
            chain.last_seen_at = observed_at;
            chain.hops.push(RebuiltDeliveryHop {
                session_id: row.session_id,
                client_ip: row.client_ip,
                server_ip: row.server_ip,
                observed_at,
                old_verdict_origin: row.old_verdict_origin,
                old_reused_from_session_id: row.old_reused_from_session_id,
                verdict_id: row.verdict_id,
                threat_level: row.threat_level,
                smtp_security_rejected: row.smtp_security_rejected,
                old_chain_verdict_id: row.old_chain_verdict_id,
                old_chain_threat_level: row.old_chain_threat_level,
            });
        } else {
            let chain_id = if used_chain_ids.insert(row.old_chain_id.clone()) {
                row.old_chain_id
            } else {
                loop {
                    let candidate = Uuid::new_v4().to_string();
                    if used_chain_ids.insert(candidate.clone()) {
                        break candidate;
                    }
                }
            };
            let index = chains.len();
            chains.push(RebuiltDeliveryChain {
                chain_id,
                fingerprint: fingerprint.clone(),
                first_session_id: row.session_id.clone(),
                first_seen_at: observed_at,
                first_server_ip: row.server_ip.clone(),
                first_verdict_id: None,
                first_threat_level: None,
                last_seen_at: observed_at,
                hops: vec![RebuiltDeliveryHop {
                    session_id: row.session_id,
                    client_ip: row.client_ip,
                    server_ip: row.server_ip,
                    observed_at,
                    old_verdict_origin: row.old_verdict_origin,
                    old_reused_from_session_id: row.old_reused_from_session_id,
                    verdict_id: row.verdict_id,
                    threat_level: row.threat_level,
                    smtp_security_rejected: row.smtp_security_rejected,
                    old_chain_verdict_id: row.old_chain_verdict_id,
                    old_chain_threat_level: row.old_chain_threat_level,
                }],
            });
            active_by_fingerprint
                .entry(fingerprint.clone())
                .or_default()
                .push(index);
        }
    }

    for chain in &mut chains {
        chain.hops = topology_order_delivery_hops(std::mem::take(&mut chain.hops));
        let first = chain
            .hops
            .first()
            .context("rebuilt delivery chain must contain a hop")?;
        chain.first_session_id = first.session_id.clone();
        chain.first_seen_at = first.observed_at;
        chain.first_server_ip = first.server_ip.clone();
        chain.first_verdict_id = first
            .verdict_id
            .clone()
            .or_else(|| first.old_chain_verdict_id.clone());
        chain.first_threat_level = first
            .threat_level
            .clone()
            .or_else(|| first.old_chain_threat_level.clone());
        chain.last_seen_at = chain
            .hops
            .iter()
            .map(|hop| hop.observed_at)
            .max()
            .context("rebuilt delivery chain must contain an observed timestamp")?;
    }

    // These are derived lineage records. Raw sessions, verdicts, and evidence
    // remain untouched; the transaction makes the derived replacement atomic.
    sqlx::query("DELETE FROM email_delivery_hops")
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM email_delivery_chains")
        .execute(&mut **tx)
        .await?;

    for chain in &chains {
        let dangerous_forwarded_count = chain
            .hops
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                *index > 0 && is_risky_threat_level(chain.first_threat_level.as_deref())
            })
            .count() as i32;
        let first_seen_at = chain.first_seen_at.to_rfc3339();
        let last_seen_at = chain.last_seen_at.to_rfc3339();
        sqlx::query(
            "INSERT INTO email_delivery_chains \
             (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
              first_verdict_id, first_threat_level, last_seen_at, hop_count, \
              dangerous_forwarded_count, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $8, $8)",
        )
        .bind(&chain.chain_id)
        .bind(&chain.fingerprint)
        .bind(&chain.first_session_id)
        .bind(&first_seen_at)
        .bind(&chain.first_server_ip)
        .bind(&chain.first_verdict_id)
        .bind(&chain.first_threat_level)
        .bind(&last_seen_at)
        .bind(chain.hops.len() as i32)
        .bind(dangerous_forwarded_count)
        .execute(&mut **tx)
        .await?;

        for (hop_index, hop) in chain.hops.iter().enumerate() {
            let is_first_hop = hop_index == 0;
            let verdict_origin = if is_first_hop {
                hop.old_verdict_origin.clone()
            } else if chain.first_verdict_id.is_some() {
                "reused_first_hop".to_string()
            } else {
                hop.old_verdict_origin.clone()
            };
            let reused_from_session_id = if is_first_hop {
                hop.old_reused_from_session_id.clone()
            } else if chain.first_verdict_id.is_some() {
                Some(chain.first_session_id.clone())
            } else {
                hop.old_reused_from_session_id.clone()
            };
            let dangerous_forwarded =
                !is_first_hop && is_risky_threat_level(chain.first_threat_level.as_deref());
            let observed_at = hop.observed_at.to_rfc3339();
            sqlx::query(
                "INSERT INTO email_delivery_hops \
                 (session_id, chain_id, fingerprint, first_session_id, hop_index, client_ip, server_ip, \
                 observed_at, first_hop_threat_level, verdict_origin, reused_from_session_id, \
                  dangerous_forwarded, smtp_security_rejected, smtp_security_rejection_metadata_ready) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, TRUE)",
            )
            .bind(&hop.session_id)
            .bind(&chain.chain_id)
            .bind(&chain.fingerprint)
            .bind(&chain.first_session_id)
            .bind(hop_index as i32)
            .bind(&hop.client_ip)
            .bind(&hop.server_ip)
            .bind(&observed_at)
            .bind(&chain.first_threat_level)
            .bind(verdict_origin)
            .bind(reused_from_session_id)
            .bind(dangerous_forwarded)
            .bind(hop.smtp_security_rejected)
            .execute(&mut **tx)
            .await?;
        }
    }

    Ok(chains.len())
}

/// Rebuild only SMTP observations that have an explicit relay edge in the
/// bounded window. Matching Message-ID and MAIL FROM alone are insufficient:
/// both are sender-controlled and can collide across unrelated messages.
fn matching_rebuilt_delivery_chain(
    chains: &[RebuiltDeliveryChain],
    active_by_fingerprint: &HashMap<String, Vec<usize>>,
    fingerprint: &str,
    observed_at: DateTime<Utc>,
    client_ip: &str,
    server_ip: &str,
) -> Option<usize> {
    active_by_fingerprint
        .get(fingerprint)?
        .iter()
        .rev()
        .copied()
        .find(|index| {
            let chain = &chains[*index];
            observed_at - chain.last_seen_at <= DELIVERY_CHAIN_WINDOW
                && chain
                    .hops
                    .iter()
                    .any(|hop| hop.server_ip == client_ip || hop.client_ip == server_ip)
        })
}

impl VigilDb {
    /// Return the individual mail/hop observations behind a dashboard
    /// delivery-risk counter. `snapshot_at` is the transaction timestamp from
    /// `get_security_stats`, keeping the historical snapshot fixed while the user
    /// opens and paginates the list.
    pub async fn list_delivery_risk_details(
        &self,
        kind: DeliveryRiskDetailKind,
        server_ip: Option<&str>,
        snapshot_at: &str,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<DeliveryRiskDetailItem>, u64)> {
        self.list_delivery_risk_details_with_terminal_override(
            kind,
            server_ip,
            snapshot_at,
            limit,
            offset,
            None,
        )
        .await
    }

    async fn list_delivery_risk_details_with_terminal_override(
        &self,
        kind: DeliveryRiskDetailKind,
        server_ip: Option<&str>,
        snapshot_at: &str,
        limit: u32,
        offset: u32,
        terminal_override: Option<Vec<String>>,
    ) -> Result<(Vec<DeliveryRiskDetailItem>, u64)> {
        let rows: Vec<DeliveryRiskDetailRow> = if kind.requires_node() {
            let server_ip = server_ip.context("server_ip is required for node detail")?;
            let use_runtime_terminal_config = terminal_override.is_none();
            let mut terminal_mail_servers = match terminal_override {
                Some(servers) => servers.into_iter().collect(),
                None => self
                    .get_capture_inbound_target_ips()
                    .await
                    .unwrap_or_default(),
            };
            if terminal_mail_servers.is_empty()
                && use_runtime_terminal_config
                && let Ok(raw) = std::env::var("INBOUND_MAIL_SERVERS")
            {
                terminal_mail_servers.extend(
                    raw.split(',')
                        .map(str::trim)
                        .filter(|ip| !ip.is_empty())
                        .map(str::to_string),
                );
            }
            let mut terminal_mail_servers = terminal_mail_servers.into_iter().collect::<Vec<_>>();
            terminal_mail_servers.sort_unstable();

            sqlx::query_as(
                r#"
                WITH settled_chains AS (
                    SELECT c.chain_id, c.first_threat_level
                    FROM email_delivery_chains c
                    WHERE vigilyx_text_timestamptz(c.first_seen_at) <= $1::timestamptz
                      AND COALESCE((
                          SELECT MAX(vigilyx_text_timestamptz(last_hop.observed_at))
                          FROM email_delivery_hops last_hop
                          WHERE last_hop.chain_id = c.chain_id
                            AND vigilyx_text_timestamptz(last_hop.observed_at) <= $1::timestamptz
                      ), vigilyx_text_timestamptz(c.first_seen_at)) <= $1::timestamptz - INTERVAL '30 seconds'
                      AND c.first_verdict_id IS NOT NULL
                      AND c.first_threat_level IN ('safe', 'low', 'medium', 'high', 'critical')
                ), gateway_ips AS MATERIALIZED (
                    SELECT DISTINCT h.server_ip AS node_ip
                    FROM settled_chains c
                    INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                    WHERE vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                      AND NOT (h.server_ip = ANY($2))
                ), node_key_candidates AS MATERIALIZED (
                    SELECT
                        h.chain_id,
                        h.server_ip AS node_ip,
                        MIN(h.hop_index * 2 + 1) AS action_order
                    FROM settled_chains c
                    INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                    WHERE vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                      AND h.server_ip IN (SELECT node_ip FROM gateway_ips)
                    GROUP BY h.chain_id, h.server_ip

                    UNION

                    SELECT
                        h.chain_id,
                        h.client_ip AS node_ip,
                        MIN(h.hop_index * 2) AS action_order
                    FROM settled_chains c
                    INNER JOIN email_delivery_hops h ON h.chain_id = c.chain_id
                    WHERE vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                      AND h.client_ip IN (SELECT node_ip FROM gateway_ips)
                      AND h.server_ip <> h.client_ip
                    GROUP BY h.chain_id, h.client_ip
                ), node_keys AS MATERIALIZED (
                    SELECT chain_id, node_ip, MIN(action_order) AS action_order
                    FROM node_key_candidates
                    GROUP BY chain_id, node_ip
                ), node_actions AS MATERIALIZED (
                    SELECT
                        k.chain_id,
                        COALESCE(
                            pass_evidence.session_id,
                            blocked_evidence.session_id,
                            input_evidence.session_id
                        ) AS session_id,
                        k.node_ip AS server_ip,
                        COALESCE(
                            pass_evidence.hop_index,
                            blocked_evidence.hop_index,
                            input_evidence.hop_index
                        ) AS hop_index,
                        COALESCE(
                            pass_evidence.observed_at,
                            blocked_evidence.observed_at,
                            input_evidence.observed_at
                        )::TEXT AS observed_at,
                        c.first_threat_level,
                        blocked_evidence.session_id IS NOT NULL AS vendor_blocked_explicit,
                        pass_evidence.session_id IS NOT NULL AS gateway_passed,
                        EXISTS (
                            SELECT 1
                            FROM email_delivery_hops terminal_hop
                            WHERE terminal_hop.chain_id = k.chain_id
                              AND terminal_hop.client_ip = k.node_ip
                              AND terminal_hop.server_ip = ANY($2)
                              AND vigilyx_text_timestamptz(terminal_hop.observed_at) <= $1::timestamptz
                        ) AS terminal_delivered
                    FROM node_keys k
                    INNER JOIN settled_chains c ON c.chain_id = k.chain_id
                    LEFT JOIN LATERAL (
                        SELECT h.session_id, h.hop_index, vigilyx_text_timestamptz(h.observed_at) AS observed_at
                        FROM email_delivery_hops h
                        WHERE h.chain_id = k.chain_id
                          AND h.server_ip = k.node_ip
                          AND vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                          AND h.smtp_security_rejection_metadata_ready
                          AND h.smtp_security_rejected
                        ORDER BY h.hop_index, vigilyx_text_timestamptz(h.observed_at)
                        LIMIT 1
                    ) blocked_evidence ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT h.session_id, h.hop_index, vigilyx_text_timestamptz(h.observed_at) AS observed_at
                        FROM email_delivery_hops h
                        WHERE h.chain_id = k.chain_id
                          AND h.client_ip = k.node_ip
                          AND h.server_ip <> k.node_ip
                          AND vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                        ORDER BY h.hop_index, vigilyx_text_timestamptz(h.observed_at)
                        LIMIT 1
                    ) pass_evidence ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT h.session_id, h.hop_index, vigilyx_text_timestamptz(h.observed_at) AS observed_at
                        FROM email_delivery_hops h
                        WHERE h.chain_id = k.chain_id
                          AND h.server_ip = k.node_ip
                          AND vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                        ORDER BY h.hop_index, vigilyx_text_timestamptz(h.observed_at)
                        LIMIT 1
                    ) input_evidence ON TRUE
                    WHERE k.node_ip = $3
                ), classified_actions AS (
                    SELECT
                        node_actions.*,
                        (cardinality($2) > 0 AND NOT gateway_passed) AS path_terminated,
                        (
                            vendor_blocked_explicit
                            OR (cardinality($2) > 0 AND NOT gateway_passed)
                        ) AS vendor_blocked
                    FROM node_actions
                ), filtered AS (
                    SELECT *,
                        CASE
                            WHEN terminal_delivered THEN 'terminal_delivery'
                            WHEN gateway_passed THEN 'forwarded'
                            WHEN vendor_blocked_explicit THEN 'explicit_rejection'
                            WHEN path_terminated THEN 'path_termination'
                            ELSE 'unconfirmed'
                        END AS action_evidence
                    FROM classified_actions
                    WHERE
                        ($4 = 'node_settled' AND (
                            (vendor_blocked AND NOT gateway_passed)
                            OR gateway_passed
                        ))
                        OR ($4 = 'node_risky'
                            AND first_threat_level IN ('low', 'medium', 'high', 'critical'))
                        OR ($4 = 'node_rejected'
                            AND vendor_blocked
                            AND NOT gateway_passed)
                        OR ($4 = 'node_forwarded'
                            AND gateway_passed)
                        OR ($4 = 'terminal_delivered'
                            AND terminal_delivered)
                        OR ($4 = 'agreement' AND (
                            (vendor_blocked
                                AND NOT gateway_passed
                                AND first_threat_level IN ('low', 'medium', 'high', 'critical'))
                            OR (gateway_passed
                                AND first_threat_level = 'safe')
                        ))
                        OR ($4 = 'disagreement' AND (
                            (gateway_passed
                                AND first_threat_level IN ('low', 'medium', 'high', 'critical'))
                            OR (vendor_blocked
                                AND NOT gateway_passed
                                AND first_threat_level = 'safe')
                        ))
                        OR ($4 = 'both_threat'
                            AND vendor_blocked
                            AND NOT gateway_passed
                            AND first_threat_level IN ('low', 'medium', 'high', 'critical'))
                        OR ($4 = 'vigilyx_only'
                            AND gateway_passed
                            AND first_threat_level IN ('low', 'medium', 'high', 'critical'))
                        OR ($4 = 'vendor_only'
                            AND vendor_blocked
                            AND NOT gateway_passed
                            AND first_threat_level = 'safe')
                        OR ($4 = 'safe_passed'
                            AND gateway_passed
                            AND first_threat_level = 'safe')
                        OR ($4 = 'unconfirmed'
                            AND NOT vendor_blocked
                            AND NOT gateway_passed)
                )
                SELECT
                    f.chain_id,
                    f.session_id,
                    f.hop_index,
                    f.server_ip,
                    f.observed_at,
                    f.first_threat_level AS threat_level,
                    f.action_evidence,
                    s.message_id,
                    s.mail_from,
                    s.rcpt_to,
                    s.subject,
                    COUNT(*) OVER()::BIGINT AS total_count
                FROM filtered f
                LEFT JOIN sessions s ON s.id = f.session_id
                ORDER BY vigilyx_text_timestamptz(f.observed_at) DESC, f.session_id
                LIMIT $5 OFFSET $6
                "#,
            )
            .bind(snapshot_at)
            .bind(&terminal_mail_servers)
            .bind(server_ip)
            .bind(kind.as_str())
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                WITH delivery_gateway_ips AS MATERIALIZED (
                    SELECT DISTINCT output_hop.client_ip AS node_ip
                    FROM email_delivery_hops output_hop
                    WHERE vigilyx_text_timestamptz(output_hop.observed_at) <= $1::timestamptz
                      AND output_hop.client_ip <> output_hop.server_ip
                      AND EXISTS (
                          SELECT 1
                          FROM email_delivery_hops input_hop
                          WHERE input_hop.server_ip = output_hop.client_ip
                            AND vigilyx_text_timestamptz(input_hop.observed_at) <= $1::timestamptz
                      )
                ), chain_candidates AS (
                    SELECT
                        c.chain_id,
                        c.first_session_id AS session_id,
                        0::INTEGER AS hop_index,
                        c.first_server_ip AS server_ip,
                        c.first_seen_at AS observed_at,
                        c.first_threat_level,
                        CASE
                            WHEN $2 = 'dangerous_forwarded' THEN 'forwarded'
                            ELSE 'first_hop'
                        END AS action_evidence
                    FROM email_delivery_chains c
                    WHERE vigilyx_text_timestamptz(c.first_seen_at) <= $1::timestamptz
                      AND (
                          $2 = 'first_hop'
                          OR ($2 = 'risky_first_hop'
                              AND c.first_verdict_id IS NOT NULL
                              AND c.first_threat_level IN ('low', 'medium', 'high', 'critical'))
                          OR ($2 = 'dangerous_forwarded'
                              AND c.first_verdict_id IS NOT NULL
                              AND c.first_threat_level IN ('low', 'medium', 'high', 'critical')
                              AND EXISTS (
                                  SELECT 1
                                  FROM email_delivery_hops pass_hop
                                  WHERE pass_hop.chain_id = c.chain_id
                                    AND pass_hop.client_ip IN (
                                        SELECT node_ip FROM delivery_gateway_ips
                                    )
                                    AND pass_hop.server_ip <> pass_hop.client_ip
                                    AND vigilyx_text_timestamptz(pass_hop.observed_at) <= $1::timestamptz
                              ))
                      )
                ), reused_candidates AS (
                    SELECT
                        h.chain_id,
                        h.session_id,
                        h.hop_index,
                        h.server_ip,
                        h.observed_at,
                        h.first_hop_threat_level,
                        'reused_hop'::TEXT AS action_evidence
                    FROM email_delivery_hops h
                    WHERE $2 = 'reused_hop'
                      AND h.hop_index > 0
                      AND h.verdict_origin = 'reused_first_hop'
                      AND vigilyx_text_timestamptz(h.observed_at) <= $1::timestamptz
                ), filtered AS (
                    SELECT * FROM chain_candidates
                    UNION ALL
                    SELECT * FROM reused_candidates
                )
                SELECT
                    f.chain_id,
                    f.session_id,
                    f.hop_index,
                    f.server_ip,
                    f.observed_at,
                    f.first_threat_level AS threat_level,
                    f.action_evidence,
                    s.message_id,
                    s.mail_from,
                    s.rcpt_to,
                    s.subject,
                    COUNT(*) OVER()::BIGINT AS total_count
                FROM filtered f
                LEFT JOIN sessions s ON s.id = f.session_id
                ORDER BY vigilyx_text_timestamptz(f.observed_at) DESC, f.session_id
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(snapshot_at)
            .bind(kind.as_str())
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?
        };

        let total = rows
            .first()
            .map(|row| row.total_count.max(0) as u64)
            .unwrap_or(0);
        Ok((
            rows.into_iter()
                .map(DeliveryRiskDetailRow::into_item)
                .collect(),
            total,
        ))
    }

    /// Test-only terminal identity injection matching the statistics snapshot
    /// helper in `verdict.rs`.
    #[cfg(feature = "infra-tests")]
    pub async fn list_delivery_risk_details_with_terminal_mail_servers_for_test(
        &self,
        kind: DeliveryRiskDetailKind,
        server_ip: Option<&str>,
        snapshot_at: &str,
        limit: u32,
        offset: u32,
        terminal_mail_servers: Vec<String>,
    ) -> Result<(Vec<DeliveryRiskDetailItem>, u64)> {
        self.list_delivery_risk_details_with_terminal_override(
            kind,
            server_ip,
            snapshot_at,
            limit,
            offset,
            Some(terminal_mail_servers),
        )
        .await
    }

    /// Rebuild the derived delivery lineage once after switching to the v3
    /// Message-ID/sender identity and SMTP-topology hop ordering. Raw sessions
    /// and security verdicts are preserved; only the correlation tables are
    /// replaced atomically.
    pub async fn reconcile_email_delivery_lineage_v3(&self) -> Result<usize> {
        // This is a one-time rebuild, but both the API and standalone engine
        // run security-table initialization. Once the marker exists, avoid
        // entering the shared schema lock on every process start; otherwise a
        // slow base-schema initializer can make the health check time out.
        let schema_migrations_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.schema_migrations') IS NOT NULL")
                .fetch_one(&self.pool)
                .await
                .context("check schema_migrations availability")?;
        if schema_migrations_exists {
            let already_applied: Option<(i32,)> =
                sqlx::query_as("SELECT 1 FROM schema_migrations WHERE version = $1")
                    .bind(DELIVERY_FINGERPRINT_REKEY_MIGRATION)
                    .fetch_optional(&self.pool)
                    .await
                    .context("check delivery lineage migration marker")?;
            if already_applied.is_some() {
                return Ok(0);
            }
        }

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            // Serialize with the base schema initializer as well as another
            // API/Engine security initializer. The migration table is shared
            // by both initialization paths.
            "SELECT pg_advisory_xact_lock(hashtextextended('vigilyx.schema_migrations', 0))",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (\
                id SERIAL PRIMARY KEY,\
                version TEXT NOT NULL UNIQUE,\
                description TEXT NOT NULL DEFAULT '',\
                executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
            )",
        )
        .execute(&mut *tx)
        .await?;

        let already_applied: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM schema_migrations WHERE version = $1")
                .bind(DELIVERY_FINGERPRINT_REKEY_MIGRATION)
                .fetch_optional(&mut *tx)
                .await?;
        if already_applied.is_some() {
            tx.commit().await?;
            return Ok(0);
        }

        let rebuilt_chains = rebuild_delivery_lineage_v3(&mut tx).await?;
        sqlx::query(
            "INSERT INTO schema_migrations (version, description) VALUES ($1, $2) \
             ON CONFLICT (version) DO NOTHING",
        )
        .bind(DELIVERY_FINGERPRINT_REKEY_MIGRATION)
        .bind("rebuild delivery lineage with Message-ID sender identity and SMTP topology order")
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rebuilt_chains)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryHopRegistration {
    pub chain_id: Uuid,
    pub first_session_id: Uuid,
    pub hop_index: i32,
    pub is_first_hop: bool,
}

impl VigilDb {
    /// Register one observed hop idempotently.
    ///
    /// A transaction-scoped advisory lock serializes concurrent captures of
    /// the same fingerprint. This keeps hop numbering and first-hop ownership
    /// deterministic when two gateways publish nearly simultaneously.
    pub async fn register_email_delivery_hop(
        &self,
        fingerprint: &str,
        session_id: Uuid,
        client_ip: &str,
        server_ip: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<DeliveryHopRegistration> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(fingerprint)
            .execute(&mut *tx)
            .await?;

        if let Some((chain_id, hop_index, first_session_id)) =
            sqlx::query_as::<_, (String, i32, String)>(
                "SELECT chain_id, hop_index, first_session_id \
             FROM email_delivery_hops WHERE session_id = $1",
            )
            .bind(session_id.to_string())
            .fetch_optional(&mut *tx)
            .await?
        {
            tx.commit().await?;
            return Ok(DeliveryHopRegistration {
                chain_id: Uuid::parse_str(&chain_id)?,
                first_session_id: Uuid::parse_str(&first_session_id)?,
                hop_index,
                is_first_hop: hop_index == 0,
            });
        }

        let now = Utc::now();
        let cutoff = (now - DELIVERY_CHAIN_WINDOW).to_rfc3339();
        let observed_at_text = observed_at.to_rfc3339();
        let now_text = now.to_rfc3339();
        let smtp_security_rejected = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM jsonb_array_elements(
                    COALESCE(content->'smtp_dialog', '[]'::jsonb)
                ) AS dialog
                WHERE dialog->>'direction' = 'inbound'
                  AND dialog->>'command'
                      ~ '^55[0-4] 5\.7\.[0-9]+ SECURITY_POLICY_REJECTED$'
            )
            FROM sessions
            WHERE id = $1
            "#,
        )
        .bind(session_id.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .unwrap_or(false);

        let existing = sqlx::query_as::<_, (String, String, i32, Option<String>)>(
            "SELECT c.chain_id, c.first_session_id, c.hop_count::INT \
                    , first_threat_level \
             FROM email_delivery_chains c \
             WHERE c.fingerprint = $1 \
               AND vigilyx_text_timestamptz(c.updated_at) >= $2::timestamptz \
               AND EXISTS ( \
                   SELECT 1 FROM email_delivery_hops h \
                   WHERE h.chain_id = c.chain_id \
                     AND (h.server_ip = $3 OR h.client_ip = $4) \
               ) \
             ORDER BY c.updated_at DESC LIMIT 1 FOR UPDATE OF c",
        )
        .bind(fingerprint)
        .bind(cutoff)
        .bind(client_ip)
        .bind(server_ip)
        .fetch_optional(&mut *tx)
        .await?;

        let (chain_id, provisional_first_session_id, provisional_hop_index, first_threat_level) =
            if let Some((chain, first, count, threat_level)) = existing {
                (chain, first, count, threat_level)
            } else {
                let chain = Uuid::new_v4().to_string();
                let first = session_id.to_string();
                sqlx::query(
                    "INSERT INTO email_delivery_chains \
                 (chain_id, fingerprint, first_session_id, first_seen_at, first_server_ip, \
                  last_seen_at, hop_count, dangerous_forwarded_count, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $4, 1, 0, $6, $6)",
                )
                .bind(&chain)
                .bind(fingerprint)
                .bind(&first)
                .bind(&observed_at_text)
                .bind(server_ip)
                .bind(&now_text)
                .execute(&mut *tx)
                .await?;
                (chain, first, 0, None)
            };

        let dangerous_forwarded =
            provisional_hop_index > 0 && is_risky_threat_level(first_threat_level.as_deref());

        sqlx::query(
            "INSERT INTO email_delivery_hops \
             (session_id, chain_id, fingerprint, first_session_id, hop_index, client_ip, server_ip, \
              observed_at, first_hop_threat_level, verdict_origin, dangerous_forwarded, \
              smtp_security_rejected, smtp_security_rejection_metadata_ready) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, TRUE)",
        )
        .bind(session_id.to_string())
        .bind(&chain_id)
        .bind(fingerprint)
        .bind(&provisional_first_session_id)
        .bind(provisional_hop_index)
        .bind(client_ip)
        .bind(server_ip)
        .bind(&observed_at_text)
        .bind(&first_threat_level)
        .bind(dangerous_forwarded)
        .bind(smtp_security_rejected)
        .execute(&mut *tx)
        .await?;

        let session_id_text = session_id.to_string();
        let (first_session_id, hop_index) =
            reindex_live_delivery_chain(&mut tx, &chain_id, &session_id_text, &now_text).await?;

        tx.commit().await?;
        Ok(DeliveryHopRegistration {
            chain_id: Uuid::parse_str(&chain_id)?,
            first_session_id: Uuid::parse_str(&first_session_id)?,
            hop_index,
            is_first_hop: hop_index == 0,
        })
    }

    /// Publish the first-hop verdict to the chain and backfill downstream
    /// hops that were registered while the first analysis was still running.
    pub async fn record_email_delivery_first_verdict(
        &self,
        first_session_id: Uuid,
        verdict_id: Uuid,
        threat_level: &str,
    ) -> Result<()> {
        let dangerous = is_risky_threat_level(Some(threat_level));
        let now = Utc::now().to_rfc3339();
        let chain_id: Option<(String,)> = sqlx::query_as(
            "UPDATE email_delivery_chains \
             SET first_verdict_id = $2, first_threat_level = $3, updated_at = $4 \
             WHERE first_session_id = $1 RETURNING chain_id",
        )
        .bind(first_session_id.to_string())
        .bind(verdict_id.to_string())
        .bind(threat_level)
        .bind(&now)
        .fetch_optional(&self.pool)
        .await?;

        let Some((chain_id,)) = chain_id else {
            return Ok(());
        };

        sqlx::query(
            "UPDATE email_delivery_hops \
             SET first_hop_threat_level = $2, \
                 dangerous_forwarded = ($3 AND hop_index > 0) \
             WHERE chain_id = $1",
        )
        .bind(&chain_id)
        .bind(threat_level)
        .bind(dangerous)
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "UPDATE email_delivery_chains c SET dangerous_forwarded_count = ( \
                 SELECT COUNT(*) FROM email_delivery_hops h \
                 WHERE h.chain_id = c.chain_id AND h.dangerous_forwarded = TRUE \
             ), updated_at = $2 WHERE c.chain_id = $1",
        )
        .bind(&chain_id)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a downstream session as reusing the first-hop verdict.
    pub async fn mark_email_delivery_hop_reused(
        &self,
        session_id: Uuid,
        source_session_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE email_delivery_hops h \
             SET first_hop_threat_level = COALESCE(c.first_threat_level, source_verdict.threat_level, h.first_hop_threat_level), \
                 dangerous_forwarded = COALESCE( \
                     COALESCE(c.first_threat_level, source_verdict.threat_level, h.first_hop_threat_level) \
                         IN ('low', 'medium', 'high', 'critical') AND h.hop_index > 0, FALSE), \
                 verdict_origin = 'reused_first_hop', reused_from_session_id = $2 \
             FROM email_delivery_chains c \
             LEFT JOIN security_verdicts source_verdict ON source_verdict.session_id = $2 \
             WHERE h.session_id = $1 AND h.chain_id = c.chain_id",
        )
        .bind(session_id.to_string())
        .bind(source_session_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(
        session_id: &str,
        client_ip: &str,
        server_ip: &str,
        observed_at: DateTime<Utc>,
    ) -> RebuiltDeliveryHop {
        RebuiltDeliveryHop {
            session_id: session_id.to_string(),
            client_ip: client_ip.to_string(),
            server_ip: server_ip.to_string(),
            observed_at,
            old_verdict_origin: "pending".to_string(),
            old_reused_from_session_id: None,
            verdict_id: None,
            threat_level: None,
            smtp_security_rejected: false,
            old_chain_verdict_id: None,
            old_chain_threat_level: None,
        }
    }

    fn rebuilt_chain(
        session_id: &str,
        client_ip: &str,
        server_ip: &str,
        observed_at: DateTime<Utc>,
    ) -> RebuiltDeliveryChain {
        RebuiltDeliveryChain {
            chain_id: format!("chain-{session_id}"),
            fingerprint: "same-sender-controlled-identity".to_string(),
            first_session_id: session_id.to_string(),
            first_seen_at: observed_at,
            first_server_ip: server_ip.to_string(),
            first_verdict_id: None,
            first_threat_level: None,
            last_seen_at: observed_at,
            hops: vec![hop(session_id, client_ip, server_ip, observed_at)],
        }
    }

    #[test]
    fn smtp_topology_wins_over_out_of_order_processing_timestamps() {
        let now = Utc::now();
        let ordered = topology_order_delivery_hops(vec![
            hop("terminal", "10.1.246.41", "10.7.126.68", now),
            hop(
                "gateway-1",
                "198.51.100.8",
                "10.1.246.40",
                now + Duration::seconds(40),
            ),
            hop(
                "gateway-2",
                "10.1.246.40",
                "10.1.246.41",
                now + Duration::seconds(5),
            ),
        ]);

        assert_eq!(
            ordered
                .iter()
                .map(|item| item.session_id.as_str())
                .collect::<Vec<_>>(),
            vec!["gateway-1", "gateway-2", "terminal"]
        );
    }

    #[test]
    fn rekey_rebuild_keeps_disconnected_same_identity_mail_in_separate_chains() {
        let now = Utc::now();
        let fingerprint = "same-sender-controlled-identity";
        let first = rebuilt_chain("first", "198.51.100.10", "10.0.0.10", now);
        let active = HashMap::from([(fingerprint.to_string(), vec![0])]);
        assert_eq!(
            matching_rebuilt_delivery_chain(
                std::slice::from_ref(&first),
                &active,
                fingerprint,
                now + Duration::seconds(1),
                "203.0.113.77",
                "10.0.0.10",
            ),
            None,
            "a separate inbound message to the same server has no SMTP edge"
        );

        let second = rebuilt_chain(
            "second",
            "203.0.113.77",
            "10.0.0.10",
            now + Duration::seconds(1),
        );
        let chains = vec![first, second];
        let active = HashMap::from([(fingerprint.to_string(), vec![0, 1])]);
        assert_eq!(
            matching_rebuilt_delivery_chain(
                &chains,
                &active,
                fingerprint,
                now + Duration::seconds(2),
                "10.0.0.10",
                "10.0.0.20",
            ),
            Some(1),
            "a downstream hop is attached to the latest connected ingress chain"
        );
    }
}
