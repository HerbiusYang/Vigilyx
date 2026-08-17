//! WebSocket 1 (SEC-H02: JWT found URL Query)

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

#[derive(Clone)]
struct WsTicketRecord {
    issued_at: Instant,
    username: String,
    client_ip: IpAddr,
    user_agent: Option<String>,
}

/// WebSocket: 1 URL JWT

/// Stream: POST /api/auth/ws-ticket get -> Connection WebSocket
/// 30, 1, Contains JWT.
pub struct WsTicketStore {
    tickets: std::sync::Mutex<HashMap<String, WsTicketRecord>>,
}

/// SEC-M12: (CWE-400)
const MAX_TICKETS: usize = 10_000;
/// SEC-F4: bound how many outstanding tickets a single user may hold within
/// the TTL window, so one authenticated account cannot exhaust the global
/// capacity and lock out everyone else.
const MAX_TICKETS_PER_USER: usize = 100;
const TICKET_TTL: Duration = Duration::from_secs(30);
const MAX_USER_AGENT_CHARS: usize = 256;

fn normalize_user_agent(user_agent: Option<&str>) -> Option<String> {
    user_agent
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(MAX_USER_AGENT_CHARS).collect())
}

impl WsTicketStore {
    pub fn new() -> Self {
        Self {
            tickets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 1 (30), user.

    /// Returns `None` if global capacity or the per-user quota is exhausted
    /// (DoS protection).
    pub fn issue(
        &self,
        username: &str,
        client_ip: IpAddr,
        user_agent: Option<&str>,
    ) -> Option<String> {
        let ticket = uuid::Uuid::new_v4().to_string();
        let mut tickets = self.tickets.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("WsTicketStore lock was poisoned, recovering");
            poisoned.into_inner()
        });

        let now = Instant::now();
        tickets.retain(|_, record| now.duration_since(record.issued_at) < TICKET_TTL);
        // SEC-M12: DoS
        if tickets.len() >= MAX_TICKETS {
            tracing::warn!("WsTicketStore 容量已满 ({MAX_TICKETS})，拒绝签发New票据");
            return None;
        }
        // SEC-F4: per-user quota within the TTL window (tickets were just
        // pruned to live ones, so the count is window-scoped).
        let user_tickets = tickets
            .values()
            .filter(|record| record.username == username)
            .count();
        if user_tickets >= MAX_TICKETS_PER_USER {
            tracing::warn!(
                username = %username,
                outstanding = user_tickets,
                "WsTicketStore per-user 配额已满 ({MAX_TICKETS_PER_USER})，拒绝签发New票据"
            );
            return None;
        }
        tickets.insert(
            ticket.clone(),
            WsTicketRecord {
                issued_at: now,
                username: username.to_string(),
                client_ip,
                user_agent: normalize_user_agent(user_agent),
            },
        );
        Some(ticket)
    }

    /// Verify (1: verify delete).

    /// ,, DoS.
    /// Verify (1: verify delete). Returns the bound username so the
    /// connection can track per-user revocation epochs.
    pub fn consume(
        &self,
        ticket: &str,
        client_ip: IpAddr,
        user_agent: Option<&str>,
    ) -> Option<String> {
        let mut tickets = self.tickets.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("WsTicketStore lock was poisoned, recovering");
            poisoned.into_inner()
        });
        let now = Instant::now();
        let record = tickets.get(ticket).cloned()?;

        if now.duration_since(record.issued_at) >= TICKET_TTL {
            tickets.remove(ticket);
            return None;
        }

        let normalized_user_agent = normalize_user_agent(user_agent);
        if record.client_ip != client_ip || record.user_agent != normalized_user_agent {
            tracing::warn!(
                username = %record.username,
                expected_ip = %record.client_ip,
                actual_ip = %client_ip,
                "WebSocket ticket source mismatch"
            );
            return None;
        }

        tickets.remove(ticket);
        Some(record.username)
    }

    pub fn clear(&self) {
        let mut tickets = self.tickets.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("WsTicketStore lock was poisoned, recovering");
            poisoned.into_inner()
        });
        tickets.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, octet))
    }

    #[test]
    fn ticket_requires_same_source_attributes() {
        let store = WsTicketStore::new();
        let ticket = store
            .issue("admin", ip(10), Some("Mozilla/5.0"))
            .expect("ticket should be issued");

        assert!(store
            .consume(&ticket, ip(10), Some("Mozilla/5.0"))
            .is_some());
        assert!(store
            .consume(&ticket, ip(10), Some("Mozilla/5.0"))
            .is_none());
    }

    #[test]
    fn mismatched_ip_does_not_consume_ticket() {
        let store = WsTicketStore::new();
        let ticket = store
            .issue("admin", ip(10), Some("Mozilla/5.0"))
            .expect("ticket should be issued");

        assert!(store
            .consume(&ticket, ip(11), Some("Mozilla/5.0"))
            .is_none());
        assert!(store
            .consume(&ticket, ip(10), Some("Mozilla/5.0"))
            .is_some());
    }

    #[test]
    fn mismatched_user_agent_does_not_consume_ticket() {
        let store = WsTicketStore::new();
        let ticket = store
            .issue("admin", ip(10), Some("Mozilla/5.0"))
            .expect("ticket should be issued");

        assert!(store
            .consume(&ticket, ip(10), Some("curl/8.0"))
            .is_none());
        assert!(store
            .consume(&ticket, ip(10), Some("Mozilla/5.0"))
            .is_some());
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let store = WsTicketStore::new();
        let ticket = "expired-ticket".to_string();
        let mut tickets = store.tickets.lock().unwrap();
        tickets.insert(
            ticket.clone(),
            WsTicketRecord {
                issued_at: Instant::now() - TICKET_TTL - Duration::from_secs(1),
                username: "admin".to_string(),
                client_ip: ip(10),
                user_agent: Some("Mozilla/5.0".to_string()),
            },
        );
        drop(tickets);

        assert!(store
            .consume(&ticket, ip(10), Some("Mozilla/5.0"))
            .is_none());
        assert!(!store.tickets.lock().unwrap().contains_key(&ticket));
    }

    #[test]
    fn per_user_quota_blocks_single_account_exhaustion() {
        // PoC: before the quota, one authenticated user could hold up to the
        // global 10k capacity, starving every other user's WebSocket logins.
        let store = WsTicketStore::new();
        for _ in 0..MAX_TICKETS_PER_USER {
            assert!(
                store.issue("attacker", ip(10), Some("Mozilla/5.0")).is_some(),
                "tickets within the per-user quota must be issued"
            );
        }
        assert!(
            store.issue("attacker", ip(10), Some("Mozilla/5.0")).is_none(),
            "the ticket past the per-user quota must be refused"
        );
    }

    #[test]
    fn per_user_quota_does_not_affect_other_users() {
        let store = WsTicketStore::new();
        for _ in 0..MAX_TICKETS_PER_USER {
            let _ = store.issue("attacker", ip(10), Some("Mozilla/5.0"));
        }

        assert!(
            store.issue("victim", ip(20), Some("Mozilla/5.0")).is_some(),
            "other users must still get tickets while one user is at quota"
        );
    }

    #[test]
    fn consuming_tickets_frees_per_user_quota() {
        let store = WsTicketStore::new();
        let mut tickets = Vec::new();
        for _ in 0..MAX_TICKETS_PER_USER {
            tickets.push(
                store
                    .issue("admin", ip(10), Some("Mozilla/5.0"))
                    .expect("within quota"),
            );
        }
        assert!(store.issue("admin", ip(10), Some("Mozilla/5.0")).is_none());

        // Consuming one ticket frees one slot for the same user.
        let consumed = tickets.pop().expect("a ticket to consume");
        assert!(store
            .consume(&consumed, ip(10), Some("Mozilla/5.0"))
            .is_some());
        assert!(store.issue("admin", ip(10), Some("Mozilla/5.0")).is_some());
    }
}
