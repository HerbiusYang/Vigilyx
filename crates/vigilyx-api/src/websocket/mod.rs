//! WebSocket Process

use axum::{
    extract::{
        ConnectInfo, Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info, warn};
use vigilyx_core::WsMessage;

use crate::AppState;
use crate::metrics::WS_CONNECTIONS_ACTIVE;
use crate::routes::{extract_client_ip, extract_user_agent};

/// SEC: per-IP WebSocket connection limit (prevents fd-exhaustion DoS, CWE-400).
const MAX_WS_PER_IP: usize = 20;
static WS_PER_IP: std::sync::LazyLock<dashmap::DashMap<std::net::IpAddr, usize>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);
const WS_AUTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Match the permission boundary of the REST resource represented by each
/// event. A transport ticket does not grant access to the shared event bus.
fn can_receive_ws_message(message: &WsMessage, permissions: &[String]) -> bool {
    let permission = match message {
        WsMessage::NewSession(_) | WsMessage::SessionUpdate(_) => "sessions.read",
        WsMessage::StatsUpdate(_) => "system.read",
        WsMessage::SecurityVerdict(_) | WsMessage::Alert(_) => "security.read",
        WsMessage::DataSecurityAlert(_) => "data_security.read",
        WsMessage::SessionInvalidated | WsMessage::Ping | WsMessage::Pong => return true,
    };
    permissions.iter().any(|candidate| candidate == permission)
}

fn authorized_ws_payload(
    message: &WsMessage,
    permissions: &[String],
) -> Result<Option<String>, serde_json::Error> {
    if !can_receive_ws_message(message, permissions) {
        return Ok(None);
    }
    serde_json::to_string(message).map(Some)
}

fn websocket_auth_epochs_current(
    state: &AppState,
    auth_epoch: u64,
    username: &str,
    user_epoch: u64,
) -> bool {
    auth_epochs_current(
        &state.ws_auth_epoch,
        &state.ws_user_epochs,
        auth_epoch,
        username,
        user_epoch,
    )
}

fn auth_epochs_current(
    global_epoch: &std::sync::atomic::AtomicU64,
    user_epochs: &dashmap::DashMap<String, u64>,
    auth_epoch: u64,
    username: &str,
    user_epoch: u64,
) -> bool {
    global_epoch.load(Ordering::Acquire) == auth_epoch
        && user_epochs.get(username).map(|entry| *entry).unwrap_or(0) == user_epoch
}

fn bump_user_epoch(user_epochs: &dashmap::DashMap<String, u64>, username: &str) {
    user_epochs
        .entry(username.to_string())
        .and_modify(|epoch| *epoch += 1)
        .or_insert(1);
}

fn try_acquire_ws_slot(client_ip: std::net::IpAddr) -> bool {
    let mut current = WS_PER_IP.entry(client_ip).or_insert(0);
    if *current >= MAX_WS_PER_IP {
        return false;
    }
    *current += 1;
    true
}

fn release_ws_slot(client_ip: std::net::IpAddr) {
    use dashmap::mapref::entry::Entry;

    if let Entry::Occupied(mut current) = WS_PER_IP.entry(client_ip) {
        if *current.get() <= 1 {
            current.remove();
        } else {
            *current.get_mut() -= 1;
        }
    }
}

pub fn invalidate_websocket_sessions(state: &crate::AppState) {
    state.ws_auth_epoch.fetch_add(1, Ordering::SeqCst);
    let _ = state.messaging.ws_tx.send(WsMessage::SessionInvalidated);
}

/// SEC (round-5): revoke only `username`'s live dashboard sockets — a single
/// logout previously broke every operator's WebSocket via the global epoch.
pub fn invalidate_websocket_sessions_for_user(state: &crate::AppState, username: &str) {
    bump_user_epoch(&state.ws_user_epochs, username);
}

/// WebSocket authentication query parameter

/// SEC-H02: `ticket` (1, JWT)
#[derive(Deserialize)]
pub struct WsAuthQuery {
    /// 1 (: POST /api/auth/ws-ticket get)
    ticket: Option<String>,
}

/// WebSocket Process
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsAuthQuery>,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    let client_ip = extract_client_ip(&headers, addr);
    let user_agent = extract_user_agent(&headers);

    // SEC-H02: 1 authentication (the ticket carries the bound username)
    let principal = if let Some(ticket) = query.ticket.as_deref() {
        match state
            .ws_tickets
            .consume(ticket, client_ip, user_agent.as_deref())
        {
            Some(principal) => principal,
            None => {
                warn!("WebSocket 票据无效或已过期");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    } else {
        warn!("WebSocket Connection被拒绝: 缺少有效 ticket parameter");
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Snapshot revocation state before reading permissions. Otherwise a role
    // change during the DB lookup could pair old grants with the new epoch.
    let auth_epoch = state.ws_auth_epoch.load(Ordering::Acquire);
    let user_epoch = state
        .ws_user_epochs
        .get(&principal.username)
        .map(|entry| *entry)
        .unwrap_or(0);

    // A ticket is only an unforgeable transport credential; it is not a
    // lifetime authorization grant. Rehydrate the user before upgrading so a
    // ticket issued before disable/role/password revocation cannot be used.
    let current_user = match state
        .engine_db
        .get_platform_auth_user(&principal.username)
        .await
    {
        Ok(Some(user)) if user.is_active && user.token_version == principal.token_version => user,
        Ok(_) => return Err(StatusCode::UNAUTHORIZED),
        Err(error) => {
            warn!(error = %error, "WebSocket authorization lookup failed");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let ws_username = current_user.username;
    let token_version = current_user.token_version;
    let permissions = current_user.permissions;

    // SEC: Reject WebSocket when default password not changed (prevents email content leak)
    let password_changed = *state.auth.config.password_changed.read().await;
    if !password_changed {
        warn!("SEC: default-password session attempted WebSocket, rejected");
        return Err(StatusCode::FORBIDDEN);
    }

    if !websocket_auth_epochs_current(&state, auth_epoch, &ws_username, user_epoch) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // SEC: per-IP connection limit (prevents fd exhaustion)
    if !try_acquire_ws_slot(client_ip) {
        warn!(ip = %client_ip, "WebSocket per-IP limit reached");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // SEC-H05: WebSocket message OOM (CWE-400)
    Ok(ws
        .max_message_size(64 * 1024) // 64 KB
        .max_frame_size(16 * 1024) // 16 KB
        .on_upgrade(move |socket| {
            let ip = client_ip;
            async move {
                handle_socket(
                    socket,
                    state,
                    auth_epoch,
                    &ws_username,
                    user_epoch,
                    token_version,
                    permissions,
                )
                .await;
                // Decrement the counter on disconnect
                release_ws_slot(ip);
            }
        }))
}

/// Process WebSocket Connection
async fn handle_socket(
    socket: WebSocket,
    state: Arc<AppState>,
    auth_epoch: u64,
    ws_username: &str,
    user_epoch: u64,
    token_version: u64,
    mut permissions: Vec<String>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Broadcast channel
    let mut rx = state.messaging.ws_tx.subscribe();

    WS_CONNECTIONS_ACTIVE.inc();
    info!("New WebSocket Connection");

    // send Statisticsinfo
    if permissions
        .iter()
        .any(|permission| permission == "system.read")
        && let Ok(stats) = state.db.get_stats().await
    {
        let msg = WsMessage::StatsUpdate(stats);
        if !websocket_auth_epochs_current(&state, auth_epoch, ws_username, user_epoch) {
            WS_CONNECTIONS_ACTIVE.dec();
            return;
        }
        if let Ok(Some(json)) = authorized_ws_payload(&msg, &permissions) {
            let _ = sender.send(Message::Text(json.into())).await;
        }
    }

    // receive message send client
    let send_state = state.clone();
    let send_username = ws_username.to_string();
    let mut send_task = tokio::spawn(async move {
        let mut auth_check = tokio::time::interval(WS_AUTH_CHECK_INTERVAL);
        loop {
            tokio::select! {
                _ = auth_check.tick() => {
                    let current_epoch = send_state.ws_auth_epoch.load(Ordering::Acquire);
                    let current_user_epoch = send_state
                        .ws_user_epochs
                        .get(&send_username)
                        .map(|entry| *entry)
                        .unwrap_or(0);
                    let password_changed = *send_state.auth.config.password_changed.read().await;
                    let user_current = send_state
                        .engine_db
                        .get_platform_auth_user(&send_username)
                        .await
                        .ok()
                        .flatten();
                    let user_valid = user_current.as_ref().is_some_and(|user| {
                        user.is_active && user.token_version == token_version
                    });
                    if current_epoch != auth_epoch
                        || current_user_epoch != user_epoch
                        || !password_changed
                        || !user_valid
                    {
                        info!(
                            user = %send_username,
                            "WebSocket auth state changed, closing connection"
                        );
                        break;
                    }
                    if let Some(user) = user_current {
                        permissions = user.permissions;
                    }
                }
                msg = rx.recv() => match msg {
                    Ok(WsMessage::SessionInvalidated) => {
                        info!("WebSocket session invalidated, closing connection");
                        break;
                    }
                    Ok(msg) => {
                        if !websocket_auth_epochs_current(
                            &send_state, auth_epoch, &send_username, user_epoch
                        ) {
                            break;
                        }
                        match authorized_ws_payload(&msg, &permissions) {
                            Ok(Some(json)) => {
                                if sender.send(Message::Text(json.into())).await.is_err() {
                                    break; // client
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                error!("序列化messagefailed: {}", e);
                            }
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                       // receive send, n items message
                        warn!(
                            "WebSocket receive方落后，跳过 {} itemsmessage，通知前端刷New",
                            n
                        );
                        if !websocket_auth_epochs_current(
                            &send_state, auth_epoch, &send_username, user_epoch
                        ) {
                            info!("WebSocket auth state changed while lagged, closing connection");
                            break;
                        }
                       // message, New
                        let refresh_msg = serde_json::json!({
                            "type": "RefreshNeeded",
                            // The shared bus lag count includes unauthorized
                            // resource events, so expose only the refresh signal.
                            "data": {}
                        });
                        if let Ok(json) = serde_json::to_string(&refresh_msg)
                            && sender.send(Message::Text(json.into())).await.is_err()
                        {
                            break;
                        }
                       // break - receive message
                    }
                    Err(RecvError::Closed) => {
                       // Broadcast channel shutdown (Service shutdown)
                        break;
                    }
                }
            }
        }
    });

    // receiveclientmessage
    let mut recv_task = tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    debug!("Receivedclientmessage: {}", text);
                    // Process Pong response
                    if let Ok(WsMessage::Pong) = serde_json::from_str::<WsMessage>(&text) {
                        debug!("Received Pong");
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("clientshutdownConnection");
                    break;
                }
                Err(e) => {
                    error!("Receive messageerror: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        },
        _ = &mut recv_task => {
            send_task.abort();
        },
    }

    WS_CONNECTIONS_ACTIVE.dec();
    info!("WebSocket Connectionshutdown");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_epoch_revocation_blocks_next_send_and_preserves_other_user_sessions() {
        let global_epoch = std::sync::atomic::AtomicU64::new(0);
        let user_epochs = dashmap::DashMap::new();
        assert!(auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "alice",
            0
        ));
        assert!(auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "bob",
            0
        ));

        // The same synchronous operation used by logout/profile changes must
        // reject Alice's cached permission snapshot before the 5s DB refresh.
        bump_user_epoch(&user_epochs, "alice");
        assert!(!auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "alice",
            0
        ));
        assert!(auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "bob",
            0
        ));

        // Role permission changes invalidate every pre-commit snapshot,
        // including a concurrently bound member absent from any user list.
        global_epoch.fetch_add(1, Ordering::SeqCst);
        assert!(!auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "bob",
            0
        ));
        assert!(!auth_epochs_current(
            &global_epoch,
            &user_epochs,
            0,
            "new-role-member",
            0
        ));
        // A connection rehydrated after the change captures fresh epochs.
        assert!(auth_epochs_current(
            &global_epoch,
            &user_epochs,
            1,
            "alice",
            1
        ));
        assert!(auth_epochs_current(
            &global_epoch,
            &user_epochs,
            1,
            "bob",
            0
        ));
    }

    fn resource_messages() -> Vec<(WsMessage, &'static str)> {
        let id = uuid::Uuid::nil();
        let session = vigilyx_core::WsSessionSignal {
            id,
            protocol: vigilyx_core::Protocol::Smtp,
            status: vigilyx_core::SessionStatus::Completed,
            threat_level: Some("high".into()),
        };
        vec![
            (WsMessage::NewSession(session.clone()), "sessions.read"),
            (WsMessage::SessionUpdate(session), "sessions.read"),
            (
                WsMessage::StatsUpdate(vigilyx_core::TrafficStats::default()),
                "system.read",
            ),
            (
                WsMessage::SecurityVerdict(vigilyx_core::SecurityVerdictSummary {
                    inspection_coverage: Default::default(),
                    coverage_reasons: vec![],
                    verdict_id: id,
                    session_id: id,
                    threat_level: "high".into(),
                    threat_type: None,
                    confidence: 0.9,
                    categories: vec!["test".into()],
                    summary: "Synthetic security event".into(),
                    modules_run: 1,
                    modules_flagged: 1,
                    total_duration_ms: 1,
                }),
                "security.read",
            ),
            (WsMessage::Alert("Synthetic alert".into()), "security.read"),
            (
                WsMessage::DataSecurityAlert(vigilyx_core::DataSecurityIncident {
                    id,
                    http_session_id: id,
                    incident_type: vigilyx_core::DataSecurityIncidentType::SelfSending,
                    severity: vigilyx_core::DataSecuritySeverity::High,
                    confidence: 0.9,
                    summary: "Synthetic data security event".into(),
                    evidence: vec![],
                    details: None,
                    dlp_matches: vec![],
                    client_ip: "192.0.2.10".into(),
                    detected_user: None,
                    request_url: "https://mail.example.test/send".into(),
                    host: Some("mail.example.test".into()),
                    method: "POST".into(),
                    created_at: chrono::Utc::now(),
                }),
                "data_security.read",
            ),
        ]
    }

    #[test]
    fn websocket_rbac_denies_resource_payloads_for_low_privilege_role() {
        // A valid audit-only/custom principal may obtain a transport ticket.
        // Authentication alone must not serialize any business event for it.
        let permissions = vec!["audit.read".into()];
        for (message, _) in resource_messages() {
            assert!(
                authorized_ws_payload(&message, &permissions)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn websocket_rbac_filters_each_resource_and_preserves_authorized_payload() {
        for permission in [
            "sessions.read",
            "system.read",
            "security.read",
            "data_security.read",
        ] {
            let permissions = vec![permission.to_string()];
            for (message, required_permission) in resource_messages() {
                let payload = authorized_ws_payload(&message, &permissions).unwrap();
                assert_eq!(payload.is_some(), permission == required_permission);
                if let Some(payload) = payload {
                    assert_eq!(
                        serde_json::from_str::<serde_json::Value>(&payload).unwrap(),
                        serde_json::to_value(&message).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn websocket_rbac_uses_updated_permissions_for_subsequent_events() {
        let message = WsMessage::Alert("Synthetic alert".into());
        let mut permissions = vec!["security.read".into()];
        assert!(
            authorized_ws_payload(&message, &permissions)
                .unwrap()
                .is_some()
        );
        permissions = vec!["system.read".into()];
        assert!(
            authorized_ws_payload(&message, &permissions)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn websocket_control_messages_remain_available_without_resource_permissions() {
        for message in [
            WsMessage::Ping,
            WsMessage::Pong,
            WsMessage::SessionInvalidated,
        ] {
            assert!(authorized_ws_payload(&message, &[]).unwrap().is_some());
        }
    }

    #[test]
    fn websocket_slot_limit_recovers_after_release() {
        let ip = "192.0.2.41".parse().unwrap();
        WS_PER_IP.remove(&ip);

        for _ in 0..MAX_WS_PER_IP {
            assert!(try_acquire_ws_slot(ip));
        }
        assert!(!try_acquire_ws_slot(ip));

        release_ws_slot(ip);
        assert!(try_acquire_ws_slot(ip));

        for _ in 0..MAX_WS_PER_IP {
            release_ws_slot(ip);
        }
        assert!(!WS_PER_IP.contains_key(&ip));
    }

    #[test]
    fn websocket_slot_release_removes_unique_ip_entries() {
        let base: std::net::Ipv4Addr = "198.51.100.0".parse().unwrap();
        let ips: Vec<std::net::IpAddr> = (1..=64)
            .map(|last| {
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    base.octets()[0],
                    base.octets()[1],
                    base.octets()[2],
                    last,
                ))
            })
            .collect();

        for ip in &ips {
            WS_PER_IP.remove(ip);
            assert!(try_acquire_ws_slot(*ip));
            release_ws_slot(*ip);
            assert!(!WS_PER_IP.contains_key(ip));
        }
    }
}
