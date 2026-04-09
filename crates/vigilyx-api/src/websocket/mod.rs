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

   // SEC-H02: 1 authentication
    if let Some(ticket) = query.ticket.as_deref() {
        if !state
            .ws_tickets
            .consume(ticket, client_ip, user_agent.as_deref())
        {
            warn!("WebSocket 票据无效或已过期");
            return Err(StatusCode::UNAUTHORIZED);
        }
    } else {
        warn!("WebSocket Connection被拒绝: 缺少有效 ticket parameter");
        return Err(StatusCode::UNAUTHORIZED);
    }

   // SEC: Reject WebSocket when default password not changed (prevents email content leak)
    let password_changed = *state.auth.config.password_changed.read().await;
    if !password_changed {
        warn!("SEC: default-password session attempted WebSocket, rejected");
        return Err(StatusCode::FORBIDDEN);
    }

    // SEC: per-IP connection limit (prevents fd exhaustion)
    let mut current = WS_PER_IP.entry(client_ip).or_insert(0);
    if *current >= MAX_WS_PER_IP {
        warn!(ip = %client_ip, count = *current, "WebSocket per-IP limit reached");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    *current += 1;
    drop(current);

   // SEC-H05: WebSocket message OOM (CWE-400)
    Ok(ws
        .max_message_size(64 * 1024) // 64 KB
        .max_frame_size(16 * 1024) // 16 KB
        .on_upgrade(move |socket| {
            let ip = client_ip;
            async move {
                handle_socket(socket, state).await;
                // Decrement the counter on disconnect
                WS_PER_IP.entry(ip).and_modify(|c| *c = c.saturating_sub(1));
            }
        }))
}

/// Process WebSocket Connection
async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

   // Broadcast channel
    let mut rx = state.messaging.ws_tx.subscribe();

    WS_CONNECTIONS_ACTIVE.inc();
    info!("New WebSocket Connection");

   // send Statisticsinfo
    if let Ok(stats) = state.db.get_stats().await {
        let msg = WsMessage::StatsUpdate(stats);
        if let Ok(json) = serde_json::to_string(&msg) {
            let _ = sender.send(Message::Text(json.into())).await;
        }
    }

   // receive message send client
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    match serde_json::to_string(&msg) {
                        Ok(json) => {
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                break; // client
                            }
                        }
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
                   // message, New
                    let refresh_msg = serde_json::json!({
                        "type": "RefreshNeeded",
                        "data": { "skipped": n }
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
    });

   // receiveclientmessage
    let recv_task = tokio::spawn(async move {
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
        _ = send_task => {},
        _ = recv_task => {},
    }

    
    WS_CONNECTIONS_ACTIVE.dec();
    info!("WebSocket Connectionshutdown");
}
