//! Local in-memory channel (Fallback for single-process mode)

use async_channel::{Receiver, Sender, bounded};
use std::sync::Arc;
use vigilyx_core::{EmailSession, TrafficStats, WsMessage};

/// Local message channel
pub struct LocalChannel<T> {
    tx: Sender<T>,
    rx: Receiver<T>,
}

impl<T: Clone + Send + 'static> LocalChannel<T> {
    /// Create new local channel
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = bounded(capacity);
        Self { tx, rx }
    }

    /// Get sender
    pub fn sender(&self) -> Sender<T> {
        self.tx.clone()
    }

    /// Get receiver
    pub fn receiver(&self) -> Receiver<T> {
        self.rx.clone()
    }

    /// Send message
    pub async fn send(&self, msg: T) -> Result<(), async_channel::SendError<T>> {
        self.tx.send(msg).await
    }

    /// Try send message (non-blocking)
    pub fn try_send(&self, msg: T) -> Result<(), async_channel::TrySendError<T>> {
        self.tx.try_send(msg)
    }

    /// Receive message
    pub async fn recv(&self) -> Result<T, async_channel::RecvError> {
        self.rx.recv().await
    }

    /// Try receive message (non-blocking)
    pub fn try_recv(&self) -> Result<T, async_channel::TryRecvError> {
        self.rx.try_recv()
    }
}

/// Event bus - For component communication in single-process mode
pub struct EventBus {
    /// Session channel
    pub sessions: LocalChannel<EmailSession>,
    /// Statistics channel
    pub stats: LocalChannel<TrafficStats>,
    /// WebSocket Broadcast channel
    pub ws_broadcast: LocalChannel<WsMessage>,
}

impl EventBus {
    /// Create new event bus
    pub fn new(capacity: usize) -> Self {
        Self {
            sessions: LocalChannel::new(capacity),
            stats: LocalChannel::new(capacity),
            ws_broadcast: LocalChannel::new(capacity),
        }
    }

    /// Create with default capacity
    pub fn default_capacity() -> Self {
        Self::new(10000)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::default_capacity()
    }
}

/// SharedEvent bus
pub type SharedEventBus = Arc<EventBus>;

/// Create shared event bus
pub fn create_event_bus(capacity: usize) -> SharedEventBus {
    Arc::new(EventBus::new(capacity))
}
