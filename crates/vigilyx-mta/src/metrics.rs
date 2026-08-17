//! Inline 判定计数器
//!
//! 进程内原子计数，随 MTA 状态心跳上报到 API（/api/system/mta），
//! 用于前端展示 inline 判定分布。计数器自进程启动累计，重启归零。

use std::sync::atomic::{AtomicU64, Ordering};

/// MTA inline 判定分布计数器（跨 SMTP/SMTPS listener 共享）。
#[derive(Debug, Default)]
pub struct VerdictMetrics {
    /// 判定放行并成功转发下游（不含 fail-open 放行）
    pub accepted: AtomicU64,
    /// 判定进入隔离区（250 对发件人透明）
    pub quarantined: AtomicU64,
    /// 判定拒绝（550）
    pub rejected: AtomicU64,
    /// 引擎判定超时/不可用且 fail-open 放行
    pub timeout_failopen: AtomicU64,
}

/// 计数器快照（随状态上报）
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct VerdictMetricsSnapshot {
    pub accepted: u64,
    pub quarantined: u64,
    pub rejected: u64,
    pub timeout_failopen: u64,
}

impl VerdictMetrics {
    pub fn inc_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_quarantined(&self) {
        self.quarantined.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeout_failopen(&self) {
        self.timeout_failopen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> VerdictMetricsSnapshot {
        VerdictMetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            quarantined: self.quarantined.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            timeout_failopen: self.timeout_failopen.load(Ordering::Relaxed),
        }
    }
}
