//! Bounded process-local snapshots for expensive operational aggregates.
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use tokio::sync::{Mutex, RwLock};

pub(crate) struct Snapshot<T> {
    value: RwLock<Option<(Instant, T)>>,
    refresh: Arc<Mutex<()>>,
}

impl<T> Default for Snapshot<T> {
    fn default() -> Self {
        Self {
            value: RwLock::new(None),
            refresh: Arc::new(Mutex::new(())),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> Snapshot<T> {
    /// Fresh for 30 seconds; serve the last successful snapshot during a
    /// single background refresh. After two minutes failures become visible
    /// to the caller rather than serving indefinitely stale or zero counts.
    pub(crate) async fn get<F, Fut>(self: &Arc<Self>, load: F) -> Result<T>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send,
    {
        const FRESH: Duration = Duration::from_secs(30);
        const HARD: Duration = Duration::from_secs(120);
        let cached = self.value.read().await.clone();
        if let Some((at, value)) = cached {
            if at.elapsed() < FRESH {
                return Ok(value);
            }
            if at.elapsed() < HARD {
                if let Ok(guard) = self.refresh.clone().try_lock_owned() {
                    let cache = self.clone();
                    tokio::spawn(async move {
                        let _guard = guard;
                        match load().await {
                            Ok(value) => *cache.value.write().await = Some((Instant::now(), value)),
                            Err(error) => {
                                tracing::warn!(%error, "Data-security aggregate refresh failed")
                            }
                        }
                    });
                }
                return Ok(value);
            }
        }
        let _guard = self.refresh.lock().await;
        if let Some((at, value)) = self.value.read().await.as_ref()
            && at.elapsed() < FRESH
        {
            return Ok(value.clone());
        }
        let value = load().await?;
        *self.value.write().await = Some((Instant::now(), value.clone()));
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrent_cold_readers_share_one_query() {
        let cache = Arc::new(Snapshot::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut readers = Vec::new();
        for _ in 0..12 {
            let cache = cache.clone();
            let calls = calls.clone();
            readers.push(tokio::spawn(async move {
                cache
                    .get(move || async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok(42)
                    })
                    .await
                    .unwrap()
            }));
        }
        for reader in readers {
            assert_eq!(reader.await.unwrap(), 42);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_reader_returns_without_waiting_for_refresh() {
        let cache = Arc::new(Snapshot::default());
        *cache.value.write().await = Some((Instant::now() - Duration::from_secs(31), 7));
        let release = Arc::new(tokio::sync::Notify::new());
        let complete = Arc::new(tokio::sync::Notify::new());
        let (r, c) = (release.clone(), complete.clone());
        assert_eq!(
            cache
                .get(move || async move {
                    r.notified().await;
                    c.notify_one();
                    Ok(8)
                })
                .await
                .unwrap(),
            7
        );
        release.notify_one();
        complete.notified().await;
        // Acquiring the refresh lock also waits for publication of the result.
        let _guard = cache.refresh.lock().await;
        assert_eq!(cache.value.read().await.as_ref().unwrap().1, 8);
    }

    #[tokio::test]
    async fn hard_expiry_propagates_failure_and_does_not_cache_zero() {
        let cache = Arc::new(Snapshot::default());
        *cache.value.write().await = Some((Instant::now() - Duration::from_secs(121), 7));
        assert!(
            cache
                .get(|| async { anyhow::bail!("database unavailable") })
                .await
                .is_err()
        );
        assert_eq!(cache.value.read().await.as_ref().unwrap().1, 7);
        assert_eq!(cache.get(|| async { Ok(9) }).await.unwrap(), 9);
    }
}
