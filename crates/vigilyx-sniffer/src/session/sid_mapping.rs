//! Coremail SID-to-user email address correlation.

use super::*;
use super::types::SidUserEntry;

impl ShardedSessionManager {
   /// sid -> user Mapping (Update LRU timestamp + add Redis write buffer)
    pub(super) fn sid_user_insert(&self, sid: String, user: String) {
        self.sid_to_user.insert(
            sid.clone(),
            SidUserEntry {
                user: user.clone(),
                last_access: std::time::Instant::now(),
            },
        );
        if let Ok(mut pending) = self.sid_user_pending.lock() {
            pending.push((sid, user));
        }
    }

   /// lookup sid -> user Mapping (Update LRU timestamp)
    pub(super) fn sid_user_get(&self, sid: &str) -> Option<String> {
        if let Some(mut entry) = self.sid_to_user.get_mut(sid) {
            entry.last_access = std::time::Instant::now();
            Some(entry.user.clone())
        } else {
            None
        }
    }

   /// LRU eviction: keep the most recently accessed 40K entries, remove the oldest.
   /// Returns evicted sid list (for Redis sync deletion).
   ///
   /// Uses `select_nth_unstable` (O(n)) instead of full sort (O(n log n))
   /// to avoid sorting 50K+ entries on the hot path.
    pub(super) fn sid_user_evict_lru(&self) -> Vec<String> {
        const MAX_SIZE: usize = 50_000;
        const KEEP_SIZE: usize = 40_000;

        if self.sid_to_user.len() <= MAX_SIZE {
            return Vec::new();
        }

        let mut entries: Vec<(String, std::time::Instant)> = self
            .sid_to_user
            .iter()
            .map(|e| (e.key().clone(), e.value().last_access))
            .collect();

       // O(n) quick-select: partition the oldest `to_remove` entries to the left
        let to_remove = entries.len().saturating_sub(KEEP_SIZE);
        if to_remove == 0 {
            return Vec::new();
        }
        entries.select_nth_unstable_by_key(to_remove, |(_, ts)| *ts);

        let mut evicted = Vec::with_capacity(to_remove);
        for (sid, _) in entries.into_iter().take(to_remove) {
            self.sid_to_user.remove(&sid);
            evicted.push(sid);
        }

        if !evicted.is_empty() {
            tracing::info!(
                "sid\u{2192}user LRU eviction: delete {} Item\u{6700}\u{65e7}Mapping (remaining {})",
                evicted.len(),
                self.sid_to_user.len()
            );
        }
        evicted
    }

   /// Extract pending buffer to be written to Redis
    pub fn take_sid_user_pending(&self) -> Vec<(String, String)> {
        match self.sid_user_pending.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(_) => Vec::new(),
        }
    }

   /// From Redis LoadofMappingBatchImport (Start)
    pub fn load_sid_user_from_redis(&self, entries: Vec<(String, String)>) {
        let now = std::time::Instant::now();
        let count = entries.len();
        for (sid, user) in entries {
            self.sid_to_user.insert(
                sid,
                SidUserEntry {
                    user,
                    last_access: now,
                },
            );
        }
        if count > 0 {
            tracing::info!("From Redis Load {} Item sid\u{2192}user Mapping", count);
        }
    }
}
