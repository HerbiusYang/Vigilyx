//! Name Management

//! Features:
//! - SenderDomain/IP/Hash Name
//! - Module should_run Check Query
//! - Memorycache + DB

use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use vigilyx_core::security::WhitelistEntry;
use vigilyx_db::VigilDb;

/// Name Type
pub const WL_DOMAIN: &str = "domain";
pub const WL_IP: &str = "ip";
pub const WL_EMAIL: &str = "email";
pub const WL_HASH: &str = "hash";

/// Name Managementhandler
/// UseMemorycacheAdd Query,DB
#[derive(Clone)]
pub struct WhitelistManager {
    db: VigilDb,
    cache: Arc<RwLock<WhitelistCache>>,
}

struct WhitelistCache {
    domains: HashSet<String>,
    ips: HashSet<String>,
    emails: HashSet<String>,
    hashes: HashSet<String>,
    loaded: bool,
}

impl WhitelistCache {
    fn new() -> Self {
        Self {
            domains: HashSet::new(),
            ips: HashSet::new(),
            emails: HashSet::new(),
            hashes: HashSet::new(),
            loaded: false,
        }
    }

    fn contains(&self, entry_type: &str, value: &str) -> bool {
        match entry_type {
            WL_DOMAIN => self.domains.contains(value),
            WL_IP => self.ips.contains(value),
            WL_EMAIL => self.emails.contains(value),
            WL_HASH => self.hashes.contains(value),
            _ => false,
        }
    }

    fn insert(&mut self, entry_type: &str, value: String) {
        match entry_type {
            WL_DOMAIN => {
                self.domains.insert(value);
            }
            WL_IP => {
                self.ips.insert(value);
            }
            WL_EMAIL => {
                self.emails.insert(value);
            }
            WL_HASH => {
                self.hashes.insert(value);
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    fn remove(&mut self, entry_type: &str, value: &str) {
        match entry_type {
            WL_DOMAIN => {
                self.domains.remove(value);
            }
            WL_IP => {
                self.ips.remove(value);
            }
            WL_EMAIL => {
                self.emails.remove(value);
            }
            WL_HASH => {
                self.hashes.remove(value);
            }
            _ => {}
        }
    }
}

impl WhitelistManager {
    pub fn new(db: VigilDb) -> Self {
        Self {
            db,
            cache: Arc::new(RwLock::new(WhitelistCache::new())),
        }
    }

    /// From DB Load Name Memorycache
    pub async fn load(&self) -> anyhow::Result<()> {
        let entries = self.db.get_whitelist().await?;
        let mut cache = self.cache.write().await;

        cache.domains.clear();
        cache.ips.clear();
        cache.emails.clear();
        cache.hashes.clear();

        for entry in &entries {
            cache.insert(&entry.entry_type, entry.value.clone());
        }
        cache.loaded = true;

        info!(
            domains = cache.domains.len(),
            ips = cache.ips.len(),
            emails = cache.emails.len(),
            hashes = cache.hashes.len(),
            "Whitelist loaded"
        );

        Ok(())
    }

    /// Checkwhether Name Medium (Memorycache)
    pub async fn is_whitelisted(&self, entry_type: &str, value: &str) -> bool {
        let cache = self.cache.read().await;
        if !cache.loaded {
            drop(cache);
            // Loadcache, DB Query
            return self
                .db
                .is_whitelisted(entry_type, value)
                .await
                .unwrap_or(false);
        }
        cache.contains(entry_type, value)
    }

    /// CheckSenderDomainwhether
    pub async fn is_trusted_domain(&self, domain: &str) -> bool {
        self.is_whitelisted(WL_DOMAIN, &domain.to_lowercase()).await
    }

    /// Check IP whether
    pub async fn is_trusted_ip(&self, ip: &str) -> bool {
        self.is_whitelisted(WL_IP, ip).await
    }

    /// CheckSenderemailwhether
    pub async fn is_trusted_email(&self, email: &str) -> bool {
        self.is_whitelisted(WL_EMAIL, &email.to_lowercase()).await
    }

    /// CheckFileHashwhether
    pub async fn is_trusted_hash(&self, hash: &str) -> bool {
        self.is_whitelisted(WL_HASH, &hash.to_lowercase()).await
    }

    /// Add Name entry
    pub async fn add(
        &self,
        entry_type: String,
        value: String,
        description: Option<String>,
    ) -> anyhow::Result<WhitelistEntry> {
        self.add_with_creator(entry_type, value, description, "admin")
            .await
    }

    /// Add Name entry ()
    pub async fn add_with_creator(
        &self,
        entry_type: String,
        value: String,
        description: Option<String>,
        created_by: &str,
    ) -> anyhow::Result<WhitelistEntry> {
        let entry = WhitelistEntry {
            id: Uuid::new_v4(),
            entry_type: entry_type.clone(),
            value: value.clone(),
            description,
            created_at: Utc::now(),
            created_by: created_by.to_string(),
        };
        self.db.add_whitelist_entry(&entry).await?;

        // Updatecache
        let mut cache = self.cache.write().await;
        cache.insert(&entry_type, value);

        Ok(entry)
    }

    /// delete Name entry
    pub async fn remove(&self, id: Uuid) -> anyhow::Result<bool> {
        // Connectdelete, cache(Avoid table findentryType)
        let deleted = self.db.delete_whitelist_entry(id).await?;
        if deleted {
            self.load().await?;
        }
        Ok(deleted)
    }

    /// Getcomplete Name (API Return)
    pub async fn list(&self) -> anyhow::Result<Vec<WhitelistEntry>> {
        self.db.get_whitelist().await
    }

    /// BatchSet Name (All,)
    pub async fn set_all(&self, entries: Vec<WhitelistEntry>) -> anyhow::Result<()> {
        // Batch (DELETE ALL + INSERT N)
        self.db.batch_set_whitelist(&entries).await?;

        // cache
        self.load().await?;

        Ok(())
    }
}
