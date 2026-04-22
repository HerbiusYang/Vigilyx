//! Engine module data registry — runtime-loaded from DB instead of hardcoded constants.
//!
//! This replaces all hardcoded `const &[&str]` / `LazyLock<HashSet>` data lists in detection
//! modules. Data is seeded via SQL migration (`engine_module_data_seed` config key) and can
//! be customized by admins via the `/api/security/module-data-overrides` endpoint.
//!
//! # Architecture
//!
//! ```text
//! shared/schemas/engine_module_data_seed.json
//!   → migration seeds to config table (key = "engine_module_data_seed")
//!   → engine startup: load seed + overrides → ModuleDataRegistry
//!   → modules call module_data().contains("list_name", value)
//!   → admin UI: GET/PUT /api/security/module-data-overrides
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ── Global singleton ────────────────────────────────────────────────

/// Embedded seed JSON — compiled into the binary so that `module_data()` can
/// self-initialize with sensible defaults even when the DB is unavailable
/// (e.g. in unit tests or if called before `init_module_data_from_db`).
const EMBEDDED_SEED_JSON: &str =
    include_str!("../../../shared/schemas/engine_module_data_seed.json");

static MODULE_DATA: OnceLock<Arc<RwLock<ModuleDataRegistry>>> = OnceLock::new();

/// Initialize (or replace) the global module data registry.
pub fn set_module_data(registry: ModuleDataRegistry) {
    let shared = MODULE_DATA.get_or_init(|| Arc::new(RwLock::new(ModuleDataRegistry::default())));
    *shared.write().expect("module data lock poisoned") = registry;
}

/// Access the global module data registry (read lock).
///
/// If `set_module_data` was never called, the registry is lazily initialized
/// from the embedded seed JSON (no DB overrides). This keeps unit tests and
/// early call sites working without an explicit init step.
pub fn module_data() -> std::sync::RwLockReadGuard<'static, ModuleDataRegistry> {
    MODULE_DATA
        .get_or_init(|| {
            let registry = ModuleDataRegistry::from_seed_and_overrides(
                EMBEDDED_SEED_JSON,
                &ModuleDataOverrides::default(),
            )
            .unwrap_or_else(|e| {
                warn!("Failed to parse embedded seed JSON: {e} — using empty registry");
                ModuleDataRegistry::default()
            });
            Arc::new(RwLock::new(registry))
        })
        .read()
        .expect("module data lock poisoned")
}

// ── Registry ────────────────────────────────────────────────────────

/// In-memory registry of all configurable module data lists.
///
/// Populated from `engine_module_data_seed` (config table) merged with
/// `engine_module_data_overrides` (admin customizations).
#[derive(Debug, Clone, Default)]
pub struct ModuleDataRegistry {
    /// Fast set lookups (lowercase): `contains("suspicious_tlds", "tk")`.
    sets: HashMap<String, HashSet<String>>,
    /// Ordered lists (original case): iteration order preserved from seed.
    lists: HashMap<String, Vec<String>>,
    /// Structured / complex data (brand mappings, etc.) — accessed via JSON Value.
    structured: HashMap<String, serde_json::Value>,
}

impl ModuleDataRegistry {
    /// Build from seed JSON and optional user overrides.
    pub fn from_seed_and_overrides(
        seed_json: &str,
        overrides: &ModuleDataOverrides,
    ) -> Result<Self, String> {
        let seed: serde_json::Value =
            serde_json::from_str(seed_json).map_err(|e| format!("seed JSON parse: {e}"))?;

        let lists_obj = seed
            .get("lists")
            .and_then(|v| v.as_object())
            .ok_or("seed JSON missing 'lists' object")?;

        let mut registry = Self::default();

        for (key, value) in lists_obj {
            let items = match value.get("items") {
                Some(v) => v,
                None => {
                    warn!(list = %key, "seed list missing 'items' — skipping");
                    continue;
                }
            };

            // Determine if items is a simple string array or structured data
            if let Some(arr) = items.as_array() {
                let is_simple_strings = arr.first().map(|v| v.is_string()).unwrap_or(true); // empty arrays are fine

                if is_simple_strings {
                    // Simple string list → build both Vec and HashSet
                    let mut list: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    let mut set: HashSet<String> = list.iter().map(|s| s.to_lowercase()).collect();

                    // Apply user overrides (add/remove)
                    if let Some(ovr) = overrides.overrides.get(key) {
                        for added in &ovr.added {
                            if !set.contains(&added.to_lowercase()) {
                                set.insert(added.to_lowercase());
                                list.push(added.clone());
                            }
                        }
                        for removed in &ovr.removed {
                            set.remove(&removed.to_lowercase());
                            list.retain(|s| s.to_lowercase() != removed.to_lowercase());
                        }
                    }

                    registry.sets.insert(key.clone(), set);
                    registry.lists.insert(key.clone(), list);
                } else {
                    // Structured data (objects/arrays of objects) — store as-is
                    // Overrides for structured data are applied at the JSON level
                    registry.structured.insert(key.clone(), items.clone());
                }
            } else {
                // Non-array items (e.g., object maps) — store as structured
                registry.structured.insert(key.clone(), items.clone());
            }
        }

        info!(
            sets = registry.sets.len(),
            structured = registry.structured.len(),
            overrides_applied = overrides.overrides.len(),
            "Module data registry built from seed"
        );

        Ok(registry)
    }

    // ── Accessors ───────────────────────────────────────────────────

    /// Check if a value exists in a named set (case-insensitive).
    #[inline]
    pub fn contains(&self, list_name: &str, value: &str) -> bool {
        self.sets
            .get(list_name)
            .map(|set| set.contains(&value.to_lowercase()))
            .unwrap_or(false)
    }

    /// Get a list by name (original case, ordered).
    pub fn get_list(&self, list_name: &str) -> &[String] {
        self.lists
            .get(list_name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get a set reference by name (lowercase keys).
    pub fn get_set(&self, list_name: &str) -> Option<&HashSet<String>> {
        self.sets.get(list_name)
    }

    /// Get structured data by name.
    pub fn get_structured(&self, list_name: &str) -> Option<&serde_json::Value> {
        self.structured.get(list_name)
    }

    /// Get an iterator over all list names.
    pub fn list_names(&self) -> impl Iterator<Item = &String> {
        self.sets.keys().chain(self.structured.keys())
    }

    /// Total number of registered lists (sets + structured).
    pub fn len(&self) -> usize {
        self.sets.len() + self.structured.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.structured.is_empty()
    }

    /// Serialize the effective (merged) data back to JSON for the API response.
    pub fn to_effective_json(&self) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (key, list) in &self.lists {
            map.insert(key.clone(), serde_json::json!(list));
        }
        for (key, val) in &self.structured {
            map.insert(key.clone(), val.clone());
        }
        serde_json::Value::Object(map)
    }
}

// ── Overrides ───────────────────────────────────────────────────────

/// Per-list add/remove overrides (admin customizations stored in config table).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModuleDataOverrides {
    #[serde(default)]
    pub overrides: HashMap<String, ListOverride>,
}

/// Add/remove entries for a single list.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ListOverride {
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}

// ── DB helpers (called from registry.rs / engine binary) ────────────

fn merge_seed_json(compiled_seed_json: &str, db_seed_json: &str) -> String {
    let Ok(compiled_seed) = serde_json::from_str::<serde_json::Value>(compiled_seed_json) else {
        return db_seed_json.to_string();
    };
    let Ok(mut merged_seed) = serde_json::from_str::<serde_json::Value>(db_seed_json) else {
        return compiled_seed_json.to_string();
    };

    let Some(compiled_lists) = compiled_seed
        .get("lists")
        .and_then(|value| value.as_object())
    else {
        return db_seed_json.to_string();
    };
    let Some(merged_lists) = merged_seed
        .get_mut("lists")
        .and_then(|value| value.as_object_mut())
    else {
        return compiled_seed_json.to_string();
    };

    for (list_name, compiled_entry) in compiled_lists {
        let Some(compiled_items) = compiled_entry
            .get("items")
            .and_then(|value| value.as_array())
        else {
            merged_lists
                .entry(list_name.clone())
                .or_insert_with(|| compiled_entry.clone());
            continue;
        };

        let Some(merged_entry) = merged_lists.get_mut(list_name) else {
            merged_lists.insert(list_name.clone(), compiled_entry.clone());
            continue;
        };

        let Some(merged_items) = merged_entry
            .get_mut("items")
            .and_then(|value| value.as_array_mut())
        else {
            continue;
        };

        let simple_compiled = compiled_items.iter().all(serde_json::Value::is_string);
        let simple_merged = merged_items.iter().all(serde_json::Value::is_string);
        if !simple_compiled || !simple_merged {
            continue;
        }

        let mut existing: HashSet<String> = merged_items
            .iter()
            .filter_map(|value| value.as_str())
            .map(|value| value.to_lowercase())
            .collect();
        for compiled_item in compiled_items.iter().filter_map(|value| value.as_str()) {
            if existing.insert(compiled_item.to_lowercase()) {
                merged_items.push(serde_json::Value::String(compiled_item.to_string()));
            }
        }
    }

    serde_json::to_string(&merged_seed).unwrap_or_else(|_| db_seed_json.to_string())
}

/// Load module data seed JSON from config table.
pub async fn load_module_data_seed(db: &vigilyx_db::VigilDb) -> String {
    match db.get_config("engine_module_data_seed").await {
        Ok(Some(json)) => merge_seed_json(EMBEDDED_SEED_JSON, &json),
        Ok(None) => {
            warn!("engine_module_data_seed not found in config table — using compiled fallback");
            include_str!("../../../shared/schemas/engine_module_data_seed.json").to_string()
        }
        Err(e) => {
            warn!("Failed to load engine_module_data_seed: {e} — using compiled fallback");
            include_str!("../../../shared/schemas/engine_module_data_seed.json").to_string()
        }
    }
}

/// Load module data overrides from config table.
pub async fn load_module_data_overrides(db: &vigilyx_db::VigilDb) -> ModuleDataOverrides {
    match db.get_config("engine_module_data_overrides").await {
        Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_else(|e| {
            warn!("engine_module_data_overrides parse failed: {e} — using empty overrides");
            ModuleDataOverrides::default()
        }),
        _ => ModuleDataOverrides::default(),
    }
}

/// Build and install the global module data registry from DB.
pub async fn init_module_data_from_db(db: &vigilyx_db::VigilDb) {
    let seed_json = load_module_data_seed(db).await;
    let overrides = load_module_data_overrides(db).await;

    match ModuleDataRegistry::from_seed_and_overrides(&seed_json, &overrides) {
        Ok(registry) => {
            info!(
                lists = registry.len(),
                "Module data registry initialized from DB"
            );
            set_module_data(registry);
        }
        Err(e) => {
            warn!("Failed to build module data registry: {e} — modules will use empty data");
            set_module_data(ModuleDataRegistry::default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_seed_json_backfills_new_compiled_string_items() {
        let compiled = r#"{
            "lists": {
                "suspicious_tlds": {
                    "items": ["xyz", "lol", "top"]
                }
            }
        }"#;
        let db = r#"{
            "lists": {
                "suspicious_tlds": {
                    "items": ["xyz"]
                }
            }
        }"#;

        let merged = merge_seed_json(compiled, db);
        let merged_json: serde_json::Value = serde_json::from_str(&merged).unwrap();
        let items = merged_json["lists"]["suspicious_tlds"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();

        assert_eq!(items, vec!["xyz", "lol", "top"]);
    }

    #[test]
    fn test_build_from_seed() {
        let seed = r#"{
            "version": 1,
            "lists": {
                "suspicious_tlds": {
                    "description": "test",
                    "category": "test",
                    "items": ["tk", "ml", "GA"]
                },
                "brand_data": {
                    "description": "test",
                    "category": "test",
                    "items": [{"brand": "Google", "domains": ["google.com"]}]
                }
            }
        }"#;

        let overrides = ModuleDataOverrides {
            overrides: {
                let mut m = HashMap::new();
                m.insert(
                    "suspicious_tlds".to_string(),
                    ListOverride {
                        added: vec!["xyz".to_string()],
                        removed: vec!["ml".to_string()],
                    },
                );
                m
            },
        };

        let registry = ModuleDataRegistry::from_seed_and_overrides(seed, &overrides).unwrap();

        // Set lookups are case-insensitive
        assert!(registry.contains("suspicious_tlds", "tk"));
        assert!(registry.contains("suspicious_tlds", "TK"));
        assert!(registry.contains("suspicious_tlds", "ga"));
        assert!(registry.contains("suspicious_tlds", "xyz")); // added
        assert!(!registry.contains("suspicious_tlds", "ml")); // removed

        // Structured data preserved
        assert!(registry.get_structured("brand_data").is_some());

        // Non-existent list
        assert!(!registry.contains("nonexistent", "foo"));
        assert!(registry.get_list("nonexistent").is_empty());
    }
}
