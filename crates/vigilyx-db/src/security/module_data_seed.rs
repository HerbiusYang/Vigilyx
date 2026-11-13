//! Compose the shared and semantic-owned datasets for every seed consumer.
//!
//! Persistence initialization and the engine's compiled fallback must see the
//! same lists. Source files have one owner; composition never overrides an
//! entry with another bundled file. Runtime DB/administrator overrides remain
//! the responsibility of the existing module-data loader.

use std::sync::LazyLock;

use serde_json::Value;

const SHARED_SEED: &str = include_str!("../../../../shared/schemas/engine_module_data_seed.json");
const SEMANTIC_SEEDS: [&str; 4] = [
    include_str!("../../../vigilyx-engine/src/semantic/data/context.json"),
    include_str!("../../../vigilyx-engine/src/semantic/data/scenarios.json"),
    include_str!("../../../vigilyx-engine/src/semantic/data/relations.json"),
    include_str!("../../../vigilyx-engine/src/semantic/data/scan.json"),
];

/// The complete compiled seed, shared by DB migration and engine bootstrap.
/// Bundled JSON is parsed once; replacements from the DB still follow the
/// engine's existing backfill and administrator-override rules.
pub fn embedded_module_data_seed() -> &'static str {
    static SEED: LazyLock<String> = LazyLock::new(|| {
        compose_seed(SHARED_SEED, &SEMANTIC_SEEDS)
            .expect("bundled module-data seeds must be valid and have unique list names")
    });
    SEED.as_str()
}

fn compose_seed(shared: &str, semantic_sources: &[&str]) -> Result<String, String> {
    let mut seed: Value = serde_json::from_str(shared)
        .map_err(|error| format!("shared module-data seed JSON is invalid: {error}"))?;
    let lists = seed
        .get_mut("lists")
        .and_then(Value::as_object_mut)
        .ok_or("shared module-data seed must contain a lists object")?;
    for source in semantic_sources {
        let semantic: Value = serde_json::from_str(source)
            .map_err(|error| format!("semantic module-data seed JSON is invalid: {error}"))?;
        let semantic_lists = semantic
            .get("lists")
            .and_then(Value::as_object)
            .ok_or("semantic module-data seed must contain a lists object")?;
        for (name, entry) in semantic_lists {
            if lists.contains_key(name) {
                return Err(format!("duplicate bundled module-data list: {name}"));
            }
            if entry.get("items").is_none() {
                return Err(format!(
                    "semantic module-data list is missing items: {name}"
                ));
            }
            lists.insert(name.clone(), entry.clone());
        }
    }
    serde_json::to_string(&seed)
        .map_err(|error| format!("composed module-data seed cannot be serialized: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_seed_includes_shared_lists_and_original_semantic_policies() {
        let seed: Value = serde_json::from_str(embedded_module_data_seed()).unwrap();
        let lists = seed["lists"].as_object().unwrap();
        assert!(lists["suspicious_tlds"]["items"].is_array());
        assert!(lists["semantic_request_markers_v1"]["items"].is_array());
        assert!(lists["semantic_extortion_policy_v2"]["items"].is_object());
        for source in SEMANTIC_SEEDS {
            let semantic: Value = serde_json::from_str(source).unwrap();
            for (name, entry) in semantic["lists"].as_object().unwrap() {
                assert_eq!(
                    lists.get(name),
                    Some(entry),
                    "lost semantic dataset: {name}"
                );
            }
        }
    }

    #[test]
    fn composition_rejects_duplicate_owners_and_malformed_sources() {
        let shared = r#"{"lists":{"existing":{"items":["original"]}}}"#;
        let duplicate = r#"{"lists":{"existing":{"items":["replacement"]}}}"#;
        assert!(
            compose_seed(shared, &[duplicate])
                .unwrap_err()
                .contains("duplicate")
        );
        let unique = r#"{"lists":{"semantic_fixture":{"items":["fixture"]}}}"#;
        assert!(
            compose_seed(shared, &[unique, unique])
                .unwrap_err()
                .contains("duplicate")
        );
        assert!(compose_seed(shared, &[r#"{"lists":[]}"#]).is_err());
        assert!(compose_seed(shared, &[r#"{"lists":{"missing_items":{}}}"#]).is_err());
        assert!(compose_seed("invalid", &[unique]).is_err());
    }
}
