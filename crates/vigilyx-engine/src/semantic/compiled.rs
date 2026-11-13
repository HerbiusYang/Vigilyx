//! Derived semantic data bound to one immutable module-data snapshot.
//!
//! Registry identity, rather than a separately loaded epoch, binds the cache:
//! a concurrent reload cannot pair an old registry with a new epoch. Existing
//! analyses retain their snapshot; subsequent analyses acquire the replacement.

use std::any::{Any, TypeId};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::{Arc, OnceLock, RwLock};

use crate::module_data::{ModuleDataRegistry, module_data};
use crate::modules::content_scan::normalize_text;
use aho_corasick::AhoCorasick;

type CompiledValue = Arc<dyn Any + Send + Sync>;
type CompiledSlot = Arc<OnceLock<CompiledValue>>;

pub(super) struct CompiledSemanticData {
    registry: Arc<ModuleDataRegistry>,
    values: RwLock<HashMap<(TypeId, &'static str), CompiledSlot>>,
}

impl CompiledSemanticData {
    pub(super) fn new(registry: Arc<ModuleDataRegistry>) -> Self {
        Self {
            registry,
            values: RwLock::new(HashMap::new()),
        }
    }

    /// Cache successful values and explicit missing/invalid policy results.
    /// Compilation runs without holding the map lock; each slot initializes
    /// once even when several analyses first request it concurrently.
    pub(super) fn cached<T, F>(&self, key: &'static str, compile: F) -> Arc<T>
    where
        T: Any + Send + Sync,
        F: FnOnce(&ModuleDataRegistry) -> T,
    {
        let cache_key = (TypeId::of::<T>(), key);
        let existing = self
            .values
            .read()
            .expect("semantic compiled-data lock poisoned")
            .get(&cache_key)
            .cloned();
        let slot = existing.unwrap_or_else(|| {
            self.values
                .write()
                .expect("semantic compiled-data lock poisoned")
                .entry(cache_key)
                .or_insert_with(|| Arc::new(OnceLock::new()))
                .clone()
        });
        Arc::clone(slot.get_or_init(|| Arc::new(compile(&self.registry))))
            .downcast::<T>()
            .expect("semantic compiled-data key includes the value type")
    }

    pub(super) fn markers(&self, list: &'static str) -> Arc<CompiledMarkerList> {
        self.cached(list, |registry| {
            if list == "semantic_object_markers_v1" {
                CompiledMarkerList::new(&object_lexicon(registry))
            } else {
                CompiledMarkerList::new(registry.get_list(list))
            }
        })
    }

    pub(super) fn primary_object(&self, objects: &[String]) -> Option<String> {
        let heads = self.cached("semantic_primary_object_heads_v1", |registry| {
            object_lexicon_with_intent(registry, false)
                .into_iter()
                .map(|s| normalize_text(&s.to_lowercase()))
                .collect::<HashSet<_>>()
        });
        // New compound concepts remain available in `objects`. They must
        // not replace an established primary head used by existing callers.
        objects
            .iter()
            .find(|object| heads.contains(*object))
            .or_else(|| objects.first())
            .cloned()
    }
}

/// The lexical layer must retain the noun arguments consumed by an enabled
/// workflow. Otherwise a valid clause such as “SMS code into this form” is
/// discarded before the relation parser can bind it. Derive these concepts
/// from the same immutable policy snapshot; they remain observations and do
/// not acquire a score or a recipient role by being matched.
fn object_lexicon(registry: &ModuleDataRegistry) -> Vec<String> {
    object_lexicon_with_intent(registry, true)
}

fn object_lexicon_with_intent(registry: &ModuleDataRegistry, include_intent: bool) -> Vec<String> {
    let mut result = registry.get_list("semantic_object_markers_v1").to_vec();
    let mut seen = result
        .iter()
        .map(|s| normalize_text(&s.to_lowercase()))
        .collect::<HashSet<_>>();
    if let Some(policy) = registry.get_structured("semantic_workflow_policy_v1")
        && policy.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)
    {
        for (group, fields) in [
            (
                "inheritance",
                &["asset_terms", "kinship_terms", "third_party_terms"][..],
            ),
            (
                "financial_pin",
                &[
                    "pin_terms",
                    "generic_pin_terms",
                    "identity_terms",
                    "otp_terms",
                    "form_terms",
                ][..],
            ),
        ] {
            for field in fields {
                if let Some(terms) = policy
                    .get(group)
                    .and_then(|g| g.get(*field))
                    .and_then(serde_json::Value::as_array)
                {
                    append_lexical_terms(&mut result, &mut seen, terms, 96);
                }
            }
        }
    }
    for policy_key in [
        "semantic_combination_risk_policy_v1",
        "semantic_phishing_intent_policy_v1",
        "semantic_economic_intent_risk_policy_v1",
        "semantic_coercive_intent_policy_v1",
    ] {
        if !include_intent && policy_key != "semantic_combination_risk_policy_v1" {
            continue;
        }
        if let Some(policy) = registry.get_structured(policy_key)
            && policy.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)
            && let Some(terms) = policy
                .get("lexical_objects")
                .and_then(serde_json::Value::as_array)
        {
            append_lexical_terms(&mut result, &mut seen, terms, 256);
        }
    }
    result
}

fn append_lexical_terms(
    result: &mut Vec<String>,
    seen: &mut HashSet<String>,
    terms: &[serde_json::Value],
    limit: usize,
) {
    // Malformed scoring policies are diagnosed by their consumers. They
    // cannot install an unbounded lexical cache before that diagnosis.
    if terms.len() > limit {
        return;
    }
    for value in terms {
        let Some(term) = value
            .as_str()
            .filter(|s| !s.trim().is_empty() && s.len() <= 128)
        else {
            continue;
        };
        let normalized = normalize_text(&term.to_lowercase());
        if normalized.trim().is_empty() {
            continue;
        }
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }
}

impl Deref for CompiledSemanticData {
    type Target = ModuleDataRegistry;

    fn deref(&self) -> &Self::Target {
        &self.registry
    }
}

pub(super) struct CompiledMarker {
    pub(super) normalized: String,
    pub(super) lowercase: String,
    pub(super) plural_lowercase: Option<String>,
}

pub(super) struct CompiledMarkerList {
    /// Registry order is retained for prefix and structural matching.
    pub(super) entries: Vec<CompiledMarker>,
    /// Stable longest-first order preserves the extractor's existing priority.
    pub(super) longest_first: Vec<usize>,
    automaton: Option<AhoCorasick>,
    forms: Vec<(usize, bool, String)>,
}

impl CompiledMarkerList {
    fn new(markers: &[String]) -> Self {
        let entries = markers
            .iter()
            .map(|marker| {
                let normalized = normalize_text(&marker.to_lowercase());
                CompiledMarker {
                    lowercase: normalized.to_lowercase(),
                    plural_lowercase: normalized
                        .is_ascii()
                        .then(|| format!("{normalized}s").to_lowercase()),
                    normalized,
                }
            })
            .collect::<Vec<_>>();
        let mut longest_first = (0..entries.len()).collect::<Vec<_>>();
        longest_first.sort_by_key(|index| Reverse(entries[*index].normalized.chars().count()));
        let mut forms = Vec::new();
        for (index, marker) in entries.iter().enumerate() {
            if !marker.lowercase.is_empty() {
                forms.push((index, false, marker.lowercase.clone()));
            }
            if let Some(plural) = &marker.plural_lowercase
                && !plural.is_empty()
            {
                forms.push((index, true, plural.clone()));
            }
        }
        let automaton = if forms.is_empty() {
            None
        } else {
            AhoCorasick::new(forms.iter().map(|(_, _, form)| form.as_str())).ok()
        };
        Self {
            entries,
            longest_first,
            automaton,
            forms,
        }
    }

    /// Preserve per-form `str::match_indices` non-overlap semantics while
    /// discovering all different marker forms with one automaton pass.
    pub(super) fn occurrences(
        &self,
        text: &str,
        allow_plural: bool,
    ) -> Vec<(usize, usize, usize, bool)> {
        let mut matches = Vec::new();
        if let Some(automaton) = &self.automaton {
            let mut last_end = vec![0; self.forms.len()];
            for found in automaton.find_overlapping_iter(text) {
                let pattern = found.pattern().as_usize();
                let (entry, plural, _) = &self.forms[pattern];
                if (*plural && !allow_plural) || found.start() < last_end[pattern] {
                    continue;
                }
                last_end[pattern] = found.end();
                matches.push((*entry, found.start(), found.end(), *plural));
            }
        } else {
            // Oversized administrator dictionaries may fail construction;
            // retain the original matcher rather than silently losing terms.
            for (entry, plural, form) in &self.forms {
                if *plural && !allow_plural {
                    continue;
                }
                matches.extend(
                    text.match_indices(form.as_str())
                        .map(|(start, _)| (*entry, start, start + form.len(), *plural)),
                );
            }
        }
        matches
    }
}

static COMPILED_DATA: OnceLock<RwLock<Option<Arc<CompiledSemanticData>>>> = OnceLock::new();

pub(super) fn compiled_semantic_data() -> Arc<CompiledSemanticData> {
    let registry = module_data();
    let shared = COMPILED_DATA.get_or_init(|| RwLock::new(None));
    {
        let cached = shared.read().expect("semantic snapshot lock poisoned");
        if let Some(cached) = cached.as_ref()
            && Arc::ptr_eq(&cached.registry, &registry)
        {
            return Arc::clone(cached);
        }
    }
    let mut cached = shared.write().expect("semantic snapshot lock poisoned");
    // Refresh after waiting for the cache lock so a delayed acquisition cannot
    // replace a newer cached registry with the snapshot it read before waiting.
    let registry = module_data();
    if let Some(cached) = cached.as_ref()
        && Arc::ptr_eq(&cached.registry, &registry)
    {
        return Arc::clone(cached);
    }
    let replacement = Arc::new(CompiledSemanticData::new(registry));
    *cached = Some(Arc::clone(&replacement));
    replacement
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_data::ModuleDataOverrides;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn automaton_keeps_each_forms_original_nonoverlap_behavior() {
        let list =
            CompiledMarkerList::new(&["哈哈".into(), "哈哈哈".into(), "aaa".into(), "aaaa".into()]);
        let text = "哈哈哈哈aaaaaa";
        let mut actual = list.occurrences(text, false);
        actual.sort_unstable();
        let mut expected = Vec::new();
        for (index, marker) in list.entries.iter().enumerate() {
            expected.extend(
                text.match_indices(marker.lowercase.as_str())
                    .map(|(start, _)| (index, start, start + marker.lowercase.len(), false)),
            );
        }
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }

    fn registry(seed: &str) -> Arc<ModuleDataRegistry> {
        Arc::new(
            ModuleDataRegistry::from_seed_and_overrides(seed, &ModuleDataOverrides::default())
                .unwrap(),
        )
    }

    #[test]
    fn policy_failure_is_cached_without_hiding_a_replacement_snapshot() {
        let previous = CompiledSemanticData::new(registry(r#"{"lists":{}}"#));
        let compilations = AtomicUsize::new(0);
        let read = || {
            previous.cached("synthetic_policy", |data| {
                compilations.fetch_add(1, Ordering::Relaxed);
                data.get_structured("synthetic_policy").cloned()
            })
        };
        assert!(read().is_none());
        assert!(read().is_none());
        assert_eq!(compilations.load(Ordering::Relaxed), 1);

        let replacement = CompiledSemanticData::new(registry(
            r#"{"lists":{"synthetic_policy":{"items":{"enabled":true}}}}"#,
        ));
        let policy = replacement.cached("synthetic_policy", |data| {
            data.get_structured("synthetic_policy").cloned()
        });
        assert_eq!(policy.as_ref().as_ref().unwrap()["enabled"], true);
        assert!(
            read().is_none(),
            "an in-flight snapshot must stay immutable"
        );
    }

    #[test]
    fn concurrent_policy_requests_compile_once() {
        let data = Arc::new(CompiledSemanticData::new(registry(r#"{"lists":{}}"#)));
        let compilations = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let data = Arc::clone(&data);
                let compilations = &compilations;
                scope.spawn(move || {
                    let value = data.cached("synthetic_policy", |_| {
                        compilations.fetch_add(1, Ordering::Relaxed);
                        42_u32
                    });
                    assert_eq!(*value, 42);
                });
            }
        });
        assert_eq!(compilations.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn workflow_arguments_survive_the_shared_lexical_layer_without_scoring_them() {
        let enabled = CompiledSemanticData::new(registry(
            r#"{"lists":{
            "semantic_object_markers_v1":{"items":["ssn"]},
            "semantic_workflow_policy_v1":{"items":{"enabled":true,"financial_pin":{
                "form_terms":["form"],"otp_terms":["SMS code"]}}}
        }}"#,
        ));
        let markers = enabled.markers("semantic_object_markers_v1");
        let text = "your sms code into this form";
        let found = markers
            .occurrences(text, false)
            .into_iter()
            .map(|(i, start, end, _)| (markers.entries[i].normalized.as_str(), &text[start..end]))
            .collect::<Vec<_>>();
        assert!(found.contains(&("sms code", "sms code")));
        assert!(found.contains(&("form", "form")));
        assert_eq!(enabled.get_list("semantic_object_markers_v1"), &["ssn"]);

        let disabled = CompiledSemanticData::new(registry(
            r#"{"lists":{
            "semantic_object_markers_v1":{"items":["ssn"]},
            "semantic_workflow_policy_v1":{"items":{"enabled":false,"financial_pin":{"form_terms":["form"]}}}
        }}"#,
        ));
        assert!(
            disabled
                .markers("semantic_object_markers_v1")
                .occurrences(text, false)
                .is_empty()
        );
        assert!(
            markers.occurrences(text, false).len() >= 2,
            "old snapshots retain their lexical bindings"
        );
    }

    #[test]
    fn combination_risk_lexicon_is_independent_and_bounded() {
        let data = CompiledSemanticData::new(registry(
            r#"{"lists":{
            "semantic_object_markers_v1":{"items":["account"]},
            "semantic_workflow_policy_v1":{"items":{"enabled":false}},
            "semantic_combination_risk_policy_v1":{"items":{"enabled":true,"lexical_objects":["CVV2","account"]}}
        }}"#,
        ));
        let markers = data.markers("semantic_object_markers_v1");
        assert_eq!(
            markers
                .entries
                .iter()
                .filter(|m| m.normalized == "account")
                .count(),
            1
        );
        assert!(!markers.occurrences("cvv2", false).is_empty());
        assert_eq!(data.get_list("semantic_object_markers_v1"), &["account"]);
        let mut values = Vec::new();
        let mut seen = HashSet::new();
        append_lexical_terms(
            &mut values,
            &mut seen,
            &vec![serde_json::json!("cvv"); 257],
            256,
        );
        assert!(values.is_empty());
        append_lexical_terms(
            &mut values,
            &mut seen,
            &[serde_json::json!("\u{200b}"), serde_json::json!("cvv")],
            256,
        );
        assert_eq!(values, ["cvv"]);
    }
}
