//! High-throughput multi-pattern substring matcher.
//!
//! ## Why this exists
//!
//! Several detection modules (`prompt_injection_scan`, `aitm_detect`,
//! `content_scan::detectors`) historically scanned email bodies with
//! `phrases.iter().any(|p| haystack.contains(p))`. With the multilingual
//! seed expansion (≈5300 phrases across 77 lists, some single lists holding
//! 100+ phrases), this naive O(haystack × patterns × pattern_len) loop became
//! the dominant CPU cost on the security pipeline hot path — well over a
//! million byte comparisons per email for a single module.
//!
//! [`PhraseMatcher`] wraps an [`aho_corasick::AhoCorasick`] automaton built
//! once per phrase list and held in a process-wide [`OnceLock`]. Matching
//! becomes O(haystack + matches) and runs on raw bytes, so we can also
//! eliminate the `body.to_lowercase()` allocation that previously preceded
//! every scan.
//!
//! ## Hot reload
//!
//! Admins can mutate phrase lists at runtime via the
//! `/api/security/module-data-overrides` endpoint, which calls
//! [`crate::module_data::set_module_data`] and bumps
//! [`crate::module_data::module_data_epoch`]. Each cached matcher remembers
//! the epoch it was built against and rebuilds itself on the next access if
//! the registry has been swapped. The check is a single `Acquire` load of an
//! `AtomicU64` — cheap enough to put in front of every scan.
//!
//! ## API shape
//!
//! Modules call free functions like [`scan_prompt_strong`] /
//! [`scan_mfa_bait_all_locales`] that return a small set of accessors:
//!
//! * [`MatchScan::is_match`] — fastest path, returns on first hit.
//! * [`MatchScan::first_pattern`] — returns the matched phrase string, useful
//!   for evidence/logging.
//! * [`MatchScan::distinct_patterns`] — set of distinct phrase indices that
//!   matched (deduped across overlapping hits in the same haystack).
//! * [`MatchScan::distinct_count`] — `distinct_patterns().len()`, but skips
//!   the allocation when the caller only needs the cardinality.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, AhoCorasickKind, MatchKind};

use crate::module_data::{module_data, module_data_epoch};

// ---------------------------------------------------------------------------
// Cache primitive
// ---------------------------------------------------------------------------

/// A lazily compiled, hot-reload-aware Aho-Corasick automaton over a fixed
/// set of phrase lists from the module data registry.
///
/// `PhraseMatcher` is cheap to *call*, expensive to *build* (≈1 ms / 100
/// patterns). We therefore cache one instance per scan site behind an
/// [`OnceLock`] (see the free functions in this module). The cache is
/// invalidated transparently whenever
/// [`module_data::set_module_data`](crate::module_data::set_module_data)
/// bumps the epoch.
pub struct PhraseMatcher {
    /// Sources of phrases (registry list names). Combined into one automaton
    /// so callers can scan multiple language variants in a single pass.
    list_names: Vec<&'static str>,
    /// Epoch-versioned inner state. We swap the whole `Inner` atomically by
    /// rebuilding inside the `Mutex` when the epoch advances.
    inner: Mutex<Inner>,
    /// Last epoch the inner state was built against. Read with `Acquire`,
    /// written with `Release`.
    built_epoch: AtomicU64,
}

struct Inner {
    /// `None` only if every requested list was empty (e.g. registry never
    /// initialized in unit tests). Callers handle the empty case as "no
    /// match".
    automaton: Option<AhoCorasick>,
    /// Original-case patterns aligned with automaton pattern IDs. Indexed by
    /// `mat.pattern().as_usize()`.
    patterns: Vec<String>,
}

impl PhraseMatcher {
    /// Builder used by the `static_matcher` helper.
    fn with_lists(list_names: Vec<&'static str>) -> Self {
        Self {
            list_names,
            inner: Mutex::new(Inner {
                automaton: None,
                patterns: Vec::new(),
            }),
            built_epoch: AtomicU64::new(u64::MAX), // sentinel: never built
        }
    }

    /// Scan a haystack and return a [`MatchScan`] that lazily exposes the
    /// match results. The automaton is rebuilt if the registry epoch has
    /// advanced since the last call.
    ///
    /// `haystack` is borrowed for the duration of the scan; no allocation
    /// happens unless the caller invokes [`MatchScan::first_pattern`] or
    /// [`MatchScan::distinct_patterns`].
    pub fn scan<'h>(&self, haystack: &'h str) -> MatchScan<'_, 'h> {
        self.ensure_built();
        MatchScan {
            owner: self,
            haystack,
        }
    }

    /// Convenience: returns `true` if any phrase appears in `haystack`.
    /// Stops at the first hit.
    #[inline]
    pub fn is_match(&self, haystack: &str) -> bool {
        self.scan(haystack).is_match()
    }

    /// Force a rebuild if the cached automaton is stale (or missing).
    fn ensure_built(&self) {
        let current = module_data_epoch();
        // Fast path: epoch matches and automaton already built.
        if self.built_epoch.load(Ordering::Acquire) == current {
            return;
        }
        // Slow path: rebuild under the mutex. Re-check inside the lock to
        // avoid duplicate rebuilds when multiple threads race.
        let mut guard = self.inner.lock().expect("PhraseMatcher mutex poisoned");
        if self.built_epoch.load(Ordering::Acquire) == current {
            return;
        }

        let registry = module_data();
        let mut patterns: Vec<String> = Vec::new();
        for list_name in &self.list_names {
            for phrase in registry.get_list(list_name) {
                if !phrase.is_empty() {
                    patterns.push(phrase.clone());
                }
            }
        }
        drop(registry);

        // Dedup so that overlapping language seeds (e.g. the same English
        // phrase in `_en` and `_all`) don't inflate match counts.
        patterns.sort();
        patterns.dedup();

        let automaton = if patterns.is_empty() {
            None
        } else {
            // `LeftmostFirst` keeps a deterministic match order matching the
            // `phrases.iter().any(...)` semantics that callers replaced.
            // `ascii_case_insensitive(true)` lets callers pass raw bodies
            // without `to_lowercase()` — phrases in the seed are already
            // lowercase ASCII for the languages we care about, and CJK is
            // case-invariant anyway.
            let built = AhoCorasickBuilder::new()
                .ascii_case_insensitive(true)
                .match_kind(MatchKind::LeftmostFirst)
                .kind(Some(AhoCorasickKind::DFA))
                .build(&patterns)
                .expect("aho-corasick build (patterns are non-empty UTF-8 strings)");
            Some(built)
        };

        guard.automaton = automaton;
        guard.patterns = patterns;
        self.built_epoch.store(current, Ordering::Release);
    }
}

/// A pending match scan over a borrowed haystack. Cheap to construct; results
/// are computed on demand by the accessor methods.
pub struct MatchScan<'m, 'h> {
    owner: &'m PhraseMatcher,
    haystack: &'h str,
}

impl<'m, 'h> MatchScan<'m, 'h> {
    /// `true` if any phrase appears in the haystack.
    pub fn is_match(&self) -> bool {
        let guard = self
            .owner
            .inner
            .lock()
            .expect("PhraseMatcher mutex poisoned");
        let Some(ac) = guard.automaton.as_ref() else {
            return false;
        };
        ac.is_match(self.haystack.as_bytes())
    }

    /// Returns the first matching phrase (original case as stored in the
    /// registry), or `None` if no phrase matches.
    pub fn first_pattern(&self) -> Option<String> {
        let guard = self
            .owner
            .inner
            .lock()
            .expect("PhraseMatcher mutex poisoned");
        let ac = guard.automaton.as_ref()?;
        let mat = ac.find(self.haystack.as_bytes())?;
        guard.patterns.get(mat.pattern().as_usize()).cloned()
    }

    /// Returns the set of distinct matching phrases (original case). The
    /// vector is deduplicated even if the haystack contains the same phrase
    /// many times.
    pub fn distinct_patterns(&self) -> Vec<String> {
        let guard = self
            .owner
            .inner
            .lock()
            .expect("PhraseMatcher mutex poisoned");
        let Some(ac) = guard.automaton.as_ref() else {
            return Vec::new();
        };
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for mat in ac.find_iter(self.haystack.as_bytes()) {
            let idx = mat.pattern().as_usize();
            if seen.insert(idx)
                && let Some(phrase) = guard.patterns.get(idx)
            {
                out.push(phrase.clone());
            }
        }
        out
    }

    /// Same as `distinct_patterns().len()` but skips allocating the
    /// `Vec<String>` when the caller only needs the cardinality.
    pub fn distinct_count(&self) -> usize {
        let guard = self
            .owner
            .inner
            .lock()
            .expect("PhraseMatcher mutex poisoned");
        let Some(ac) = guard.automaton.as_ref() else {
            return 0;
        };
        let mut seen = std::collections::HashSet::new();
        for mat in ac.find_iter(self.haystack.as_bytes()) {
            seen.insert(mat.pattern().as_usize());
        }
        seen.len()
    }
}

// ---------------------------------------------------------------------------
// Module-scoped accessors (one OnceLock per scan site)
// ---------------------------------------------------------------------------

/// Internal helper: lazily build (and re-use) a [`PhraseMatcher`] keyed by
/// the requested list-name set.
fn static_matcher(
    slot: &'static OnceLock<PhraseMatcher>,
    lists: &'static [&'static str],
) -> &'static PhraseMatcher {
    slot.get_or_init(|| PhraseMatcher::with_lists(lists.to_vec()))
}

// ── Prompt injection ───────────────────────────────────────────────────────

/// Strong override patterns ("ignore previous instructions" etc.).
pub fn prompt_strong() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["prompt_injection_strong_patterns"];
    static_matcher(&SLOT, LISTS)
}

/// Role-reset / persona-hijack patterns ("you are now", "act as a", "DAN mode").
pub fn prompt_role_reset() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["prompt_injection_role_reset_patterns"];
    static_matcher(&SLOT, LISTS)
}

/// Weak / output-shaping patterns ("respond only with", "<|im_start|>", ...).
pub fn prompt_weak() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["prompt_injection_weak_patterns"];
    static_matcher(&SLOT, LISTS)
}

// ── AitM detection ────────────────────────────────────────────────────────

/// Union of every locale-specific MFA bait phrase list, so a single scan
/// covers EN/ZH/JA/KO/RU/ES/PT/FR/DE/AR in one pass.
pub fn mfa_bait_all_locales() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &[
        "mfa_bait_phrases_en",
        "mfa_bait_phrases_zh",
        "mfa_bait_phrases_ja",
        "mfa_bait_phrases_ko",
        "mfa_bait_phrases_ru",
        "mfa_bait_phrases_es",
        "mfa_bait_phrases_pt",
        "mfa_bait_phrases_fr",
        "mfa_bait_phrases_de",
        "mfa_bait_phrases_ar",
    ];
    static_matcher(&SLOT, LISTS)
}

/// Urgency phrases that amplify MFA-bait signals.
pub fn aitm_urgency() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["aitm_urgency_phrases"];
    static_matcher(&SLOT, LISTS)
}

/// Path patterns indicative of AitM / phishing toolkits (`/login`, `/auth/`,
/// `/o365/`, ...). Used against URL paths.
pub fn aitm_toolkit_paths() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["aitm_toolkit_path_patterns"];
    static_matcher(&SLOT, LISTS)
}

/// CAPTCHA / challenge indicators (Cloudflare Turnstile, hCaptcha, ...).
pub fn captcha_indicators() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["captcha_indicators"];
    static_matcher(&SLOT, LISTS)
}

// ── Content scan ──────────────────────────────────────────────────────────

/// Account-security threat phrases ("your account has been compromised", ...).
pub fn account_security_threats() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["account_security_threat_phrases_body"];
    static_matcher(&SLOT, LISTS)
}

/// Account-security action phrases ("verify now", "click here to confirm", ...).
pub fn account_security_actions() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["account_security_action_phrases_body"];
    static_matcher(&SLOT, LISTS)
}

/// Subject-line threat keywords (used as a body-less fallback).
pub fn subject_threat_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["subject_threat_keywords"];
    static_matcher(&SLOT, LISTS)
}

/// Subsidy / tax fraud benefit keywords (body variant).
pub fn subsidy_keywords_body() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["subsidy_keywords_body"];
    static_matcher(&SLOT, LISTS)
}

/// Subsidy / tax fraud urgency phrases (body variant).
pub fn subsidy_urgency_body() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["subsidy_urgency_keywords_body"];
    static_matcher(&SLOT, LISTS)
}

/// Subsidy / tax fraud benefit keywords (subject variant).
pub fn subsidy_keywords_subject() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["subsidy_keywords_subject"];
    static_matcher(&SLOT, LISTS)
}

// ── Transaction correlation (BEC) ─────────────────────────────────────────

/// Payment-change instruction keywords ("update bank account", ...).
pub fn payment_change_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["payment_change_keywords"];
    static_matcher(&SLOT, LISTS)
}

/// Urgency keywords used as a financial-context multiplier.
pub fn transaction_urgency_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["transaction_urgency_keywords"];
    static_matcher(&SLOT, LISTS)
}

// ── RMM / Remote Management Tool lures ────────────────────────────────────

/// Brand keywords for known RMM products (TeamViewer, AnyDesk, ...).
pub fn rmm_brand_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["rmm_brand_keywords"];
    static_matcher(&SLOT, LISTS)
}

/// Installer file names commonly bundled with RMM lures.
pub fn rmm_installer_filenames() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["rmm_installer_filenames"];
    static_matcher(&SLOT, LISTS)
}

/// Action / lure keywords used to coerce the recipient into installing RMM
/// tooling ("download support tool", "remote assistance", ...).
pub fn rmm_lure_action_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["rmm_lure_action_keywords"];
    static_matcher(&SLOT, LISTS)
}

// ── TOAD (Telephone-Oriented Attack Delivery) ─────────────────────────────

/// "Call this number now" callback verbs.
pub fn toad_callback_verbs() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["toad_callback_verbs"];
    static_matcher(&SLOT, LISTS)
}

/// Urgency phrases used by TOAD lures.
pub fn toad_urgency_phrases() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["toad_urgency_phrases"];
    static_matcher(&SLOT, LISTS)
}

// ── Device code phishing (AitM) ───────────────────────────────────────────

/// "Enter this code" imperative phrases used in OAuth device-code phishing.
pub fn device_code_enter_phrases() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["device_code_enter_phrases"];
    static_matcher(&SLOT, LISTS)
}

// ── HTML scan ─────────────────────────────────────────────────────────────

/// CSS/HTML patterns that indicate hidden content
/// (`display:none`, `visibility:hidden`, `font-size:0`, ...).
pub fn css_hidden_content_patterns() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["css_hidden_content_patterns"];
    static_matcher(&SLOT, LISTS)
}

// ── Link content ──────────────────────────────────────────────────────────

/// Suspicious URL path keywords (`/login`, `/wp-admin/`, `/.git/`, ...).
/// Used by `link_content` against URL paths and fragments.
pub fn suspicious_path_keywords() -> &'static PhraseMatcher {
    static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
    static LISTS: &[&str] = &["suspicious_path_keywords"];
    static_matcher(&SLOT, LISTS)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module_data::{ModuleDataRegistry, set_module_data};

    /// Serialize tests that mutate the global registry. `module_data()` is a
    /// process-wide singleton, so two tests racing on `set_module_data` would
    /// observe each other's writes. Tests that only *read* the registry can
    /// run freely.
    fn registry_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── Empty / boundary behaviour ───────────────────────────────────────

    #[test]
    fn matcher_handles_empty_list_gracefully() {
        // List that does not exist in the seed → empty automaton, no match.
        static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
        static LISTS: &[&str] = &["definitely_does_not_exist_xyz"];
        let m = static_matcher(&SLOT, LISTS);
        assert!(!m.is_match("anything goes here"));
        assert_eq!(m.scan("foo").distinct_count(), 0);
        assert!(m.scan("foo").first_pattern().is_none());
        assert!(m.scan("foo").distinct_patterns().is_empty());
    }

    #[test]
    fn matcher_returns_no_match_on_empty_haystack() {
        let m = mfa_bait_all_locales();
        assert!(!m.is_match(""));
        assert_eq!(m.scan("").distinct_count(), 0);
        assert!(m.scan("").first_pattern().is_none());
    }

    // ── Case insensitivity & original case preservation ──────────────────

    #[test]
    fn matcher_finds_phrases_case_insensitively() {
        // Pull a real phrase out of the seed registry and probe both upper /
        // lower / mixed case haystacks. We don't hardcode the phrase string
        // because the seed is allowed to evolve; instead we rely on the seed
        // having at least one English MFA bait phrase loaded.
        let m = mfa_bait_all_locales();
        let registry = module_data();
        let phrases = registry.get_list("mfa_bait_phrases_en");
        let Some(phrase) = phrases.iter().find(|p| !p.is_empty()).cloned() else {
            // If the seed is ever pruned to nothing, just exit silently
            // rather than emit a noisy assertion.
            return;
        };
        drop(registry);

        assert!(m.is_match(&phrase));
        assert!(m.is_match(&phrase.to_uppercase()));
        let mixed: String = phrase
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(m.is_match(&mixed));
    }

    #[test]
    fn first_pattern_returns_original_case_from_registry() {
        // ascii_case_insensitive(true) lets us match upper-case haystacks,
        // but the returned phrase must be the *original* form stored in the
        // registry (typically lowercase).
        let m = mfa_bait_all_locales();
        let registry = module_data();
        let phrases = registry.get_list("mfa_bait_phrases_en");
        let Some(phrase) = phrases.iter().find(|p| !p.is_empty()).cloned() else {
            return;
        };
        drop(registry);

        let upper_haystack = phrase.to_uppercase();
        let returned = m
            .scan(&upper_haystack)
            .first_pattern()
            .expect("uppercase haystack should still match");
        // Either the registry happened to store it uppercase (unlikely but
        // legal), or the returned form should equal the original phrase, not
        // the haystack form.
        assert!(
            returned == phrase || returned.to_lowercase() == phrase.to_lowercase(),
            "first_pattern returned {returned:?} but registry stored {phrase:?}"
        );
        // The returned form must come from the registry, so it must match
        // some entry in `mfa_bait_phrases_en`.
        let registry = module_data();
        let phrases = registry.get_list("mfa_bait_phrases_en");
        assert!(
            phrases.iter().any(|p| p == &returned),
            "{returned:?} not in mfa_bait_phrases_en"
        );
    }

    // ── distinct_patterns / distinct_count semantics ─────────────────────

    #[test]
    fn distinct_count_dedups_repeated_hits() {
        static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
        static LISTS: &[&str] = &["account_security_action_phrases_body"];
        let m = static_matcher(&SLOT, LISTS);
        let registry = module_data();
        let phrases = registry.get_list("account_security_action_phrases_body");
        if let Some(phrase) = phrases.first().cloned() {
            drop(registry);
            let haystack = format!("{phrase} ... {phrase} ... {phrase}");
            assert_eq!(m.scan(&haystack).distinct_count(), 1);
            assert_eq!(m.scan(&haystack).distinct_patterns().len(), 1);
        }
    }

    #[test]
    fn distinct_patterns_returns_each_unique_phrase_once() {
        // Concatenate two distinct phrases from the same list and confirm
        // both are reported, exactly once each.
        static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
        static LISTS: &[&str] = &["mfa_bait_phrases_en"];
        let m = static_matcher(&SLOT, LISTS);
        let registry = module_data();
        let phrases: Vec<String> = registry
            .get_list("mfa_bait_phrases_en")
            .iter()
            .filter(|p| !p.is_empty())
            .take(2)
            .cloned()
            .collect();
        drop(registry);
        if phrases.len() < 2 {
            return; // not enough seed data to exercise the assertion
        }
        let haystack = format!("{} ::: {}", phrases[0], phrases[1]);
        let hits = m.scan(&haystack).distinct_patterns();
        assert_eq!(hits.len(), 2, "expected 2 distinct hits, got {hits:?}");
        // Both phrases must appear in the dedup'd output. The matcher's
        // dedup is by pattern ID, so even if the input had identical phrases
        // we'd see each ID only once.
        for expected in &phrases {
            assert!(
                hits.iter().any(|h| h.eq_ignore_ascii_case(expected)),
                "missing phrase {expected:?} in {hits:?}"
            );
        }
    }

    // ── Multi-list union ─────────────────────────────────────────────────

    #[test]
    fn multi_list_matcher_unions_all_lists() {
        // mfa_bait_all_locales merges 10 per-language lists into one
        // automaton. For every language list that contains at least one
        // phrase, the merged matcher must recognize that phrase.
        let m = mfa_bait_all_locales();
        let langs = [
            "mfa_bait_phrases_en",
            "mfa_bait_phrases_zh",
            "mfa_bait_phrases_ja",
            "mfa_bait_phrases_ko",
            "mfa_bait_phrases_ru",
            "mfa_bait_phrases_es",
            "mfa_bait_phrases_pt",
            "mfa_bait_phrases_fr",
            "mfa_bait_phrases_de",
            "mfa_bait_phrases_ar",
        ];
        let registry = module_data();
        for lang in langs {
            let Some(phrase) = registry
                .get_list(lang)
                .iter()
                .find(|p| !p.is_empty())
                .cloned()
            else {
                continue;
            };
            assert!(
                m.is_match(&phrase),
                "merged mfa_bait matcher missed {lang} phrase {phrase:?}"
            );
        }
    }

    #[test]
    fn prompt_injection_matchers_recognize_seed_samples_in_each_category() {
        // The three prompt_injection lists are flat unions of 10+ language
        // variants each. Every entry must be findable through the matcher
        // accessor that owns that list. We sample up to 5 phrases per list
        // to keep the test fast while still covering ASCII + CJK + RTL.
        for (name, matcher) in [
            ("prompt_injection_strong_patterns", prompt_strong()),
            ("prompt_injection_role_reset_patterns", prompt_role_reset()),
            ("prompt_injection_weak_patterns", prompt_weak()),
        ] {
            let registry = module_data();
            let phrases: Vec<String> = registry
                .get_list(name)
                .iter()
                .filter(|p| !p.is_empty())
                .take(5)
                .cloned()
                .collect();
            drop(registry);
            assert!(
                !phrases.is_empty(),
                "seed list {name} is empty — multilingual expansion regression?"
            );
            for phrase in phrases {
                let haystack = format!("preamble noise ... {phrase} ... trailing fluff");
                assert!(
                    matcher.is_match(&haystack),
                    "prompt matcher for {name} missed {phrase:?}"
                );
            }
        }
    }

    #[test]
    fn seed_keeps_minimum_multilingual_coverage() {
        // Sanity check on the multilingual seed expansion: every advertised
        // language list must hold at least one entry. Catches accidental
        // truncation during seed edits.
        let critical_lists = [
            "mfa_bait_phrases_en",
            "mfa_bait_phrases_zh",
            "mfa_bait_phrases_ja",
            "mfa_bait_phrases_ko",
            "mfa_bait_phrases_ru",
            "mfa_bait_phrases_es",
            "mfa_bait_phrases_pt",
            "mfa_bait_phrases_fr",
            "mfa_bait_phrases_de",
            "mfa_bait_phrases_ar",
            "prompt_injection_strong_patterns",
            "prompt_injection_role_reset_patterns",
            "prompt_injection_weak_patterns",
        ];
        let registry = module_data();
        for name in critical_lists {
            let count = registry
                .get_list(name)
                .iter()
                .filter(|p| !p.is_empty())
                .count();
            assert!(
                count > 0,
                "seed list {name} unexpectedly empty (count={count})"
            );
        }
    }

    // ── Hot reload ───────────────────────────────────────────────────────

    #[test]
    fn epoch_bump_triggers_rebuild_with_new_phrases() {
        let _guard = registry_test_lock();

        // 1. Snapshot current registry so we can restore it at the end.
        //    We keep the full snapshot intact and only *augment* it with a
        //    synthetic list, so other tests running in parallel still see
        //    the real seed for every other list.
        let saved: ModuleDataRegistry = (*module_data()).clone();

        // 2. Clone the saved registry and augment with a synthetic list
        //    name that no other test or detector references.
        let mut augmented = saved.clone();
        let synth_list = "__matcher_hot_reload_test_list";
        let synth_phrase = "sentinel_phrase_xyz_for_hot_reload_test";
        augmented.replace_list_for_test(synth_list, vec![synth_phrase.to_string()]);

        // 3. Build a matcher that points at the synthetic list. Before the
        //    hot reload, the list does not exist in the registry, so the
        //    automaton is empty and `is_match` must return false.
        static SLOT: OnceLock<PhraseMatcher> = OnceLock::new();
        static LISTS: &[&str] = &["__matcher_hot_reload_test_list"];
        let m = static_matcher(&SLOT, LISTS);
        // Force a build against the original (saved) registry where the
        // synthetic list does not exist.
        assert!(
            !m.is_match(synth_phrase),
            "synthetic phrase should not match the original seed registry"
        );
        let initial_built_epoch = m.built_epoch.load(Ordering::Acquire);

        // 4. Hot-replace the registry with the augmented copy. Epoch must
        //    advance.
        let pre_epoch = module_data_epoch();
        set_module_data(augmented);
        let post_epoch = module_data_epoch();
        assert!(
            post_epoch > pre_epoch,
            "epoch did not advance after set_module_data: {pre_epoch} -> {post_epoch}"
        );

        // 5. The cached matcher should rebuild and now match the synthetic
        //    phrase that wasn't there before.
        assert!(
            m.is_match(synth_phrase),
            "matcher did not pick up the new phrase after hot reload"
        );
        let new_built_epoch = m.built_epoch.load(Ordering::Acquire);
        assert!(
            new_built_epoch > initial_built_epoch,
            "built_epoch did not advance: {initial_built_epoch} -> {new_built_epoch}"
        );

        // 6. Restore. Subsequent tests share the global registry.
        set_module_data(saved);
    }

    #[test]
    fn epoch_unchanged_skips_rebuild() {
        let _guard = registry_test_lock();

        // First call forces a build.
        let m = mfa_bait_all_locales();
        let _ = m.is_match("warmup");
        let after_first = m.built_epoch.load(Ordering::Acquire);
        let registry_epoch_after_first = module_data_epoch();

        // Hammer the matcher many times with no registry mutation in
        // between. `built_epoch` must not change, proving the fast path
        // (load + early return) is taken.
        for _ in 0..1000 {
            let _ = m.is_match("not a phrase, just a probe");
        }

        let after_loop = m.built_epoch.load(Ordering::Acquire);
        let registry_epoch_after_loop = module_data_epoch();
        assert_eq!(after_first, after_loop, "rebuild happened without reload");
        assert_eq!(
            registry_epoch_after_first, registry_epoch_after_loop,
            "registry epoch drifted unexpectedly"
        );
    }
}
