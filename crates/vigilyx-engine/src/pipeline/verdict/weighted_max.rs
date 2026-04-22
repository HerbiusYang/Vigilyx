// Weighted-MAX (Backward compatible)

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use uuid::Uuid;

use vigilyx_core::security::{
    ALL_PILLARS, ModuleResult, PILLAR_COUNT, Pillar, SecurityVerdict, ThreatLevel,
};

use crate::config::VerdictConfig;

use super::empty_verdict;
use super::noisy_or::{DANGEROUS_COMBOS, apply_alignment_discount, build_summary};

pub(super) fn aggregate_weighted_max(
    session_id: Uuid,
    results: &HashMap<String, ModuleResult>,
    config: &VerdictConfig,
) -> SecurityVerdict {
    let now = Utc::now();

    let module_results: Vec<&ModuleResult> = results
        .values()
        .filter(|r| r.module_id != "verdict")
        .collect();

    if module_results.is_empty() {
        return empty_verdict(session_id, now);
    }

    let mut pillar_scores: HashMap<String, f64> = HashMap::new();
    let mut pillar_counts: [(f64, u32); PILLAR_COUNT] = [(0.0, 0); PILLAR_COUNT];
    let mut max_score: f64 = 0.0;
    let mut max_confidence: f64 = 1.0;
    let mut categories: Vec<String> = Vec::new();
    let mut modules_flagged: u32 = 0;
    let mut total_duration_ms: u64 = 0;

    for r in &module_results {
        let weight = config.weights.get(&r.module_id).copied().unwrap_or(1.0);
        let effective = r.threat_level.as_numeric() * weight * r.confidence;

        let entry = &mut pillar_counts[r.pillar.as_index()];
        if effective > entry.0 {
            entry.0 = effective;
        }
        entry.1 += 1;

        if effective > max_score {
            max_score = effective;
            max_confidence = r.confidence;
        }

        if r.threat_level > ThreatLevel::Safe {
            modules_flagged += 1;
            categories.extend(r.categories.iter().cloned());
        }

        total_duration_ms += r.duration_ms;
    }

    for &pillar in &ALL_PILLARS {
        let (score, _) = pillar_counts[pillar.as_index()];
        if score > 0.0 {
            pillar_scores.insert(pillar.to_string(), score);
        }
    }

    categories.sort_unstable();
    categories.dedup();

    let mut boost: f64 = 0.0;

    let flagged_pillars: HashSet<&Pillar> = module_results
        .iter()
        .filter(|r| r.threat_level > ThreatLevel::Safe)
        .map(|r| &r.pillar)
        .collect();
    if flagged_pillars.len() >= 3 {
        boost += 0.25;
    } else if flagged_pillars.len() >= 2 {
        boost += 0.15;
    }

    let cat_set: HashSet<&str> = categories.iter().map(|s| s.as_str()).collect();
    for (a, b) in DANGEROUS_COMBOS {
        if cat_set.contains(a) && cat_set.contains(b) {
            boost += 0.20;
            break;
        }
    }

    if modules_flagged >= 4 {
        boost += 0.15;
    } else if modules_flagged >= 3 {
        boost += 0.10;
    }

    let mut boosted_score = (max_score + boost).min(1.0);
    boosted_score = apply_alignment_discount(boosted_score, results);

    let final_level = ThreatLevel::from_score(boosted_score);
    let summary = build_summary(
        final_level,
        &categories,
        modules_flagged,
        module_results.len() as u32,
    );

    SecurityVerdict {
        id: Uuid::new_v4(),
        session_id,
        threat_level: final_level,
        confidence: max_confidence,
        categories,
        summary,
        pillar_scores,
        modules_run: module_results.len() as u32,
        modules_flagged,
        total_duration_ms,
        created_at: now,
        fusion_details: None,
    }
}
