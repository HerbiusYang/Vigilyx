
// Noisy-OR According to model (keep)


// giving N independent detecthandler, Output s [0,1],
// of:
// P(threat) = 1 - (1 - s) (Noisy-OR)


// Step 1: T = 1 - (1 - s w)
// Step 2: S = 1 - (1 - T)
// Step 3: large S' = S + (1-S) (k/5)
// Step 4: Danger S" = S' + (1-S') (if combo hit)
// Step 5: Sf = S" (1 - trust 0.4)


use std::collections::{HashMap, HashSet};

use chrono::Utc;
use uuid::Uuid;

use vigilyx_core::security::{
    ALL_PILLARS, ModuleResult, PILLAR_COUNT, SecurityVerdict, ThreatLevel,
};

use crate::config::{
    COMBO_GAMMA, DIVERSITY_BETA, DIVERSITY_THRESHOLD, TOTAL_PILLARS, TRUST_DISCOUNT_FACTOR,
    VerdictConfig,
};

use super::empty_verdict;

pub(super) fn aggregate_noisy_or(
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

   // Time/CountTraverse: Yuandata + According to
    let mut pillar_scores_raw: [Vec<f64>; PILLAR_COUNT] = Default::default();
    let mut categories: Vec<String> = Vec::new();
    let mut modules_flagged: u32 = 0;
    let mut total_duration_ms: u64 = 0;
    let mut max_confidence: f64 = 0.0;

    for r in &module_results {
        let raw_score = r.raw_score();
        let weight = config.weights.get(&r.module_id).copied().unwrap_or(1.0);
        let effective = (raw_score * weight).min(1.0);

        if effective > 0.0 {
            pillar_scores_raw[r.pillar.as_index()].push(effective);
        }

        if r.threat_level > ThreatLevel::Safe {
            modules_flagged += 1;
            categories.extend(r.categories.iter().cloned());
            if r.confidence > max_confidence {
                max_confidence = r.confidence;
            }
        }

        total_duration_ms += r.duration_ms;
    }

    if max_confidence == 0.0 {
        max_confidence = 1.0;
    }

    categories.sort_unstable();
    categories.dedup();

   // Step 1 & 2: Noisy-OR -> Noisy-OR
    let mut pillar_threat: HashMap<String, f64> = HashMap::new();
    let mut cross_product = 1.0_f64;

    for &pillar in &ALL_PILLARS {
        let scores = &pillar_scores_raw[pillar.as_index()];
        let t_p = if scores.is_empty() {
            0.0
        } else {
            let product: f64 = scores.iter().fold(1.0, |acc, &s| acc * (1.0 - s));
            1.0 - product
        };

        pillar_threat.insert(pillar.to_string(), t_p);
        let alpha = config.pillar_weight(&pillar.to_string());
        cross_product *= 1.0 - (t_p * alpha).min(1.0);
    }

    let s_base = 1.0 - cross_product;

   // Step 3: Signal large
    let k = pillar_threat
        .values()
        .filter(|&&t| t > DIVERSITY_THRESHOLD)
        .count() as f64;
    let diversity = k / TOTAL_PILLARS;
    let s_amp = s_base + (1.0 - s_base) * diversity * DIVERSITY_BETA;

   // Step 4: DangerClass
    let cat_set: HashSet<&str> = categories.iter().map(|s| s.as_str()).collect();
    let has_dangerous_combo = DANGEROUS_COMBOS
        .iter()
        .any(|(a, b)| cat_set.contains(a) && cat_set.contains(b));

    let s_boosted = if has_dangerous_combo {
        s_amp + (1.0 - s_amp) * COMBO_GAMMA
    } else {
        s_amp
    };

   // Step 5: Sender alignment
    let s_final = apply_alignment_discount(s_boosted, results);

    let final_level = ThreatLevel::from_score(s_final);
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
        pillar_scores: pillar_threat,
        modules_run: module_results.len() as u32,
        modules_flagged,
        total_duration_ms,
        created_at: now,
        fusion_details: None,
    }
}

/// DangerClass - Same found headroom
pub(super) const DANGEROUS_COMBOS: &[(&str, &str)] = &[
    ("external_impersonation", "nonsensical_spam"),
    ("external_impersonation", "phishing"),
    ("phishing", "spoofing"),
    ("phishing", "malware"),
    ("phishing", "nonsensical_spam"),
];

/// Sender alignment can soften low-confidence structural anomalies,
/// but it must not discount corroborated phishing/malware evidence.
pub(super) fn apply_alignment_discount(score: f64, results: &HashMap<String, ModuleResult>) -> f64 {
    let flagged_modules = results
        .values()
        .filter(|result| result.threat_level > ThreatLevel::Safe)
        .count();
    let has_corroborated_threat = results.values().any(|result| {
        if result.threat_level <= ThreatLevel::Safe {
            return false;
        }
        matches!(
            result.module_id.as_str(),
            "link_scan"
                | "link_content"
                | "link_reputation"
                | "attach_hash"
                | "av_eml_scan"
                | "av_attach_scan"
                | "sandbox_scan"
                | "yara_scan"
        ) || result.categories.iter().any(|category| {
            matches!(
                category.as_str(),
                "phishing"
                    | "account_security_phishing"
                    | "targeted_credential_phishing"
                    | "ioc_ip_hit"
                    | "sender_ip_malicious"
                    | "malware_hash"
                    | "virus_detected"
                    | "suspicious_params"
            )
        })
    });

    if flagged_modules > 1 || has_corroborated_threat {
        return score;
    }

    if let Some(dv) = results.get("domain_verify")
        && dv.threat_level == ThreatLevel::Safe
        && let Some(alignment) = dv
            .details
            .get("alignment_score")
            .or_else(|| dv.details.get("trust_score"))
            .and_then(|v| v.as_f64())
        && alignment > 0.0
    {
        let discount = 1.0 - alignment * TRUST_DISCOUNT_FACTOR;
        return score * discount;
    }
    score
}

pub(super) fn build_summary(
    level: ThreatLevel,
    categories: &[String],
    flagged: u32,
    total: u32,
) -> String {
    if level == ThreatLevel::Safe {
        return format!("No security threats found ({total} modules completed)");
    }

    let level_str = match level {
        ThreatLevel::Low => "Low risk",
        ThreatLevel::Medium => "Medium risk",
        ThreatLevel::High => "High risk",
        ThreatLevel::Critical => "Critical threat",
        ThreatLevel::Safe => "Safe",
    };

    let cat_str = if categories.is_empty() {
        String::new()
    } else {
        format!(" ({})", categories.join(", "))
    };

    format!("{level_str}{cat_str} — {flagged}/{total} modules flagged")
}
