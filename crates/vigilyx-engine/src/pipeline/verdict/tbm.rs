
// v5.0 TBM


// Step 0: ModuleOutput (b, d, u,) 4Yuan
// Step 1: According toEngine (A-H),Engine Dempster Composition
// Step 2: (A-E): Copula -> Murphy Add All
// Step 3: District (F-G-H): Standard Dempster Composition
// Step 4: Cautious Composition: max(b), max(d), min(u), max()
// Step 5: K_cross, Novelty, BetP
// Step 6: Risk = b + u -> ThreatLevel

// District (vs ds_murphy):
// -> 0 table Unknown
// - District (F-G-H) independent Cautious Composition,only downgrade
// - Novelty SignaldetectNew Attack,K_cross detect


use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use vigilyx_core::security::{
    ALL_PILLARS, Bpa, EngineBpaDetail, ModuleResult, PILLAR_COUNT, SecurityVerdict, ThreatLevel,
    dempster_combine_n,
};

use crate::config::VerdictConfig;
use crate::engine_map::{self, ENGINE_COUNT, EngineId};
use crate::grouped_fusion;

use super::{FusionDetails, empty_verdict};

pub(super) fn aggregate_tbm_v5(
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

   // Single-pass: collect metadata + group BPAs by engine
    let mut engine_bpas: [Vec<Bpa>; ENGINE_COUNT] = Default::default();
    let mut engine_modules: [Vec<String>; ENGINE_COUNT] = Default::default();
    let mut engine_factors: [Vec<String>; ENGINE_COUNT] = Default::default();
    let mut categories: Vec<String> = Vec::new();
    let mut modules_flagged: u32 = 0;
    let mut total_duration_ms: u64 = 0;
    let mut max_confidence: f64 = 0.0;
    let mut pillar_scores_raw: [Vec<f64>; PILLAR_COUNT] = Default::default();

    for r in &module_results {
       // Use module BPA, applying default_epsilon if module didn't set one
        let mut bpa = r.effective_bpa();
        if bpa.epsilon == 0.0 && config.default_epsilon > 0.0 {
           // Inject default epsilon for TBM: redistribute a small fraction to
            let eps = config.default_epsilon;
            let scale = 1.0 - eps;
            bpa = Bpa {
                b: bpa.b * scale,
                d: bpa.d * scale,
                u: bpa.u * scale,
                epsilon: eps,
            };
        }
        let raw_score = r.raw_score();

       // Map to engine
        if let Some(eid) = r
            .engine_id
            .as_deref()
            .and_then(engine_map::EngineId::from_label)
            .or_else(|| engine_map::module_to_engine(&r.module_id))
        {
            let idx = eid.as_index();
            engine_bpas[idx].push(bpa);
            engine_modules[idx].push(r.module_id.clone());
            if r.threat_level > ThreatLevel::Safe {
                for e in r.evidence.iter().take(2) {
                    engine_factors[idx].push(e.description.clone());
                }
            }
        }

       // Legacy pillar scores
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

   // Step 1: Within-engine Dempster combination
    let mut engine_bpa_pairs: Vec<(EngineId, Bpa)> = Vec::with_capacity(ENGINE_COUNT);
    let mut engine_details: Vec<EngineBpaDetail> = Vec::with_capacity(ENGINE_COUNT);

    for &eid in &EngineId::ALL {
        let idx = eid.as_index();
        let bpas = &engine_bpas[idx];
        if bpas.is_empty() {
            continue;
        }
        let combined = if bpas.len() == 1 {
            bpas[0]
        } else {
            dempster_combine_n(bpas).combined
        };
        if combined.is_vacuous() {
            continue;
        }
        engine_bpa_pairs.push((eid, combined));
        engine_details.push(EngineBpaDetail {
            engine_id: eid.label().to_string(),
            engine_name: eid.name_cn().to_string(),
            bpa: combined,
            modules: std::mem::take(&mut engine_modules[idx]),
            key_factors: std::mem::take(&mut engine_factors[idx]),
        });
    }

    if engine_bpa_pairs.is_empty() {
        return empty_verdict(session_id, now);
    }

   // Step 2-5: Grouped fusion (tech + blind-spot -> cautious combine)
    let corr_flat = config
        .correlation_matrix
        .as_deref()
        .unwrap_or(&crate::engine_map::DEFAULT_CORRELATION_MATRIX);

    let gf = grouped_fusion::grouped_fusion(&engine_bpa_pairs, corr_flat, config.eta);

   // Step 6: Risk score from fused BPA
    let eta = config.eta;
    let risk_single = gf.fused.risk_score(eta);
    let final_level = ThreatLevel::from_score(risk_single);

   // Build credibility weights map (from tech layer)
    let mut credibility_weights = HashMap::new();
   // Map tech credibility weights back to engine labels
    let tech_engine_labels: Vec<String> = engine_bpa_pairs
        .iter()
        .filter(|(eid, _)| {
            matches!(
                eid,
                EngineId::A | EngineId::B | EngineId::C | EngineId::D | EngineId::E
            )
        })
        .map(|(eid, _)| eid.label().to_string())
        .collect();
    for (i, label) in tech_engine_labels.iter().enumerate() {
        if let Some(&w) = gf.tech_credibility_weights.get(i) {
            credibility_weights.insert(label.clone(), w);
        }
    }

   // Legacy pillar scores
    let mut pillar_threat: HashMap<String, f64> = HashMap::new();
    for &pillar in &ALL_PILLARS {
        let scores = &pillar_scores_raw[pillar.as_index()];
        let t_p = if scores.is_empty() {
            0.0
        } else {
            let product: f64 = scores.iter().fold(1.0, |acc, &s| acc * (1.0 - s));
            1.0 - product
        };
        pillar_threat.insert(pillar.to_string(), t_p);
    }

    let summary = build_tbm_summary(
        final_level,
        &categories,
        modules_flagged,
        module_results.len() as u32,
        risk_single,
        gf.novelty,
        gf.k_cross,
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
        fusion_details: Some(FusionDetails {
            fused_bpa: gf.fused,
            k_conflict: gf.k_conflict_tech,
            risk_single,
            eta,
            engine_details,
            credibility_weights,
            novelty: Some(gf.novelty),
            k_cross: Some(gf.k_cross),
            betp: Some(gf.betp),
            fusion_method: Some("tbm_v5".to_string()),
            circuit_breaker: None,
            convergence_breaker: None,
        }),
    }
}

fn build_tbm_summary(
    level: ThreatLevel,
    categories: &[String],
    flagged: u32,
    total: u32,
    risk: f64,
    novelty: f64,
    k_cross: f64,
) -> String {
    if level == ThreatLevel::Safe {
        return format!("No security threats found ({total} modules, TBM fusion, risk={risk:.3})");
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

    let mut extras = Vec::new();
    if novelty > 0.3 {
        extras.push(format!("Novelty={novelty:.2}"));
    }
    if k_cross > 0.3 {
        extras.push(format!("K_cross={k_cross:.2}"));
    }
    let extras_str = if extras.is_empty() {
        String::new()
    } else {
        format!(" ⚠{}", extras.join(","))
    };

    format!("{level_str}{cat_str} — {flagged}/{total} modules flagged, TBM risk={risk:.3}{extras_str}")
}
