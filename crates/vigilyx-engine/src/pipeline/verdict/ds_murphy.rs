
// Murphy-corrected D-S According to (Add new)


// Step 0: ModuleOutput (b, d, u) 3Yuan, AutoFrom (score, confidence) Convert
// Step 1: According toEngine (A-H),Engine Dempster Composition
// Step 2: Copula Dependency (Engine)
// Step 3: Murphy Add All (Jousselme -> Trusted -> Add All BPA)
// Step 4: Composition N-1 Time/Count (Standard Dempster Rule)
// Step 5: Risk = b_final + u_final


// - (u) RiskSignal,=0.7 -> 70% of " "
// - due to K> 0.7 Auto P0 Alert (Engine -> possibly Highlevel)
// - Copula Engineof According to


use std::collections::HashMap;

use chrono::Utc;
use uuid::Uuid;

use vigilyx_core::security::{
    ALL_PILLARS, Bpa, CircuitBreakerInfo, ConvergenceBreakerInfo, EngineBpaDetail, ModuleResult,
    PILLAR_COUNT, SecurityVerdict, ThreatLevel, dempster_combine, dempster_combine_n,
};

use crate::config::VerdictConfig;
use crate::engine_map::{self, ENGINE_COUNT, EngineId};
use crate::fusion::{self, FusionResult};
use crate::robustness;

use super::{FusionDetails, empty_verdict};

pub(super) fn aggregate_ds_murphy(
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
    let mut flagged_module_ids: Vec<String> = Vec::new();
   // ConvergeBreak/JudgeRoadhandler: count belief>= ofModule,prevent Signal
    let mut convergence_flagged: u32 = 0;
    let mut convergence_flagged_ids: Vec<String> = Vec::new();
    let convergence_belief_thresh = config.convergence_belief_threshold;
    let mut total_duration_ms: u64 = 0;
    let mut max_confidence: f64 = 0.0;
    let mut pillar_scores_raw: [Vec<f64>; PILLAR_COUNT] = Default::default();
   // Break/JudgeRoadhandler: TraceRuleModuleMedium Highof belief value confidence
    
   // : TraceRuleModule (is_remote=false), packet AI/NLP Module.
   // due to: AI Modulemisclassified High (~60%),if Break/JudgeRoadhandler,
   // 14 RuleModuleof"Security" 1 handler.
   // AI ModuleofSignal AndConvergeBreak/JudgeRoadhandler (Module),
   // only * * Security.
    
   // : Trace confidence>= 0.80 ofModule.
   // due to: if 1Low Module High belief (if link_content
   // score=0.70/conf=0.75 -> b=0.525), 1High Module
   // (if content_scan score=0.55/conf=0.85 -> b=0.4675).
   // Break/JudgeRoadhandlerofModule,Butdue to large belief.
   // confidence,Break/JudgeRoadhandlerTraceof " Trustedof Signal" " ofSignal".
    const MIN_CONFIDENCE_FOR_BREAKER: f64 = 0.80;
    let mut max_module_belief: f64 = 0.0;
    let mut max_belief_module_id: String = String::new();
    let mut max_belief_module_confidence: f64 = 0.0;

    for r in &module_results {
        let bpa = r.effective_bpa();
        let raw_score = r.raw_score();

       // Trace HighModule belief: RuleModule confidence Break/JudgeRoadhandler
        let is_rule_module = !r.categories.iter().any(|c| c.starts_with("nlp_"));
        if is_rule_module && r.confidence >= MIN_CONFIDENCE_FOR_BREAKER && bpa.b > max_module_belief
        {
            max_module_belief = bpa.b;
            max_belief_module_id.clone_from(&r.module_id);
            max_belief_module_confidence = r.confidence;
        }

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
           // Collect top evidence as key factors
            if r.threat_level > ThreatLevel::Safe {
                for e in r.evidence.iter().take(2) {
                    engine_factors[idx].push(e.description.clone());
                }
            }
        }

       // Legacy pillar scores (for backward compat)
        let weight = config.weights.get(&r.module_id).copied().unwrap_or(1.0);
        let effective = (raw_score * weight).min(1.0);
        if effective > 0.0 {
            pillar_scores_raw[r.pillar.as_index()].push(effective);
        }

        if r.threat_level > ThreatLevel::Safe {
            modules_flagged += 1;
            flagged_module_ids.push(r.module_id.clone());
            categories.extend(r.categories.iter().cloned());
            if r.confidence > max_confidence {
                max_confidence = r.confidence;
            }
           // ConvergeBreak/JudgeRoadhandler: count belief enoughHighofModule
           // NLP Convergecount - - When NLP RuleModuleSame,
           // +Rule Engine1 Rule ofConvergeSignal.
           // NLP (belief <0.20), RuleModule Converge.
            if bpa.b >= convergence_belief_thresh {
                convergence_flagged += 1;
                convergence_flagged_ids.push(r.module_id.clone());
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
   // Sequential: ENGINE_COUNT=8, each combine is O(k) for k sub-BPAs.
   // Rayon dispatch overhead (~2s) far exceeds 8 x ~100ns computation.
    let engine_combined: Vec<(EngineId, Option<Bpa>)> = EngineId::ALL
        .iter()
        .map(|&eid| {
            let bpas = &engine_bpas[eid.as_index()];
            if bpas.is_empty() {
                return (eid, None);
            }
            let combined = if bpas.len() == 1 {
                bpas[0]
            } else {
                dempster_combine_n(bpas).combined
            };
            if combined.is_vacuous() {
                (eid, None)
            } else {
                (eid, Some(combined))
            }
        })
        .collect();

   // Collect active engines (sequential - needs mutable engine_modules/factors)
    let mut combined_engine_bpas: Vec<Bpa> = Vec::with_capacity(ENGINE_COUNT);
    let mut active_engine_ids: Vec<EngineId> = Vec::with_capacity(ENGINE_COUNT);
    let mut engine_details: Vec<EngineBpaDetail> = Vec::with_capacity(ENGINE_COUNT);

    for (eid, combined) in engine_combined {
        if let Some(bpa) = combined {
            let idx = eid.as_index();
            combined_engine_bpas.push(bpa);
            active_engine_ids.push(eid);
            engine_details.push(EngineBpaDetail {
                engine_id: eid.label().to_string(),
                engine_name: eid.name_cn().to_string(),
                bpa,
                modules: std::mem::take(&mut engine_modules[idx]),
                key_factors: std::mem::take(&mut engine_factors[idx]),
            });
        }
    }

   // Handle case where all engines are vacuous
    if combined_engine_bpas.is_empty() {
        return empty_verdict(session_id, now);
    }

   // Step 2-4: Copula discount + Murphy fusion
    let corr_matrix = config.correlation_matrix.as_deref().unwrap_or({
       // Build sub-matrix for active engines from default
        &[] // will trigger fallback in fuse_engines
    });

   // Build active-only correlation matrix
    let active_corr = if corr_matrix.is_empty() {
        engine_map::active_correlation_matrix(&active_engine_ids)
    } else {
        corr_matrix.to_vec()
    };

    let fusion_result = fusion::fuse_engines(&combined_engine_bpas, &active_corr);

   // Step 5: Robustness enforcement (9.2 diversity constraint)
    let mut cred_weights = fusion_result.credibility_weights.clone();
    let _robustness =
        robustness::check_and_enforce(&combined_engine_bpas, &mut cred_weights, config.eta);

   // Re-compute fused BPA with diversity-enforced weights
    let fused_bpa = {
        let mut b = 0.0_f64;
        let mut d = 0.0_f64;
        let mut u = 0.0_f64;
        for (bpa, &w) in combined_engine_bpas.iter().zip(cred_weights.iter()) {
            b += w * bpa.b;
            d += w * bpa.d;
            u += w * bpa.u;
        }
        Bpa::new(b, d, u)
    };

   // Self-combine N-1 times (standard Dempster rule, same as Murphy step 5)
    let n_active = combined_engine_bpas.len();
    let mut fused = fused_bpa;
    let mut total_k = 0.0_f64;
    for _ in 0..(n_active.saturating_sub(1)) {
        let r = dempster_combine(fused, fused_bpa);
        total_k = 1.0 - (1.0 - total_k) * (1.0 - r.conflict);
        fused = r.combined;
    }

   // Step 6: Risk score
    let eta = config.eta;
    let mut risk_single = fused.risk_score(eta);
    let mut final_level = ThreatLevel::from_score(risk_single);

   // Step 6.5: Post-fusion safety circuit breaker
    
   // D-S Murphy SecuritydetectMediumpossibly Signal:
   // - handler: value = handler ->
   // - Securitydetectfound: value = possibly 1Detected ofEngine ->
    
   // When Moduleof BPA belief Threshold,But Connect 0,
   // LowRisk, SignalAt least 1 ofRiskwaitlevel.
    let mut circuit_breaker_info: Option<CircuitBreakerInfo> = None;
    let threshold = config.alert_belief_threshold;
    let factor = config.alert_floor_factor;
    tracing::debug!(
        max_module_belief,
        threshold,
        factor,
        max_belief_module_confidence,
        risk_single,
        max_belief_module_id = %max_belief_module_id,
        "Circuit breaker check"
    );
    if threshold > 0.0 && max_module_belief >= threshold && max_belief_module_confidence >= 0.80 {
        let mut floor = max_module_belief * factor;

       // Converge large: When 3+ independentHigh ModuleSame, Moduleof belief
       // According to.According toConvergeModule large value.
        
       // : content_scan belief=0.47, Add 3 ModuleConverge
       // floor = 0.47 * 1.0 * (1 + 0.15 * (5-2)) = 0.47 * 1.45 = 0.68 -> High
        
       // Ensure: Module -> Medium (); ModuleConverge -> High ()
        if convergence_flagged >= 3 {
            let boost = 1.0 + 0.15 * (convergence_flagged as f64 - 2.0);
            floor *= boost;
        }
       // : Critical of,AvoidBreak/JudgeRoadhandler Critical verdict
        floor = floor.min(0.90);

       // (Multi-Engine Consensus Gating)
        
       // : Break/JudgeRoadhandler Signal.
       // ButWhen1Module, Break/JudgeRoadhandlerSame large ErrorSignal,
       // immediately 7 Engine Safe.
        
       // : Break/JudgeRoadhandlerof Engineof.
       // When Module " "(EngineAll Signal), large value;
       // When Engineall Signal, Keep Output.
        
       // Count supporting engines by MODULE-level beliefs, not engine-level BPA.
       // Engine BPA can show b0 when one flagging module (e.g., content_scan b=0.85)
       // is absorbed by many safe modules during intra-engine Dempster composition.
       // Using module-level beliefs ensures the consensus gate sees the true signal count.
        let supporting_engines = {
            let mut engines_with_signal = std::collections::HashSet::new();
            for r in &module_results {
               // Use effective_bpa() which computes from (score, confidence) when bpa is None
                let bpa = r.effective_bpa();
                if bpa.b > 0.05
                    && let Some(ref eid) = r
                        .engine_id
                        .as_deref()
                        .and_then(engine_map::EngineId::from_label)
                        .or_else(|| engine_map::module_to_engine(&r.module_id))
                {
                    engines_with_signal.insert(eid.label().to_string());
                }
            }
            engines_with_signal.len()
        };
        let consensus_factor = match supporting_engines {
            0..=1 => 0.30, // lone signal: heavy suppression
            2 => 0.50,     // isolated signal: moderate suppression
            3 => 0.75,     // corroborated: light suppression
            _ => 1.00,     // multi-source convergence: full output
        };
        floor *= consensus_factor;
        floor = floor.max(0.15);

        tracing::debug!(
            supporting_engines,
            consensus_factor,
            floor,
            "Consensus-gated circuit breaker"
        );

        if risk_single < floor {
            circuit_breaker_info = Some(CircuitBreakerInfo {
                trigger_module_id: max_belief_module_id,
                trigger_belief: max_module_belief,
                floor_value: floor,
                original_risk: risk_single,
            });
            risk_single = floor;
            final_level = ThreatLevel::from_score(risk_single);
        }
    }

   // Step 6.6: Multi-signal convergence breaker
    
   // : Safe ModuleReturn confidence=1.0 -> BPA {b:0, d:1.0, u:0} (Security).
   // Engine Dempster CompositionMedium, 1 Yuan - - Signal d=1.0
   // Composition belief 0.When 3+ independentModuleallDetected But Engine
   // of Safe Module,Murphy of 7 " Security"ofEngine.
    
   // : When N ModuleindependentMark, Converge According to,
   // LowRisk Signal.
    
   // Performance notes: Use convergence_flagged (belief>= threshold ofModulecount)
   // modules_flagged (threat_level> Safe).
   // Mobile phoneNumberdetect (belief0.14), Keywords Medium (belief0.10) waitLow Module
   // may be Convergecount,Avoid Legitimateemail.
    let mut convergence_breaker_info: Option<ConvergenceBreakerInfo> = None;
    let convergence_min = config.convergence_min_modules;
    let mut convergence_floor = config.convergence_base_floor;

   // Converge large: Break/JudgeRoadhandler Same - - 3+ ModuleConverge
   // : 5 ModuleConverge -> floor = 0.40 * 1.45 = 0.58 (Medium But Connect High)
   // 7 ModuleConverge -> floor = 0.40 * 1.75 = 0.70 -> High
    if convergence_flagged >= 3 {
        let boost = 1.0 + 0.15 * (convergence_flagged as f64 - 2.0);
        convergence_floor = (convergence_floor * boost).min(0.90);
    }

   // Convergence breaker consensus gate: same module-level approach as circuit breaker.
    {
        let supporting_engines = {
            let mut engines_with_signal = std::collections::HashSet::new();
            for r in &module_results {
               // Use effective_bpa() which computes from (score, confidence) when bpa is None
                let bpa = r.effective_bpa();
                if bpa.b > 0.05
                    && let Some(ref eid) = r
                        .engine_id
                        .as_deref()
                        .and_then(engine_map::EngineId::from_label)
                        .or_else(|| engine_map::module_to_engine(&r.module_id))
                {
                    engines_with_signal.insert(eid.label().to_string());
                }
            }
            engines_with_signal.len()
        };
        let convergence_consensus = match supporting_engines {
            0..=1 => 0.50, // module-level convergence but no engine support: moderate suppression
            2 => 0.75,     // partial engine support
            _ => 1.00,     // multi-engine support: full output
        };
        convergence_floor *= convergence_consensus;
        convergence_floor = convergence_floor.max(0.15);
    }

    if convergence_min > 0
        && convergence_flagged >= convergence_min
        && risk_single < convergence_floor
    {
        convergence_breaker_info = Some(ConvergenceBreakerInfo {
            modules_flagged: convergence_flagged,
            floor_value: convergence_floor,
            original_risk: risk_single,
            flagged_modules: convergence_flagged_ids,
        });
        tracing::warn!(
            convergence_flagged,
            convergence_floor,
            original_risk = risk_single,
            belief_threshold = convergence_belief_thresh,
            "Multi-signal convergence breaker activated: {} modules (belief >= {:.2}) flagged threats but D-S fusion suppressed to {:.4}",
            convergence_flagged,
            convergence_belief_thresh,
            risk_single,
        );
        risk_single = convergence_floor;
        final_level = ThreatLevel::from_score(risk_single);
    }

   // Step 6.7: Phishing + gateway pre-classification boost
    
   // [](gateway_pre_classified)
   // account_security_phishing,
   // (suixuejiaoyu.com DGA),
   // Medium.
   // Critical vs Low.
    {
        let has_phishing = categories.iter().any(|c| c == "account_security_phishing");
        let has_gateway = categories.iter().any(|c| c == "gateway_pre_classified");
        if has_phishing && has_gateway && risk_single < 0.40 {
            let phishing_floor = 0.50; // Medium
            tracing::info!(
                risk_single,
                phishing_floor,
                "Phishing + gateway boost: account_security_phishing + gateway_pre_classified → floor {:.2}",
                phishing_floor,
            );
            risk_single = phishing_floor;
            final_level = ThreatLevel::from_score(risk_single);
        }
    }

   // Build credibility weights map (post-robustness)
    let mut credibility_weights = HashMap::new();
    for (i, eid) in active_engine_ids.iter().enumerate() {
        if let Some(&w) = cred_weights.get(i) {
            credibility_weights.insert(eid.label().to_string(), w);
        }
    }

   // Legacy pillar_scores for backward compatibility
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

    let summary = build_ds_summary(
        final_level,
        &categories,
        modules_flagged,
        module_results.len() as u32,
        &fusion_result,
        risk_single,
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
            fused_bpa: fused,
            k_conflict: total_k,
            risk_single,
            eta,
            engine_details,
            credibility_weights,
            novelty: None,
            k_cross: None,
            betp: None,
            fusion_method: Some("ds_murphy".to_string()),
            circuit_breaker: circuit_breaker_info,
            convergence_breaker: convergence_breaker_info,
        }),
    }
}

fn build_ds_summary(
    level: ThreatLevel,
    categories: &[String],
    flagged: u32,
    total: u32,
    fusion: &FusionResult,
    risk: f64,
) -> String {
    if level == ThreatLevel::Safe {
        return format!(
            "No security threats found ({total} modules, {eng} engines, risk={risk:.3})",
            eng = fusion.engine_count
        );
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

    let conflict_str = if fusion.k_conflict > 0.5 {
        format!(" ⚠conflict={:.2}", fusion.k_conflict)
    } else {
        String::new()
    };

    format!("{level_str}{cat_str} — {flagged}/{total} modules flagged, risk={risk:.3}{conflict_str}")
}
