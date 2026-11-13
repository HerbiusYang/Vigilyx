//! Versioned D-S learning contracts. Labels and evidence are separate from policy.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsLearningEvidence {
    pub source_id: String,
    pub causal_key: Option<String>,
    pub cluster: String,
    pub raw_score: f64,
    pub confidence: f64,
    pub item_scored: bool,
    pub legacy_mass: f64,
    pub confirmed_anchor_mass: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DsSourceParameters {
    pub slope: f64,
    pub intercept: f64,
    pub reliability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DsCalibration {
    pub slope: f64,
    pub intercept: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DsModelParameters {
    pub schema_version: u32,
    pub parameter_version: String,
    pub training_status: String,
    pub sources: BTreeMap<String, DsSourceParameters>,
    pub base_rate: f64,
    pub calibration: Option<DsCalibration>,
    pub training_sample_count: u64,
}

impl DsModelParameters {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.parameter_version.trim().is_empty()
            || self.parameter_version.len() > 128
            || !matches!(
                self.training_status.as_str(),
                "bootstrap" | "candidate" | "validated"
            )
            || !self.base_rate.is_finite()
            || !(0.0..=1.0).contains(&self.base_rate)
            || self.sources.len() > 512
        {
            return Err("Invalid DS model metadata".into());
        }
        for (source, p) in &self.sources {
            if source.len() > 256
                || !source.split_once(':').is_some_and(|(module, category)| {
                    !module.trim().is_empty() && !category.trim().is_empty()
                })
                || !p.slope.is_finite()
                || !(0.0..=16.0).contains(&p.slope)
                || !p.intercept.is_finite()
                || !(-16.0..=16.0).contains(&p.intercept)
                || !p.reliability.is_finite()
                || !(0.0..=1.0).contains(&p.reliability)
            {
                return Err("Invalid DS source parameters".into());
            }
        }
        if let Some(c) = &self.calibration
            && (!c.slope.is_finite()
                || !(0.0..=16.0).contains(&c.slope)
                || !c.intercept.is_finite()
                || !(-16.0..=16.0).contains(&c.intercept))
        {
            return Err("Invalid DS probability calibration".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsLearningDiagnostics {
    pub status: String,
    pub parameter_version: Option<String>,
    pub parameter_sha256: Option<String>,
    pub learned_items: u32,
    pub fallback_items: u32,
    pub dependency_groups: u32,
    pub projected_probability: Option<f64>,
    pub calibrated_probability: Option<f64>,
    pub candidate_belief: Option<f64>,
    pub candidate_probability: Option<f64>,
}
