//! D-S / TBM evidence fusion mathematics.

//! Contains the core mathematical operations for combining evidence
//! from multiple detection engines: Dempster-Shafer theory, TBM
//! open-world extension, Murphy weighted fusion, and Copula discount.

pub mod bpa;
pub mod engine_map;
pub mod grouped_fusion;
mod murphy;
pub mod robustness;
pub mod tbm;

// Re-export murphy.rs contents at the fusion:: level.
// Preserves backward-compatible paths like crate::fusion::murphy_fusion,
// crate::fusion::FusionResult, crate::fusion::copula_discount_flat, etc.
pub use murphy::*;
