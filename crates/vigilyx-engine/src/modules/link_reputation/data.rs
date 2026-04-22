//! Static data lists for link reputation analysis.
//!
//! This module now uses module_data() from the global registry instead of
//! hardcoded constants. All data lists are loaded from engine_module_data_seed.json.

use regex::Regex;
use std::sync::LazyLock;

/// Match random domain: contiguous 4+ consonants
pub(super) static RE_RANDOM_DOMAIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[bcdfghjklmnpqrstvwxyz]{4,}").unwrap());
