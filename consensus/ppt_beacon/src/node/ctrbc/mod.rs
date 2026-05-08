//! Per-round PPT state.
//!
//! The submodule name `ctrbc` is kept only for backward compatibility
//! with the original hashrand layout. The full Cachin-Tessaro RBC
//! pipeline is no longer part of the PPT path: only `state.rs`
//! survives and it now holds purely PPT-relevant state (AVSS book,
//! ACS-decided dealer set, batch reconstruction, post-ACS audit
//! evidence, and beacon-output bookkeeping).

pub mod state;
pub use state::*;
