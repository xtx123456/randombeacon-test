//! Asynchronous Common Subset (ACS) sub-module for the PPT
//! random-beacon path.
//!
//! - `state.rs` holds the per-round state machine.
//! - `protocol.rs` is the driver wired into `Context`: it handles
//!   `ACSPropose`, `ACSWitness1`, `ACSWitness2` ingress/egress,
//!   re-validation cascades, and emits the final decided dealer
//!   set into `Context::round_state` so reconstruction can start.

pub mod state;
pub mod protocol;
