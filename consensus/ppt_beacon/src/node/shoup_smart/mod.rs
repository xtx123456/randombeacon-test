//! Shoup-Smart 2024 AVSS protocol building blocks.
//!
//! Reference: Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//! Verifiable Secret Sharing with Optimal Resilience", Journal of
//! Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//!
//! This module hierarchy implements the protocol stack described in
//! Sections 3, 4, and 5 of the paper:
//!
//! ```text
//! Π_avss1 (Sec 5)        — top-level AVSS protocol [TODO commits 6-7]
//!   ├─ F_Beacon (Sec 3.1)  — already provided by Context::theta_per_round / coin_per_round
//!   ├─ F_ReliableBroadcast (Sec 3.2.2 = Π_CompactBroadcast)  [TODO commit 2]
//!   ├─ F_OneSidedVote (Sec 3.2.5)                            [TODO commit 2]
//!   └─ F_SecMsgDst (Sec 3.3 = Π_SecMsgDst Sec 4.3)           [TODO commit 5]
//!       ├─ Π_RelMsgDst (Sec 4.1)                             [TODO commit 3]
//!       └─ Π_SecKeyDst (Sec 4.2)                             [TODO commit 4]
//! ```
//!
//! The implementation is built on top of the **lightweight**
//! cryptographic primitives the paper requires: hash functions
//! (`crypto::hash::do_hash`) plus an erasure code (Reed-Solomon over
//! GF(2^8), implemented in `reed_solomon`). This is a strict subset
//! of the primitives the rest of the PPT codebase already uses, so
//! adding the Shoup-Smart stack does not introduce any new
//! cryptographic dependency, in line with the brief's PQ-safe
//! constraint.
//!
//! Each submodule below exposes a state-machine API plus an
//! `Action` enum for side effects, mirroring the existing
//! `acs::aba` / `acs::rbc` patterns. The driver code in
//! `consensus/ppt_beacon/src/node/process.rs` will eventually wire
//! these state machines into `Context` (commits 6-7).

pub mod reed_solomon;
