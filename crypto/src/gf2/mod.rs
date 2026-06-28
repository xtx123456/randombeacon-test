//! GF(2^w) binary-extension-field arithmetic for the PPT random-beacon
//! two-field optimization.
//!
//! Migration roadmap
//! -----------------
//!
//! This module is the foundation for replacing the `BigUint`-based
//! prime-field two-field optimization (`shamir::two_field`) with a
//! parameterized binary-extension-field tower. Subsequent commits
//! will:
//!
//! 1. Wire `Gf2Profile` through `node::Context` via a CLI flag
//!    `--field=GF2(w_p,w_q)`.
//! 2. Replace `BigUint` arithmetic in the AVSS share path
//!    (`batch_wssinit.rs`, `secret_reconstruct.rs`) with
//!    `Gf2Element` operations.
//! 3. Update the Fiat-Shamir degree test
//!    (`shoup_smart::sec_msg_dst.rs`) to derive challenges as
//!    `Gf2Element` values.
//! 4. Extend the wire format (`types::msg::beacon`) with a profile
//!    descriptor so heterogeneous nodes can fail fast on mismatch.
//!
//! This commit lays the math infrastructure with **no protocol
//! wiring** — every existing test continues to pass and no behaviour
//! changes outside the `gf2` module.
//!
//! Design summary
//! --------------
//!
//! * `Gf2Profile { w_p, w_q }` is the runtime configuration. `w_p`
//!   sizes the small "secret" field; `w_q` sizes the large "mask /
//!   challenge" field. Constraint: `w_p | w_q` and `w_q / w_p` is a
//!   power of 2.
//!
//! * `poly` provides bare F_2[x] primitives — carry-less mul, schoolbook
//!   reduction, EEA-based inversion, Rabin's irreducibility test.
//!
//! * `tower` recursively combines two `GF(2^(w/2))` halves into a
//!   `GF(2^w)` element via Karatsuba over the Artin-Schreier
//!   extension `m(y) = y² + y + α`, with `α` chosen so `Tr(α) = 1`.
//!
//! * `Gf2Element` is the public API: a `[u8; 32]` envelope that
//!   carries its profile and exposes `add`, `mul`, `inv`, plus the
//!   subfield embedding `lift_small` / `project_to_small`.

pub mod element;
pub mod poly;
pub mod profile;
pub mod tower;

pub use element::Gf2Element;
pub use profile::{Gf2Profile, MAX_BASE_WIDTH, MAX_LARGE_WIDTH};
