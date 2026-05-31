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
pub mod compact_broadcast;
pub mod rel_msg_dst;
pub mod sec_key_dst;

use crypto::aes_hash::Proof;

/// Reconstruct the leaf index of a Merkle inclusion proof from the
/// path-bit sequence produced by `MerkleTree::gen_proof`.
///
/// `crypto::aes_hash::merkle::gen_proof` records `path[i] = (j & 1 == 0)`
/// at level `i` (then `j >>= 1`). So `path[i] == true` means the leaf is
/// the *left* child at level `i` (LSB of `j` was 0), and `path[i] == false`
/// means *right* child (LSB was 1).
///
/// Reconstruction: `idx = OR_i (1 << i) for which path[i] == false`.
///
/// This is needed to defend against Byzantine attacks where an
/// adversary supplies a Merkle path/fragment pair for one leaf
/// position but claims it lives at a different position. Without
/// this check, the dispersal-phase decoder may mis-position
/// fragments and produce garbage output even with an honest dealer.
/// (Forward sub-protocol's rebuild step does catch the corruption,
/// but the cheap distribution-phase `handle_dispersal` /
/// `handle_echo` checks must enforce it directly.)
pub(crate) fn proof_leaf_index(proof: &Proof) -> usize {
    let mut idx: usize = 0;
    for (i, &b) in proof.path().iter().enumerate() {
        if !b {
            idx |= 1usize << i;
        }
    }
    idx
}

#[cfg(test)]
mod proof_leaf_index_tests {
    use super::*;
    use crypto::aes_hash::{HashState, MerkleTree};
    use crypto::hash::{do_hash, Hash};
    use std::sync::Arc;

    fn hash_state() -> Arc<HashState> {
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        Arc::new(HashState::new(key0, key1, key2))
    }

    #[test]
    fn matches_gen_proof_index_for_power_of_two_n() {
        // n = 4 (power of two): every leaf index recoverable exactly.
        let leaves: Vec<Hash> = (0..4u8).map(|i| do_hash(&[i; 32])).collect();
        let tree = MerkleTree::new(leaves, &hash_state());
        for i in 0..4 {
            let proof = tree.gen_proof(i);
            assert_eq!(proof_leaf_index(&proof), i);
        }
    }

    #[test]
    fn matches_gen_proof_index_for_n16() {
        let leaves: Vec<Hash> = (0..16u8).map(|i| do_hash(&[i; 8])).collect();
        let tree = MerkleTree::new(leaves, &hash_state());
        for i in 0..16 {
            let proof = tree.gen_proof(i);
            assert_eq!(proof_leaf_index(&proof), i);
        }
    }

    #[test]
    fn matches_gen_proof_index_for_odd_n() {
        // n = 7: tree pads to 8 leaves; real indices live in [0, 7).
        let leaves: Vec<Hash> = (0..7u8).map(|i| do_hash(&[i; 4])).collect();
        let tree = MerkleTree::new(leaves, &hash_state());
        for i in 0..7 {
            let proof = tree.gen_proof(i);
            assert_eq!(proof_leaf_index(&proof), i);
        }
    }
}
