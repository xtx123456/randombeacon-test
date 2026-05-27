//! Self-bootstrapping common coin for the PPT random beacon's ACS
//! pipeline.
//!
//! Each ACS round finishes by producing the next round's "previous
//! beacon" seed: the first reconstructed coin of the round (coin_num
//! == 0). The MMR ABA inside that ACS round needs a 1-bit common
//! coin per ABA round per ABA instance; we derive that bit by
//! hashing the previous beacon's bytes together with the ABA
//! instance ID and the ABA round counter.
//!
//! For round 0 there is no previous beacon, so we substitute a
//! fixed public genesis seed (`PPT_GENESIS_COIN_SEED`). This is
//! safe because the ABA termination property only requires the coin
//! to be unpredictable to the adversary BEFORE round 0's BVALs are
//! sent — and round 0 is the bootstrapping case where every honest
//! node enters with the same input bit unconditionally (see PPT
//! slide pg 17 "random beacon is a long running system": only the
//! genesis instance is bootstrapped, every later instance has a
//! prior beacon to seed off of).
//!
//! PQ-safety: this module uses only `crypto::hash::do_hash` (a
//! 256-bit hash family). No DL, no pairing, no RSA, no threshold
//! primitive, no external VRF — exactly what the PPT scheme allows.

use types::Round;

use crate::node::Context;

/// Public, deterministic seed used to derive the round-0 ABA common
/// coins. Every node uses this, so all ABA instances in round 0 see
/// the same coin bit. The byte string is intentionally distinct
/// from `PPT_GENESIS_THETA_SEED` so the two derivations never
/// produce correlated outputs.
pub const PPT_GENESIS_COIN_SEED: &[u8] = b"PPT_BEACON_GENESIS_COIN_v1";

/// Domain-separation prefix so the ACS coin derivation never
/// collides with other hash-based derivations elsewhere in the
/// protocol.
const COIN_DOMAIN: &[u8] = b"PPT_ACS_COIN_v1::";

impl Context {
    /// Return the bytes used to seed every ABA coin derivation in
    /// the ACS instance for `acs_round`.
    ///
    /// - For `acs_round == 0` we return `PPT_GENESIS_COIN_SEED`.
    /// - For `acs_round > 0` we look up the previous round's beacon
    ///   bytes that were recorded in `coin_per_round` at the moment
    ///   `record_beacon_output_for_coin(acs_round - 1, ...)` was
    ///   called from `self_coin_check_transmit` (coin_num == 0
    ///   path).
    ///
    /// Returns `None` for `acs_round > 0` when the previous round's
    /// beacon has not yet been recorded locally (transient async
    /// race, just like `theta_for_round`). The caller MUST handle
    /// `None` by deferring — never by dropping or silently picking
    /// a default value, since that would let a slow node disagree
    /// with everyone else on the coin bit.
    pub fn coin_seed_for_acs_round(&self, acs_round: Round) -> Option<Vec<u8>> {
        if acs_round == 0 {
            return Some(PPT_GENESIS_COIN_SEED.to_vec());
        }
        self.coin_per_round.get(&acs_round).cloned()
    }

    /// Derive the 1-bit common coin for `(acs_round, aba_instance_id,
    /// aba_round)`. All honest nodes derive the same bit because the
    /// inputs are deterministic protocol-level integers and the seed
    /// is either the public genesis seed or the previous round's
    /// reconstructed beacon (which is identical at every honest
    /// node by ACS / batch-recover safety).
    ///
    /// Returns `None` only when the previous-round beacon hasn't
    /// been recorded yet (caller defers — see
    /// `coin_seed_for_acs_round`).
    pub fn coin_bit_for(
        &self,
        acs_round: Round,
        aba_instance_id: usize,
        aba_round: u64,
    ) -> Option<bool> {
        let seed = self.coin_seed_for_acs_round(acs_round)?;
        Some(coin_bit_from_seed(&seed, aba_instance_id, aba_round))
    }

    /// Record the round-`acs_round` first-coin beacon output as the
    /// source of round-(acs_round + 1)'s ACS common-coin derivation.
    /// Called from `self_coin_check_transmit` in the `coin_num == 0`
    /// branch, immediately after `record_beacon_output_for_theta`.
    ///
    /// We store the raw bytes (not a hash) so the derivation in
    /// `coin_bit_for` can include domain-separated context (instance
    /// id, aba_round) and produce uncorrelated bits across instances.
    pub fn record_beacon_output_for_coin(&mut self, acs_round: Round, output_bytes: &[u8]) {
        self.coin_per_round.insert(acs_round + 1, output_bytes.to_vec());
    }
}

/// Pure function (no `&self`) for unit testing the coin derivation.
/// Hash inputs are length-prefixed so an adversary cannot collide
/// (`(round=10, aba=5, r=0)` vs `(round=1, aba=0, r=50)`) by
/// shifting bytes around.
pub fn coin_bit_from_seed(seed: &[u8], aba_instance_id: usize, aba_round: u64) -> bool {
    let mut buf = Vec::with_capacity(COIN_DOMAIN.len() + seed.len() + 8 + 8 + 8);
    buf.extend_from_slice(COIN_DOMAIN);
    let seed_len = seed.len() as u64;
    buf.extend_from_slice(&seed_len.to_be_bytes());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&(aba_instance_id as u64).to_be_bytes());
    buf.extend_from_slice(&aba_round.to_be_bytes());
    let hash = crypto::hash::do_hash(buf.as_slice());
    // Take the lowest bit of the last byte. Equivalent to "first
    // bit of any uniform byte from a CRH" which is uniform under
    // the random oracle assumption.
    let last = hash[hash.len() - 1];
    (last & 1u8) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_coin_is_deterministic_per_instance_and_round() {
        // Two callers using the same genesis seed must derive the
        // exact same bit for the same (instance, round).
        let bit_a = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 0, 0);
        let bit_b = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 0, 0);
        assert_eq!(bit_a, bit_b);

        let bit_a = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 7, 13);
        let bit_b = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 7, 13);
        assert_eq!(bit_a, bit_b);
    }

    #[test]
    fn coin_bits_are_independent_across_instance_and_round() {
        // Different (instance_id, round) pairs MUST hash to
        // statistically uncorrelated bits. We sample a small bag
        // and require some variation in the first few outputs —
        // not a perfect uniformity test, but good enough to catch
        // a "constant 0" / "constant 1" / "round-only" regression.
        let seed = b"some-random-beacon-bytes";
        let mut zeros = 0usize;
        let mut ones = 0usize;
        let mut last: Option<bool> = None;
        let mut differences = 0usize;
        for inst in 0..16 {
            for r in 0..16u64 {
                let bit = coin_bit_from_seed(seed, inst, r);
                if bit { ones += 1; } else { zeros += 1; }
                if let Some(p) = last {
                    if p != bit { differences += 1; }
                }
                last = Some(bit);
            }
        }
        assert!(zeros > 0 && ones > 0, "coin not flipping across (inst, r): zeros={} ones={}", zeros, ones);
        assert!(differences > 16, "coin too sticky across (inst, r): {} flips out of 256", differences);
    }

    #[test]
    fn coin_changes_when_seed_changes() {
        // Two distinct seeds with the same (instance, round) must
        // produce statistically distinct outputs (probability of
        // accidental match for a single sample is 1/2 — but across
        // a small batch the chance of 100% match is 2^{-batch}).
        let seed_a = b"BEACON_OUTPUT_ROUND_3";
        let seed_b = b"BEACON_OUTPUT_ROUND_4";
        let mut differences = 0usize;
        for r in 0..32u64 {
            let bit_a = coin_bit_from_seed(seed_a, 0, r);
            let bit_b = coin_bit_from_seed(seed_b, 0, r);
            if bit_a != bit_b { differences += 1; }
        }
        assert!(differences > 0, "two distinct seeds produced identical coin bits");
    }
}
