//! Rejection-sampling mapper from raw beacon coin values to uniform
//! application-level outputs (leader election and binary common coin).
//!
//! The beacon produces coins that are uniform elements of a finite
//! domain — either `GF(2^w_p)` (size `2^w_p`) or `[0, p)` for a
//! prime `p`. A naive `v mod n` mapping to `{0, …, n−1}` is biased
//! whenever the domain size is not divisible by `n`:
//!
//! ```text
//!     naive modulo mapping has unequal preimage counts unless n divides domain
//! ```
//!
//! **First-match rejection sampling** eliminates this bias entirely.
//! Define `cutoff = n · ⌊domain / n⌋`. Accept a value `v` iff
//! `v < cutoff`, then output `v mod n`. Every accepted outcome maps
//! to equally many pre-images, so the output is exactly uniform.
//! Values in `[cutoff, domain)` are rejected; the first accepted
//! value in (coin, sub-output) batch order is the round's output.
//!
//! Rejection probability per coin is at most `(n−1) / domain`.
//! For typical parameters (`w_p ≥ 8`, `n ≤ 64`) this is small
//! enough that a batch of `B = 1000` coins almost never fails to
//! produce at least one accepted value.
//!
//! Binary common coin
//! -------------------
//!
//! A binary coin is leader election with `n = 2`. For `GF(2^w_p)`
//! the domain is a power of two, so `2 | domain` and the cutoff
//! equals the domain — every value is accepted and the output is
//! `v & 1`. For a prime `p > 2` the rejection probability is `1/p`,
//! negligible for any cryptographic-size prime.

use num_bigint::BigUint;

use crypto::gf2::Gf2Profile;

/// A `CoinMapper` maps raw coin bytes to uniform application-level
/// values for a fixed `n` (number of nodes) and domain.
///
/// Construct with [`CoinMapper::for_gf2`] or [`CoinMapper::for_prime`],
/// then call [`try_leader`](CoinMapper::try_leader) or
/// [`try_bit`](CoinMapper::try_bit) on each coin output.
pub struct CoinMapper {
    n: usize,
    inner: Inner,
}

enum Inner {
    /// Domain = `2^w_p`. Values live in `[0, 2^w_p)`.
    Gf2 { w_p: usize, small_byte_len: usize, cutoff: Option<u128> },
    /// Domain = prime `p`. Values live in `[0, p)`.
    Prime { p: BigUint, cutoff: BigUint },
}

/// The result of the first-match scan over a batch of coin outputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstMatchLeader {
    /// The leader number in `{1, …, n}`.
    pub leader: usize,
    /// Which coin in the batch produced the accepted value.
    pub coin_index: usize,
    /// Which sub-output within that coin (super-invertible extraction
    /// produces `R = |decided| − f` sub-outputs per coin column).
    pub sub_index: usize,
    /// The raw accepted coin bytes for auditability.
    pub raw_bytes: Vec<u8>,
}

impl CoinMapper {
    /// Build a mapper for `GF(2^w_p)` beacon outputs.
    ///
    /// Fails when `n == 0` or when `n > 2^w_p` (the field has fewer
    /// elements than nodes, so no uniform mapping exists).
    pub fn for_gf2(profile: Gf2Profile, n: usize) -> Result<Self, String> {
        if n == 0 {
            return Err("CoinMapper: n must be >= 1".into());
        }
        if profile.w_p < 64 {
            let domain = 1u128 << profile.w_p;
            if (n as u128) > domain {
                return Err(format!(
                    "CoinMapper: n = {} exceeds the GF(2^{}) domain size {}",
                    n, profile.w_p, domain
                ));
            }
        }
        Ok(Self {
            n,
            inner: Inner::Gf2 {
                w_p: profile.w_p,
                small_byte_len: profile.small_byte_len(),
                cutoff: gf2_cutoff(profile.w_p, n),
            },
        })
    }

    /// Build a mapper for BigUint beacon outputs in `[0, p)`.
    ///
    /// Fails when `n == 0` or `n > p`.
    pub fn for_prime(secret_domain: &BigUint, n: usize) -> Result<Self, String> {
        if n == 0 {
            return Err("CoinMapper: n must be >= 1".into());
        }
        if BigUint::from(n as u64) > *secret_domain {
            return Err(format!(
                "CoinMapper: n = {} exceeds the prime domain {}",
                n, secret_domain
            ));
        }
        Ok(Self {
            n,
            inner: Inner::Prime {
                p: secret_domain.clone(),
                cutoff: (secret_domain / BigUint::from(n as u64)) * BigUint::from(n as u64),
            },
        })
    }

    pub fn n(&self) -> usize {
        self.n
    }

    /// Upper bound on the rejection probability per coin for leader
    /// election with this mapper's `n`.
    ///
    /// A small nonzero probability is still reported as nonzero.
    pub fn rejection_bound(&self) -> f64 {
        match &self.inner {
            Inner::Gf2 { w_p, .. } => {
                let remainder = pow2_remainder(*w_p, self.n);
                (remainder as f64) / 2.0f64.powi(*w_p as i32)
            }
            Inner::Prime { p, .. } => {
                let n = BigUint::from(self.n as u64);
                let remainder = p % &n;
                // remainder / p — approximate with f64 for reporting.
                let rem_f = remainder.to_f64_lossy();
                let p_f = p.to_f64_lossy();
                if p_f == 0.0 {
                    0.0
                } else {
                    rem_f / p_f
                }
            }
        }
    }

    /// Map a raw coin value to a leader in `{1, …, n}`, or `None` if
    /// the value falls in the rejection zone.
    ///
    /// `coin_bytes` is the canonical encoding of the coin output:
    /// - GF2: 32-byte little-endian `Gf2Element` payload (low `w_p`
    ///   bits are the value).
    /// - BigUint: big-endian byte encoding of a value in `[0, p)`.
    pub fn try_leader(&self, coin_bytes: &[u8]) -> Option<usize> {
        match &self.inner {
            Inner::Gf2 {
                w_p,
                small_byte_len,
                cutoff,
            } => {
                let v = read_le_u128(coin_bytes, *small_byte_len, *w_p);
                if cutoff.map(|bound| v >= bound).unwrap_or(false) {
                    None
                } else {
                    Some((v % self.n as u128) as usize + 1)
                }
            }
            Inner::Prime { p, cutoff } => {
                let v = BigUint::from_bytes_be(coin_bytes) % p;
                if &v >= cutoff {
                    None
                } else {
                    prime_try_map(&v, p, self.n).map(|k| k + 1)
                }
            }
        }
    }

    /// Map a raw coin value to a binary bit (`false` = 0, `true` = 1),
    /// or `None` if the value falls in the rejection zone.
    ///
    /// For `GF(2^w_p)` with `w_p ≥ 1` this never rejects: `2`
    /// divides `2^w_p`, so every value is accepted and the output is
    /// the LSB.
    ///
    /// For a prime `p > 2` the rejection probability is `1/p`.
    pub fn try_bit(&self, coin_bytes: &[u8]) -> Option<bool> {
        match &self.inner {
            Inner::Gf2 {
                w_p,
                small_byte_len,
                ..
            } => {
                let v = read_le_u128(coin_bytes, *small_byte_len, *w_p);
                gf2_try_map(v, *w_p, 2).map(|k| k == 1)
            }
            Inner::Prime { p, .. } => {
                let v = BigUint::from_bytes_be(coin_bytes) % p;
                prime_try_map(&v, p, 2).map(|k| k == 1)
            }
        }
    }

    /// Whether the value is in the acceptance range for leader
    /// election. Equivalent to `try_leader(..).is_some()` but avoids
    /// the mod.
    pub fn is_accepted(&self, coin_bytes: &[u8]) -> bool {
        self.try_leader(coin_bytes).is_some()
    }

    /// Scan a batch of `(coin_index, sub_index, raw_bytes)` triples
    /// in order and return the first accepted leader.
    ///
    /// All honest nodes see the same outputs in the same deterministic
    /// order (same ACS-decided set, same super-invertible extraction),
    /// so every honest node picks the same leader.
    pub fn first_match<'a, I>(&self, outputs: I) -> Option<FirstMatchLeader>
    where
        I: IntoIterator<Item = (usize, usize, &'a [u8])>,
    {
        for (coin_index, sub_index, bytes) in outputs {
            if let Some(leader) = self.try_leader(bytes) {
                return Some(FirstMatchLeader {
                    leader,
                    coin_index,
                    sub_index,
                    raw_bytes: bytes.to_vec(),
                });
            }
        }
        None
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

/// Read the low `w_p` bits from a little-endian coin-byte buffer as a
/// `u128`. Masks to exactly `w_p` bits.
fn read_le_u128(coin_bytes: &[u8], small_byte_len: usize, w_p: usize) -> u128 {
    let n_read = small_byte_len.min(16).min(coin_bytes.len());
    let mut buf = [0u8; 16];
    buf[..n_read].copy_from_slice(&coin_bytes[..n_read]);
    let raw = u128::from_le_bytes(buf);
    if w_p >= 128 {
        raw
    } else {
        raw & ((1u128 << w_p) - 1)
    }
}

/// GF(2^w_p) rejection-sampling map: returns `Some(k)` in `{0, …, n-1}`
/// when accepted, `None` when rejected.
fn gf2_try_map(v: u128, w_p: usize, n: usize) -> Option<usize> {
    if n == 0 || w_p == 0 || w_p > 128 {
        return None;
    }
    if w_p < 128 && (n as u128 > (1u128 << w_p) || v >= (1u128 << w_p)) {
        return None;
    }
    if gf2_cutoff(w_p, n).map(|bound| v >= bound).unwrap_or(false) {
        return None;
    }
    Some((v % n as u128) as usize)
}

fn pow2_remainder(w_p: usize, n: usize) -> u128 {
    let modulus = n as u128;
    let mut remainder = 1 % modulus;
    for _ in 0..w_p {
        remainder = (remainder * 2) % modulus;
    }
    remainder
}

/// None denotes the full domain. This also handles 2^128 without overflow.
fn gf2_cutoff(w_p: usize, n: usize) -> Option<u128> {
    let remainder = pow2_remainder(w_p, n);
    if remainder == 0 {
        None
    } else if w_p == 128 {
        Some(u128::MAX - (remainder - 1))
    } else {
        Some((1u128 << w_p) - remainder)
    }
}

/// BigUint rejection-sampling map.
fn prime_try_map(v: &BigUint, p: &BigUint, n: usize) -> Option<usize> {
    debug_assert!(n >= 1);
    if n == 1 {
        return Some(0);
    }
    let n_big = BigUint::from(n as u64);
    let cutoff = (p / &n_big) * &n_big;
    if *v < cutoff {
        let k = v % &n_big;
        let k_bytes = k.to_bytes_be();
        let mut val = 0usize;
        for &b in &k_bytes {
            val = (val << 8) | (b as usize);
        }
        Some(val)
    } else {
        None
    }
}

/// Helper trait on BigUint for the lossy f64 conversion used in
/// `rejection_bound`.
trait ToF64Lossy {
    fn to_f64_lossy(&self) -> f64;
}

impl ToF64Lossy for BigUint {
    fn to_f64_lossy(&self) -> f64 {
        let bytes = self.to_bytes_be();
        if bytes.is_empty() {
            return 0.0;
        }
        let bits = self.bits();
        if bits <= 53 {
            // Exact conversion.
            let mut v = 0u64;
            for &b in &bytes {
                v = (v << 8) | (b as u64);
            }
            v as f64
        } else {
            // Take the top 53 bits and scale.
            let shift = bits - 53;
            let top = self >> shift;
            let top_bytes = top.to_bytes_be();
            let mut v = 0u64;
            for &b in &top_bytes {
                v = (v << 8) | (b as u64);
            }
            (v as f64) * (2.0f64).powi(shift as i32)
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- GF2 helpers ---

    fn gf2_mapper(w_p: usize, n: usize) -> CoinMapper {
        let profile = Gf2Profile::new(w_p, w_p).unwrap();
        CoinMapper::for_gf2(profile, n).unwrap()
    }

    fn coin_bytes_from_u128(v: u128) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&v.to_le_bytes());
        buf
    }

    // --- Correctness: exhaustive at small fields ---

    #[test]
    fn exhaustive_uniformity_gf2_8_n10() {
        let mapper = gf2_mapper(8, 10);
        let domain = 256u128;
        let mut counts = vec![0usize; 10];
        let mut rejected = 0usize;
        for v in 0..domain {
            let bytes = coin_bytes_from_u128(v);
            match mapper.try_leader(&bytes) {
                Some(leader) => {
                    assert!(
                        leader >= 1 && leader <= 10,
                        "leader {} out of range",
                        leader
                    );
                    counts[leader - 1] += 1;
                }
                None => rejected += 1,
            }
        }
        // 256 / 10 = 25, cutoff = 250, rejected = 6.
        assert_eq!(rejected, 6, "rejection count");
        // Each of the 10 bins gets exactly 25 values.
        for (k, &c) in counts.iter().enumerate() {
            assert_eq!(c, 25, "bin {} has {} values, expected 25", k, c);
        }
    }

    #[test]
    fn exhaustive_uniformity_gf2_4_n5() {
        let mapper = gf2_mapper(4, 5);
        let domain = 16u128;
        let mut counts = vec![0usize; 5];
        let mut rejected = 0usize;
        for v in 0..domain {
            let bytes = coin_bytes_from_u128(v);
            match mapper.try_leader(&bytes) {
                Some(leader) => counts[leader - 1] += 1,
                None => rejected += 1,
            }
        }
        // 16 / 5 = 3, cutoff = 15, rejected = 1.
        assert_eq!(rejected, 1);
        for (k, &c) in counts.iter().enumerate() {
            assert_eq!(c, 3, "bin {} has {} values, expected 3", k, c);
        }
    }

    #[test]
    fn gf2_power_of_two_n_has_zero_rejection() {
        // 2^8 / 4 = 64, so cutoff = 256, no rejection.
        let mapper = gf2_mapper(8, 4);
        assert_eq!(mapper.rejection_bound(), 0.0);
        let mut counts = vec![0usize; 4];
        for v in 0u128..256 {
            let bytes = coin_bytes_from_u128(v);
            let leader = mapper.try_leader(&bytes).expect("should accept");
            counts[leader - 1] += 1;
        }
        for (k, &c) in counts.iter().enumerate() {
            assert_eq!(c, 64, "bin {} has {} values, expected 64", k, c);
        }
    }

    #[test]
    fn gf2_n_equals_1_always_returns_leader_1() {
        let mapper = gf2_mapper(8, 1);
        for v in 0u128..256 {
            let bytes = coin_bytes_from_u128(v);
            assert_eq!(mapper.try_leader(&bytes), Some(1));
        }
    }

    // --- Binary coin ---

    #[test]
    fn gf2_binary_coin_never_rejects() {
        for &w_p in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
            let profile = Gf2Profile::new(w_p, w_p).unwrap();
            let mapper = CoinMapper::for_gf2(profile, 2).unwrap();
            // 2 | 2^w_p always, so rejection bound is 0.
            assert_eq!(
                mapper.rejection_bound(),
                0.0,
                "w_p = {}: binary coin should have zero rejection",
                w_p
            );
            // Spot-check: the all-ones value is accepted.
            let bytes = coin_bytes_from_u128(if w_p < 128 {
                (1u128 << w_p) - 1
            } else {
                u128::MAX
            });
            assert!(
                mapper.try_bit(&bytes).is_some(),
                "w_p = {}: max value should accept",
                w_p
            );
        }
    }

    #[test]
    fn gf2_binary_coin_is_uniform_exhaustive() {
        let profile = Gf2Profile::new(8, 8).unwrap();
        let mapper = CoinMapper::for_gf2(profile, 2).unwrap();
        let mut zeros = 0usize;
        let mut ones = 0usize;
        for v in 0u128..256 {
            let bytes = coin_bytes_from_u128(v);
            match mapper.try_bit(&bytes).unwrap() {
                false => zeros += 1,
                true => ones += 1,
            }
        }
        assert_eq!(zeros, 128);
        assert_eq!(ones, 128);
    }

    // --- BigUint ---

    #[test]
    fn prime_exhaustive_uniformity() {
        // p = 11, n = 4. cutoff = 4 * 2 = 8. Accepted: 0..8.
        let p = BigUint::from(11u32);
        let mapper = CoinMapper::for_prime(&p, 4).unwrap();
        let mut counts = vec![0usize; 4];
        let mut rejected = 0usize;
        for v in 0u32..11 {
            let bytes = BigUint::from(v).to_bytes_be();
            match mapper.try_leader(&bytes) {
                Some(leader) => counts[leader - 1] += 1,
                None => rejected += 1,
            }
        }
        assert_eq!(rejected, 3); // 8, 9, 10
        for (k, &c) in counts.iter().enumerate() {
            assert_eq!(c, 2, "bin {} has {} values, expected 2", k, c);
        }
    }

    #[test]
    fn prime_binary_coin_rejects_exactly_one_value() {
        // p = 11 (odd), n = 2. cutoff = 2 * 5 = 10.
        // Only v = 10 (which is 10 mod 11 = 10 >= 10) is rejected.
        let p = BigUint::from(11u32);
        let mapper = CoinMapper::for_prime(&p, 2).unwrap();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for v in 0u32..11 {
            let bytes = BigUint::from(v).to_bytes_be();
            match mapper.try_bit(&bytes) {
                Some(_) => accepted += 1,
                None => rejected += 1,
            }
        }
        assert_eq!(rejected, 1);
        assert_eq!(accepted, 10);
    }

    // --- Rejection bound ---

    #[test]
    fn rejection_bound_is_correct() {
        let mapper = gf2_mapper(8, 10);
        // 256 mod 10 = 6, so bound = 6/256 = 0.0234375.
        let expected = 6.0 / 256.0;
        assert!((mapper.rejection_bound() - expected).abs() < 1e-12);
    }

    #[test]
    fn rejection_bound_zero_for_divides() {
        let mapper = gf2_mapper(8, 16);
        assert_eq!(mapper.rejection_bound(), 0.0);
    }

    #[test]
    fn rejection_bound_wide_field_is_nonzero() {
        let profile = Gf2Profile::new(64, 256).unwrap();
        let mapper = CoinMapper::for_gf2(profile, 100).unwrap();
        assert!(mapper.rejection_bound() > 0.0);
    }

    // --- first_match scan ---

    #[test]
    fn first_match_picks_earliest_accepted() {
        let mapper = gf2_mapper(8, 10);
        // v = 253 is rejected (253 >= 250), v = 7 is accepted (leader = 8).
        let rejected_bytes = coin_bytes_from_u128(253);
        let accepted_bytes = coin_bytes_from_u128(7);
        let outputs = vec![
            (0usize, 0usize, rejected_bytes.as_slice()),
            (0, 1, accepted_bytes.as_slice()),
        ];
        let result = mapper.first_match(outputs).unwrap();
        assert_eq!(result.leader, 8); // 7 mod 10 + 1
        assert_eq!(result.coin_index, 0);
        assert_eq!(result.sub_index, 1);
    }

    #[test]
    fn first_match_returns_none_when_all_rejected() {
        let mapper = gf2_mapper(4, 5);
        // Domain 16, cutoff 15. Only v = 15 is rejected.
        let bytes = coin_bytes_from_u128(15);
        let outputs = vec![(0usize, 0usize, bytes.as_slice())];
        assert!(mapper.first_match(outputs).is_none());
    }

    // --- Edge cases ---

    #[test]
    fn n_exceeds_domain_is_rejected() {
        let profile = Gf2Profile::new(4, 4).unwrap();
        let result = CoinMapper::for_gf2(profile, 17);
        assert!(result.is_err());
    }

    #[test]
    fn n_zero_is_rejected() {
        let profile = Gf2Profile::new(8, 8).unwrap();
        assert!(CoinMapper::for_gf2(profile, 0).is_err());
        assert!(CoinMapper::for_prime(&BigUint::from(11u32), 0).is_err());
    }

    #[test]
    fn n_equals_domain_has_zero_rejection() {
        // w_p = 4, domain = 16, n = 16. cutoff = 16. No rejection.
        let mapper = gf2_mapper(4, 16);
        assert_eq!(mapper.rejection_bound(), 0.0);
        let mut counts = vec![0usize; 16];
        for v in 0u128..16 {
            let leader = mapper.try_leader(&coin_bytes_from_u128(v)).unwrap();
            counts[leader - 1] += 1;
        }
        for (k, &c) in counts.iter().enumerate() {
            assert_eq!(c, 1, "bin {} should have exactly 1", k);
        }
    }

    // --- Statistical test on wider fields ---

    #[test]
    fn chi_squared_uniformity_gf2_16_n10() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let profile = Gf2Profile::new(16, 16).unwrap();
        let mapper = CoinMapper::for_gf2(profile, 10).unwrap();
        let mut rng = StdRng::seed_from_u64(0x1234);
        let trials = 100_000usize;
        let mut counts = vec![0usize; 10];
        let mut rejected = 0usize;
        for _ in 0..trials {
            let v: u16 = rng.gen();
            let bytes = coin_bytes_from_u128(v as u128);
            match mapper.try_leader(&bytes) {
                Some(leader) => counts[leader - 1] += 1,
                None => rejected += 1,
            }
        }
        let accepted = trials - rejected;
        let expected = accepted as f64 / 10.0;
        let chi2: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        // chi-squared critical value at df=9, alpha=0.001 is 27.88.
        assert!(
            chi2 < 30.0,
            "chi-squared = {:.2} exceeds threshold (counts: {:?})",
            chi2,
            counts
        );
        // Rejection rate should be close to (65536 mod 10) / 65536 = 6/65536 ≈ 0.009%
        let rej_rate = rejected as f64 / trials as f64;
        assert!(
            rej_rate < 0.002,
            "rejection rate {:.4} unexpectedly high",
            rej_rate
        );
    }

    // --- Two-field profiles (w_p != w_q) ---

    #[test]
    fn two_field_profile_uses_small_field() {
        // GF2(8, 64): coins are GF(2^8) elements, domain = 256.
        let profile = Gf2Profile::new(8, 64).unwrap();
        let mapper = CoinMapper::for_gf2(profile, 10).unwrap();
        // The mapper uses w_p = 8, not w_q = 64.
        assert!((mapper.rejection_bound() - 6.0 / 256.0).abs() < 1e-12);
        let bytes = coin_bytes_from_u128(249);
        assert_eq!(mapper.try_leader(&bytes), Some(10)); // 249 mod 10 + 1 = 10
        let bytes = coin_bytes_from_u128(250);
        assert!(mapper.try_leader(&bytes).is_none()); // 250 >= 250
    }

    #[test]
    fn wide_small_field_rejects_the_tail() {
        for &(w_p, w_q) in &[(64usize, 128usize), (64, 256), (128, 256), (128, 128)] {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let mapper = CoinMapper::for_gf2(profile, 100).unwrap();
            assert!(mapper.rejection_bound() > 0.0);
            // 100 does not divide 2^w_p: the maximum value is rejected.
            let bytes = coin_bytes_from_u128(u128::MAX);
            assert!(mapper.try_leader(&bytes).is_none());
        }
    }
}
