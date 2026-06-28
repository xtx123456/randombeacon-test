//! Recursive Karatsuba multiplication over the quadratic-tower
//! construction `GF(2^w_q) ⊃ GF(2^w_p)`.
//!
//! Layout of an element
//! --------------------
//!
//! At every tower level `w`, an element is encoded as the low `w` bits
//! of a `u128` (for `w ≤ 128`) or as a `(u128, u128)` "lo, hi" pair
//! (for `w = 256`). Within each level the encoding is split into two
//! halves of `w/2` bits each:
//!
//! ```text
//!     element = a_lo + y · a_hi          (mod  m(y) = y² + y + α)
//! ```
//!
//! where `a_lo, a_hi ∈ GF(2^(w/2))` and `α` is `profile::quadratic_alpha(w/2)`.
//! `m(y)` is irreducible over `GF(2^(w/2))` because `α` was chosen so
//! `Tr_{GF(2^(w/2))/F_2}(α) = 1` (Artin-Schreier), see
//! `profile::quadratic_alpha` and the `tower_alphas_have_trace_one`
//! test.
//!
//! Multiplication recurrence (Karatsuba, char-2 simplifications)
//! -------------------------------------------------------------
//!
//! `(a_lo + a_hi · y)(b_lo + b_hi · y)` modulo `y² + y + α`:
//!
//! ```text
//!     y² ≡ y + α
//!     so the cross-term y² · (a_hi · b_hi) becomes
//!     (y + α) · (a_hi · b_hi) = y · t1 + α · t1   where t1 = a_hi · b_hi.
//! ```
//!
//! Karatsuba in characteristic 2:
//!
//! ```text
//!     a_lo · b_hi + a_hi · b_lo  =  (a_lo + a_hi)(b_lo + b_hi) + a_lo·b_lo + a_hi·b_hi
//! ```
//!
//! gives:
//!
//! ```text
//!     low_out  = t0 + α · t1
//!     high_out = t0 + t2
//! ```
//!
//! with `t0 = a_lo · b_lo`, `t1 = a_hi · b_hi`, `t2 = (a_lo + a_hi)(b_lo + b_hi)`.
//! Three recursive multiplications + one extra by `α`. The α-multiply
//! is itself a sub-field multiplication, so it could share a Karatsuba
//! triple if `α` is sparse (1 set bit by construction in our registry).
//!
//! Inversion
//! ---------
//!
//! For tower elements we exploit the same `m(y) = y² + y + α` identity:
//!
//! ```text
//!     (a_lo + a_hi · y)(a_lo + a_hi · (y+1))
//!         = a_lo² + a_lo · a_hi · (y + (y+1)) + a_hi² · y · (y+1)
//!         = a_lo² + a_lo · a_hi + a_hi² · α            (a constant in the subfield)
//! ```
//!
//! The right-hand side `N = a_lo² + a_lo·a_hi + α · a_hi²` lives in the
//! sub-field `GF(2^(w/2))` (the relative norm). Inverting `a` therefore
//! reduces to one sub-field inverse plus a few sub-field multiplies.

use super::poly;
use super::profile::{self, Gf2Profile};

/// Multiply two GF(2^level_w) elements packed into the low `level_w`
/// bits of a `u128`. Recurses through every quadratic level down to
/// the base field `GF(2^w_p)` where it dispatches to `poly::gf_mul`.
///
/// Pre: `level_w` ∈ `{w_p, 2*w_p, 4*w_p, ..., 128}`.
/// Pre: the high `(128 − level_w)` bits of `a, b` are zero.
pub fn mul_u128(profile: &Gf2Profile, level_w: usize, a: u128, b: u128) -> u128 {
    debug_assert!(level_w <= 128);
    if level_w == profile.w_p {
        let m_p = profile::base_irreducible(profile.w_p)
            .expect("profile invariant: base_irreducible registered");
        return poly::gf_mul(a, b, profile.w_p, m_p);
    }
    let half = level_w / 2;
    let mask_half: u128 = mask_low(half);

    let a_lo = a & mask_half;
    let a_hi = (a >> half) & mask_half;
    let b_lo = b & mask_half;
    let b_hi = (b >> half) & mask_half;

    let t0 = mul_u128(profile, half, a_lo, b_lo);
    let t1 = mul_u128(profile, half, a_hi, b_hi);
    let t2 = mul_u128(profile, half, a_lo ^ a_hi, b_lo ^ b_hi);

    let alpha = profile::quadratic_alpha(half)
        .expect("profile invariant: alpha registered for every level visited");
    let alpha_t1 = mul_u128(profile, half, alpha, t1);

    let lo_out = t0 ^ alpha_t1;
    let hi_out = t0 ^ t2;

    (lo_out & mask_half) | ((hi_out & mask_half) << half)
}

/// Square a GF(2^level_w) element; same precondition as `mul_u128`.
/// Char-2 squaring is `F_2`-linear, so the recursion is shorter than
/// general multiplication: at each level the cross-term `(a_hi · y)·(a_hi · y)`
/// vanishes because `2 a_lo a_hi y = 0`.
pub fn sqr_u128(profile: &Gf2Profile, level_w: usize, a: u128) -> u128 {
    debug_assert!(level_w <= 128);
    if level_w == profile.w_p {
        let m_p = profile::base_irreducible(profile.w_p).expect("registered");
        return poly::gf_sqr(a, profile.w_p, m_p);
    }
    let half = level_w / 2;
    let mask_half = mask_low(half);
    let a_lo = a & mask_half;
    let a_hi = (a >> half) & mask_half;

    // (a_lo + a_hi · y)^2 = a_lo² + a_hi² · y² = a_lo² + a_hi² · (y + α)
    //                    = (a_lo² + α · a_hi²) + a_hi² · y
    let s_lo = sqr_u128(profile, half, a_lo);
    let s_hi = sqr_u128(profile, half, a_hi);
    let alpha = profile::quadratic_alpha(half).expect("registered");
    let alpha_shi = mul_u128(profile, half, alpha, s_hi);
    let lo_out = s_lo ^ alpha_shi;
    let hi_out = s_hi;
    (lo_out & mask_half) | ((hi_out & mask_half) << half)
}

/// Invert a nonzero GF(2^level_w) element using the recursive norm
/// identity (see module docstring). Returns 0 if `a == 0`.
pub fn inv_u128(profile: &Gf2Profile, level_w: usize, a: u128) -> u128 {
    debug_assert!(level_w <= 128);
    if a == 0 {
        return 0;
    }
    if level_w == profile.w_p {
        let m_p = profile::base_irreducible(profile.w_p).expect("registered");
        return poly::gf_inv(a, profile.w_p, m_p);
    }
    let half = level_w / 2;
    let mask_half = mask_low(half);
    let a_lo = a & mask_half;
    let a_hi = (a >> half) & mask_half;
    let alpha = profile::quadratic_alpha(half).expect("registered");

    // Norm to subfield: N = a_lo² + a_lo · a_hi + α · a_hi²
    let a_lo_sq = sqr_u128(profile, half, a_lo);
    let a_hi_sq = sqr_u128(profile, half, a_hi);
    let cross = mul_u128(profile, half, a_lo, a_hi);
    let alpha_a_hi_sq = mul_u128(profile, half, alpha, a_hi_sq);
    let norm = a_lo_sq ^ cross ^ alpha_a_hi_sq;

    // (a_lo + a_hi y) · (a_lo + a_hi (y+1)) = N. So
    //   a^{-1} = N^{-1} · (a_lo + a_hi · (y + 1))
    //          = N^{-1} · ((a_lo + a_hi) + a_hi · y)
    let n_inv = inv_u128(profile, half, norm);
    let new_lo = mul_u128(profile, half, n_inv, a_lo ^ a_hi);
    let new_hi = mul_u128(profile, half, n_inv, a_hi);

    (new_lo & mask_half) | ((new_hi & mask_half) << half)
}

/// Multiply two GF(2^256) elements, where each operand is a (lo, hi)
/// pair of `u128` halves. Used only when `profile.w_q == 256`.
///
/// One Karatsuba step at the top level expands to three sub-field
/// multiplications at level `128`, each of which uses `mul_u128`.
pub fn mul_u256(profile: &Gf2Profile, a: (u128, u128), b: (u128, u128)) -> (u128, u128) {
    debug_assert_eq!(profile.w_q, 256);
    // Each operand: low half = a.0 (bits 0..127), high half = a.1 (bits 128..255).
    let half = 128usize;
    let t0 = mul_u128(profile, half, a.0, b.0);
    let t1 = mul_u128(profile, half, a.1, b.1);
    let t2 = mul_u128(profile, half, a.0 ^ a.1, b.0 ^ b.1);

    let alpha = profile::quadratic_alpha(half).expect("registered");
    let alpha_t1 = mul_u128(profile, half, alpha, t1);

    (t0 ^ alpha_t1, t0 ^ t2)
}

/// Square a GF(2^256) element. See `sqr_u128` for the recurrence.
pub fn sqr_u256(profile: &Gf2Profile, a: (u128, u128)) -> (u128, u128) {
    debug_assert_eq!(profile.w_q, 256);
    let half = 128usize;
    let s_lo = sqr_u128(profile, half, a.0);
    let s_hi = sqr_u128(profile, half, a.1);
    let alpha = profile::quadratic_alpha(half).expect("registered");
    let alpha_shi = mul_u128(profile, half, alpha, s_hi);
    (s_lo ^ alpha_shi, s_hi)
}

/// Invert a nonzero GF(2^256) element. Returns `(0, 0)` for the zero
/// input. See `inv_u128` for the norm-based recurrence.
pub fn inv_u256(profile: &Gf2Profile, a: (u128, u128)) -> (u128, u128) {
    debug_assert_eq!(profile.w_q, 256);
    if a.0 == 0 && a.1 == 0 {
        return (0, 0);
    }
    let half = 128usize;
    let alpha = profile::quadratic_alpha(half).expect("registered");

    let a_lo_sq = sqr_u128(profile, half, a.0);
    let a_hi_sq = sqr_u128(profile, half, a.1);
    let cross = mul_u128(profile, half, a.0, a.1);
    let alpha_a_hi_sq = mul_u128(profile, half, alpha, a_hi_sq);
    let norm = a_lo_sq ^ cross ^ alpha_a_hi_sq;

    let n_inv = inv_u128(profile, half, norm);
    let new_lo = mul_u128(profile, half, n_inv, a.0 ^ a.1);
    let new_hi = mul_u128(profile, half, n_inv, a.1);
    (new_lo, new_hi)
}

/// Build the `u128` mask covering bits `0..w` (inclusive of bit
/// `w − 1`). Special-cases `w = 128` to avoid `1u128 << 128` UB.
#[inline]
pub(crate) fn mask_low(w: usize) -> u128 {
    if w >= 128 {
        u128::MAX
    } else {
        (1u128 << w) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_in_w(rng: &mut impl rand::Rng, w: usize) -> u128 {
        let r = rng.gen::<u128>();
        r & mask_low(w)
    }

    fn rand_in_w_q_256(rng: &mut impl rand::Rng) -> (u128, u128) {
        (rng.gen::<u128>(), rng.gen::<u128>())
    }

    /// Field axioms: a · 1 = a, a · 0 = 0, a · b = b · a, distributivity.
    #[test]
    fn field_axioms_at_various_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xc0ffee);
        for &(w_p, w_q) in &[
            (8usize, 8usize),
            (8, 16),
            (8, 64),
            (8, 128),
            (16, 64),
            (32, 64),
            (32, 128),
            (64, 64),
            (64, 128),
            (128, 128),
        ] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..16 {
                let a = rand_in_w(&mut rng, w_q);
                let b = rand_in_w(&mut rng, w_q);
                let c = rand_in_w(&mut rng, w_q);
                let one: u128 = 1;
                let zero: u128 = 0;

                // Identity / zero
                assert_eq!(mul_u128(&p, w_q, a, one), a, "a·1 ≠ a at ({},{})", w_p, w_q);
                assert_eq!(mul_u128(&p, w_q, a, zero), 0, "a·0 ≠ 0");
                // Commutativity
                assert_eq!(
                    mul_u128(&p, w_q, a, b),
                    mul_u128(&p, w_q, b, a),
                    "non-commutative at ({},{})",
                    w_p,
                    w_q
                );
                // Distributivity: a·(b+c) = a·b + a·c
                let bc = b ^ c;
                let lhs = mul_u128(&p, w_q, a, bc);
                let rhs = mul_u128(&p, w_q, a, b) ^ mul_u128(&p, w_q, a, c);
                assert_eq!(lhs, rhs, "non-distributive at ({},{})", w_p, w_q);
                // sqr_u128 matches mul_u128(a, a)
                let sa = sqr_u128(&p, w_q, a);
                let mma = mul_u128(&p, w_q, a, a);
                assert_eq!(sa, mma, "sqr ≠ mul(a,a) at ({},{})", w_p, w_q);
            }
        }
    }

    #[test]
    fn inverse_is_correct_at_various_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdeadbeef);
        for &(w_p, w_q) in &[
            (8usize, 8usize),
            (8, 16),
            (8, 32),
            (8, 64),
            (16, 64),
            (32, 64),
            (32, 128),
            (64, 64),
            (64, 128),
            (128, 128),
        ] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..32 {
                let a = rand_in_w(&mut rng, w_q);
                if a == 0 {
                    continue;
                }
                let inv = inv_u128(&p, w_q, a);
                let prod = mul_u128(&p, w_q, a, inv);
                assert_eq!(
                    prod, 1,
                    "a · a^-1 ≠ 1: w_p={} w_q={} a={:#x} inv={:#x} prod={:#x}",
                    w_p, w_q, a, inv, prod
                );
            }
        }
    }

    /// `inv_u128(0)` returns `0` — caller should never use this, but
    /// we want predictable behaviour rather than panic.
    #[test]
    fn inv_of_zero_is_zero_sentinel() {
        let p = Gf2Profile::new(64, 128).unwrap();
        assert_eq!(inv_u128(&p, 128, 0), 0);
    }

    #[test]
    fn baseline_field_axioms_at_w_q_256() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xa1b2c3d4);
        for &(w_p, w_q) in &[(64usize, 256usize), (32, 256), (8, 256), (128, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..8 {
                let a = rand_in_w_q_256(&mut rng);
                let b = rand_in_w_q_256(&mut rng);
                let c = rand_in_w_q_256(&mut rng);
                let one = (1u128, 0u128);
                let zero = (0u128, 0u128);

                let prod_one = mul_u256(&p, a, one);
                assert_eq!(prod_one, a);
                let prod_zero = mul_u256(&p, a, zero);
                assert_eq!(prod_zero, zero);

                let p_ab = mul_u256(&p, a, b);
                let p_ba = mul_u256(&p, b, a);
                assert_eq!(p_ab, p_ba, "non-commutative");

                let bc = (b.0 ^ c.0, b.1 ^ c.1);
                let lhs = mul_u256(&p, a, bc);
                let p_ab = mul_u256(&p, a, b);
                let p_ac = mul_u256(&p, a, c);
                let rhs = (p_ab.0 ^ p_ac.0, p_ab.1 ^ p_ac.1);
                assert_eq!(lhs, rhs, "non-distributive at ({},{})", w_p, w_q);

                let sa = sqr_u256(&p, a);
                let maa = mul_u256(&p, a, a);
                assert_eq!(sa, maa, "sqr ≠ mul(a,a) at w_q=256");
            }
        }
    }

    #[test]
    fn inverse_at_w_q_256() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for &(w_p, w_q) in &[(64usize, 256usize), (32, 256), (128, 256), (8, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..8 {
                let a = rand_in_w_q_256(&mut rng);
                if a == (0, 0) {
                    continue;
                }
                let inv = inv_u256(&p, a);
                let prod = mul_u256(&p, a, inv);
                assert_eq!(
                    prod,
                    (1, 0),
                    "a · a^-1 ≠ 1 at ({},{}): a={:?} inv={:?} prod={:?}",
                    w_p,
                    w_q,
                    a,
                    inv,
                    prod
                );
            }
        }
    }

    /// `(w_p, w_p)` profiles must give the same arithmetic as raw
    /// `poly::gf_mul`. Validates that the recursion's base case
    /// dispatches correctly with no off-by-one at the boundary.
    #[test]
    fn baseline_matches_poly_when_w_q_eq_w_p() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeedface);
        for &w in &[8usize, 16, 32, 64, 128] {
            let p = Gf2Profile::new(w, w).unwrap();
            let m = profile::base_irreducible(w).unwrap();
            for _ in 0..32 {
                let a = rand_in_w(&mut rng, w);
                let b = rand_in_w(&mut rng, w);
                let via_tower = mul_u128(&p, w, a, b);
                let via_poly = poly::gf_mul(a, b, w, m);
                assert_eq!(via_tower, via_poly, "tower ≠ poly at w={}", w);
            }
        }
    }
}
