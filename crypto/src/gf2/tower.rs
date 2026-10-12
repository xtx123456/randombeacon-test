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
//! where `a_lo, a_hi ∈ GF(2^(w/2))` and `α` is
//! `profile::quadratic_alpha(w_p, w/2)`. `m(y)` is irreducible over
//! `GF(2^(w/2))` because `α` was chosen so `Tr_{GF(2^(w/2))/F_2}(α) = 1`
//! (Artin-Schreier) **in this tower's representation** — the trace
//! condition is representation-sensitive, which is why `α` is keyed by
//! the tower base width `w_p` and not by the level alone. See
//! `profile::quadratic_alpha` and the
//! `tower_alpha_trace_is_one_in_tower_representation` test below,
//! which recomputes the trace from its definition using this module's
//! own arithmetic.
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

    let alpha = profile::quadratic_alpha(profile.w_p, half)
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
    let alpha = profile::quadratic_alpha(profile.w_p, half).expect("registered");
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
    let alpha = profile::quadratic_alpha(profile.w_p, half).expect("registered");

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

    let alpha = profile::quadratic_alpha(profile.w_p, half).expect("registered");
    let alpha_t1 = mul_u128(profile, half, alpha, t1);

    (t0 ^ alpha_t1, t0 ^ t2)
}

/// Square a GF(2^256) element. See `sqr_u128` for the recurrence.
pub fn sqr_u256(profile: &Gf2Profile, a: (u128, u128)) -> (u128, u128) {
    debug_assert_eq!(profile.w_q, 256);
    let half = 128usize;
    let s_lo = sqr_u128(profile, half, a.0);
    let s_hi = sqr_u128(profile, half, a.1);
    let alpha = profile::quadratic_alpha(profile.w_p, half).expect("registered");
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
    let alpha = profile::quadratic_alpha(profile.w_p, half).expect("registered");

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

/// Multiply a full `GF(2^level_w)` element by a **base-field** scalar
/// `b_small ∈ GF(2^w_p)`, bypassing the Karatsuba recursion.
///
/// Why this is a strictly cheaper, equal-valued path
/// -------------------------------------------------
///
/// `L = GF(2^level_w)` is a vector space over `K = GF(2^w_p)` of
/// dimension `e = level_w / w_p`. The quadratic-tower encoding lays an
/// element out as exactly `e` consecutive `w_p`-bit chunks, and those
/// chunks ARE the coordinates with respect to a `K`-basis of `L`
/// (recursively, the products of the per-level `y` generators). For a
/// scalar `b ∈ K`, `K`-linearity gives
///
/// ```text
///     a · b  =  (Σ_k a_k · B_k) · b  =  Σ_k (a_k · b) · B_k
/// ```
///
/// so the product is obtained by scaling each coordinate
/// independently — the cross terms that general multiplication has to
/// fold back through `y² ≡ y + α` never arise, because `b` has no
/// component outside `K`.
///
/// Cost: `e` base-field multiplies instead of the `e^log2(3)`
/// (≈ `e^1.585`) that Karatsuba needs, e.g. 8 vs 27 at `(32, 256)` and
/// 32 vs 243 at `(8, 256)`.
///
/// # Precondition
///
/// `b_small` MUST lie in the low `w_p` bits. This is a correctness
/// precondition, not a hint: if `b_small` has a component outside the
/// base field the coordinate-wise formula silently computes the wrong
/// product. Callers must have established the invariant by
/// construction or by an explicit membership check — never by
/// assumption about unvalidated input. The control flow here depends
/// only on the public widths `w_p` and `level_w`, so routing a value
/// through this path leaks nothing about it that the general path
/// would not.
pub fn mul_by_small_u128(profile: &Gf2Profile, level_w: usize, a: u128, b_small: u128) -> u128 {
    debug_assert!(level_w <= 128);
    debug_assert_eq!(
        b_small & !mask_low(profile.w_p),
        0,
        "mul_by_small: scalar must lie in the base field GF(2^w_p)"
    );
    let w_p = profile.w_p;
    let m_p = profile::base_irreducible(w_p).expect("profile invariant: registered base");
    if level_w == w_p {
        return poly::gf_mul(a, b_small, w_p, m_p);
    }
    let chunk_mask = mask_low(w_p);
    let chunks = level_w / w_p;
    let mut out: u128 = 0;
    for k in 0..chunks {
        let shift = k * w_p;
        let coord = (a >> shift) & chunk_mask;
        // No `coord == 0` shortcut: skipping would make the trip count
        // depend on the operand's bit pattern for no real saving.
        out |= poly::gf_mul(coord, b_small, w_p, m_p) << shift;
    }
    out
}

/// `mul_by_small_u128` for the `w_q == 256` envelope. The 256-bit flat
/// encoding is `256 / w_p` chunks of `w_p` bits, so scaling each
/// `u128` half independently scales every coordinate exactly once.
///
/// Same base-field precondition on `b_small` as `mul_by_small_u128`.
pub fn mul_by_small_u256(profile: &Gf2Profile, a: (u128, u128), b_small: u128) -> (u128, u128) {
    debug_assert_eq!(profile.w_q, 256);
    debug_assert_eq!(
        128 % profile.w_p,
        0,
        "w_p must divide 128 for the 256-bit envelope to split evenly"
    );
    (
        mul_by_small_u128(profile, 128, a.0, b_small),
        mul_by_small_u128(profile, 128, a.1, b_small),
    )
}

/// Absolute trace `Tr_{GF(2^level_w)/F_2}(a) = a + a² + a⁴ + … +
/// a^(2^(level_w − 1))`, computed **from the definition** using this
/// module's own tower squaring.
///
/// This is deliberately the slow, unoptimised route: it exists so the
/// closed-form `α` table in `profile.rs` (which is derived from the
/// "relative trace = high coordinate" identity) can be cross-checked
/// against an independent computation instead of against itself. The
/// result always lands in `{0, 1}` for a well-formed tower; a value
/// outside that set is itself evidence that the level is not a field.
pub fn absolute_trace(profile: &Gf2Profile, level_w: usize, a: u128) -> u128 {
    let mut t: u128 = 0;
    let mut cur = a;
    for _ in 0..level_w {
        t ^= cur;
        cur = sqr_u128(profile, level_w, cur);
    }
    t
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

    use rand::Rng as _;

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

    /// Every `(w_p, w_q)` profile the registry admits, enumerated so
    /// the field-law tests below cannot quietly skip a configuration.
    fn all_supported_profiles() -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for &w_p in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
            let mut w_q = w_p;
            while w_q <= 256 {
                if Gf2Profile::new(w_p, w_q).is_ok() {
                    out.push((w_p, w_q));
                }
                w_q *= 2;
            }
        }
        out
    }

    /// **Core correctness gate for the tower construction.**
    ///
    /// For every registered base width and every tower level built on
    /// it, the `α` that `profile::quadratic_alpha` hands to the
    /// Karatsuba step must satisfy `Tr(α) = 1` *in the representation
    /// this module actually computes in*. Artin-Schreier then makes
    /// `y² + y + α` irreducible, which is exactly what makes the next
    /// level a field rather than a ring with zero divisors.
    ///
    /// The trace is recomputed from its definition
    /// (`a + a² + a⁴ + …` via `absolute_trace`), NOT from the
    /// high-coordinate identity used to build the table, so this is a
    /// genuine cross-check between two different computations.
    ///
    /// Regression: before the base-keyed α table, this failed at
    /// `(base 8, level ≥ 16)`, `(base 16, level ≥ 32)` and
    /// `(base 64, level 128)`, which is what broke `GF2(8,64)`,
    /// `GF2(8,256)`, `GF2(16,64)` and `GF2(64,256)`.
    #[test]
    fn tower_alpha_trace_is_one_in_tower_representation() {
        for &base_w in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
            let mut level_w = base_w;
            while level_w <= 128 {
                // Arithmetic at `level_w` only needs α for levels
                // strictly below it, which earlier iterations already
                // validated — so the induction is well-founded.
                let p = Gf2Profile::new(base_w, level_w).expect("registered profile");
                let alpha = profile::quadratic_alpha(base_w, level_w).expect("registered α");
                let tr = absolute_trace(&p, level_w, alpha);
                assert_eq!(
                    tr,
                    1,
                    "Tr_(tower GF(2^{}) over base {})({:#x}) = {} — y² + y + α is \
                     REDUCIBLE, so level {} would not be a field",
                    level_w,
                    base_w,
                    alpha,
                    tr,
                    level_w * 2
                );
                level_w *= 2;
            }
        }
    }

    /// The closed form in `profile.rs` rests on
    /// `Tr_{L/K}(a_lo + a_hi·y) = a_hi`, i.e. the relative trace of a
    /// quadratic Artin-Schreier extension is just the high coordinate.
    /// Check that against the definition-based absolute trace via
    /// transitivity `Tr_{L/F_2} = Tr_{K/F_2} ∘ Tr_{L/K}`.
    #[test]
    fn relative_trace_equals_high_coordinate() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x7ace);
        for &(base_w, level_w) in &[(8usize, 16usize), (8, 32), (16, 32), (32, 64), (64, 128)] {
            let half = level_w / 2;
            let p_full = Gf2Profile::new(base_w, level_w).unwrap();
            let p_half = Gf2Profile::new(base_w, half).unwrap();
            for _ in 0..16 {
                let a = rand_in_w(&mut rng, level_w);
                let a_hi = (a >> half) & mask_low(half);
                assert_eq!(
                    absolute_trace(&p_full, level_w, a),
                    absolute_trace(&p_half, half, a_hi),
                    "transitivity broken at base={} level={} a={:#x}",
                    base_w,
                    level_w,
                    a
                );
            }
        }
    }

    /// Direct irreducibility check by exhaustive root search, for the
    /// levels where `2^half` is small enough to enumerate. `y² + y + α`
    /// is reducible over `GF(2^half)` exactly when some `c` satisfies
    /// `c² + c = α`. This avoids relying on Artin-Schreier at all.
    #[test]
    fn no_artin_schreier_root_exhaustive_at_small_levels() {
        for &(base_w, half) in &[(8usize, 8usize), (8, 16), (16, 16), (4, 8), (2, 8), (1, 8)] {
            let p = Gf2Profile::new(base_w, half).unwrap();
            let alpha = profile::quadratic_alpha(base_w, half).unwrap();
            let limit = 1u128 << half;
            let mut found: Option<u128> = None;
            let mut c: u128 = 0;
            while c < limit {
                if sqr_u128(&p, half, c) ^ c == alpha {
                    found = Some(c);
                    break;
                }
                c += 1;
            }
            assert!(
                found.is_none(),
                "y² + y + {:#x} has root {:#x} over tower GF(2^{}) rooted at {} \
                 — the extension is reducible",
                alpha,
                found.unwrap(),
                half,
                base_w
            );
        }
    }

    /// Regression for the two reported zero-divisor counterexamples.
    /// Under the old level-keyed α these products were exactly zero
    /// despite both operands being nonzero.
    #[test]
    fn reported_zero_divisors_are_gone() {
        // GF2(8,64): a = 0x187a2, b = 0x187a3.
        let p = Gf2Profile::new(8, 64).unwrap();
        let a: u128 = 0x187a2;
        let b: u128 = 0x187a3;
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(
            mul_u128(&p, 64, a, b),
            0,
            "GF2(8,64): {:#x} · {:#x} must not be zero in a field",
            a,
            b
        );

        // GF2(64,256): the 256-bit pair reported in the audit.
        let p256 = Gf2Profile::new(64, 256).unwrap();
        let a2 = (0x1e0d022a05393ffcc1d98b6c5c00e678u128, 0x1u128);
        let b2 = (0x1e0d022a05393ffcc1d98b6c5c00e679u128, 0x1u128);
        assert_ne!(
            mul_u256(&p256, a2, b2),
            (0, 0),
            "GF2(64,256): reported pair must not multiply to zero"
        );
    }

    /// A field has no zero divisors. Randomised sweep across every
    /// supported profile — this is the property that the broken α
    /// silently violated for four of them.
    #[test]
    fn no_zero_divisors_across_all_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x2026_1012);
        for (w_p, w_q) in all_supported_profiles() {
            // GF(2^1) and GF(2^2) are too small for a meaningful
            // random sweep but are covered by the exhaustive tests.
            if w_q < 4 {
                continue;
            }
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..24 {
                if w_q <= 128 {
                    let a = rand_in_w(&mut rng, w_q);
                    let b = rand_in_w(&mut rng, w_q);
                    if a == 0 || b == 0 {
                        continue;
                    }
                    assert_ne!(
                        mul_u128(&p, w_q, a, b),
                        0,
                        "zero divisor at ({},{}) : {:#x} · {:#x}",
                        w_p,
                        w_q,
                        a,
                        b
                    );
                } else {
                    let a = rand_in_w_q_256(&mut rng);
                    let b = rand_in_w_q_256(&mut rng);
                    if a == (0, 0) || b == (0, 0) {
                        continue;
                    }
                    assert_ne!(
                        mul_u256(&p, a, b),
                        (0, 0),
                        "zero divisor at ({},{})",
                        w_p,
                        w_q
                    );
                }
            }
        }
    }

    /// Associativity across every supported profile. Karatsuba with a
    /// reducible modulus can stay commutative and distributive while
    /// failing associativity, so this is checked separately from
    /// `field_axioms_at_various_profiles`.
    #[test]
    fn associativity_across_all_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xa550c);
        for (w_p, w_q) in all_supported_profiles() {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..12 {
                if w_q <= 128 {
                    let a = rand_in_w(&mut rng, w_q);
                    let b = rand_in_w(&mut rng, w_q);
                    let c = rand_in_w(&mut rng, w_q);
                    let lhs = mul_u128(&p, w_q, mul_u128(&p, w_q, a, b), c);
                    let rhs = mul_u128(&p, w_q, a, mul_u128(&p, w_q, b, c));
                    assert_eq!(lhs, rhs, "non-associative at ({},{})", w_p, w_q);
                } else {
                    let a = rand_in_w_q_256(&mut rng);
                    let b = rand_in_w_q_256(&mut rng);
                    let c = rand_in_w_q_256(&mut rng);
                    let lhs = mul_u256(&p, mul_u256(&p, a, b), c);
                    let rhs = mul_u256(&p, a, mul_u256(&p, b, c));
                    assert_eq!(lhs, rhs, "non-associative at ({},{})", w_p, w_q);
                }
            }
        }
    }

    /// Every nonzero element must be invertible, across every
    /// supported profile (not just the hand-picked subset the
    /// original tests used).
    #[test]
    fn every_nonzero_is_invertible_across_all_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1117_5e5);
        for (w_p, w_q) in all_supported_profiles() {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..12 {
                if w_q <= 128 {
                    let a = rand_in_w(&mut rng, w_q);
                    if a == 0 {
                        continue;
                    }
                    assert_eq!(
                        mul_u128(&p, w_q, a, inv_u128(&p, w_q, a)),
                        1,
                        "a·a⁻¹ ≠ 1 at ({},{}) a={:#x}",
                        w_p,
                        w_q,
                        a
                    );
                } else {
                    let a = rand_in_w_q_256(&mut rng);
                    if a == (0, 0) {
                        continue;
                    }
                    assert_eq!(
                        mul_u256(&p, a, inv_u256(&p, a)),
                        (1, 0),
                        "a·a⁻¹ ≠ 1 at ({},{})",
                        w_p,
                        w_q
                    );
                }
            }
        }
    }

    /// The multiplicative group of `GF(2^w)` has order `2^w − 1`, so
    /// `a^(2^w) = a` for every element. Checked by `w` repeated
    /// squarings — an independent structural witness that the level
    /// really has `2^w` elements forming a field (a reducible modulus
    /// fails this).
    #[test]
    fn frobenius_order_matches_field_size() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xf20b);
        for (w_p, w_q) in all_supported_profiles() {
            if w_q > 128 {
                continue; // sqr_u256 path covered by inverse/assoc tests
            }
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..6 {
                let a = rand_in_w(&mut rng, w_q);
                let mut cur = a;
                for _ in 0..w_q {
                    cur = sqr_u128(&p, w_q, cur);
                }
                assert_eq!(
                    cur, a,
                    "a^(2^{}) ≠ a at ({},{}) a={:#x} — level is not GF(2^{})",
                    w_q, w_p, w_q, a, w_q
                );
            }
        }
    }

    /// The `mul_by_small` fast path must agree with the general
    /// (fixed) tower multiplication **exactly**, for every supported
    /// profile, on zero, one, the base-field generator, and random
    /// values. If these ever diverge, the optimisation is changing
    /// results rather than just saving work.
    #[test]
    fn mul_by_small_matches_general_mul_across_all_profiles() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ca1ab1e);
        for (w_p, w_q) in all_supported_profiles() {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let small_mask = mask_low(w_p);

            // Deterministic edge cases plus random draws.
            let mut small_vals: Vec<u128> = vec![0, 1, small_mask];
            if w_p >= 2 {
                small_vals.push(2);
            }
            for _ in 0..8 {
                small_vals.push(rng.gen::<u128>() & small_mask);
            }

            for &b in &small_vals {
                if w_q <= 128 {
                    let mut a_vals: Vec<u128> = vec![0, 1, mask_low(w_q)];
                    for _ in 0..8 {
                        a_vals.push(rand_in_w(&mut rng, w_q));
                    }
                    for &a in &a_vals {
                        assert_eq!(
                            mul_by_small_u128(&p, w_q, a, b),
                            mul_u128(&p, w_q, a, b),
                            "mul_by_small ≠ mul at ({},{}) a={:#x} b={:#x}",
                            w_p,
                            w_q,
                            a,
                            b
                        );
                    }
                } else {
                    let mut a_vals: Vec<(u128, u128)> =
                        vec![(0, 0), (1, 0), (u128::MAX, u128::MAX)];
                    for _ in 0..6 {
                        a_vals.push(rand_in_w_q_256(&mut rng));
                    }
                    let b_elem = (b, 0u128);
                    for &a in &a_vals {
                        assert_eq!(
                            mul_by_small_u256(&p, a, b),
                            mul_u256(&p, a, b_elem),
                            "mul_by_small ≠ mul at ({},{}) a={:?} b={:#x}",
                            w_p,
                            w_q,
                            a,
                            b
                        );
                    }
                }
            }
        }
    }

    /// `mul_by_small` must still obey the algebra it claims: it is
    /// `K`-linear in the large operand and multiplicative in the
    /// scalar.
    #[test]
    fn mul_by_small_is_linear_and_multiplicative() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xb1_11ea4);
        for &(w_p, w_q) in &[(8usize, 64usize), (16, 64), (32, 128), (64, 128)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let m_p = profile::base_irreducible(w_p).unwrap();
            let small_mask = mask_low(w_p);
            for _ in 0..16 {
                let a1 = rand_in_w(&mut rng, w_q);
                let a2 = rand_in_w(&mut rng, w_q);
                let b1 = rng.gen::<u128>() & small_mask;
                let b2 = rng.gen::<u128>() & small_mask;

                // Linear in the large operand: (a1 + a2)·b = a1·b + a2·b
                assert_eq!(
                    mul_by_small_u128(&p, w_q, a1 ^ a2, b1),
                    mul_by_small_u128(&p, w_q, a1, b1) ^ mul_by_small_u128(&p, w_q, a2, b1),
                    "not additive at ({},{})",
                    w_p,
                    w_q
                );
                // Multiplicative in the scalar: a·(b1·b2) = (a·b1)·b2
                let b_prod = poly::gf_mul(b1, b2, w_p, m_p);
                assert_eq!(
                    mul_by_small_u128(&p, w_q, a1, b_prod),
                    mul_by_small_u128(&p, w_q, mul_by_small_u128(&p, w_q, a1, b1), b2),
                    "scalar action not associative at ({},{})",
                    w_p,
                    w_q
                );
            }
        }
    }

    /// The whole two-field construction rests on the claim that the
    /// bit pattern of a `GF(2^w_p)` element, read as the low `w_p`
    /// bits of a `GF(2^w_q)` element, really is the image of the
    /// subfield embedding — i.e. that it preserves `0`, `1`, addition
    /// and multiplication.
    ///
    /// Addition is XOR on both sides, so the content is in the
    /// multiplicative law: `emb(a ·_K b) == emb(a) ·_L emb(b)`, where
    /// the left product is computed by `poly::gf_mul` in the base
    /// field's own polynomial basis and the right one by the full
    /// tower multiplication. The two use entirely different code
    /// paths, so agreement is a real cross-check rather than one
    /// function confirming itself.
    #[test]
    fn subfield_embedding_is_a_ring_homomorphism() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x3_b3d);
        for (w_p, w_q) in all_supported_profiles() {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let m_p = profile::base_irreducible(w_p).unwrap();
            let small_mask = mask_low(w_p);

            // emb(1) must be the large field's multiplicative
            // identity, not merely the integer 1.
            if w_q <= 128 {
                for _ in 0..8 {
                    let a = rand_in_w(&mut rng, w_q);
                    assert_eq!(
                        mul_u128(&p, w_q, a, 1),
                        a,
                        "emb(1) is not the identity at ({},{})",
                        w_p,
                        w_q
                    );
                }
            } else {
                for _ in 0..8 {
                    let a = rand_in_w_q_256(&mut rng);
                    assert_eq!(
                        mul_u256(&p, a, (1, 0)),
                        a,
                        "emb(1) is not the identity at ({},{})",
                        w_p,
                        w_q
                    );
                }
            }

            let mut vals: Vec<u128> = vec![0, 1, small_mask];
            if w_p >= 2 {
                vals.push(2);
            }
            for _ in 0..10 {
                vals.push(rng.gen::<u128>() & small_mask);
            }

            for &a in &vals {
                for &b in &vals {
                    let sum_k = a ^ b;
                    let prod_k = poly::gf_mul(a, b, w_p, m_p);
                    // The base-field product must itself still be a
                    // base-field element; otherwise "embedding" would
                    // be leaking into higher coordinates.
                    assert_eq!(
                        prod_k & !small_mask,
                        0,
                        "base product escaped GF(2^{})",
                        w_p
                    );

                    if w_q <= 128 {
                        assert_eq!(
                            sum_k,
                            a ^ b,
                            "embedding must preserve addition at ({},{})",
                            w_p,
                            w_q
                        );
                        assert_eq!(
                            mul_u128(&p, w_q, a, b),
                            prod_k,
                            "embedding breaks multiplication at ({},{}) a={:#x} b={:#x}",
                            w_p,
                            w_q,
                            a,
                            b
                        );
                    } else {
                        let (lo, hi) = mul_u256(&p, (a, 0), (b, 0));
                        assert_eq!(
                            (lo, hi),
                            (prod_k, 0),
                            "embedding breaks multiplication at ({},{}) a={:#x} b={:#x}",
                            w_p,
                            w_q,
                            a,
                            b
                        );
                    }
                }
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
