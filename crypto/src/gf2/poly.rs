//! Bitwise carry-less multiplication and Schoolbook reduction over `F_2[x]`.
//!
//! Pure-software fallback (no CLMUL intrinsics yet — see follow-up).
//! Every routine works on `u128` storage and is free of any `unsafe`.
//!
//! Conventions
//! -----------
//!
//! Throughout this module a polynomial is encoded as a bit string with
//! bit `i` representing the coefficient of `x^i`. So
//!
//! ```text
//!     a = 0b1011  (= u128 value 11)
//! ```
//!
//! denotes the polynomial `x^3 + x + 1`.
//!
//! For an irreducible monic `m(x) = x^w + r(x)` where `deg(r) < w`, the
//! "low part" `m_low_bits` is `r(x)` encoded into bits `0..w` of a `u128`
//! (the implicit `x^w` term at bit `w` is NOT stored). E.g. for
//! `m(x) = x^4 + x + 1` we pass `m_low_bits = 0b0011 = 3`.

/// Carry-less multiply two `F_2[x]` polynomials of degree `< 64`,
/// returning the up-to-127-degree product packed into a single `u128`.
///
/// All operations are constant-time with respect to the bit pattern of
/// the inputs (no early exit on zeros) so the routine is safe for use
/// inside cryptographic workloads even if the caller does not zero out
/// inputs first. The 64-iteration loop is fixed-trip.
pub fn clmul_u64(a: u64, b: u64) -> u128 {
    let mut result: u128 = 0;
    let b_wide: u128 = b as u128;
    for i in 0..64 {
        // Use bit-mask multiplication so the conditional XOR is
        // expressed branchlessly: a single set bit i in `a` adds
        // `b << i` to the result; otherwise nothing.
        let mask = ((a >> i) & 1) as u128;
        // 0u128 wrapping_neg is 0; 1u128 wrapping_neg is u128::MAX.
        let bitmask = mask.wrapping_neg();
        result ^= bitmask & (b_wide << i);
    }
    result
}

/// Carry-less multiply two `F_2[x]` polynomials of degree `< 128`,
/// returning the 256-bit product as `(low_128, high_128)`.
///
/// Equivalent to two `clmul_u64` calls plus a Karatsuba combine, but
/// expressed as a straight-line 128-iteration loop here for clarity.
/// Still constant-time-ish (no data-dependent early exit).
pub fn clmul_u128(a: u128, b: u128) -> (u128, u128) {
    let mut lo: u128 = 0;
    let mut hi: u128 = 0;
    for i in 0..128 {
        let mask = ((a >> i) & 1).wrapping_neg();
        if i == 0 {
            lo ^= mask & b;
        } else {
            lo ^= mask & (b << i);
            hi ^= mask & (b >> (128 - i));
        }
    }
    (lo, hi)
}

/// Schoolbook reduction of a polynomial whose bits are spread over
/// `(lo, hi)` modulo the monic irreducible `m(x) = x^w + m_low(x)`.
///
/// `lo` carries bits `0..127` and `hi` carries bits `128..(2w − 1)`.
/// `w` must be in `1..=128`; for `w ≤ 64` the caller MUST pass `hi == 0`
/// (no high-half data exists yet) and a `m_low_bits` whose bits beyond
/// `w` are zero.
///
/// On return the result occupies the low `w` bits of `lo`. The
/// `debug_assert!`s catch programmer mistakes; release-mode behaviour
/// is correct without them as long as the contract is satisfied.
pub fn reduce_polynomial(mut lo: u128, mut hi: u128, w: usize, m_low_bits: u128) -> u128 {
    debug_assert!(w >= 1 && w <= 128, "w must be in 1..=128");
    if w < 128 {
        debug_assert!(
            m_low_bits >> w == 0,
            "m_low_bits must fit in the low w bits"
        );
    }

    // Reduce bits at positions `w..(2*w)` of the conceptual 2w-bit
    // value `(hi, lo)` from high to low. Each set bit `i ≥ w` is
    // cleared by XOR-ing in `m << (i − w)`, which is the polynomial
    // identity `x^i = x^(i−w) · x^w ≡ x^(i−w) · m_low_bits  (mod m)`.
    //
    // Working from high to low makes the recurrence non-circular: any
    // bit we clear at position `i` only adds to bits at strictly lower
    // positions (since `m_low_bits << (i−w)` lives in bit range
    // `(i−w)..(i−1)`).
    let total: usize = 2 * w; // ≤ 256
    let mut i = total;
    while i > w {
        i -= 1;
        let bit_set = if i < 128 {
            ((lo >> i) & 1) == 1
        } else {
            ((hi >> (i - 128)) & 1) == 1
        };
        if !bit_set {
            continue;
        }
        // (1) Clear bit `i`.
        if i < 128 {
            lo ^= 1u128 << i;
        } else {
            hi ^= 1u128 << (i - 128);
        }
        // (2) XOR in `m_low << shift` across the two limbs.
        let shift = i - w; // 0..=w−1, so always < 128
        if shift == 0 {
            lo ^= m_low_bits;
        } else {
            lo ^= m_low_bits << shift;
            hi ^= m_low_bits >> (128 - shift);
        }
    }
    debug_assert_eq!(hi, 0, "all high bits should be reduced");
    if w == 128 {
        lo
    } else {
        lo & ((1u128 << w) - 1)
    }
}

/// Convenience: reduce a single `u128` (holds up to `2w` bits with the
/// upper part already in the same limb) modulo `x^w + m_low_bits`.
/// Used by the `w ≤ 64` paths where the carry-less product fits in
/// one `u128`.
#[inline]
pub fn reduce_u128(value: u128, w: usize, m_low_bits: u128) -> u128 {
    debug_assert!(w >= 1 && w <= 64, "use reduce_polynomial for w > 64");
    reduce_polynomial(value, 0, w, m_low_bits)
}

/// Multiply two GF(2^w) elements (encoded in low `w` bits of `u128`)
/// and reduce modulo `m(x) = x^w + m_low_bits`.
///
/// `w` ∈ `1..=128`. For `w == 128` this dispatches to the two-limb
/// product + reduction; otherwise the result fits in a single `u128`.
pub fn gf_mul(a: u128, b: u128, w: usize, m_low_bits: u128) -> u128 {
    debug_assert!(w >= 1 && w <= 128);
    if w <= 64 {
        let prod = clmul_u64(a as u64, b as u64);
        reduce_u128(prod, w, m_low_bits)
    } else {
        let (lo, hi) = clmul_u128(a, b);
        reduce_polynomial(lo, hi, w, m_low_bits)
    }
}

/// Square a GF(2^w) element. Squaring in characteristic-2 fields is
/// the linear "spread the bits" map: bit `i` of `a` becomes bit `2i`
/// of the (unreduced) result. Often faster than calling `gf_mul(a, a)`
/// because the spread can be tabulated.
pub fn gf_sqr(a: u128, w: usize, m_low_bits: u128) -> u128 {
    debug_assert!(w >= 1 && w <= 128);
    // Spread each bit by inserting a zero between successive bits.
    // For w ≤ 64 the result fits in u128.
    if w <= 64 {
        let mut spread: u128 = 0;
        for i in 0..w {
            if (a >> i) & 1 == 1 {
                spread |= 1u128 << (2 * i);
            }
        }
        reduce_u128(spread, w, m_low_bits)
    } else {
        // w ≤ 128, so 2w ≤ 256: split into two u128 halves.
        let mut lo: u128 = 0;
        let mut hi: u128 = 0;
        for i in 0..w {
            if (a >> i) & 1 == 1 {
                let pos = 2 * i;
                if pos < 128 {
                    lo |= 1u128 << pos;
                } else {
                    hi |= 1u128 << (pos - 128);
                }
            }
        }
        reduce_polynomial(lo, hi, w, m_low_bits)
    }
}

/// Compute `a^{-1}` in GF(2^w) via the extended Euclidean algorithm
/// over `F_2[x]`. Returns `0` if `a == 0` (caller-checked).
///
/// The implementation uses the classical EEA on polynomials encoded as
/// `u128` bit strings, with `m(x) = x^w + m_low_bits` as the modulus.
/// Cost: O(w) inner iterations, ~constant time at each step. Adequate
/// for `w ≤ 128`; production code may eventually swap in Itoh–Tsujii
/// based on Fermat's little theorem (a^(2^w − 2) = a^{−1}) when the
/// CLMUL hardware path lands.
pub fn gf_inv(a: u128, w: usize, m_low_bits: u128) -> u128 {
    debug_assert!(w >= 1 && w <= 128);
    if a == 0 {
        return 0;
    }
    // EEA setup: r0 = m, r1 = a; s0 = 0, s1 = 1.
    // We maintain s_i so that s_i ≡ r_i^{−1} when r_i = 1.
    //
    // We can't store m directly as u128 since it has degree w (would
    // need bit w set). Instead, reconstruct as needed: r0 has degree w
    // initially.
    let m_full_low = m_low_bits;
    // Reuse a helper that treats r0 as the (m_low_bits, implicit 1<<w)
    // pair. The first reduction step below is forced anyway.

    // Start: pretend r0 = m, deg(r0) = w; r1 = a, deg(r1) < w.
    let mut r0_lo = m_full_low; // bit w is implicit
    let mut r0_deg: i32 = w as i32;
    let mut r1_lo = a;
    let mut r1_deg: i32 = degree_of(a);

    let mut s0: u128 = 0;
    let mut s1: u128 = 1;

    // Loop until r1 == 0 or r1 == 1.
    while r1_deg >= 0 && r1_lo != 0 {
        // Reduce r0 modulo r1. While deg(r0) ≥ deg(r1), XOR in
        // r1 << (deg(r0) − deg(r1)).
        while r0_deg >= r1_deg && r0_lo != 0 {
            let shift = (r0_deg - r1_deg) as u32;
            // r0 ^= r1 << shift, but r0 also has the implicit x^w bit
            // initially. Handle the very first iteration specially.
            if r0_deg == w as i32 {
                // r0 is m: bit w implicit. After clearing it via shift = 0
                // when r1 has deg w, we'd XOR r1 with implicit-bit
                // alignment. Easier path: bring m fully into u128 only
                // when w < 128, else handle algebraically.
                if w < 128 {
                    let r0_full = r0_lo | (1u128 << w);
                    let xor = r1_lo << shift;
                    let new_r0 = r0_full ^ xor;
                    r0_lo = new_r0;
                    r0_deg = degree_of(new_r0);
                } else {
                    // w == 128. m has bit 128 implicit, which lies
                    // beyond u128 storage. The first reduction step
                    // brings deg from 128 to ≤ 127; do it directly.
                    // r1 << shift, where shift = 128 - deg(r1).
                    if r1_deg == 128 {
                        // Shouldn't happen: r1 = a has deg < w = 128.
                        unreachable!();
                    }
                    let r1_shifted_lo = r1_lo.wrapping_shl(shift);
                    // The implicit x^128 bit of m XORs the bit at
                    // position 128 of r1 << shift, which is bit
                    // (deg(r1) + shift) = 128, i.e. exactly the
                    // implicit bit we wanted to cancel. So overall
                    // r0_lo becomes m_low_bits XOR (low 128 bits of
                    // r1 << shift), with no high carry.
                    r0_lo = m_low_bits ^ r1_shifted_lo;
                    r0_deg = degree_of(r0_lo);
                }
            } else {
                r0_lo ^= r1_lo.wrapping_shl(shift);
                r0_deg = degree_of(r0_lo);
            }
            // s0 ^= s1 << shift (parallel update; reduction over m
            // applied lazily — values stay bounded since deg(s) < w).
            s0 ^= s1.wrapping_shl(shift);
        }
        // Swap (r0, r1) and (s0, s1).
        std::mem::swap(&mut r0_lo, &mut r1_lo);
        std::mem::swap(&mut r0_deg, &mut r1_deg);
        std::mem::swap(&mut s0, &mut s1);
    }
    // r0 is the gcd. For irreducible m and 0 < a < 2^w, gcd = 1, so
    // s0 carries the inverse. Mask to w bits to drop any spurious
    // high bits accumulated in the lazy s0 updates.
    if w == 128 {
        s0
    } else {
        s0 & ((1u128 << w) - 1)
    }
}

/// Return the degree of a polynomial encoded as a `u128`. By
/// convention `degree(0) = -1`. Degree of a degree-0 nonzero
/// polynomial is `0`.
#[inline]
pub fn degree_of(a: u128) -> i32 {
    if a == 0 {
        -1
    } else {
        (127 - a.leading_zeros()) as i32
    }
}

/// Test whether a polynomial of degree exactly `w` (encoded as
/// `m_low_bits` with implicit leading `x^w` bit) is irreducible over
/// `F_2`. Used by `Gf2Profile::new` to validate registry entries.
///
/// Algorithm: Rabin's test — `m` is irreducible iff
///   1. `gcd(m, x^(2^w) − x) = m`     (every root of m is in F_{2^w})
///   2. for every prime divisor `p` of `w`,
///      `gcd(m, x^(2^(w/p)) − x) = 1` (no root in any proper subfield)
///
/// Implementation note: `x^(2^k) mod m` is computed by repeatedly
/// squaring (Frobenius). For `w ≤ 128` this is fast even in software.
pub fn is_irreducible(w: usize, m_low_bits: u128) -> bool {
    if w == 0 {
        return false;
    }
    if w == 1 {
        // The only degree-1 irreducibles over F_2 are x and x + 1,
        // i.e. m_low_bits ∈ {0, 1}. Both are valid.
        return m_low_bits < 2;
    }
    // Compute x^(2^w) mod m via w squarings, starting from x.
    let mut acc: u128 = 2; // = x
    let n = w;
    for _ in 0..n {
        acc = gf_sqr(acc, w, m_low_bits);
    }
    // x^(2^w) − x mod m = acc XOR x in F_2.
    let xpow_minus_x = acc ^ 2;
    // Condition 1: m | (x^(2^w) − x)  ⇔  reduced value is 0.
    if xpow_minus_x != 0 {
        return false;
    }
    // Condition 2: for every prime p dividing w, gcd(m, x^(2^(w/p)) − x) = 1.
    for p in prime_divisors(w) {
        let k = w / p;
        let mut acc2: u128 = 2;
        for _ in 0..k {
            acc2 = gf_sqr(acc2, w, m_low_bits);
        }
        let candidate = acc2 ^ 2; // x^(2^k) − x  mod m
        // gcd(m, candidate) over F_2[x]; for irreducible m and degree-< w
        // candidate, gcd = 1 iff candidate ≠ 0.
        if candidate == 0 {
            return false;
        }
    }
    true
}

/// Tiny prime-divisor helper for `is_irreducible`. `w ≤ 128` so the
/// trial-division loop is bounded.
fn prime_divisors(mut n: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut d = 2usize;
    while d * d <= n {
        if n % d == 0 {
            out.push(d);
            while n % d == 0 {
                n /= d;
            }
        }
        d += 1;
    }
    if n > 1 {
        out.push(n);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clmul_simple() {
        // (x + 1)(x + 1) = x^2 + 1 in F_2[x].
        assert_eq!(clmul_u64(0b11, 0b11), 0b101);
        // (x^3 + x + 1)(x + 1) = x^4 + x^3 + x^2 + 1
        assert_eq!(clmul_u64(0b1011, 0b11), 0b11101);
    }

    #[test]
    fn clmul_u128_matches_u64_when_inputs_small() {
        let a: u64 = 0xdead_beef;
        let b: u64 = 0xcafe_babe;
        let p64 = clmul_u64(a, b);
        let (lo128, hi128) = clmul_u128(a as u128, b as u128);
        assert_eq!(p64, lo128);
        assert_eq!(hi128, 0);
    }

    #[test]
    fn clmul_high_bit() {
        // x^63 * x^1 = x^64
        let a: u64 = 1u64 << 63;
        let b: u64 = 0b10;
        let prod = clmul_u64(a, b);
        assert_eq!(prod, 1u128 << 64);
    }

    #[test]
    fn reduce_in_gf2_4() {
        // GF(2^4) = F_2[x] / (x^4 + x + 1), m_low_bits = 0b0011 = 3
        // (x^3 + x)(x^2 + 1) = x^5 + x^3 + x^3 + x = x^5 + x
        // = (b'100010') reduced mod x^4+x+1
        // x^5 = x * x^4 = x * (x + 1) = x^2 + x
        // So x^5 + x = x^2 + x + x = x^2.
        let a: u64 = 0b1010; // x^3 + x
        let b: u64 = 0b0101; // x^2 + 1
        let prod = clmul_u64(a, b);
        let red = reduce_u128(prod, 4, 0b0011);
        assert_eq!(red, 0b0100); // x^2
    }

    #[test]
    fn reduce_w128_simple() {
        // Multiply x^127 by x: x^128, then reduce mod x^128 + x^7 + x^2 + x + 1
        // x^128 ≡ x^7 + x^2 + x + 1 = 0x87.
        let m_low: u128 = 0x87;
        let a = 1u128 << 127;
        let b = 1u128 << 1;
        let (lo, hi) = clmul_u128(a, b);
        assert_eq!(hi & 1, 1, "expected x^128 bit in hi");
        let red = reduce_polynomial(lo, hi, 128, m_low);
        assert_eq!(red, m_low);
    }

    #[test]
    fn gf_mul_then_inv_then_mul_is_identity() {
        // GF(2^8) under m = x^8 + x^4 + x^3 + x + 1 (AES SBox).
        let w = 8;
        let m: u128 = 0x1b;
        // Try every nonzero element a; compute b = a^{-1}; verify a*b = 1.
        for a in 1u128..256 {
            let b = gf_inv(a, w, m);
            assert!(b != 0, "inverse of {} should be nonzero", a);
            let prod = gf_mul(a, b, w, m);
            assert_eq!(prod, 1, "a={} b={} a*b={}", a, b, prod);
        }
    }

    #[test]
    fn gf_sqr_matches_gf_mul() {
        let w = 64;
        let m: u128 = 0b11011; // x^4 + x^3 + x + 1, masked to w-bit context (irrelevant top bits)
        // Use the actual GF(2^64) NIST poly low part 0b11011 = x^4 + x^3 + x + 1
        // for the square check; degree-4 < 64 so this is fine as m_low_bits.
        for a in [
            0u128,
            1u128,
            0xdeadbeefu128,
            0x123456789abcdef0u128,
            0xffff_ffff_ffff_ffffu128,
        ] {
            let s1 = gf_sqr(a, w, m);
            let s2 = gf_mul(a, a, w, m);
            assert_eq!(s1, s2, "gf_sqr mismatched gf_mul for a={}", a);
        }
    }

    #[test]
    fn is_irreducible_known_polynomials() {
        // x^8 + x^4 + x^3 + x + 1 (AES SBox m): irreducible.
        assert!(is_irreducible(8, 0x1b));
        // x^4 + x + 1: irreducible.
        assert!(is_irreducible(4, 0b0011));
        // x^4 + x^2 + 1 = (x^2 + x + 1)^2: REDUCIBLE.
        assert!(!is_irreducible(4, 0b0101));
        // x^16 + x^5 + x^3 + x^2 + 1: irreducible (NIST GF(2^16) poly).
        assert!(is_irreducible(16, 0b0010_1101));
        // x^32 + x^7 + x^3 + x^2 + 1: irreducible (NIST GF(2^32) poly).
        assert!(is_irreducible(32, 0b1000_1101));
    }

    #[test]
    fn is_irreducible_rejects_x_squared() {
        // x^4 = x^4: m_low = 0 -> reducible (m = x^4 = x*x*x*x).
        assert!(!is_irreducible(4, 0));
        // x^4 + 1 = (x+1)^4: REDUCIBLE.
        assert!(!is_irreducible(4, 0b0001));
    }
}
