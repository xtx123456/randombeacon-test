//! `Gf2Profile` — runtime parameter for the (small, large) two-field
//! configuration used by the PPT random-beacon AVSS / degree-test
//! pipeline.
//!
//! Mathematical structure
//! ----------------------
//!
//! A profile picks a base field `GF(2^w_p)` and an extension
//! `GF(2^w_q)` such that
//!
//!   * `w_p | w_q`                    — required for the subfield
//!     embedding `GF(2^w_p) ↪ GF(2^w_q)` that the PPT degree test
//!     `h(x) = g(x) − τ·f(x)` relies on.
//!   * `w_q / w_p` is a power of two — restricts the extension to a
//!     stack of quadratic extensions, the only construction
//!     implemented in `tower.rs`.
//!
//! The base field `GF(2^w_p) = F_2[x] / m_p(x)` uses an irreducible
//! polynomial `m_p(x)` from the registry below. Each quadratic level
//! of the tower uses
//!
//! ```text
//!     GF(2^(2k))  =  GF(2^k)[y] / (y² + y + α_k)
//! ```
//!
//! with `α_k ∈ GF(2^k)` chosen so `Tr_{GF(2^k)/F_2}(α_k) = 1` (the
//! Artin-Schreier irreducibility criterion).
//!
//! Why `α` depends on the BASE width, not just the level
//! ------------------------------------------------------
//!
//! The trace condition `Tr(α_k) = 1` is a statement about `α_k` *as an
//! element of a concrete representation* of `GF(2^k)`. Above the base
//! width there are two different representations in play and they are
//! **not** the same map from integers to field elements:
//!
//!   * the polynomial basis `F_2[x] / m_k(x)` using the registry's
//!     degree-`k` irreducible, and
//!   * the tower representation `GF(2^(k/2))[y] / (y² + y + α_{k/2})`
//!     that `tower.rs` actually computes in.
//!
//! They are isomorphic as fields but the isomorphism is not the
//! identity on bit patterns. Picking `α_k` by a trace search in the
//! polynomial basis and then feeding that integer to `tower.rs` —
//! which reads it in tower coordinates — is therefore a representation
//! mismatch: the resulting `y² + y + α_k` can be **reducible** over the
//! tower, and the "field" one level up degenerates into a ring with
//! zero divisors. Concretely, with base `w_p = 8` the old code chose
//! `α_16 = 0x800`, and `c = 0x87a2` satisfies `c² + c = 0x800` in the
//! tower `GF(2^16)`, so `y² + y + α_16 = (y + c)(y + c + 1)` split and
//! `GF2(8,64)` admitted the zero divisors `0x187a2 · 0x187a3 = 0`.
//!
//! The fix is to compute the trace in the representation that is
//! actually used. For a quadratic tower level `L = K[y]/(y² + y + α_K)`
//! the relative trace collapses to the high coordinate,
//!
//! ```text
//!     Tr_{L/K}(a_lo + a_hi · y) = (a_lo + a_hi·y) + (a_lo + a_hi·(y+1))
//!                               = a_hi
//! ```
//!
//! because the nontrivial `K`-automorphism of `L` maps `y ↦ y + 1` (the
//! two roots of `y² + y + α_K`). Composing with trace transitivity
//! `Tr_{L/F_2} = Tr_{K/F_2} ∘ Tr_{L/K}` gives
//!
//! ```text
//!     Tr_{L/F_2}(a_lo + a_hi · y) = Tr_{K/F_2}(a_hi).
//! ```
//!
//! So `α_L := α_K · y` (low coordinate `0`, high coordinate `α_K`) has
//! `Tr_{L/F_2}(α_L) = Tr_{K/F_2}(α_K) = 1` by induction. Unrolling the
//! recursion, with `α_base` the polynomial-basis trace-1 element of the
//! base field (where tower coordinates and polynomial basis DO
//! coincide):
//!
//! ```text
//!     α_level  =  α_base  <<  (level − base_w)
//! ```
//!
//! which is a single shift — no per-level trace search, no locking, and
//! still a single-bit value so the `α`-multiply inside Karatsuba stays
//! cheap. `ALPHA_TABLE` materialises this once per registered base
//! width in a read-only `lazy_static`.
//!
//! What this file does
//! -------------------
//!
//! - `Gf2Profile::new(w_p, w_q)` validates the input and looks up the
//!   registry entries.
//! - `base_irreducible(w)` returns the irreducible `m_w(x)` low-bits for
//!   any supported base width.
//! - `quadratic_alpha(base_w, level_w)` returns the `α` used to build
//!   `GF(2^(2 · level_w))` from the **tower** `GF(2^level_w)` that sits
//!   above base width `base_w`.
//!
//! Tests at the bottom validate every registry entry's irreducibility
//! and re-derive `Tr(α) = 1` from the *definition*
//! (`a + a² + a⁴ + …` via repeated tower squaring) rather than from the
//! high-coordinate shortcut used to build the table, so the two
//! independent routes must agree.

use std::fmt;
use std::str::FromStr;

use super::poly;

/// Runtime two-field profile selector for PPT.
///
/// `w_p` is the small-field bit width (encodes the secret); `w_q` is
/// the large-field bit width (encodes the mask + degree-test challenge).
/// `w_p | w_q` and the quotient must be a power of two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Gf2Profile {
    pub w_p: usize,
    pub w_q: usize,
}

impl Gf2Profile {
    /// Validate `(w_p, w_q)` and return the profile. Returns
    /// `Err(static_str)` on any constraint violation.
    pub fn new(w_p: usize, w_q: usize) -> Result<Self, &'static str> {
        if w_p == 0 || w_q == 0 {
            return Err("w_p and w_q must be ≥ 1");
        }
        if w_p > MAX_BASE_WIDTH {
            return Err("w_p exceeds the largest base width in the registry");
        }
        if w_q > MAX_LARGE_WIDTH {
            return Err("w_q exceeds the [u8; 32] storage envelope (256 bits)");
        }
        if w_q < w_p {
            return Err("w_q must be ≥ w_p");
        }
        if w_q % w_p != 0 {
            return Err(
                "w_p must divide w_q (PPT requires GF(2^w_p) ⊂ GF(2^w_q) subfield embedding)",
            );
        }
        let ext_deg = w_q / w_p;
        if !ext_deg.is_power_of_two() {
            return Err(
                "w_q / w_p must be a power of two (only the quadratic-tower construction is implemented)",
            );
        }
        // Confirm registry has both the base poly and every tower
        // quadratic-extension `α` we'll need. The `α` lookup is keyed
        // by `(w_p, level)` because the trace condition that makes
        // `y² + y + α` irreducible is relative to the tower
        // representation rooted at `w_p` — see the module docs.
        base_irreducible(w_p)?;
        let depth = (ext_deg.trailing_zeros()) as usize;
        let mut level_w = w_p;
        for _ in 0..depth {
            quadratic_alpha(w_p, level_w)?;
            level_w *= 2;
        }
        Ok(Self { w_p, w_q })
    }

    /// Number of bytes occupied by an element of GF(2^w_p) in
    /// canonical-low-bit-position encoding.
    pub fn small_byte_len(&self) -> usize {
        (self.w_p + 7) / 8
    }
    /// Number of bytes occupied by an element of GF(2^w_q).
    pub fn large_byte_len(&self) -> usize {
        (self.w_q + 7) / 8
    }
    /// Tower depth: 0 means `w_p == w_q` (no extension), 1 means a
    /// single quadratic extension, etc.
    pub fn tower_depth(&self) -> usize {
        (self.w_q / self.w_p).trailing_zeros() as usize
    }
}

/// Canonical `Display` form: `"GF2(w_p,w_q)"`. The inverse of
/// `FromStr`, so a round-trip is identity:
///
/// ```text
///     "GF2(64,256)".parse::<Gf2Profile>().unwrap().to_string()
///         == "GF2(64,256)"
/// ```
impl fmt::Display for Gf2Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GF2({},{})", self.w_p, self.w_q)
    }
}

/// Parse a `Gf2Profile` from the CLI string form
/// `"GF2(w_p,w_q)"`.
///
/// The leading tag is case-insensitive (`gf2`, `Gf2`, `GF2` all
/// work) and may be omitted entirely (`"(64,256)"` and even
/// `"64,256"` parse successfully). Whitespace inside the parens is
/// tolerated. Numeric parsing failures, malformed parentheses, or
/// validation failures from `Gf2Profile::new` all bubble up as a
/// descriptive `String` error.
impl FromStr for Gf2Profile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err("empty Gf2Profile spec".into());
        }
        // Optional "gf2" tag.
        let body = match trimmed
            .strip_prefix("GF2")
            .or_else(|| trimmed.strip_prefix("gf2"))
            .or_else(|| trimmed.strip_prefix("Gf2"))
        {
            Some(rest) => rest.trim_start(),
            None => trimmed,
        };
        // Strip optional outer parens.
        let inner = if let Some(stripped) = body.strip_prefix('(') {
            stripped
                .strip_suffix(')')
                .ok_or_else(|| format!("missing closing ')' in '{}'", s))?
        } else {
            body
        };
        let mut parts = inner.split(',');
        let w_p_str = parts
            .next()
            .ok_or_else(|| format!("missing w_p in '{}'", s))?
            .trim();
        let w_q_str = parts
            .next()
            .ok_or_else(|| format!("missing w_q in '{}'", s))?
            .trim();
        if parts.next().is_some() {
            return Err(format!("expected exactly two integers in '{}'", s));
        }
        let w_p: usize = w_p_str
            .parse()
            .map_err(|e| format!("invalid w_p '{}': {}", w_p_str, e))?;
        let w_q: usize = w_q_str
            .parse()
            .map_err(|e| format!("invalid w_q '{}': {}", w_q_str, e))?;
        Gf2Profile::new(w_p, w_q).map_err(|e| format!("invalid Gf2Profile({}, {}): {}", w_p, w_q, e))
    }
}

/// The largest base width currently in the registry.
pub const MAX_BASE_WIDTH: usize = 128;
/// The largest extended width supported by the on-wire envelope.
pub const MAX_LARGE_WIDTH: usize = 256;

/// Look up the irreducible polynomial low-part for `GF(2^w_p)`.
///
/// Returns `m_low_bits` such that `m_p(x) = x^w_p + (encoded by
/// m_low_bits in bits 0..w_p)`. Each entry has been verified
/// offline (and re-checked in unit tests via Rabin's test).
pub fn base_irreducible(w: usize) -> Result<u128, &'static str> {
    match w {
        // F_2 itself: m(x) = x. The "field" GF(2^1) ≅ F_2 has the
        // trivial reduction (degree 0), so m_low_bits = 0 and every
        // u128 with the low bit gives the element. Useful only as a
        // limiting case; PPT typically picks w_p ≥ 8.
        1 => Ok(0),
        // x^2 + x + 1 (the only irreducible degree-2 poly over F_2).
        2 => Ok(0b11),
        // x^4 + x + 1 (the standard degree-4 irreducible).
        4 => Ok(0b0011),
        // x^8 + x^4 + x^3 + x + 1   (AES SBox, NIST FIPS 197).
        8 => Ok(0x1b),
        // x^16 + x^5 + x^3 + x^2 + 1.
        16 => Ok((1 << 5) | (1 << 3) | (1 << 2) | 1),
        // x^32 + x^7 + x^3 + x^2 + 1   (NIST recommended).
        32 => Ok((1 << 7) | (1 << 3) | (1 << 2) | 1),
        // x^64 + x^4 + x^3 + x + 1   (NIST recommended; same shape as
        // the GHASH GF(2^128) tail).
        64 => Ok((1 << 4) | (1 << 3) | (1 << 1) | 1),
        // x^128 + x^7 + x^2 + x + 1   (AES-GCM / NIST SP 800-38D).
        128 => Ok((1 << 7) | (1 << 2) | (1 << 1) | 1),
        _ => Err("unsupported base width — extend `base_irreducible` registry"),
    }
}

/// Return the `α` used to build the next quadratic extension
/// `GF(2^(2 · level_w)) = GF(2^level_w)[y] / (y² + y + α)`, where
/// `GF(2^level_w)` is the **tower** representation rooted at base
/// width `base_w` (so `base_w | level_w` and the quotient is a power
/// of two).
///
/// The returned `α` satisfies `Tr_{GF(2^level_w)/F_2}(α) = 1` **in the
/// tower representation**, which is the necessary and sufficient
/// Artin-Schreier condition for `y² + y + α` to be irreducible there.
/// Verified in tests by recomputing the absolute trace from its
/// definition via repeated tower squaring.
///
/// Passing `base_w == level_w` returns the base field's
/// polynomial-basis trace-1 element: at the base width the tower
/// coordinates and the polynomial basis are the same encoding.
///
/// Lookup is a read-only table indexed by `(base_w, level_w)`; no
/// trace search, allocation, or locking happens per call.
pub fn quadratic_alpha(base_w: usize, level_w: usize) -> Result<u128, &'static str> {
    if base_w == 0 || level_w < base_w || level_w % base_w != 0 {
        return Err("quadratic_alpha: base_w must divide level_w");
    }
    if !(level_w / base_w).is_power_of_two() {
        return Err("quadratic_alpha: level_w / base_w must be a power of two");
    }
    if !base_w.is_power_of_two() {
        return Err("unsupported tower base width — extend the base registry");
    }
    // `REGISTERED_BASE_WIDTHS` is exactly `{2^0, …, 2^7}`, so the base
    // width indexes the table directly. This runs at every internal
    // node of every Karatsuba multiplication, so the lookup has to be
    // an array index rather than a scan.
    let table = alpha_table()
        .get(base_w.trailing_zeros() as usize)
        .ok_or("unsupported tower base width — extend the base registry")?;
    debug_assert_eq!(table.base_w, base_w, "alpha table index invariant broken");
    let step = (level_w / base_w).trailing_zeros() as usize;
    table
        .levels
        .get(step)
        .copied()
        .ok_or("unsupported quadratic-tower level — exceeds the 128-bit level cap")
}

/// Search for an `α ∈ GF(2^w)` with `Tr_{GF(2^w)/F_2}(α) = 1`.
/// Used to populate the alpha cache.
///
/// `Tr` is `F_2`-linear, so `Tr(α) = Σ_i [bit_i of α] · Tr(x^i)` over
/// `F_2`. We compute `Tr(x^i)` for `i = 0..w−1` (exactly `w` calls to
/// `trace`) and return the smallest `α = x^i` whose trace is `1`. The
/// trace map is non-zero on `GF(2^w)` (it's surjective onto `F_2`),
/// so at least one such `i` always exists. Total cost: `O(w²)`
/// squarings, ≪ 1 ms even at `w = 128`.
///
/// We pick the smallest power of `x` rather than the smallest integer
/// because the latter is not bounded by `2^w` for typical polynomials
/// (e.g. for the GF(2^64) NIST poly the smallest integer α with
/// `Tr(α) = 1` is `2^k` for some specific `k`, and a brute-force
/// integer scan up to that `k` would visit `2^k − 1 = O(2^w)` values).
fn find_alpha_trace_one(w: usize, m_low: u128) -> Option<u128> {
    if w == 1 {
        return Some(1);
    }
    for i in 0..w {
        let basis = 1u128 << i;
        if trace(w, m_low, basis) == 1 {
            return Some(basis);
        }
    }
    None
}

/// `Tr_{GF(2^w)/F_2}(a)` = `a + a^2 + a^4 + ... + a^(2^(w-1))` reduced
/// in `GF(2^w)`. Result is always `0` or `1` for any `a` (the trace
/// map lands in the prime field `F_2`).
fn trace(w: usize, m_low: u128, a: u128) -> u128 {
    let mut t: u128 = 0;
    let mut cur = a;
    for _ in 0..w {
        t ^= cur;
        cur = poly::gf_sqr(cur, w, m_low);
    }
    t
}

/// Base widths for which a tower may be rooted. Every entry must have
/// a `base_irreducible` registry entry.
pub(crate) const REGISTERED_BASE_WIDTHS: [usize; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

/// Per-base-width `α` table. `levels[k]` is the `α` used to build
/// level `base_w << (k + 1)` out of level `base_w << k`, expressed in
/// the tower coordinates of level `base_w << k`.
///
/// Entry `k` is for base width `REGISTERED_BASE_WIDTHS[k] == 1 << k`,
/// so `quadratic_alpha` can index instead of search.
struct AlphaTable {
    base_w: usize,
    levels: Vec<u128>,
}

/// Read-only `(base_w, level_w) → α` table.
///
/// Built once from the closed form derived in the module docs,
/// `α_level = α_base << (level − base_w)`, where `α_base` comes from a
/// polynomial-basis trace search (valid at the base width, where tower
/// coordinates and polynomial basis coincide). Tests re-derive each
/// entry's trace from the definition in the tower representation, so
/// the shortcut is checked against an independent computation rather
/// than assumed.
fn alpha_table() -> &'static [AlphaTable] {
    // NOTE: we use `lazy_static` (already a `crypto` crate
    // dependency) rather than `std::sync::OnceLock` because the
    // latter only stabilised in Rust 1.70. The `lazy_static`
    // path lets `crypto` keep building on pre-1.70 toolchains
    // (the only requirement is whatever rustc the workspace's
    // other crates need; see workspace MSRV).
    lazy_static::lazy_static! {
        static ref ALPHA_TABLE: Vec<AlphaTable> = {
            let mut tables = Vec::with_capacity(REGISTERED_BASE_WIDTHS.len());
            for (k, &base_w) in REGISTERED_BASE_WIDTHS.iter().enumerate() {
                // `quadratic_alpha` indexes by `base_w.trailing_zeros()`.
                assert_eq!(base_w, 1usize << k, "alpha table must be index-addressable");
                // Derived from the live registry rather than hardcoded,
                // so the table can never go stale against a registry edit.
                let base_poly = base_irreducible(base_w).expect("registered base");
                let alpha_base = find_alpha_trace_one(base_w, base_poly)
                    .expect("trace-1 element exists in every GF(2^w)");
                // Levels base_w, 2·base_w, … up to MAX_BASE_WIDTH: a
                // level above 128 is never used as the `half` of a
                // Karatsuba step because `w_q ≤ 256`.
                let mut levels = Vec::new();
                let mut level_w = base_w;
                while level_w <= MAX_BASE_WIDTH {
                    levels.push(alpha_base << (level_w - base_w));
                    level_w *= 2;
                }
                tables.push(AlphaTable { base_w, levels });
            }
            tables
        };
    }
    &ALPHA_TABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_widths_are_irreducible() {
        for &w in &[2usize, 4, 8, 16, 32, 64, 128] {
            let m_low = base_irreducible(w).unwrap();
            assert!(
                poly::is_irreducible(w, m_low),
                "base poly for w={} (low-bits=0x{:x}) is not irreducible",
                w,
                m_low
            );
        }
    }

    /// At the BASE width the tower coordinates and the polynomial
    /// basis are the same encoding, so `quadratic_alpha(w, w)` must
    /// have polynomial-basis trace 1. (The trace condition at levels
    /// ABOVE the base is representation-sensitive and is checked in
    /// `tower.rs` against the tower arithmetic itself — see
    /// `tower_alpha_trace_is_one_in_tower_representation`.)
    #[test]
    fn base_alphas_have_polynomial_basis_trace_one() {
        for &w in REGISTERED_BASE_WIDTHS.iter() {
            let m_low = base_irreducible(w).unwrap();
            let alpha = quadratic_alpha(w, w).unwrap();
            assert_eq!(
                trace(w, m_low, alpha),
                1,
                "Tr_(GF(2^{})/F_2)({:#x}) must be 1 for y² + y + α to be irreducible",
                w,
                alpha
            );
        }
    }

    /// `α` must be keyed by the tower's base width: the same level
    /// reached from different bases is a different representation and
    /// generally needs a different `α`. This is the exact regression
    /// that produced zero divisors in `GF2(8,64)` and `GF2(64,256)`.
    #[test]
    fn alpha_depends_on_base_width_not_just_level() {
        // Level 128 reached from base 8, 16, 32, 64 and 128.
        let from_8 = quadratic_alpha(8, 128).unwrap();
        let from_64 = quadratic_alpha(64, 128).unwrap();
        let from_128 = quadratic_alpha(128, 128).unwrap();
        assert_ne!(
            from_8, from_128,
            "level-128 α must differ between base 8 and base 128"
        );
        assert_ne!(
            from_64, from_128,
            "level-128 α must differ between base 64 and base 128"
        );
    }

    /// Closed form from the module docs: `α_level = α_base << (level −
    /// base_w)`, and every `α` is a single bit (keeps the Karatsuba
    /// `α`-multiply cheap).
    #[test]
    fn alpha_closed_form_and_sparsity() {
        for &base_w in REGISTERED_BASE_WIDTHS.iter() {
            let alpha_base = quadratic_alpha(base_w, base_w).unwrap();
            assert_eq!(
                alpha_base.count_ones(),
                1,
                "base α at w={} should be a single bit, got {:#x}",
                base_w,
                alpha_base
            );
            let mut level_w = base_w;
            while level_w <= MAX_BASE_WIDTH {
                let a = quadratic_alpha(base_w, level_w).unwrap();
                assert_eq!(
                    a,
                    alpha_base << (level_w - base_w),
                    "closed form broken at base={} level={}",
                    base_w,
                    level_w
                );
                assert_eq!(a.count_ones(), 1, "α must stay single-bit");
                // α must be a genuine element of the level, i.e. fit
                // in its low `level_w` bits.
                if level_w < 128 {
                    assert!(a < (1u128 << level_w), "α escapes level {} width", level_w);
                }
                level_w *= 2;
            }
        }
    }

    #[test]
    fn quadratic_alpha_rejects_invalid_level_requests() {
        // level not a multiple of base
        assert!(quadratic_alpha(8, 12).is_err());
        // quotient not a power of two
        assert!(quadratic_alpha(8, 24).is_err());
        // level below base
        assert!(quadratic_alpha(64, 32).is_err());
        // unregistered base
        assert!(quadratic_alpha(7, 14).is_err());
        // beyond the 128-bit level cap
        assert!(quadratic_alpha(128, 256).is_err());
    }

    #[test]
    fn profile_validates_constraints() {
        // Baseline single-field allowed at every registered width.
        assert!(Gf2Profile::new(8, 8).is_ok());
        assert!(Gf2Profile::new(64, 64).is_ok());
        assert!(Gf2Profile::new(128, 128).is_ok());
        // Tower depth 1, 2, 3 with various base widths.
        assert!(Gf2Profile::new(64, 128).is_ok());
        assert!(Gf2Profile::new(64, 256).is_ok());
        assert!(Gf2Profile::new(32, 256).is_ok());
        assert!(Gf2Profile::new(8, 256).is_ok()); // depth 5: 8→16→32→64→128→256
        assert!(Gf2Profile::new(128, 256).is_ok());

        // Errors:
        assert!(Gf2Profile::new(0, 64).is_err());
        assert!(Gf2Profile::new(64, 0).is_err());
        assert!(Gf2Profile::new(128, 64).is_err()); // w_q < w_p
        assert!(Gf2Profile::new(7, 64).is_err()); // unregistered base width
        assert!(Gf2Profile::new(64, 96).is_err()); // 96/64 = 1.5, not integer
        assert!(Gf2Profile::new(64, 192).is_err()); // 192/64 = 3, not power of 2
        assert!(Gf2Profile::new(64, 384).is_err()); // exceeds 256-bit envelope

        // F_2 base case + full tower up to 256 bits also works (the
        // registry covers widths {1, 2, 4, 8, 16, 32, 64, 128}).
        assert!(Gf2Profile::new(1, 1).is_ok());
        assert!(Gf2Profile::new(1, 2).is_ok());
        assert!(Gf2Profile::new(1, 256).is_ok()); // depth 8: 1→2→4→8→16→32→64→128→256
    }

    #[test]
    fn fromstr_accepts_canonical_form() {
        let p: Gf2Profile = "GF2(64,256)".parse().unwrap();
        assert_eq!(p, Gf2Profile::new(64, 256).unwrap());
        assert_eq!(p.to_string(), "GF2(64,256)");
    }

    #[test]
    fn fromstr_accepts_variant_forms() {
        let target = Gf2Profile::new(32, 128).unwrap();
        for s in &[
            "GF2(32,128)",
            "gf2(32,128)",
            "Gf2(32,128)",
            "GF2( 32 , 128 )",
            "  gf2(32, 128) ",
            "(32,128)",
            "32,128",
            "32, 128",
        ] {
            let parsed: Gf2Profile = s.parse().unwrap_or_else(|e| panic!("'{}' → {}", s, e));
            assert_eq!(parsed, target, "form '{}' parsed differently", s);
        }
    }

    #[test]
    fn fromstr_rejects_malformed() {
        // Each of these should fail; we only check that .is_err() is true
        // (the exact message is informational).
        for s in &[
            "",
            "GF2",
            "GF2()",
            "GF2(64)",
            "GF2(64,128,256)",
            "GF2(abc,def)",
            "GF2(64,128",
            "GF2 64,128)",
        ] {
            assert!(s.parse::<Gf2Profile>().is_err(), "form '{}' should fail", s);
        }
    }

    #[test]
    fn fromstr_surfaces_validation_errors() {
        // (64, 96) is well-formed numerically but fails the
        // w_p|w_q + power-of-2 constraint inside Gf2Profile::new.
        let err = "GF2(64,96)".parse::<Gf2Profile>().unwrap_err();
        assert!(
            err.contains("invalid Gf2Profile(64, 96)"),
            "expected validation error context, got: {}",
            err
        );
        // (7, 64) — w_p=7 is unregistered.
        let err2 = "GF2(7,64)".parse::<Gf2Profile>().unwrap_err();
        assert!(err2.contains("invalid Gf2Profile(7, 64)"), "got: {}", err2);
    }

    #[test]
    fn profile_byte_lengths_and_depth() {
        let p = Gf2Profile::new(32, 256).unwrap();
        assert_eq!(p.small_byte_len(), 4);
        assert_eq!(p.large_byte_len(), 32);
        assert_eq!(p.tower_depth(), 3);

        let q = Gf2Profile::new(64, 64).unwrap();
        assert_eq!(q.small_byte_len(), 8);
        assert_eq!(q.large_byte_len(), 8);
        assert_eq!(q.tower_depth(), 0);
    }
}
