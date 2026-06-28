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
//! Artin-Schreier irreducibility criterion). The level-specific
//! `α_k` is stored alongside the base poly in the registry.
//!
//! What this file does
//! -------------------
//!
//! - `Gf2Profile::new(w_p, w_q)` validates the input and looks up the
//!   registry entries.
//! - `BASE_REGISTRY` returns the irreducible `m_p(x)` low-bits for any
//!   supported `w_p`.
//! - `quadratic_alpha(level_w)` returns the `α` used to build
//!   `GF(2^(2 · level_w))` from `GF(2^(level_w))`.
//!
//! Tests at the bottom validate every registry entry's irreducibility
//! and the `Tr(α) = 1` condition at startup-equivalent rigor.

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
        // quadratic-extension `α` we'll need.
        base_irreducible(w_p)?;
        let depth = (ext_deg.trailing_zeros()) as usize;
        let mut level_w = w_p;
        for _ in 0..depth {
            quadratic_alpha(level_w)?;
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

/// Return the `α ∈ GF(2^level_w)` used to build the next quadratic
/// extension `GF(2^(2 · level_w)) = GF(2^level_w)[y] / (y² + y + α)`.
///
/// All returned `α` satisfy `Tr_{GF(2^level_w)/F_2}(α) = 1`
/// (verified by `tower_alphas_have_trace_one` in tests), which is
/// the necessary and sufficient condition for `y² + y + α` to be
/// irreducible over `GF(2^level_w)` (Artin-Schreier).
///
/// Convention: `α` encoded in the low `level_w` bits of a `u128`,
/// using the same polynomial-basis encoding as the base field.
///
/// Implementation: the value is the smallest positive integer `α`
/// (when interpreted by polynomial-bit encoding) whose trace under
/// the registered `m_p(x)` is `1`. Cached on first call.
pub fn quadratic_alpha(level_w: usize) -> Result<u128, &'static str> {
    if level_w == 1 {
        // F_2: the only nonzero element is 1, and Tr_{F_2/F_2}(1) = 1.
        return Ok(1);
    }
    // Lookup precomputed; populate on first call.
    let cache = alpha_cache();
    cache
        .iter()
        .find(|&&(w, _)| w == level_w)
        .map(|&(_, a)| a)
        .ok_or("unsupported quadratic-tower level — extend `BASE_REGISTRY` and re-run cache")
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

fn alpha_cache() -> &'static [(usize, u128)] {
    // NOTE: we use `lazy_static` (already a `crypto` crate
    // dependency) rather than `std::sync::OnceLock` because the
    // latter only stabilised in Rust 1.70. The `lazy_static`
    // path lets `crypto` keep building on pre-1.70 toolchains
    // (the only requirement is whatever rustc the workspace's
    // other crates need; see workspace MSRV).
    lazy_static::lazy_static! {
        static ref ALPHA_CACHE: Vec<(usize, u128)> = {
            let mut v = Vec::new();
            for &w in &[2usize, 4, 8, 16, 32, 64, 128] {
                let m_low = base_irreducible(w).expect("registered base");
                let alpha = find_alpha_trace_one(w, m_low)
                    .expect("trace-1 element exists in any GF(2^w), w ≥ 2");
                v.push((w, alpha));
            }
            v
        };
    }
    &ALPHA_CACHE
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

    /// For `m(y) = y² + y + α` over GF(2^k), irreducibility is
    /// equivalent to `Tr_{GF(2^k)/F_2}(α) = 1` (Artin-Schreier).
    /// We verify this for every registered base width, using the
    /// `α` returned by `quadratic_alpha` (which itself was computed
    /// by an offline search for the smallest valid α).
    #[test]
    fn tower_alphas_have_trace_one() {
        for &w in &[1usize, 2, 4, 8, 16, 32, 64, 128] {
            let m_low = base_irreducible(w).unwrap();
            let alpha = quadratic_alpha(w).unwrap();
            assert_eq!(
                trace(w, m_low, alpha),
                1,
                "Tr_(GF(2^{})/F_2)({:#x}) must be 1 for y² + y + α to be irreducible",
                w,
                alpha
            );
        }
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
