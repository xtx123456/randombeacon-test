//! `Gf2Element` — the on-wire envelope for any `GF(2^w_q)` value.
//!
//! Storage convention
//! ------------------
//!
//! Every element occupies a fixed-size `[u8; 32]` little-endian
//! buffer. The low `w_q` bits hold the polynomial-basis encoding;
//! the remaining `(256 − w_q)` bits MUST be zero (verified on
//! deserialization). Using a uniform 32-byte payload regardless of
//! `w_q` keeps the wire format compatible with the existing
//! `types::msg::beacon::Val = [u8; HASH_SIZE]` interface.
//!
//! Subfield embedding
//! ------------------
//!
//! Because the tower builds `GF(2^w_q)` recursively from
//! `GF(2^w_p)` via quadratic Artin–Schreier extensions
//! `m(y) = y² + y + α`, the sub-field `GF(2^w_p)` embeds into
//! `GF(2^w_q)` simply as the "low half of the lowest level": an
//! element `s ∈ GF(2^w_p)` lifts to `(s, 0, 0, …, 0)` in tower
//! coordinates. In the flat `[u8; 32]` encoding this is just the
//! low `w_p` bits — see `lift_small()` and `project_to_small()`.
//!
//! This embedding preserves the field structure: `lift(a + b) =
//! lift(a) + lift(b)` (XOR commutes with truncation) and
//! `lift(a · b) = lift(a) · lift(b)` (the recursion's base case
//! IS the small-field multiplication).

use rand::Rng;

use super::profile::Gf2Profile;
use super::tower;

/// Wire-compatible binary-extension-field element.
///
/// The envelope is fixed at 32 bytes regardless of `w_q`. Each
/// element carries the originating `Gf2Profile` for arithmetic
/// dispatch; the profile is *not* part of the wire format — peer
/// nodes share the profile via configuration / the CLI flag
/// wiring done in a follow-up commit, and convert
/// `[u8; HASH_SIZE]` ↔ `Gf2Element` explicitly at the boundary
/// using `from_bytes` / `as_bytes`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gf2Element {
    bytes: [u8; 32],
    profile: Gf2Profile,
}

impl std::fmt::Debug for Gf2Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gf2Element[w_p={}, w_q={}, bytes=",
            self.profile.w_p, self.profile.w_q
        )?;
        let n = self.profile.large_byte_len();
        for b in &self.bytes[..n] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, "]")
    }
}

impl Gf2Element {
    /// The all-zero element under `profile`.
    pub fn zero(profile: Gf2Profile) -> Self {
        Self {
            bytes: [0u8; 32],
            profile,
        }
    }

    /// The multiplicative identity (`1`) under `profile`.
    pub fn one(profile: Gf2Profile) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        Self { bytes, profile }
    }

    /// Construct from raw 32-byte storage. Returns `Err` if the bytes
    /// have any set bit beyond position `w_q`. Use this to ingest
    /// data received over the wire.
    pub fn from_bytes(profile: Gf2Profile, bytes: [u8; 32]) -> Result<Self, &'static str> {
        let used = profile.large_byte_len();
        // Bytes beyond `used` must all be zero.
        for &b in &bytes[used..] {
            if b != 0 {
                return Err("Gf2Element: bytes beyond w_q-byte boundary must be zero");
            }
        }
        // Within the last "partial" byte, the bits beyond `w_q % 8` must also be zero.
        let extra_bits = profile.w_q % 8;
        if extra_bits != 0 && used > 0 {
            let tail = bytes[used - 1];
            let allowed_mask = (1u8 << extra_bits) - 1;
            if tail & !allowed_mask != 0 {
                return Err("Gf2Element: high bits in the boundary byte must be zero");
            }
        }
        Ok(Self { bytes, profile })
    }

    /// Construct from raw bytes without validation. Caller asserts
    /// the high bits are already zero. Used internally by arithmetic
    /// where the canonical-form invariant is preserved by construction;
    /// will become hot in follow-up commits when AVSS share-handling
    /// switches over to `Gf2Element` end-to-end.
    #[allow(dead_code)]
    pub(crate) fn from_bytes_unchecked(profile: Gf2Profile, bytes: [u8; 32]) -> Self {
        Self { bytes, profile }
    }

    /// Borrow the raw 32-byte payload.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Consume `self` and return the raw 32-byte payload.
    #[inline]
    pub fn into_bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// The profile this element belongs to.
    #[inline]
    pub fn profile(&self) -> Gf2Profile {
        self.profile
    }

    /// Sample a uniformly random element of `GF(2^w_q)`.
    ///
    /// Cryptographic-strength randomness is the caller's
    /// responsibility — pass an appropriately seeded `Rng` such as
    /// `OsRng`. The function masks the result to the canonical low
    /// `w_q` bits.
    pub fn random<R: Rng>(profile: Gf2Profile, rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[..]);
        // Mask off bits beyond w_q.
        let used = profile.large_byte_len();
        for b in &mut bytes[used..] {
            *b = 0;
        }
        let extra_bits = profile.w_q % 8;
        if extra_bits != 0 && used > 0 {
            let mask = (1u8 << extra_bits) - 1;
            bytes[used - 1] &= mask;
        }
        Self { bytes, profile }
    }

    /// Lift a small-field value `s ∈ GF(2^w_p)` (low `w_p` bits of
    /// `small_bytes`) into the large field `GF(2^w_q)`. The
    /// embedding is the canonical "place into low coordinate"
    /// inclusion `GF(2^w_p) ↪ GF(2^w_q)`.
    ///
    /// `small_bytes` must be at least `w_p / 8` bytes long. Bits
    /// beyond `w_p` are ignored.
    pub fn lift_small(profile: Gf2Profile, small_bytes: &[u8]) -> Self {
        let small_len = profile.small_byte_len();
        debug_assert!(
            small_bytes.len() >= small_len,
            "small_bytes must have at least small_byte_len() bytes"
        );
        let mut bytes = [0u8; 32];
        // Copy the low w_p bits of `small_bytes` into `bytes[..small_len]`.
        bytes[..small_len].copy_from_slice(&small_bytes[..small_len]);
        // Mask the boundary byte of the small-field representation.
        let small_extra_bits = profile.w_p % 8;
        if small_extra_bits != 0 && small_len > 0 {
            let mask = (1u8 << small_extra_bits) - 1;
            bytes[small_len - 1] &= mask;
        }
        Self { bytes, profile }
    }

    /// Project a (presumed-small-field) `Gf2Element` of `GF(2^w_q)`
    /// down to its low `w_p` bits as the small-field encoding.
    /// Returns the low-`w_p`-bits raw bytes (length `small_byte_len()`).
    ///
    /// Note: the projection is only the inverse of `lift_small` when
    /// the upper coordinates of the tower decomposition are zero.
    /// Used by callers that expect a sub-field element (e.g. the
    /// PPT secret reconstruction step).
    pub fn project_to_small(&self) -> Vec<u8> {
        let small_len = self.profile.small_byte_len();
        let mut out = vec![0u8; small_len];
        out.copy_from_slice(&self.bytes[..small_len]);
        // Clear bits beyond w_p in the boundary byte of the result.
        let small_extra_bits = self.profile.w_p % 8;
        if small_extra_bits != 0 && small_len > 0 {
            let mask = (1u8 << small_extra_bits) - 1;
            out[small_len - 1] &= mask;
        }
        out
    }

    /// Test whether the element actually lives in the small-field
    /// sub-image, i.e. whether `project_to_small` followed by
    /// `lift_small` recovers `self`. Equivalent to checking that the
    /// high `w_q − w_p` bits of `bytes` are zero.
    pub fn is_in_small_field(&self) -> bool {
        let small_len = self.profile.small_byte_len();
        let large_len = self.profile.large_byte_len();
        // Bytes strictly above the small-field boundary must be zero.
        if self.bytes[small_len..large_len].iter().any(|&b| b != 0) {
            return false;
        }
        // Within the small-field boundary byte, bits above `w_p`
        // (but still in the same byte) must be zero.
        let small_extra = self.profile.w_p % 8;
        if small_extra != 0 && small_len > 0 {
            let mask = (1u8 << small_extra) - 1;
            if self.bytes[small_len - 1] & !mask != 0 {
                return false;
            }
        }
        true
    }

    /// Field addition (XOR over each byte).
    pub fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.profile, rhs.profile, "add: profile mismatch");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.bytes[i] ^ rhs.bytes[i];
        }
        Self {
            bytes: out,
            profile: self.profile,
        }
    }

    /// Field multiplication, dispatched by `profile.w_q`.
    pub fn mul(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.profile, rhs.profile, "mul: profile mismatch");
        if self.profile.w_q <= 128 {
            let a = u128_from_lo(&self.bytes);
            let b = u128_from_lo(&rhs.bytes);
            let prod = tower::mul_u128(&self.profile, self.profile.w_q, a, b);
            let mut out = [0u8; 32];
            write_u128_lo(&mut out, prod);
            Self {
                bytes: out,
                profile: self.profile,
            }
        } else {
            // w_q == 256 path
            let a = u256_from_bytes(&self.bytes);
            let b = u256_from_bytes(&rhs.bytes);
            let prod = tower::mul_u256(&self.profile, a, b);
            Self {
                bytes: u256_to_bytes(prod),
                profile: self.profile,
            }
        }
    }

    /// Field inversion. `0.inv()` returns `Self::zero()` (sentinel —
    /// callers must check `is_zero()` first when correctness matters).
    pub fn inv(&self) -> Self {
        if self.profile.w_q <= 128 {
            let a = u128_from_lo(&self.bytes);
            let inv = tower::inv_u128(&self.profile, self.profile.w_q, a);
            let mut out = [0u8; 32];
            write_u128_lo(&mut out, inv);
            Self {
                bytes: out,
                profile: self.profile,
            }
        } else {
            let a = u256_from_bytes(&self.bytes);
            let inv = tower::inv_u256(&self.profile, a);
            Self {
                bytes: u256_to_bytes(inv),
                profile: self.profile,
            }
        }
    }

    /// Check whether this is the zero element.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
}

// Internal helpers for converting between `[u8; 32]` and `u128` /
// `(u128, u128)`. We choose little-endian to match common AES-like
// wire formats and because the polynomial-basis "bit i is x^i" view
// agrees with little-endian byte order (low bytes first).

#[inline]
fn u128_from_lo(bytes: &[u8; 32]) -> u128 {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_le_bytes(buf)
}

#[inline]
fn write_u128_lo(out: &mut [u8; 32], value: u128) {
    out[..16].copy_from_slice(&value.to_le_bytes());
}

#[inline]
fn u256_from_bytes(bytes: &[u8; 32]) -> (u128, u128) {
    let mut lo_buf = [0u8; 16];
    let mut hi_buf = [0u8; 16];
    lo_buf.copy_from_slice(&bytes[..16]);
    hi_buf.copy_from_slice(&bytes[16..]);
    (u128::from_le_bytes(lo_buf), u128::from_le_bytes(hi_buf))
}

#[inline]
fn u256_to_bytes((lo, hi): (u128, u128)) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo.to_le_bytes());
    out[16..].copy_from_slice(&hi.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn from_bytes_rejects_dirty_high_bits() {
        let profile = Gf2Profile::new(8, 64).unwrap();
        // Ten bytes used (well, 8), set a bit at position 70.
        let mut bytes = [0u8; 32];
        bytes[8] = 1; // bit 64
        assert!(Gf2Element::from_bytes(profile, bytes).is_err());

        // For w_q = 64 (whole bytes), bytes[8..] must be zero.
        let mut clean = [0u8; 32];
        clean[..8].copy_from_slice(&[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88]);
        assert!(Gf2Element::from_bytes(profile, clean).is_ok());
    }

    #[test]
    fn from_bytes_rejects_partial_boundary_byte() {
        // w_q = 12 means 1.5 bytes used; the high 4 bits of byte[1] must be zero.
        // Use a profile with w_p | w_q. (8, 16) is closest and integer-byte;
        // we instead synthesize a manual test with (1, 1).
        // Better: register a custom test profile (1, 1) — wq is 1 bit.
        let profile = Gf2Profile::new(1, 1).unwrap();
        // w_q = 1 -> only bit 0 of byte 0 may be set.
        let mut ok = [0u8; 32];
        ok[0] = 1;
        assert!(Gf2Element::from_bytes(profile, ok).is_ok());
        let mut bad = [0u8; 32];
        bad[0] = 2; // bit 1 set
        assert!(Gf2Element::from_bytes(profile, bad).is_err());
    }

    #[test]
    fn random_stays_in_canonical_form() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        for &(w_p, w_q) in &[(8usize, 16usize), (32, 64), (32, 128), (8, 256), (64, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..32 {
                let e = Gf2Element::random(p, &mut rng);
                // Round-trip through from_bytes should succeed.
                let same = Gf2Element::from_bytes(p, *e.as_bytes()).expect("canonical");
                assert_eq!(e, same);
            }
        }
    }

    /// Random elements should not all collide. We don't try to
    /// estimate min-entropy here; we just check that 16 samples in
    /// `GF(2^16)` and above are all distinct.
    #[test]
    fn random_distinct_at_w_q_ge_16() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(12345);
        for &(w_p, w_q) in &[(8usize, 16usize), (8, 64), (32, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let n = 16;
            let mut seen = std::collections::HashSet::new();
            for _ in 0..n {
                seen.insert(Gf2Element::random(p, &mut rng).bytes);
            }
            assert_eq!(seen.len(), n, "random duplicates at ({},{})", w_p, w_q);
        }
    }

    #[test]
    fn lift_then_project_is_identity_on_small() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xabcdef);
        for &(w_p, w_q) in &[(8usize, 64usize), (8, 256), (32, 256), (16, 128), (64, 128)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let small_len = p.small_byte_len();
            for _ in 0..32 {
                // Random small-field bytes.
                let mut s_bytes = vec![0u8; small_len];
                rng.fill(&mut s_bytes[..]);
                // Mask to small-field boundary.
                let extra = w_p % 8;
                if extra != 0 {
                    s_bytes[small_len - 1] &= (1u8 << extra) - 1;
                }
                let lifted = Gf2Element::lift_small(p, &s_bytes);
                assert!(lifted.is_in_small_field());
                let projected = lifted.project_to_small();
                assert_eq!(projected, s_bytes, "lift∘project mismatch at ({},{})", w_p, w_q);
            }
        }
    }

    /// Lifting commutes with addition and multiplication: for
    /// `s, t ∈ GF(2^w_p)`,
    ///     lift(s + t) = lift(s) + lift(t)
    ///     lift(s · t) = lift(s) · lift(t)
    /// The first is trivial (XOR commutes with truncation); the
    /// second is the substantive check that the tower's base-case
    /// dispatch lines up with `poly::gf_mul`.
    #[test]
    fn lift_homomorphism_at_various_profiles() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4242);
        for &(w_p, w_q) in &[(8usize, 64usize), (16, 128), (32, 256), (8, 256), (64, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let small_len = p.small_byte_len();
            for _ in 0..16 {
                let mut s_bytes = vec![0u8; small_len];
                let mut t_bytes = vec![0u8; small_len];
                rng.fill(&mut s_bytes[..]);
                rng.fill(&mut t_bytes[..]);
                let extra = w_p % 8;
                if extra != 0 {
                    s_bytes[small_len - 1] &= (1u8 << extra) - 1;
                    t_bytes[small_len - 1] &= (1u8 << extra) - 1;
                }
                let lift_s = Gf2Element::lift_small(p, &s_bytes);
                let lift_t = Gf2Element::lift_small(p, &t_bytes);

                // s + t in small bytes
                let mut sum_bytes = vec![0u8; small_len];
                for i in 0..small_len {
                    sum_bytes[i] = s_bytes[i] ^ t_bytes[i];
                }
                let lift_sum = Gf2Element::lift_small(p, &sum_bytes);
                assert_eq!(lift_s.add(&lift_t), lift_sum);

                // s · t in small bytes via raw poly::gf_mul. Encode
                // both into a `u128` and compute the product in the
                // small field; then project back to small_byte_len.
                let s_u128 = small_to_u128(&s_bytes);
                let t_u128 = small_to_u128(&t_bytes);
                let m_p = super::super::profile::base_irreducible(w_p).unwrap();
                let prod_small = super::super::poly::gf_mul(s_u128, t_u128, w_p, m_p);
                let mut prod_bytes = vec![0u8; small_len];
                u128_to_small(&mut prod_bytes, prod_small);
                let lift_prod = Gf2Element::lift_small(p, &prod_bytes);

                assert_eq!(lift_s.mul(&lift_t), lift_prod, "mul lift mismatch");
            }
        }
    }

    fn small_to_u128(bytes: &[u8]) -> u128 {
        let mut buf = [0u8; 16];
        buf[..bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
        u128::from_le_bytes(buf)
    }

    fn u128_to_small(out: &mut [u8], value: u128) {
        let bytes = value.to_le_bytes();
        out.copy_from_slice(&bytes[..out.len()]);
    }

    /// Field axioms via the `Gf2Element` API directly.
    #[test]
    fn element_field_axioms() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x9999);
        for &(w_p, w_q) in &[(8usize, 64usize), (32, 128), (8, 256), (64, 256)] {
            let p = Gf2Profile::new(w_p, w_q).unwrap();
            let zero = Gf2Element::zero(p);
            let one = Gf2Element::one(p);
            for _ in 0..16 {
                let a = Gf2Element::random(p, &mut rng);
                assert_eq!(a.add(&zero), a);
                assert_eq!(a.mul(&one), a);
                assert_eq!(a.mul(&zero), zero);
                if !a.is_zero() {
                    let inv = a.inv();
                    assert_eq!(a.mul(&inv), one);
                }
            }
        }
    }

    /// Wire-format roundtrip: send only the 32-byte payload over the
    /// network; the receiver reconstructs `Gf2Element` using its own
    /// profile. This mirrors how the existing `Val = [u8; HASH_SIZE]`
    /// pipeline already works in `types::msg::beacon`.
    #[test]
    fn wire_bytes_roundtrip() {
        let p = Gf2Profile::new(64, 128).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let e = Gf2Element::random(p, &mut rng);
        let on_wire: [u8; 32] = *e.as_bytes();
        let received = Gf2Element::from_bytes(p, on_wire).unwrap();
        assert_eq!(received, e);
    }
}
