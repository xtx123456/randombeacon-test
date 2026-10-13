//! PPT two-field dealer over the `GF(2^w_p) ⊂ GF(2^w_q)` tower.
//!
//! This is the **GF(2^w) sibling** of `shamir::two_field::TwoFieldDealer`,
//! providing the same API shape (`sample_shares`,
//! `compute_degree_test_poly`, `verify_share`, `share_secret`) but
//! operating entirely on `crypto::gf2::Gf2Element` values rather
//! than `BigUint`.
//!
//! Commit 3 of the GF(2^w) migration introduces this module **side
//! by side** with the legacy BigUint dealer; no existing call site
//! is rewired yet. Commits 4+ branch each call site on
//! `Context::gf2_profile.is_some()` and route to the appropriate
//! dealer.
//!
//! Mathematical mapping vs. the BigUint dealer
//! -------------------------------------------
//!
//! | BigUint quantity         | GF(2^w) equivalent                                    |
//! |--------------------------|-------------------------------------------------------|
//! | small_field `p`          | base field `GF(2^w_p)` of the tower                   |
//! | large_field `q`          | extension `GF(2^w_q)` of the tower                    |
//! | f(x) coeffs mod `p`      | f(x) coeffs in `GF(2^w_p)` (i.e. small-field image)   |
//! | g(x) coeffs mod `q`      | g(x) coeffs in `GF(2^w_q)` (full-width random)        |
//! | h = g - θ·f mod `q`      | h = g + θ·f over `GF(2^w_q)` (char-2: `−` ≡ `+`)      |
//! | f(i) mod `p` (`secret`)  | f(i) ∈ `GF(2^w_p)` subfield image                     |
//! | f(i) mod `q` (`f_large`) | same f(i), viewed as an element of `GF(2^w_q)`        |
//! | Lagrange (1/x_j − x_k)   | char-2 Lagrange: `1/(x_j + x_k)` (subtraction ≡ XOR)  |
//!
//! Three char-2 simplifications collapse compared to the BigUint path:
//!
//! 1. **Subtraction is addition.** `g − θ·f` and `g + θ·f` are the
//!    same operation (XOR). `verify_share` and `compute_degree_test_poly`
//!    use addition throughout — no need for the BigUint code's
//!    `if g >= θf { … } else { q + … }` underflow guard.
//!
//! 2. **Subfield closure substitutes for "lift then re-evaluate".**
//!    In the BigUint dealer, computing `f_large(i)` requires a
//!    second polynomial evaluation `mod q` because `(c mod p) mod q
//!    ≠ c mod q` when polynomial sums exceed `p`. In GF(2^w), the
//!    embedding `GF(2^w_p) ↪ GF(2^w_q)` is a ring homomorphism, so
//!    `f(i)` computed entirely in `GF(2^w_q)` on small-field inputs
//!    stays in the small-field image (the tower's Karatsuba
//!    recursion vanishes the high halves at every level). The
//!    two views — `secret_shares` and `f_large_shares` — therefore
//!    coincide bit-for-bit and are emitted as the same `Gf2Element`.
//!
//! 3. **Evaluation points are integer bit-patterns.** Node `i ∈ 1..=n`
//!    maps to the element whose polynomial-basis encoding is the
//!    little-endian byte representation of `i`, lifted into
//!    `GF(2^w_q)`. This requires `n < 2^w_p` so the `n` evaluation
//!    points are distinct in the small field; the constructor
//!    rejects any `(profile, share_amount)` that violates this.

use rand::Rng;

use crypto::gf2::{Gf2Element, Gf2Profile};

// `crypto` uses `rand 0.8`; `ppt_beacon` is still on `rand 0.6`.
// We do NOT call `Gf2Element::random` (which requires a `rand 0.8`
// `Rng`); instead we fill `[u8; 32]` via this crate's local `rand 0.6`
// RNG and call `Gf2Element::from_random_bytes`, which is rand-
// version-agnostic. This keeps commit 3 free of any cross-version
// dependency surgery.

/// PPT two-field dealer parametrised by a `Gf2Profile`.
///
/// `threshold = t = f + 1` is the Shamir reconstruction threshold
/// (also the number of polynomial coefficients, equal to one plus
/// the polynomial degree). `share_amount = n = 3f + 1` is the
/// number of recipients.
#[derive(Clone, Debug)]
pub struct Gf2TwoFieldDealer {
    pub profile: Gf2Profile,
    pub threshold: usize,
    pub share_amount: usize,
    /// Cached `(w_p, w_p)` profile for the **small-field-only**
    /// arithmetic path (commit 8b). Used by `sample_shares` to run
    /// the f-polynomial Horner evaluation in `GF(2^w_p)` instead of
    /// the larger tower, skipping `tower_depth` levels of Karatsuba
    /// recursion per multiplication. Subfield closure guarantees the
    /// result lies in the same small-field image bytes whether we
    /// compute in `(w_p, w_p)` or `(w_p, w_q)`, so this is purely a
    /// performance optimisation — no observable correctness or wire
    /// format change.
    small_profile: Gf2Profile,
}

/// Full set of per-recipient shares plus the public degree-test
/// polynomial `h(x)`. Mirrors `shamir::two_field::TwoFieldShares`.
///
/// In GF(2^w), `secret_shares[i]` and `f_large_shares[i]` carry
/// **the same bytes** for every `i` (subfield closure); both fields
/// are retained to keep the API shape parity with the BigUint
/// dealer and to make later migration commits a straightforward
/// type substitution.
#[derive(Clone, Debug)]
pub struct Gf2TwoFieldShares {
    /// `f(i)` for each node `i`, viewed as a small-field element.
    pub secret_shares: Vec<(usize, Gf2Element)>,
    /// `f(i)` for each node `i`, viewed as a large-field element.
    /// In GF(2^w) this equals `secret_shares[i].1` byte-for-byte.
    pub f_large_shares: Vec<(usize, Gf2Element)>,
    /// `g(i)` for each node `i`, full-width large-field random.
    pub mask_shares: Vec<(usize, Gf2Element)>,
    /// Coefficients of `h(x) = g(x) + θ·f(x)` over `GF(2^w_q)`.
    pub degree_test_coeffs: Vec<Gf2Element>,
}

/// Pre-Fiat-Shamir intermediate: shares + raw polynomials without
/// the degree-test polynomial `h` (which needs θ derived from the
/// commitment). Mirrors `shamir::two_field::TwoFieldSampled`.
#[derive(Clone, Debug)]
pub struct Gf2TwoFieldSampled {
    pub secret_shares: Vec<(usize, Gf2Element)>,
    pub f_large_shares: Vec<(usize, Gf2Element)>,
    pub mask_shares: Vec<(usize, Gf2Element)>,
    /// `f(x)` coefficients (small-field image).
    pub f_poly: Vec<Gf2Element>,
    /// `g(x)` coefficients (full-width large field).
    pub g_poly: Vec<Gf2Element>,
}

/// Main-batch sampling: B small-field polynomials and ONE large-field mask.
pub(crate) struct Gf2TwoFieldBatch {
    pub secrets: Vec<Vec<Gf2Element>>,
    pub f_polys: Vec<Vec<Gf2Element>>,
    pub mask_shares: Vec<Gf2Element>,
    pub g_poly: Vec<Gf2Element>,
}

impl Gf2TwoFieldDealer {
    /// Sample a complete R=1 batch without generating B unused mask polynomials.
    /// Small-field evaluations retain the existing depth-zero arithmetic path.
    pub(crate) fn sample_batch(&self, batch_size: usize) -> Gf2TwoFieldBatch {
        let mut rng = rand::thread_rng();
        let mut secrets = vec![Vec::with_capacity(batch_size); self.share_amount];
        let mut f_polys = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let polynomial: Vec<_> = (0..self.threshold)
                .map(|_| random_small_field(self.profile, &mut rng)).collect();
            let small: Vec<_> = polynomial.iter().map(|coefficient| {
                Gf2Element::from_bytes(self.small_profile, *coefficient.as_bytes())
                    .expect("sampled coefficient is in the base field")
            }).collect();
            for (recipient, shares) in secrets.iter_mut().enumerate() {
                let x = small_field_point(self.small_profile, recipient + 1);
                let value = eval_poly_horner(self.small_profile, &small, x);
                shares.push(Gf2Element::from_bytes(self.profile, *value.as_bytes())
                    .expect("base-field value embeds canonically"));
            }
            f_polys.push(polynomial);
        }
        let g_poly: Vec<_> = (0..self.threshold)
            .map(|_| random_large_field(self.profile, &mut rng)).collect();
        let mask_shares = (1..=self.share_amount).map(|recipient| {
            eval_poly_horner_small_x(self.profile, &g_poly, small_field_point(self.profile, recipient))
        }).collect();
        Gf2TwoFieldBatch { secrets, f_polys, mask_shares, g_poly }
    }

    /// Construct a dealer for the given profile, threshold, and
    /// share count. Returns `Err` with a human-readable message
    /// when any constraint is violated:
    ///
    /// * `threshold ≥ 1`
    /// * `share_amount ≥ threshold`
    /// * `share_amount < 2^w_p` — enforces distinct evaluation
    ///   points `{1, 2, …, n}` in the small field `GF(2^w_p)`.
    pub fn new(
        profile: Gf2Profile,
        threshold: usize,
        share_amount: usize,
    ) -> Result<Self, String> {
        if threshold == 0 {
            return Err("threshold must be ≥ 1".into());
        }
        if share_amount < threshold {
            return Err(format!(
                "share_amount ({}) must be ≥ threshold ({})",
                share_amount, threshold
            ));
        }
        let max = max_share_amount_for_w_p(profile.w_p);
        if share_amount > max {
            // ceil(log2(share_amount + 1)) — the smallest w_p that
            // would admit this many recipients.
            let needed_bits = (share_amount as u64 + 1).next_power_of_two().trailing_zeros();
            return Err(format!(
                "share_amount ({}) > 2^w_p - 1 ({}); evaluation points 1..n must be \
                 distinct in GF(2^{}). Pick a Gf2Profile with w_p >= {} bits.",
                share_amount, max, profile.w_p, needed_bits
            ));
        }
        // Cached small-field-only profile for the 8b fast path. Always
        // valid when `profile` itself is valid (registry covers all
        // `w` ≥ 1).
        let small_profile = Gf2Profile::new(profile.w_p, profile.w_p)
            .expect("(w_p, w_p) is always a valid registered profile");
        Ok(Self {
            profile,
            threshold,
            share_amount,
            small_profile,
        })
    }

    /// Convenience: combine `sample_shares` + `compute_degree_test_poly`
    /// when θ is already known. Production (Fiat-Shamir) uses
    /// `sample_shares` then `compute_degree_test_poly` separately so
    /// θ can be derived from a commitment over the shares.
    pub fn share_secret(&self, secret: Gf2Element, theta: &Gf2Element) -> Gf2TwoFieldShares {
        let sampled = self.sample_shares(secret);
        let h = self.compute_degree_test_poly(&sampled.f_poly, &sampled.g_poly, theta);
        Gf2TwoFieldShares {
            secret_shares: sampled.secret_shares,
            f_large_shares: sampled.f_large_shares,
            mask_shares: sampled.mask_shares,
            degree_test_coeffs: h,
        }
    }

    /// Sample `f` (encoding `secret`) and the random mask `g`,
    /// returning all per-recipient shares plus the raw polynomials
    /// — but WITHOUT computing `h` (which needs θ).
    ///
    /// Pre: `secret.profile() == self.profile` and `secret` lies in
    /// the small-field image (high bits beyond `w_p` are zero). The
    /// dealer enforces both via `debug_assert!`.
    pub fn sample_shares(&self, secret: Gf2Element) -> Gf2TwoFieldSampled {
        debug_assert_eq!(
            secret.profile(),
            self.profile,
            "secret profile must match dealer profile"
        );
        debug_assert!(
            secret.is_in_small_field(),
            "secret must lie in the small-field image (high bits beyond w_p must be zero)"
        );
        let mut rng = rand::thread_rng();

        // f(x): coeff[0] = secret, coeff[1..t] uniform in GF(2^w_p).
        let mut f_poly = Vec::with_capacity(self.threshold);
        f_poly.push(secret);
        for _ in 1..self.threshold {
            f_poly.push(random_small_field(self.profile, &mut rng));
        }

        // g(x): coeff[0..t] uniform in GF(2^w_q) (full-width mask).
        let mut g_poly = Vec::with_capacity(self.threshold);
        for _ in 0..self.threshold {
            g_poly.push(random_large_field(self.profile, &mut rng));
        }

        // f(i) for i = 1..=n. **Commit 8b fast path**: instead of
        // evaluating f in the large field `(w_p, w_q)` and relying on
        // subfield closure to keep the result in the image, we
        // re-type f's coefficients into `(w_p, w_p)` (depth-0 tower)
        // and run Horner there. Each multiplication then bottoms out
        // at a single `poly::gf_mul(w_p, …)` call instead of the
        // `tower_depth` levels of Karatsuba recursion the large field
        // does — roughly a `3^d` speedup for depth `d` (e.g. ~9× for
        // `(32, 128)`, ~27× for `(32, 256)`).
        //
        // Re-typing is byte-aliasing only (the bytes of a small-image
        // element are profile-agnostic) so the per-coin cost added
        // here is a handful of byte copies, negligible.
        let f_poly_small: Vec<Gf2Element> = f_poly
            .iter()
            .map(|c| {
                Gf2Element::from_bytes(self.small_profile, *c.as_bytes())
                    .expect("f-poly coefficient is in small-field image")
            })
            .collect();
        let mut secret_shares = Vec::with_capacity(self.share_amount);
        let mut f_large_shares = Vec::with_capacity(self.share_amount);
        for i in 1..=self.share_amount {
            let x_small = small_field_point(self.small_profile, i);
            let y_small = eval_poly_horner(self.small_profile, &f_poly_small, x_small);
            // Re-encode y under the large profile for the API.
            // Small-image bytes are byte-equal across the two profiles
            // so `from_bytes` succeeds (high bytes already zero).
            let y_large = Gf2Element::from_bytes(self.profile, *y_small.as_bytes())
                .expect("small-image bytes are canonical under (w_p, w_q)");
            debug_assert!(
                y_large.is_in_small_field(),
                "subfield closure broken: f({}) escaped the GF(2^{}) image",
                i,
                self.profile.w_p
            );
            secret_shares.push((i, y_large));
            f_large_shares.push((i, y_large));
        }

        // g(i) for i = 1..=n. `g` has full-width `GF(2^w_q)`
        // coefficients so this cannot drop to the base field the way
        // the f-evaluation did — but the evaluation POINT is a
        // base-field element, so each Horner step is a large-by-small
        // product and takes the `mul_small` coordinate-scaling path
        // instead of the full Karatsuba recursion.
        let mut mask_shares = Vec::with_capacity(self.share_amount);
        for i in 1..=self.share_amount {
            let x = small_field_point(self.profile, i);
            let y = eval_poly_horner_small_x(self.profile, &g_poly, x);
            mask_shares.push((i, y));
        }

        Gf2TwoFieldSampled {
            secret_shares,
            f_large_shares,
            mask_shares,
            f_poly,
            g_poly,
        }
    }

    /// The canonical number of coefficients in any committed
    /// polynomial of this scheme: `t = f + 1`, i.e. degree `≤ f`.
    ///
    /// `h = g + θ·f` is a sum of two degree-`≤ f` polynomials, so an
    /// honest dealer always emits exactly this many coefficients. The
    /// receiver treats the count as part of the encoding and rejects
    /// anything else — see `verify_share`.
    pub fn canonical_coeff_len(&self) -> usize {
        self.threshold
    }

    /// Compute `h(x) = g(x) + θ · f(x)` over `GF(2^w_q)`.
    ///
    /// In char 2 this is equal to the textbook `g(x) − θ · f(x)`
    /// (subtraction is XOR); we use the additive form for clarity.
    ///
    /// The output always has exactly `threshold` coefficients,
    /// zero-padded if either input is shorter, so the wire encoding is
    /// fixed-length and the receiver's degree-bound check is a simple
    /// length comparison.
    pub fn compute_degree_test_poly(
        &self,
        f_poly: &[Gf2Element],
        g_poly: &[Gf2Element],
        theta: &Gf2Element,
    ) -> Vec<Gf2Element> {
        debug_assert!(
            f_poly.len() <= self.threshold && g_poly.len() <= self.threshold,
            "dealer polynomials must have degree <= f (at most {} coefficients)",
            self.threshold
        );
        let zero = Gf2Element::zero(self.profile);
        let mut h = Vec::with_capacity(self.threshold);
        for i in 0..self.threshold {
            let g_i = g_poly.get(i).copied().unwrap_or(zero);
            let f_i = f_poly.get(i).copied().unwrap_or(zero);
            // `f` has base-field coefficients by construction (the
            // secret and every sampled coefficient come from
            // `random_small_field` / `lift_small`), so θ·f_i is a
            // large-by-small product.
            debug_assert!(
                f_i.is_in_small_field(),
                "f-polynomial coefficients must lie in GF(2^w_p)"
            );
            let theta_f = theta.mul_small(&f_i);
            h.push(g_i.add(&theta_f));
        }
        h
    }

    /// Verify one recipient's share pair against the publicly
    /// known `h(x)` coefficients and the degree-test challenge `θ`.
    ///
    /// Returns `Ok(())` iff ALL of the following hold; each failure
    /// is a distinct, nameable reason so the caller can attribute
    /// blame rather than seeing an undifferentiated `false`.
    ///
    /// 1. **Degree bound.** `h_coeffs.len() == threshold = f + 1`,
    ///    i.e. `deg(h) ≤ f`. Checking only the pointwise identity
    ///    `h(e_i) = g(e_i) + θ·f(e_i)` is NOT sufficient: a dealer
    ///    can take `F(x) = x^(f+1)`, `G = 0` and publish
    ///    `h = θ·F`, whose coefficient vector has `f + 2` entries.
    ///    The identity then holds at every evaluation point — the
    ///    dealer is simply telling the truth about an over-degree
    ///    polynomial — so the secret is no longer `f`-private and
    ///    `f + 1` shares no longer determine it. The degree bound
    ///    has to be enforced on the *encoding*, which is why the
    ///    coefficient count is fixed and lower-degree polynomials
    ///    are zero-padded rather than truncated.
    ///
    /// 2. **Base-field membership of the share.** `f_large_share`
    ///    must lie in `GF(2^w_p)`. The two-field construction only
    ///    gives `f`-privacy over the *small* field, and the
    ///    reconstruction path interpolates these values as base-field
    ///    elements; accepting a share with components outside the
    ///    base field would let a dealer smuggle large-field values
    ///    into a small-field interpolation. Note this is a rejection,
    ///    not a repair: masking the high bits of a malicious input
    ///    and carrying on would accept a share the dealer never
    ///    committed to.
    ///
    /// 3. **Degree test.** `g(i) + θ · f_large(i) == h(i)` over
    ///    `GF(2^w_q)`.
    pub fn verify_share_checked(
        &self,
        node_id: usize,
        f_large_share: &Gf2Element,
        g_share: &Gf2Element,
        h_coeffs: &[Gf2Element],
        theta: &Gf2Element,
    ) -> Result<(), &'static str> {
        if node_id < 1 || node_id > self.share_amount {
            return Err("node_id outside 1..=share_amount");
        }
        if h_coeffs.len() != self.threshold {
            return Err("degree-test polynomial violates the deg <= f bound");
        }
        if !f_large_share.is_in_small_field() {
            return Err("share is not an element of the small field GF(2^w_p)");
        }
        let x = small_field_point(self.profile, node_id);
        let h_at_x = eval_poly_horner_small_x(self.profile, h_coeffs, x);
        // Checked immediately above, so the `mul_small` precondition
        // holds on this untrusted value.
        let theta_f = theta.mul_small(f_large_share);
        if g_share.add(&theta_f) != h_at_x {
            return Err("degree test failed");
        }
        Ok(())
    }

    /// Boolean wrapper around `verify_share_checked` for call sites
    /// that do not need the failure reason.
    pub fn verify_share(
        &self,
        node_id: usize,
        f_large_share: &Gf2Element,
        g_share: &Gf2Element,
        h_coeffs: &[Gf2Element],
        theta: &Gf2Element,
    ) -> bool {
        self.verify_share_checked(node_id, f_large_share, g_share, h_coeffs, theta)
            .is_ok()
    }
}

// =========================================================================
// Helpers — exported because reconstruction code in later commits needs
// to compute the same evaluation points and recover via Lagrange.
// =========================================================================

/// Compute the largest `share_amount` admissible for a given `w_p`,
/// i.e. `2^w_p − 1` (room for evaluation points `{1, 2, …, n}` to be
/// distinct in `GF(2^w_p)`). For `w_p ≥ 64` we just return
/// `usize::MAX` (the actual `1 << w_p` overflows `usize` on 64-bit
/// platforms, and no realistic deployment hits `2^64` recipients).
pub fn max_share_amount_for_w_p(w_p: usize) -> usize {
    if w_p >= (usize::BITS as usize) {
        usize::MAX
    } else {
        (1usize << w_p) - 1
    }
}

/// Validate that `node_id` is usable as a `GF(2^w_p)` evaluation
/// point under `profile`.
///
/// Two ways this fails, both of which would otherwise be hidden by
/// the silent truncation inside `lift_small`:
///
/// * `node_id == 0` maps to the zero element, which is the point the
///   Shamir polynomial is reconstructed AT. Including it among the
///   interpolation points makes the Vandermonde system singular.
/// * `node_id > 2^w_p − 1` wraps: with `w_p = 8`, ids `1` and `257`
///   both truncate to the byte `0x01`, and id `256` truncates to the
///   zero element. A collision like that silently corrupts the
///   interpolation instead of failing.
pub fn check_point_capacity(profile: Gf2Profile, node_id: usize) -> Result<(), String> {
    if node_id == 0 {
        return Err(
            "evaluation point 0 is reserved for the reconstructed secret and cannot be \
             used as a share index"
                .to_string(),
        );
    }
    let max = max_share_amount_for_w_p(profile.w_p);
    if node_id > max {
        return Err(format!(
            "evaluation point {} exceeds the GF(2^{}) point capacity 2^w_p - 1 = {}; \
             distinct points are required, and truncating would alias it onto another \
             point. Pick a Gf2Profile with w_p >= {} bits.",
            node_id,
            profile.w_p,
            max,
            (node_id as u64 + 1).next_power_of_two().trailing_zeros()
        ));
    }
    Ok(())
}

/// Validate a whole set of evaluation points: each individually in
/// range, and all pairwise distinct. Returns the first violation.
pub fn check_point_set(profile: Gf2Profile, node_ids: &[usize]) -> Result<(), String> {
    use std::collections::HashSet;
    let mut seen = HashSet::with_capacity(node_ids.len());
    for &id in node_ids {
        check_point_capacity(profile, id)?;
        if !seen.insert(id) {
            return Err(format!(
                "duplicate evaluation point {} in the interpolation set",
                id
            ));
        }
    }
    Ok(())
}

/// Map an integer node id `1..=n` to its `GF(2^w_p) ↪ GF(2^w_q)`
/// evaluation point. The result is a `Gf2Element` whose low `w_p`
/// bits encode the little-endian byte representation of `node_id`
/// and whose remaining bits are zero (i.e. the element lies in the
/// small-field image).
///
/// # Precondition
///
/// `check_point_capacity(profile, node_id)` must already hold. This
/// function truncates `node_id` to `w_p` bits, so an out-of-range id
/// would silently alias onto another point rather than fail; every
/// public constructor in this module validates the point set up front
/// and only then calls into this hot-path helper.
pub fn small_field_point(profile: Gf2Profile, node_id: usize) -> Gf2Element {
    debug_assert!(
        check_point_capacity(profile, node_id).is_ok(),
        "small_field_point called with an out-of-capacity node_id"
    );
    let small_len = profile.small_byte_len().max(1);
    let mut buf = vec![0u8; small_len];
    let id_bytes = node_id.to_le_bytes();
    let copy_len = small_len.min(id_bytes.len());
    buf[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
    Gf2Element::lift_small(profile, &buf)
}

/// Sample a uniformly-random `GF(2^w_p)` element, returned as a
/// `Gf2Element` of the full `profile` whose high bits beyond `w_p`
/// are zero (i.e. in the small-field image).
fn random_small_field<R: Rng>(profile: Gf2Profile, rng: &mut R) -> Gf2Element {
    let len = profile.small_byte_len();
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    Gf2Element::lift_small(profile, &bytes)
}

/// Sample a uniformly-random `GF(2^w_q)` element via this crate's
/// `rand 0.6` interface. Mirrors `Gf2Element::random` (rand 0.8) but
/// using the byte API so we don't import a second `rand` version.
fn random_large_field<R: Rng>(profile: Gf2Profile, rng: &mut R) -> Gf2Element {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    Gf2Element::from_random_bytes(profile, bytes)
}

/// Evaluate a polynomial (given by ascending-degree coefficients)
/// at point `x` via Horner's scheme over `GF(2^w_q)`. `t` recursive
/// multiplications plus `t` additions.
pub fn eval_poly_horner(
    profile: Gf2Profile,
    coeffs: &[Gf2Element],
    x: Gf2Element,
) -> Gf2Element {
    let mut acc = Gf2Element::zero(profile);
    for c in coeffs.iter().rev() {
        acc = acc.mul(&x).add(c);
    }
    acc
}

/// Horner evaluation specialised to an evaluation point that lies in
/// the base field `GF(2^w_p)`.
///
/// Every evaluation point PPT uses is `small_field_point(id)`, which
/// is a base-field element by construction, while the accumulator
/// ranges over the full `GF(2^w_q)`. Each Horner step is therefore a
/// large-by-small product and can use `Gf2Element::mul_small`, which
/// scales the `w_q / w_p` base-field coordinates directly instead of
/// recursing through Karatsuba. The value is identical to
/// `eval_poly_horner`; only the work differs.
///
/// # Precondition
///
/// `x.is_in_small_field()`. Established by construction at every call
/// site (the point comes from `small_field_point`), never assumed of
/// unvalidated input.
pub fn eval_poly_horner_small_x(
    profile: Gf2Profile,
    coeffs: &[Gf2Element],
    x: Gf2Element,
) -> Gf2Element {
    debug_assert!(
        x.is_in_small_field(),
        "eval_poly_horner_small_x: evaluation point must be a base-field element"
    );
    let mut acc = Gf2Element::zero(profile);
    for c in coeffs.iter().rev() {
        acc = acc.mul_small(&x).add(c);
    }
    acc
}

/// Precomputed Lagrange basis values `L_j(0)` for one fixed set of
/// evaluation points.
///
/// Building the basis costs `O(t²)` base-field multiplications plus
/// `t` inversions — by far the dominant term in reconstruction. The
/// points, however, are the *provider ids*, which are shared across
/// every coin and (usually) every dealer in a round. Splitting the
/// basis out lets the `O(t²)` work happen once per distinct provider
/// set while each individual recovery degenerates to a `t`-term dot
/// product.
///
/// Coefficients are stored under the `(w_p, w_p)` profile: both the
/// points and the recovered secret live in the base field, so the
/// whole computation can skip the tower levels entirely.
#[derive(Clone, Debug)]
pub struct Gf2LagrangeBasis {
    small_profile: Gf2Profile,
    /// `coeffs[k] = L_k(0)`, aligned with the **ascending** order of
    /// the evaluation points supplied to `new`.
    coeffs: Vec<Gf2Element>,
}

impl Gf2LagrangeBasis {
    /// Build the basis for `node_ids`, which must be given in
    /// ascending order, pairwise distinct, nonzero, and within the
    /// `GF(2^w_p)` point capacity.
    pub fn new(profile: Gf2Profile, node_ids: &[usize]) -> Result<Self, String> {
        if node_ids.is_empty() {
            return Err("Lagrange basis needs at least one evaluation point".to_string());
        }
        check_point_set(profile, node_ids)?;
        let small_profile = Gf2Profile::new(profile.w_p, profile.w_p)
            .map_err(|e| format!("cannot derive (w_p, w_p) profile: {}", e))?;

        let t = node_ids.len();
        let xs: Vec<Gf2Element> = node_ids
            .iter()
            .map(|&id| small_field_point(small_profile, id))
            .collect();

        let one = Gf2Element::one(small_profile);
        let mut coeffs = Vec::with_capacity(t);
        for j in 0..t {
            // L_j(0) = Π_{k ≠ j} x_k / (x_j + x_k).
            // char 2: 0 − x_k = x_k and x_j − x_k = x_j + x_k.
            let mut num = one;
            let mut den = one;
            for k in 0..t {
                if k != j {
                    num = num.mul(&xs[k]);
                    let diff = xs[j].add(&xs[k]);
                    if diff.is_zero() {
                        // Unreachable given `check_point_set`, but an
                        // inverse of zero must never be silently
                        // treated as zero.
                        return Err(format!(
                            "evaluation points {} and {} collide in GF(2^{})",
                            node_ids[j], node_ids[k], profile.w_p
                        ));
                    }
                    den = den.mul(&diff);
                }
            }
            if den.is_zero() {
                return Err("singular Lagrange denominator".to_string());
            }
            coeffs.push(num.mul(&den.inv()));
        }
        Ok(Self {
            small_profile,
            coeffs,
        })
    }

    /// Number of evaluation points this basis was built for.
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Recover `f(0)` as `Σ_k coeffs[k] · shares[k]`, where `shares`
    /// is aligned with the ascending point order given to `new` and
    /// every entry lies in the base field.
    pub fn recover(
        &self,
        profile: Gf2Profile,
        shares: &[Gf2Element],
    ) -> Result<Gf2Element, String> {
        if shares.len() != self.coeffs.len() {
            return Err(format!(
                "Lagrange basis has {} points but {} shares were supplied",
                self.coeffs.len(),
                shares.len()
            ));
        }
        let mut acc = Gf2Element::zero(self.small_profile);
        for (k, y) in shares.iter().enumerate() {
            if !y.is_in_small_field() {
                return Err(format!(
                    "share {} is not a GF(2^{}) element; cached basis recovery requires \
                     base-field shares",
                    k, profile.w_p
                ));
            }
            let y_small = Gf2Element::from_bytes(self.small_profile, *y.as_bytes())
                .map_err(|e| format!("share {} re-encode failed: {}", k, e))?;
            acc = acc.add(&self.coeffs[k].mul(&y_small));
        }
        Gf2Element::from_bytes(profile, *acc.as_bytes())
            .map_err(|e| format!("recovered value re-encode failed: {}", e))
    }
}

/// Bounded cache of `Gf2LagrangeBasis` keyed by the field definition
/// and the canonical (ascending) evaluation-point set.
///
/// A round reconstructs `batch × |decided|` secrets. Providers
/// respond per dealer, so different dealers can legitimately end up
/// with different `f+1` provider sets — the cache keys on the actual
/// set rather than assuming a single global one, which keeps the
/// "any `f+1` validated shares" liveness property intact while still
/// collapsing the common case (same providers for every coin of a
/// dealer, and usually across dealers too) to one basis build.
///
/// `capacity` bounds the number of retained bases so a long run
/// cannot accumulate one entry per transient provider set. On
/// overflow the cache is cleared rather than evicting by age: the
/// access pattern is "a handful of hot sets per round", so a full
/// reset at a round boundary is both cheap and self-limiting.
pub struct Gf2LagrangeCache {
    profile: Gf2Profile,
    /// Key: `(w_p, w_q, ascending point ids)`. The widths are part of
    /// the key so an entry can never be reused under a different
    /// field definition.
    entries: std::collections::HashMap<(usize, usize, Vec<usize>), Gf2LagrangeBasis>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl Gf2LagrangeCache {
    /// Default bound on retained bases. One round needs at most a few
    /// distinct provider sets; 256 leaves ample headroom while keeping
    /// the map small enough to stay cache-resident.
    pub const DEFAULT_CAPACITY: usize = 256;

    pub fn new(profile: Gf2Profile) -> Self {
        Self::with_capacity(profile, Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(profile: Gf2Profile, capacity: usize) -> Self {
        Self {
            profile,
            entries: std::collections::HashMap::new(),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
        }
    }

    /// `(hits, misses)` since construction — used by the benchmark to
    /// report how much repeated work the cache actually removed,
    /// rather than asserting a speedup.
    pub fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }

    /// Recover `f(0)` from `points`, reusing a cached basis whenever
    /// the same evaluation-point set has been seen before.
    ///
    /// `points` may be in any order; the basis is keyed and stored in
    /// ascending point order and the shares are permuted to match, so
    /// two callers that supply the same set in different orders still
    /// share one basis and both get the correct answer.
    pub fn recover_at_zero(
        &mut self,
        points: &[(usize, Gf2Element)],
    ) -> Result<Gf2Element, String> {
        if points.is_empty() {
            return Err("cannot recover from an empty share set".to_string());
        }
        // Canonical ascending order over evaluation points.
        let mut order: Vec<usize> = (0..points.len()).collect();
        order.sort_unstable_by_key(|&i| points[i].0);
        let ids: Vec<usize> = order.iter().map(|&i| points[i].0).collect();

        let key = (self.profile.w_p, self.profile.w_q, ids.clone());
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= self.capacity {
                self.entries.clear();
            }
            let basis = Gf2LagrangeBasis::new(self.profile, &ids)?;
            self.entries.insert(key.clone(), basis);
            self.misses += 1;
        } else {
            self.hits += 1;
        }
        let basis = self
            .entries
            .get(&key)
            .expect("just inserted or already present");

        let shares: Vec<Gf2Element> = order.iter().map(|&i| points[i].1).collect();
        basis.recover(self.profile, &shares)
    }
}

/// Recover `f(0)` from `t` (or more) `(node_id, share)` pairs via
/// Lagrange interpolation. Uses the **char-2-specialised** formula:
///
/// ```text
///     L_j(0) = Π_{k ≠ j} x_k / (x_j + x_k)
/// ```
///
/// (In char 2: `0 − x_k = x_k` and `x_j − x_k = x_j + x_k`.)
///
/// Fails with a descriptive error — rather than silently returning a
/// wrong value — when the point set is empty, contains duplicates,
/// contains `0`, or exceeds the `GF(2^w_p)` point capacity. A
/// singular Lagrange denominator is reported, never treated as zero.
///
/// This is the uncached entry point; callers that recover many
/// secrets over the same provider set should hold a
/// `Gf2LagrangeCache` instead, which reuses the `O(t²)` basis.
pub fn lagrange_recover_at_zero(
    profile: Gf2Profile,
    points: &[(usize, Gf2Element)],
) -> Result<Gf2Element, String> {
    if points.is_empty() {
        return Err("cannot recover from an empty share set".to_string());
    }
    let mut order: Vec<usize> = (0..points.len()).collect();
    order.sort_unstable_by_key(|&i| points[i].0);
    let ids: Vec<usize> = order.iter().map(|&i| points[i].0).collect();

    // All production callers (`secret_reconstruct`, `acs::coin`) pass
    // base-field shares, and the recovered `f(0)` is in the base field
    // too by closure, so the whole basis + dot product runs in
    // `(w_p, w_p)`: no tower levels, and every inversion lands in the
    // narrowest field. Inputs outside the base field take the
    // large-profile route below.
    if points.iter().all(|(_, y)| y.is_in_small_field()) {
        let basis = Gf2LagrangeBasis::new(profile, &ids)?;
        let shares: Vec<Gf2Element> = order.iter().map(|&i| points[i].1).collect();
        return basis.recover(profile, &shares);
    }
    lagrange_recover_at_zero_large(profile, points)
}

/// Slow-path Lagrange that runs entirely in the caller's large
/// profile. Used when at least one input has components outside the
/// base field, so the cached base-field basis does not apply.
fn lagrange_recover_at_zero_large(
    profile: Gf2Profile,
    points: &[(usize, Gf2Element)],
) -> Result<Gf2Element, String> {
    let ids: Vec<usize> = points.iter().map(|(i, _)| *i).collect();
    check_point_set(profile, &ids)?;

    let t = points.len();
    let xs: Vec<Gf2Element> = ids.iter().map(|&i| small_field_point(profile, i)).collect();
    let ys: Vec<Gf2Element> = points.iter().map(|(_, y)| *y).collect();

    let mut result = Gf2Element::zero(profile);
    let one = Gf2Element::one(profile);
    for j in 0..t {
        let mut num = one;
        let mut den = one;
        for k in 0..t {
            if k != j {
                // x_k is a base-field point, so this is a
                // large-by-small product.
                num = num.mul_small(&xs[k]);
                let diff = xs[j].add(&xs[k]);
                if diff.is_zero() {
                    return Err(format!(
                        "evaluation points {} and {} collide in GF(2^{})",
                        ids[j], ids[k], profile.w_p
                    ));
                }
                den = den.mul_small(&diff);
            }
        }
        if den.is_zero() {
            return Err("singular Lagrange denominator".to_string());
        }
        let l_j = num.mul(&den.inv());
        result = result.add(&ys[j].mul(&l_j));
    }
    Ok(result)
}

/// Super-invertible (hyper-invertible) randomness extractor for the
/// GF(2^w_p) ⊂ GF(2^w_q) tower-field profile. **Sibling of
/// `shamir::two_field::SuperInvExtractor` (BigUint)**, with byte-for-
/// byte parallel API so the consumer site (`ctrbc::state::coin_check`)
/// can dispatch on profile.
///
/// Construction
/// ------------
///
/// Given `m` distinct input evaluation points `α_1..α_m` (the
/// 1-based dealer ids in the ACS-decided set, after sorting) and
/// `R` distinct output points `β_1..β_R` (chosen deterministically
/// as `max(α)+1 .. max(α)+R` so all `m + R` points are distinct in
/// the small field), the matrix `M[i][j] = L_j(β_i)` — with `L_j`
/// the Lagrange basis polynomial pinned by the `α_k` points — is
/// **hyper-invertible**: every square sub-matrix is invertible. All
/// arithmetic happens in **`GF(2^w_p)` via the small-field image**;
/// by subfield closure, products of small-field elements stay in
/// the small field, so we can use the full `(w_p, w_q)` `Gf2Profile`
/// arithmetic without ever leaving the image.
///
/// Char-2 specialisations
/// ----------------------
/// Same as `lagrange_recover_at_zero`:
///   * `β − α_k`  ≡  `β + α_k`  (XOR)
///   * `α_j − α_k` ≡ `α_j + α_k`  (XOR)
/// — no underflow guards needed.
///
/// Security / extraction rate
/// --------------------------
/// At most `f` of the `m` decided dealers are Byzantine; their
/// `x_j` were committed during AVSS (independently of the at-most-
/// `f` honest, uniform, secret inputs). Hyper-invertibility
/// guarantees that for any choice of which `f` columns are
/// adversarial, the `R = m − f` outputs are a bijective image of the
/// `m − f` honest inputs (the honest-column sub-matrix is square and
/// invertible). The `R` outputs are therefore uniformly random and
/// independent over `GF(2^w_p)` — uniform extraction tolerating `f`
/// adversarial contributions.
#[derive(Clone, Debug)]
pub struct Gf2SuperInvExtractor {
    pub profile: Gf2Profile,
    pub num_inputs: usize,
    pub num_outputs: usize,
    /// `matrix[i][j] = L_j(β_i)` typed under the **small-field-only**
    /// `(w_p, w_p)` profile (commit 8b). The matrix entries
    /// previously carried the full `(w_p, w_q)` profile and ran
    /// through the tower mul on every extract — at depth `d` that's
    /// `~3^d` Karatsuba sub-multiplies per entry. Storing them under
    /// `small_profile` puts every mul directly on `poly::gf_mul` at
    /// width `w_p`.
    matrix: Vec<Vec<Gf2Element>>,
    /// Cached `(w_p, w_p)` profile so `extract` can re-type inputs
    /// without recomputing.
    small_profile: Gf2Profile,
}

impl Gf2SuperInvExtractor {
    /// Apply the agreed matrix to LOCAL dealer shares, before reconstruction.
    /// Exact input ordering/length and base-field membership are mandatory.
    pub fn transform_shares(&self, inputs: &[Gf2Element]) -> Result<Vec<Gf2Element>, String> {
        if inputs.len() != self.num_inputs || inputs.iter().any(|v|
            Gf2Element::from_bytes(self.small_profile, *v.as_bytes()).is_err()) {
            return Err("matrix input must contain exactly the selected dealers' small-field shares".into());
        }
        Ok(self.extract(inputs))
    }
    /// Build the extractor. `alpha_points` are 1-based integer node
    /// ids (sorted decided dealers' ids + 1, matching the BigUint
    /// path). `num_outputs` is the number of extracted beacon values
    /// per coin column (`m − f`).
    ///
    /// Pre: `alpha_points` are pairwise distinct, each in
    /// `1..=share_amount`. The dealer constructor's
    /// `share_amount < 2^w_p` capacity guarantee carries over: all
    /// `m + num_outputs` `small_field_point` values are distinct.
    /// Returns `Err` — rather than silently producing fewer or
    /// colliding outputs — when the point budget does not fit:
    ///
    /// * any `α` is zero, duplicated, or beyond `2^w_p − 1`;
    /// * `max(α) + num_outputs > 2^w_p − 1`, i.e. the `β` outputs
    ///   would wrap past the base field's point capacity and alias
    ///   onto an existing point. With `w_p = 8` and `max(α) = 250`,
    ///   asking for `R = 10` outputs would silently reuse the points
    ///   `251..255` and then wrap to `0..4`, so the "hyper-invertible"
    ///   matrix would have repeated rows and the extraction argument
    ///   would no longer hold.
    pub fn new(
        profile: Gf2Profile,
        alpha_points: Vec<usize>,
        num_outputs: usize,
    ) -> Result<Self, String> {
        if alpha_points.is_empty() {
            return Err("super-invertible extractor needs at least one input point".to_string());
        }
        let small_profile = Gf2Profile::new(profile.w_p, profile.w_p)
            .map_err(|e| format!("cannot derive (w_p, w_p) profile: {}", e))?;

        // Input points must be usable and pairwise distinct.
        check_point_set(profile, &alpha_points)?;

        let m = alpha_points.len();
        let max_alpha = alpha_points.iter().copied().max().expect("non-empty");
        let capacity = max_share_amount_for_w_p(profile.w_p);

        // Output points are max(α)+1 .. max(α)+R, so the budget check
        // is a single comparison — but it has to be done in a form
        // that cannot overflow `usize` when `w_p >= 64` saturates
        // `capacity` to `usize::MAX`.
        if num_outputs > capacity.saturating_sub(max_alpha) {
            return Err(format!(
                "super-invertible extractor needs {} output points above max(α) = {}, but \
                 GF(2^{}) only has {} usable points. All {} input and output points must be \
                 distinct; truncating β would alias them. Pick a Gf2Profile with a larger w_p.",
                num_outputs,
                max_alpha,
                profile.w_p,
                capacity,
                m + num_outputs
            ));
        }

        // Build the entire Lagrange-basis matrix under `small_profile`.
        // All α / β points are integer ids in [1, max(α)+R];
        // small_field_point lifts them into the small-field image of
        // `small_profile`, which makes every mul + inv inside the
        // basis loop a depth-0 base-field operation.
        let alphas: Vec<Gf2Element> = alpha_points
            .iter()
            .map(|&a| small_field_point(small_profile, a))
            .collect();

        let beta_ids: Vec<usize> = (1..=num_outputs).map(|i| max_alpha + i).collect();
        // Belt and braces: assert the full input ∪ output set really
        // is distinct rather than trusting the arithmetic above.
        let mut all_ids = alpha_points.clone();
        all_ids.extend_from_slice(&beta_ids);
        check_point_set(profile, &all_ids)?;

        let betas: Vec<Gf2Element> = beta_ids
            .iter()
            .map(|&b| small_field_point(small_profile, b))
            .collect();

        let one = Gf2Element::one(small_profile);

        // `den_inv[j] = (Π_{k ≠ j} (α_j + α_k))^{-1}` depends only on
        // the α set, so it is hoisted out of the β loop: `m`
        // inversions instead of `m · R`.
        let mut den_inv = Vec::with_capacity(m);
        for j in 0..m {
            let mut den = one;
            for k in 0..m {
                if k != j {
                    let diff = alphas[j].add(&alphas[k]);
                    if diff.is_zero() {
                        return Err(format!(
                            "input points {} and {} collide in GF(2^{})",
                            alpha_points[j], alpha_points[k], profile.w_p
                        ));
                    }
                    den = den.mul(&diff);
                }
            }
            if den.is_zero() {
                return Err("singular super-invertible denominator".to_string());
            }
            den_inv.push(den.inv());
        }

        let mut matrix = Vec::with_capacity(num_outputs);
        for beta in betas.iter() {
            let mut row = Vec::with_capacity(m);
            for j in 0..m {
                // L_j(β) = Π_{k ≠ j} (β + α_k) / (α_j + α_k)
                let mut num = one;
                for k in 0..m {
                    if k != j {
                        num = num.mul(&beta.add(&alphas[k]));
                    }
                }
                row.push(num.mul(&den_inv[j]));
            }
            matrix.push(row);
        }
        Ok(Self {
            profile,
            num_inputs: m,
            num_outputs,
            matrix,
            small_profile,
        })
    }

    /// Extract `num_outputs` values from one column of `m` secrets
    /// (`inputs[j]` is the secret at evaluation point
    /// `alpha_points[j]`, in the SAME order passed to `new`).
    ///
    /// Output element `i` equals `P(β_i)` where `P` is the unique
    /// degree-`<m` polynomial interpolating `(α_j, inputs[j])`.
    /// Inputs are expected to be in the small-field image (the case
    /// in PPT production); fall back to large-profile arithmetic
    /// otherwise.
    pub fn extract(&self, inputs: &[Gf2Element]) -> Vec<Gf2Element> {
        let cols = self.num_inputs.min(inputs.len());
        // Pre-convert inputs to `small_profile` once. The fast path
        // (production case) skips the tower recursion on every mul;
        // a slow-path fallback re-runs the inner product under the
        // large profile if any input has dirty high bits.
        let mut inputs_small: Vec<Gf2Element> = Vec::with_capacity(cols);
        let mut any_dirty = false;
        for inp in inputs.iter().take(cols) {
            match Gf2Element::from_bytes(self.small_profile, *inp.as_bytes()) {
                Ok(e) => inputs_small.push(e),
                Err(_) => {
                    any_dirty = true;
                    break;
                }
            }
        }
        let zero_small = Gf2Element::zero(self.small_profile);
        let mut out = Vec::with_capacity(self.num_outputs);
        if !any_dirty {
            for i in 0..self.num_outputs {
                let mut acc = zero_small;
                for j in 0..cols {
                    acc = acc.add(&self.matrix[i][j].mul(&inputs_small[j]));
                }
                let acc_large = Gf2Element::from_bytes(self.profile, *acc.as_bytes())
                    .expect("small-image bytes are canonical under any larger profile");
                out.push(acc_large);
            }
        } else {
            // Fallback: re-type matrix entries to large profile and
            // run the inner product there. This branch is dead in
            // PPT production (inputs are always f_d(0) ∈ small image)
            // but kept for safety / unit-test inputs.
            let zero_large = Gf2Element::zero(self.profile);
            for i in 0..self.num_outputs {
                let mut acc = zero_large;
                for j in 0..cols {
                    let m_large =
                        Gf2Element::from_bytes(self.profile, *self.matrix[i][j].as_bytes())
                            .expect("small-image matrix entry");
                    acc = acc.add(&m_large.mul(&inputs[j]));
                }
                out.push(acc);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn make_dealer(w_p: usize, w_q: usize, t: usize, n: usize) -> Gf2TwoFieldDealer {
        let profile = Gf2Profile::new(w_p, w_q).expect("registered profile");
        Gf2TwoFieldDealer::new(profile, t, n).expect("validated dealer params")
    }

    fn small_random(profile: Gf2Profile, rng: &mut impl Rng) -> Gf2Element {
        random_small_field(profile, rng)
    }

    /// Test helper: `lagrange_recover_at_zero` for inputs that are
    /// expected to be well-formed. Tests that exercise the rejection
    /// paths call the fallible function directly.
    fn lagrange_recover_at_zero_ok(
        profile: Gf2Profile,
        points: &[(usize, Gf2Element)],
    ) -> Gf2Element {
        lagrange_recover_at_zero(profile, points).expect("well-formed point set")
    }

    /// Profiles the implementation claims to support. Every test that
    /// sweeps configurations uses this list so a new registry entry
    /// cannot slip through untested.
    const SUPPORTED_PROFILES: &[(usize, usize)] = &[
        (64, 64),   // same-field baseline
        (128, 128), // same-field baseline
        (8, 64),
        (16, 64),
        (32, 128),
        (32, 256),
        (64, 128),
        (64, 256),
        (128, 256),
        (8, 256),
    ];

    // =====================================================================
    // Degree-bound enforcement on the public h polynomial
    // =====================================================================

    /// **The attack the pointwise degree test does not catch.**
    ///
    /// A dealer picks `F(x) = x^(f+1)` — degree `f + 1`, one above the
    /// bound — sets `G = 0`, and publishes `h = θ·F`. Then for every
    /// recipient `i`:
    ///
    /// ```text
    ///     g(i) + θ·f(i)  =  0 + θ·F(i)  =  h(i)
    /// ```
    ///
    /// so the identity holds at every evaluation point and a verifier
    /// that only evaluates the supplied coefficient vector accepts.
    /// But `deg(F) = f + 1`, so `f + 1` shares no longer determine the
    /// secret and `f`-privacy is gone.
    ///
    /// The receiver must reject on the ENCODING (coefficient count),
    /// which is what this test pins down — at the dealer-API level
    /// here, and on the real inbound packet path in
    /// `process::tests::avss_rejects_over_degree_h_polynomial`.
    #[test]
    fn over_degree_h_is_rejected_even_though_pointwise_identity_holds() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xde6_bad);
        for &(w_p, w_q) in SUPPORTED_PROFILES {
            let f = 5usize;
            let t = f + 1;
            let n = 16usize;
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let theta = random_large_field(profile, &mut rng);

            // F(x) = x^(f+1): coefficient vector of length f + 2 whose
            // only nonzero entry is the leading one.
            let zero = Gf2Element::zero(profile);
            let one = Gf2Element::one(profile);
            let mut f_poly = vec![zero; t + 1];
            f_poly[t] = one;
            // G = 0.
            let g_poly = vec![zero; t + 1];
            // h = G + θ·F = θ·F.
            let h: Vec<Gf2Element> = f_poly
                .iter()
                .zip(g_poly.iter())
                .map(|(fi, gi)| gi.add(&theta.mul(fi)))
                .collect();
            assert_eq!(h.len(), t + 1, "the malicious h has f + 2 coefficients");

            for node_id in 1..=n {
                let x = small_field_point(profile, node_id);
                let f_at = eval_poly_horner(profile, &f_poly, x);
                let g_at = eval_poly_horner(profile, &g_poly, x);

                // The pointwise identity really does hold — this is
                // what makes the attack work against an evaluation-only
                // verifier.
                let h_at = eval_poly_horner(profile, &h, x);
                assert_eq!(
                    g_at.add(&theta.mul(&f_at)),
                    h_at,
                    "precondition of the attack broke at ({},{}) node {}",
                    w_p,
                    w_q,
                    node_id
                );

                // And yet the verifier must reject, on the length.
                let err = dealer
                    .verify_share_checked(node_id, &f_at, &g_at, &h, &theta)
                    .expect_err("over-degree h must be rejected");
                assert_eq!(
                    err, "degree-test polynomial violates the deg <= f bound",
                    "wrong rejection reason at ({},{})",
                    w_p, w_q
                );
            }
        }
    }

    /// A short coefficient vector is rejected too: the encoding is
    /// fixed-length, so a dealer cannot shrink it to dodge the count
    /// check. Honest low-degree polynomials are zero-padded by
    /// `compute_degree_test_poly` instead.
    #[test]
    fn non_canonical_h_length_is_rejected_in_both_directions() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1e0);
        let profile = Gf2Profile::new(32, 128).unwrap();
        let (f, n) = (5usize, 16usize);
        let t = f + 1;
        let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);

        assert_eq!(
            shares.degree_test_coeffs.len(),
            t,
            "honest dealer must emit exactly t = f + 1 coefficients"
        );

        let id = shares.secret_shares[0].0;
        let f_large = &shares.f_large_shares[0].1;
        let g = &shares.mask_shares[0].1;
        assert!(dealer
            .verify_share_checked(id, f_large, g, &shares.degree_test_coeffs, &theta)
            .is_ok());

        // Too long (trailing zero appended — still "the same"
        // polynomial mathematically, but not the canonical encoding).
        let mut too_long = shares.degree_test_coeffs.clone();
        too_long.push(Gf2Element::zero(profile));
        assert!(dealer
            .verify_share_checked(id, f_large, g, &too_long, &theta)
            .is_err());

        // Too short.
        let too_short = shares.degree_test_coeffs[..t - 1].to_vec();
        assert!(dealer
            .verify_share_checked(id, f_large, g, &too_short, &theta)
            .is_err());
    }

    // =====================================================================
    // Base-field membership of shares
    // =====================================================================

    /// A share with components outside `GF(2^w_p)` must be rejected,
    /// not silently masked down to the base field. Masking would mean
    /// accepting a value the dealer never committed to.
    #[test]
    fn share_outside_small_field_is_rejected() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x00751de);
        for &(w_p, w_q) in SUPPORTED_PROFILES {
            if w_p == w_q {
                // Same-field baseline: every element of the "large"
                // field is already in the base field, so there is no
                // out-of-subfield value to construct.
                continue;
            }
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let (f, n) = (5usize, 16usize);
            let t = f + 1;
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let secret = small_random(profile, &mut rng);
            let theta = random_large_field(profile, &mut rng);
            let shares = dealer.share_secret(secret, &theta);

            let id = shares.secret_shares[0].0;
            let honest = shares.f_large_shares[0].1;
            let g = &shares.mask_shares[0].1;
            assert!(honest.is_in_small_field());

            // Set a bit just above the small field's boundary.
            let mut bytes = *honest.as_bytes();
            let bit = w_p; // first bit outside GF(2^w_p)
            bytes[bit / 8] ^= 1u8 << (bit % 8);
            let dirty = Gf2Element::from_bytes(profile, bytes)
                .expect("still within w_q, so from_bytes accepts it");
            assert!(
                !dirty.is_in_small_field(),
                "test setup failed to escape the small field at ({},{})",
                w_p,
                w_q
            );

            let err = dealer
                .verify_share_checked(id, &dirty, g, &shares.degree_test_coeffs, &theta)
                .expect_err("non-base-field share must be rejected");
            assert_eq!(
                err, "share is not an element of the small field GF(2^w_p)",
                "wrong rejection reason at ({},{})",
                w_p, w_q
            );
        }
    }

    // =====================================================================
    // Evaluation-point capacity and collisions
    // =====================================================================

    /// Truncation must not hide a point collision. With `w_p = 8`,
    /// ids `1` and `257` both reduce to the byte `0x01`, and `256`
    /// reduces to the zero element; all three must be refused.
    #[test]
    fn out_of_capacity_points_are_rejected_not_truncated() {
        let profile = Gf2Profile::new(8, 64).unwrap();
        assert!(check_point_capacity(profile, 1).is_ok());
        assert!(check_point_capacity(profile, 255).is_ok());
        assert!(check_point_capacity(profile, 0).is_err(), "0 is reserved");
        assert!(check_point_capacity(profile, 256).is_err());
        assert!(check_point_capacity(profile, 257).is_err());

        // Duplicates inside a set.
        assert!(check_point_set(profile, &[1, 2, 3]).is_ok());
        assert!(check_point_set(profile, &[1, 2, 2]).is_err());

        // And the recovery entry point refuses them rather than
        // returning a wrong value.
        let y = Gf2Element::one(profile);
        assert!(lagrange_recover_at_zero(profile, &[(1, y), (257, y)]).is_err());
        assert!(lagrange_recover_at_zero(profile, &[(1, y), (1, y)]).is_err());
        assert!(lagrange_recover_at_zero(profile, &[(0, y), (1, y)]).is_err());
        assert!(lagrange_recover_at_zero(profile, &[]).is_err());
    }

    /// The super-invertible extractor must refuse to build when the
    /// `m + R` input and output points do not fit in `GF(2^w_p)`,
    /// instead of wrapping `β` onto existing points (which would make
    /// the "hyper-invertible" matrix have aliased rows).
    #[test]
    fn super_inv_rejects_exhausted_point_budget() {
        let profile = Gf2Profile::new(8, 64).unwrap(); // 255 usable points

        // Fits: max(α) = 16, 10 outputs → β in 17..26.
        let alpha: Vec<usize> = (1..=16).collect();
        assert!(Gf2SuperInvExtractor::new(profile, alpha, 10).is_ok());

        // Does not fit: max(α) = 250, 10 outputs would need 251..260
        // but the field only has 255 points.
        let alpha_high: Vec<usize> = (241..=250).collect();
        let err = Gf2SuperInvExtractor::new(profile, alpha_high, 10)
            .expect_err("exhausted β budget must be rejected");
        assert!(
            err.contains("point capacity") || err.contains("usable points"),
            "unexpected error text: {}",
            err
        );

        // Duplicate / zero input points.
        assert!(Gf2SuperInvExtractor::new(profile, vec![1, 2, 2], 2).is_err());
        assert!(Gf2SuperInvExtractor::new(profile, vec![0, 1, 2], 2).is_err());
        assert!(Gf2SuperInvExtractor::new(profile, vec![], 2).is_err());

        // A wide base field has plenty of room.
        let wide = Gf2Profile::new(64, 256).unwrap();
        assert!(Gf2SuperInvExtractor::new(wide, (1..=16).collect(), 11).is_ok());
    }

    // =====================================================================
    // Lagrange coefficient cache
    // =====================================================================

    /// The cache must return exactly what the uncached path returns,
    /// for the same provider set and for different ones, and must
    /// actually register reuse (hits) when a set repeats.
    #[test]
    fn lagrange_cache_matches_uncached_and_reuses_bases() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xcac8e);
        for &(w_p, w_q) in SUPPORTED_PROFILES {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let (f, n) = (5usize, 16usize);
            let t = f + 1;
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let mut cache = Gf2LagrangeCache::new(profile);

            // Several dealers, two distinct provider sets.
            let set_a: Vec<usize> = (1..=t).collect();
            let set_b: Vec<usize> = (n - t + 1..=n).collect();
            assert_ne!(set_a, set_b);

            for d in 0..6usize {
                let secret = small_random(profile, &mut rng);
                let theta = random_large_field(profile, &mut rng);
                let shares = dealer.share_secret(secret, &theta);
                let ids = if d % 2 == 0 { &set_a } else { &set_b };

                let points: Vec<(usize, Gf2Element)> = ids
                    .iter()
                    .map(|&id| (id, shares.secret_shares[id - 1].1))
                    .collect();

                let cached = cache.recover_at_zero(&points).expect("valid set");
                let uncached = lagrange_recover_at_zero(profile, &points).expect("valid set");
                assert_eq!(
                    cached, uncached,
                    "cached != uncached at ({},{}) dealer {}",
                    w_p, w_q, d
                );
                assert_eq!(
                    cached, secret,
                    "recovery wrong at ({},{}) dealer {}",
                    w_p, w_q, d
                );
            }
            let (hits, misses) = cache.stats();
            assert_eq!(misses, 2, "exactly two distinct provider sets were used");
            assert_eq!(hits, 4, "the remaining four recoveries must reuse a basis");
        }
    }

    /// Point order must not matter: the same set supplied in a
    /// different order shares one cached basis and still recovers the
    /// same secret.
    #[test]
    fn lagrange_cache_is_order_insensitive() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x00de4);
        let profile = Gf2Profile::new(32, 128).unwrap();
        let (f, n) = (5usize, 16usize);
        let t = f + 1;
        let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);

        let ascending: Vec<(usize, Gf2Element)> =
            shares.secret_shares.iter().take(t).copied().collect();
        let mut descending = ascending.clone();
        descending.reverse();

        let mut cache = Gf2LagrangeCache::new(profile);
        let a = cache.recover_at_zero(&ascending).unwrap();
        let b = cache.recover_at_zero(&descending).unwrap();
        assert_eq!(a, secret);
        assert_eq!(b, secret);
        let (hits, misses) = cache.stats();
        assert_eq!((hits, misses), (1, 1), "reordering must hit the same basis");
    }

    /// Different honest subsets of `f+1` shares must all recover the
    /// same secret, with the cache in play — this is the "any f+1
    /// validated providers" liveness property, which the cache must
    /// not quietly narrow to one fixed set.
    #[test]
    fn any_f_plus_one_subset_recovers_identically_through_the_cache() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5ab5e7);
        for &(w_p, w_q) in SUPPORTED_PROFILES {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let (f, n) = (5usize, 16usize);
            let t = f + 1;
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let secret = small_random(profile, &mut rng);
            let theta = random_large_field(profile, &mut rng);
            let shares = dealer.share_secret(secret, &theta);

            let mut cache = Gf2LagrangeCache::new(profile);
            // Sliding windows give n - t + 1 distinct provider sets.
            for start in 0..=(n - t) {
                let points: Vec<(usize, Gf2Element)> =
                    shares.secret_shares[start..start + t].to_vec();
                let got = cache.recover_at_zero(&points).expect("valid set");
                assert_eq!(
                    got, secret,
                    "subset starting at {} recovered a different secret at ({},{})",
                    start, w_p, w_q
                );
            }
            let (_, misses) = cache.stats();
            assert_eq!(
                misses as usize,
                n - t + 1,
                "each distinct provider set needs its own basis"
            );
        }
    }

    /// The cache is bounded: feeding it more distinct sets than its
    /// capacity must not grow it without limit, and must not change
    /// any answer.
    #[test]
    fn lagrange_cache_is_bounded() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xb0117d);
        let profile = Gf2Profile::new(16, 64).unwrap();
        let (f, n) = (5usize, 40usize);
        let t = f + 1;
        let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);

        let mut cache = Gf2LagrangeCache::with_capacity(profile, 4);
        for start in 0..=(n - t) {
            let points: Vec<(usize, Gf2Element)> = shares.secret_shares[start..start + t].to_vec();
            assert_eq!(cache.recover_at_zero(&points).unwrap(), secret);
            assert!(
                cache.entries.len() <= 4,
                "cache exceeded its capacity: {}",
                cache.entries.len()
            );
        }
    }

    // =====================================================================
    // mul_small fast path, as used by this module
    // =====================================================================

    /// Dealer output must be bit-identical whether the hot paths use
    /// `mul_small` or the general multiplication. Recomputes `g(i)`,
    /// `h`, and `h(i)` the slow way and compares.
    #[test]
    fn mul_small_hot_paths_match_general_arithmetic() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfa57_9a70);
        for &(w_p, w_q) in SUPPORTED_PROFILES {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let (f, n) = (5usize, 16usize);
            let t = f + 1;
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let secret = small_random(profile, &mut rng);
            let theta = random_large_field(profile, &mut rng);
            let sampled = dealer.sample_shares(secret);
            let h = dealer.compute_degree_test_poly(&sampled.f_poly, &sampled.g_poly, &theta);

            // h via the general mul.
            for i in 0..t {
                let expected = sampled.g_poly[i].add(&theta.mul(&sampled.f_poly[i]));
                assert_eq!(h[i], expected, "h[{}] differs at ({},{})", i, w_p, w_q);
            }

            for node_id in 1..=n {
                let x = small_field_point(profile, node_id);
                // g(i) via the general Horner.
                assert_eq!(
                    sampled.mask_shares[node_id - 1].1,
                    eval_poly_horner(profile, &sampled.g_poly, x),
                    "g({}) differs at ({},{})",
                    node_id,
                    w_p,
                    w_q
                );
                // h(i) via the general Horner.
                assert_eq!(
                    eval_poly_horner_small_x(profile, &h, x),
                    eval_poly_horner(profile, &h, x),
                    "h({}) differs at ({},{})",
                    node_id,
                    w_p,
                    w_q
                );
            }
        }
    }

    /// Full PPT loop across a representative profile matrix:
    /// dealer.share_secret -> verify_share(every recipient) ->
    /// lagrange_recover_at_zero(any t shares) -> secret.
    #[test]
    fn full_ppt_loop_at_various_profiles() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xabcdef);
        let cases = [
            (8usize, 8usize, 2usize, 4usize),   // single-field baseline
            (8, 64, 2, 4),                       // depth 3 tower
            (16, 64, 5, 16),                     // BFT-shape n=16, t=f+1=5
            (32, 128, 5, 16),
            (32, 256, 5, 16),                    // depth 3 with big mask
            (64, 256, 5, 16),                    // depth 2
            (8, 256, 11, 32),                    // depth 5, n=32
            (128, 128, 5, 16),                   // single-field at w_p=128
            (128, 256, 5, 16),                   // single quadratic level
        ];
        for &(w_p, w_q, t, n) in &cases {
            let dealer = make_dealer(w_p, w_q, t, n);
            let profile = dealer.profile;
            let secret = small_random(profile, &mut rng);
            let theta = random_large_field(profile, &mut rng);
            let shares = dealer.share_secret(secret, &theta);

            // (a) every recipient's share verifies.
            for i in 0..n {
                let id = shares.secret_shares[i].0;
                let f_large = &shares.f_large_shares[i].1;
                let g = &shares.mask_shares[i].1;
                assert!(
                    dealer.verify_share(id, f_large, g, &shares.degree_test_coeffs, &theta),
                    "verify failed at ({},{},t={},n={}) node {}",
                    w_p, w_q, t, n, id
                );
            }

            // (b) Lagrange-recover from the first t shares.
            let recovered = lagrange_recover_at_zero_ok(profile, &shares.secret_shares[..t]);
            assert_eq!(
                recovered, secret,
                "recover failed at ({},{},t={},n={})",
                w_p, w_q, t, n
            );

            // (c) Recover from a DIFFERENT subset of t shares — should
            //     give the same result (polynomial uniqueness).
            if n >= t + 2 {
                let alt: Vec<_> = (0..t).map(|j| shares.secret_shares[n - 1 - j]).collect();
                let recovered_alt = lagrange_recover_at_zero_ok(profile, &alt);
                assert_eq!(
                    recovered_alt, secret,
                    "alt-subset recover failed at ({},{},t={},n={})",
                    w_p, w_q, t, n
                );
            }
        }
    }

    /// In GF(2^w), the secret-share view and the f_large view are
    /// the same bits for every recipient (subfield closure). This
    /// test pins that property down — future commits should NOT
    /// silently break it (e.g. by reducing twice through different
    /// representations).
    #[test]
    fn secret_share_and_f_large_share_coincide_in_gf2() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x1234);
        let dealer = make_dealer(32, 128, 3, 9);
        let profile = dealer.profile;
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);
        for i in 0..9 {
            assert_eq!(
                shares.secret_shares[i], shares.f_large_shares[i],
                "secret_shares[{}] must equal f_large_shares[{}] in GF(2^w)", i, i
            );
        }
    }

    /// Subfield closure: every f(i) lives in the small-field image,
    /// even though arithmetic was performed in the large field. If
    /// this ever breaks, the dealer's optimization (skipping a
    /// separate small-field eval) is no longer correct.
    #[test]
    fn subfield_closure_holds_for_f_shares() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xbeef);
        for &(w_p, w_q) in &[(8usize, 64usize), (32, 128), (32, 256), (64, 256)] {
            let dealer = make_dealer(w_p, w_q, 5, 16);
            let secret = small_random(dealer.profile, &mut rng);
            let sampled = dealer.sample_shares(secret);
            for (id, y) in &sampled.secret_shares {
                assert!(
                    y.is_in_small_field(),
                    "f({}) escaped small-field image at ({}, {})",
                    id, w_p, w_q
                );
            }
        }
    }

    /// Tampering with f_large, g, h_coeffs, or θ must each cause
    /// `verify_share` to return false (with overwhelming probability).
    #[test]
    fn tampered_share_fails_verification() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let dealer = make_dealer(32, 128, 3, 9);
        let profile = dealer.profile;
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);
        let id = shares.secret_shares[0].0;
        let f_large = &shares.f_large_shares[0].1;
        let g = &shares.mask_shares[0].1;

        // Sanity: clean share verifies.
        assert!(dealer.verify_share(id, f_large, g, &shares.degree_test_coeffs, &theta));

        // 1. Flip a bit in f_large.
        {
            let mut bytes = *f_large.as_bytes();
            bytes[0] ^= 1;
            let tampered = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert!(
                !dealer.verify_share(id, &tampered, g, &shares.degree_test_coeffs, &theta),
                "tampered f_large should not verify"
            );
        }
        // 2. Flip a bit in g.
        {
            let mut bytes = *g.as_bytes();
            bytes[0] ^= 1;
            let tampered_g = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert!(
                !dealer.verify_share(id, f_large, &tampered_g, &shares.degree_test_coeffs, &theta),
                "tampered g should not verify"
            );
        }
        // 3. Flip a bit in h_coeffs.
        {
            let mut bad_h = shares.degree_test_coeffs.clone();
            let mut bytes = *bad_h[0].as_bytes();
            bytes[0] ^= 1;
            bad_h[0] = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert!(
                !dealer.verify_share(id, f_large, g, &bad_h, &theta),
                "tampered h_coeffs should not verify"
            );
        }
        // 4. Use a different θ.
        {
            let mut bytes = *theta.as_bytes();
            bytes[0] ^= 1;
            let bad_theta = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert!(
                !dealer.verify_share(id, f_large, g, &shares.degree_test_coeffs, &bad_theta),
                "wrong θ should not verify"
            );
        }
    }

    /// `h_i` must equal `g_i + θ · f_i` element-wise. Pins down the
    /// char-2 arithmetic of `compute_degree_test_poly`.
    #[test]
    fn degree_test_poly_uses_char2_arithmetic() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(13);
        let dealer = make_dealer(16, 64, 3, 9);
        let profile = dealer.profile;
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let sampled = dealer.sample_shares(secret);
        let h = dealer.compute_degree_test_poly(&sampled.f_poly, &sampled.g_poly, &theta);
        assert_eq!(h.len(), sampled.f_poly.len().max(sampled.g_poly.len()));
        for i in 0..h.len() {
            let f_i = sampled.f_poly.get(i).copied().unwrap_or(Gf2Element::zero(profile));
            let g_i = sampled.g_poly.get(i).copied().unwrap_or(Gf2Element::zero(profile));
            let expected = g_i.add(&theta.mul(&f_i));
            assert_eq!(h[i], expected, "h_{} mismatch", i);
        }
    }

    /// Information-theoretic: t-1 shares should NOT recover the
    /// secret (overwhelming probability across a random polynomial).
    /// We don't probe the IT bound directly; instead we observe that
    /// recovery from t shares gives `secret`, and from t+1 shares
    /// also gives `secret` (consistency), but a Lagrange fit through
    /// t-1 points is unconstrained at x=0 and almost certainly
    /// returns a different value.
    #[test]
    fn fewer_than_t_shares_does_not_recover() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xdead);
        let dealer = make_dealer(32, 128, 5, 16);
        let profile = dealer.profile;
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);
        let recovered_t = lagrange_recover_at_zero_ok(profile, &shares.secret_shares[..5]);
        assert_eq!(recovered_t, secret);
        let recovered_tp1 = lagrange_recover_at_zero_ok(profile, &shares.secret_shares[..6]);
        assert_eq!(recovered_tp1, secret, "t+1 shares must also recover");
        let recovered_tm1 = lagrange_recover_at_zero_ok(profile, &shares.secret_shares[..4]);
        // With w_p = 32 the collision probability is 2^-32 ≈ 2e-10,
        // negligible at a single random sample.
        assert_ne!(
            recovered_tm1, secret,
            "t-1 shares accidentally recovered (overwhelmingly unlikely; check polynomial sampling)"
        );
    }

    #[test]
    fn validates_dealer_params() {
        let profile = Gf2Profile::new(8, 64).unwrap();
        assert!(Gf2TwoFieldDealer::new(profile, 1, 1).is_ok());
        assert!(Gf2TwoFieldDealer::new(profile, 86, 255).is_ok());
        // n = 256 exceeds 2^8 - 1.
        let err = Gf2TwoFieldDealer::new(profile, 86, 256).unwrap_err();
        assert!(err.contains("share_amount (256) > 2^w_p - 1 (255)"));
        // threshold > share_amount.
        assert!(Gf2TwoFieldDealer::new(profile, 10, 9).is_err());
        // threshold = 0.
        assert!(Gf2TwoFieldDealer::new(profile, 0, 4).is_err());
    }

    #[test]
    fn small_field_point_is_injective_within_dealer_capacity() {
        // For w_p = 8 with n = 200, all small_field_point(i) values
        // must be pairwise distinct in GF(2^w_q).
        let profile = Gf2Profile::new(8, 64).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 1..=200 {
            let pt = small_field_point(profile, i);
            assert!(seen.insert(*pt.as_bytes()), "small_field_point({}) collided", i);
        }
    }

    /// `lagrange_recover_at_zero` on a constant polynomial (t=1).
    /// f(x) = c, evaluated at x=1 gives c, recovered at x=0 gives c.
    #[test]
    fn lagrange_recovers_constant_polynomial() {
        let profile = Gf2Profile::new(32, 128).unwrap();
        let c = Gf2Element::lift_small(profile, &[0x12, 0x34, 0x56, 0x78]);
        let recovered = lagrange_recover_at_zero_ok(profile, &[(3, c)]);
        assert_eq!(recovered, c);
    }

    /// Polynomial evaluation at x=0 must equal the constant
    /// term. Trivial Horner sanity.
    #[test]
    fn horner_at_zero_equals_constant_term() {
        let profile = Gf2Profile::new(32, 128).unwrap();
        let coeffs = vec![
            Gf2Element::lift_small(profile, &[0xaa, 0xbb, 0xcc, 0xdd]),
            random_large_field(profile, &mut rand::thread_rng()),
            random_large_field(profile, &mut rand::thread_rng()),
        ];
        let zero = Gf2Element::zero(profile);
        assert_eq!(eval_poly_horner(profile, &coeffs, zero), coeffs[0]);
    }

    /// `max_share_amount_for_w_p` boundary check.
    #[test]
    fn max_share_amount_table() {
        assert_eq!(max_share_amount_for_w_p(1), 1);
        assert_eq!(max_share_amount_for_w_p(2), 3);
        assert_eq!(max_share_amount_for_w_p(8), 255);
        assert_eq!(max_share_amount_for_w_p(16), 65535);
        // w_p >= 64 saturates to usize::MAX on 64-bit systems.
        assert_eq!(max_share_amount_for_w_p(64), usize::MAX);
        assert_eq!(max_share_amount_for_w_p(128), usize::MAX);
    }

    /// Commit 5 reconstruct-path invariant: shares stored as
    /// `BigUint::from_bytes_be(Gf2Element::as_bytes())` survive the
    /// `Context::pad_shares` → `Gf2Element::from_bytes` round-trip
    /// that the production GF2 Lagrange branch performs inside the
    /// `spawn_blocking` closure.
    ///
    /// This pins down the byte-preservation contract that lets us
    /// keep the `reconstructed_secrets: HashMap<.., BigUint>`
    /// storage type during the intermediate state between commits 5
    /// and 6 (BigUint envelope around GF2 element bytes; no real
    /// BigUint arithmetic happens on these values until commit 6
    /// completes the SuperInvExtractor migration).
    #[test]
    fn share_bytes_roundtrip_through_biguint_envelope() {
        use num_bigint::BigUint;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x2026);
        for &(w_p, w_q) in &[
            (8usize, 8usize),
            (8, 64),
            (16, 64),
            (32, 128),
            (32, 256),
            (64, 256),
            (128, 256),
        ] {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            for _ in 0..16 {
                let mut bytes = [0u8; 32];
                rng.fill(&mut bytes[..]);
                let original = Gf2Element::from_random_bytes(profile, bytes);
                // Production flow: as_bytes() → BigUint::from_bytes_be
                // (in `add_secret_share`) → pad_shares (in the
                // spawn_blocking closure) → from_bytes.
                let big = BigUint::from_bytes_be(original.as_bytes());
                let mut padded = [0u8; 32];
                let be = big.to_bytes_be();
                assert!(be.len() <= 32, "BigUint can't exceed 32 bytes");
                let pad_len = 32 - be.len();
                padded[pad_len..].copy_from_slice(&be);
                let recovered = Gf2Element::from_bytes(profile, padded).expect("canonical");
                assert_eq!(
                    recovered, original,
                    "byte roundtrip via BigUint envelope failed at ({}, {})",
                    w_p, w_q
                );
            }
        }
    }

    /// End-to-end Lagrange test mirroring the production
    /// `secret_reconstruct.rs` GF2 path: build a `Gf2TwoFieldDealer`,
    /// generate shares, store each share's bytes in a `BigUint`
    /// envelope (= what `CTRBCState::add_secret_share` would do for an
    /// inbound GF2 packet), then run the EXACT same conversion-chain
    /// the production `spawn_blocking` closure performs to recover
    /// `f(0)` and check it matches the original secret bytes.
    #[test]
    fn biguint_enveloped_shares_recover_original_secret() {
        use num_bigint::BigUint;
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xCAFEBABE);
        for &(w_p, w_q, t, n) in &[
            (8usize, 64usize, 2usize, 4usize),
            (16, 64, 5, 16),
            (32, 128, 5, 16),
            (32, 256, 5, 16),
            (64, 256, 5, 16),
            (8, 256, 11, 32),
        ] {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();
            let secret_bytes = {
                let small_len = profile.small_byte_len();
                let mut buf = vec![0u8; small_len];
                rng.fill(&mut buf[..]);
                buf
            };
            let secret = Gf2Element::lift_small(profile, &secret_bytes);
            let theta = random_large_field(profile, &mut rng);
            let shares = dealer.share_secret(secret, &theta);

            // Simulate the production flow: each Gf2 share gets stored
            // as `BigUint::from_bytes_be(elem.as_bytes())` (the same
            // call that `add_secret_share` makes after parsing the
            // inbound `Val`).
            let stored_biguints: Vec<BigUint> = shares
                .secret_shares
                .iter()
                .take(t)
                .map(|(_, elem)| BigUint::from_bytes_be(elem.as_bytes()))
                .collect();
            let eval_points: Vec<usize> =
                shares.secret_shares.iter().take(t).map(|(i, _)| *i).collect();

            // Production recovery flow inside the spawn_blocking
            // closure (see secret_reconstruct.rs).
            let mut points: Vec<(usize, Gf2Element)> = Vec::with_capacity(t);
            for (idx, big) in stored_biguints.iter().enumerate() {
                let be = big.to_bytes_be();
                let mut padded = [0u8; 32];
                let pad_len = 32 - be.len();
                padded[pad_len..].copy_from_slice(&be);
                let elem = Gf2Element::from_bytes(profile, padded).unwrap();
                points.push((eval_points[idx], elem));
            }
            let recovered = lagrange_recover_at_zero_ok(profile, &points);
            assert_eq!(
                recovered, secret,
                "BigUint-enveloped reconstruction failed at ({},{},t={},n={})",
                w_p, w_q, t, n
            );
        }
    }

    /// ACS coin-secret combine path (`acs/coin.rs::ingest_coin_reveal_shares`):
    /// per-dealer `c_d = lagrange(...)`, then `acc = acc + c_d` over
    /// GF(2^w_q) (XOR). The final XOR-sum must equal what we'd get by
    /// summing the dealers' secret constants (`f_d(0)`) directly — i.e.
    /// the homomorphism `lagrange(shares_of(f_d(0))) = f_d(0)`
    /// composed with char-2 sum commutes with the per-dealer
    /// reconstruction order.
    #[test]
    fn coin_secret_xor_sum_matches_direct_sum() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4242);
        let profile = Gf2Profile::new(32, 128).unwrap();
        let t = 3usize;
        let n = 9usize;
        let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();

        // 5 dealers each contribute a coin-secret. The "common coin"
        // C = XOR of all 5 secrets.
        let num_dealers = 5;
        let mut secrets = Vec::with_capacity(num_dealers);
        let mut all_shares = Vec::with_capacity(num_dealers);
        for _ in 0..num_dealers {
            let small_len = profile.small_byte_len();
            let mut secret_bytes = vec![0u8; small_len];
            rng.fill(&mut secret_bytes[..]);
            let secret = Gf2Element::lift_small(profile, &secret_bytes);
            secrets.push(secret);
            let theta = random_large_field(profile, &mut rng);
            all_shares.push(dealer.share_secret(secret, &theta));
        }

        // Expected: XOR of all per-dealer secrets.
        let mut expected = Gf2Element::zero(profile);
        for s in &secrets {
            expected = expected.add(s);
        }

        // Production path: for each dealer reconstruct c_d from t
        // shares; accumulate via XOR.
        let mut acc = Gf2Element::zero(profile);
        for shares in &all_shares {
            let points: Vec<(usize, Gf2Element)> =
                shares.secret_shares.iter().take(t).copied().collect();
            let c_d = lagrange_recover_at_zero_ok(profile, &points);
            acc = acc.add(&c_d);
        }
        assert_eq!(
            acc, expected,
            "ACS coin XOR-sum across {} dealers does not match direct sum",
            num_dealers
        );
    }

    /// Gf2SuperInvExtractor produces `output_i = P(β_i)` where `P`
    /// is the unique degree-`<m` polynomial interpolating
    /// `(α_j, inputs[j])`. Verified by recomputing `P(β_i)` via an
    /// independent Lagrange evaluation in the small-field-image.
    /// Mirrors the BigUint `super_inv_matches_polynomial_evaluation`
    /// test in `two_field.rs`.
    #[test]
    fn gf2_super_inv_matches_polynomial_evaluation() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x7777);
        for &(w_p, w_q, m, f) in &[
            (8usize, 64usize, 7usize, 2usize),
            (16, 64, 7, 2),
            (32, 128, 10, 3),
            (8, 256, 10, 3),
        ] {
            let profile = Gf2Profile::new(w_p, w_q).unwrap();
            let r = m - f;
            let alpha: Vec<usize> = (1..=m).collect();

            // Sample m small-field inputs.
            let inputs: Vec<Gf2Element> = (0..m)
                .map(|_| random_small_field(profile, &mut rng))
                .collect();

            let extractor = Gf2SuperInvExtractor::new(profile, alpha.clone(), r).unwrap();
            let outputs = extractor.extract(&inputs);
            assert_eq!(outputs.len(), r);

            // Independent reference: P(β_i) via direct Lagrange
            // through (alpha_j, inputs[j]) using the same
            // small_field_point encoding.
            let max_alpha = *alpha.iter().max().unwrap();
            let alphas: Vec<Gf2Element> = alpha
                .iter()
                .map(|&a| small_field_point(profile, a))
                .collect();
            for i in 0..r {
                let beta = small_field_point(profile, max_alpha + 1 + i);
                let mut expected = Gf2Element::zero(profile);
                for j in 0..m {
                    // L_j(β) via the same char-2 formula.
                    let mut num = Gf2Element::one(profile);
                    let mut den = Gf2Element::one(profile);
                    for k in 0..m {
                        if k != j {
                            num = num.mul(&beta.add(&alphas[k]));
                            den = den.mul(&alphas[j].add(&alphas[k]));
                        }
                    }
                    let lj = num.mul(&den.inv());
                    expected = expected.add(&lj.mul(&inputs[j]));
                }
                assert_eq!(
                    outputs[i], expected,
                    "output {} must equal P(β_{}) at ({}, {})",
                    i, i, w_p, w_q
                );
            }
        }
    }

    /// Hyper-invertibility: flipping any single input must change
    /// EVERY output. This is what makes one honest uniform input
    /// randomise the entire output vector, which a single summed
    /// output cannot do for more than one output.
    /// Mirrors `super_inv_every_output_depends_on_each_input`.
    #[test]
    fn gf2_super_inv_every_output_depends_on_each_input() {
        let profile = Gf2Profile::new(16, 64).unwrap();
        let m = 6usize;
        let f = 1usize;
        let r = m - f;
        let alpha: Vec<usize> = (1..=m).collect();
        let extractor = Gf2SuperInvExtractor::new(profile, alpha, r).unwrap();

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xC0FE);
        let base: Vec<Gf2Element> = (0..m)
            .map(|_| random_small_field(profile, &mut rng))
            .collect();
        let base_out = extractor.extract(&base);

        for flip in 0..m {
            let mut alt = base.clone();
            // Add a nonzero delta to input `flip`. In char 2, "add"
            // is XOR; flipping a single bit makes the new value
            // strictly different.
            let mut delta_bytes = [0u8; 32];
            delta_bytes[0] = 1u8;
            let delta = Gf2Element::from_random_bytes(profile, delta_bytes);
            alt[flip] = alt[flip].add(&delta);
            assert_ne!(alt[flip], base[flip]);

            let alt_out = extractor.extract(&alt);
            for i in 0..r {
                assert_ne!(
                    base_out[i], alt_out[i],
                    "output {} did not change when input {} changed",
                    i, flip
                );
            }
        }
    }

    /// Symmetric to the BigUint integration: dealer→shares→Lagrange
    /// recovers each `f_d(0)`, then SuperInvExtractor produces `R`
    /// uniform outputs. Smoke-test that the chain runs end-to-end on
    /// a representative GF2 profile with no panic.
    #[test]
    fn gf2_extract_end_to_end_after_lagrange() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xBEEF42);
        let profile = Gf2Profile::new(32, 128).unwrap();
        let n = 9usize;
        let f = 2usize;
        let t = f + 1;
        let dealer = Gf2TwoFieldDealer::new(profile, t, n).unwrap();

        // 7 decided dealers each share a small-field secret; we
        // recover each one then run SuperInvExtractor on the 7-vector.
        let m = 7usize;
        let r = m - f;
        let mut per_dealer_secret = Vec::with_capacity(m);
        let mut per_dealer_recovered = Vec::with_capacity(m);
        for _ in 0..m {
            let small_len = profile.small_byte_len();
            let mut secret_bytes = vec![0u8; small_len];
            rng.fill(&mut secret_bytes[..]);
            let secret = Gf2Element::lift_small(profile, &secret_bytes);
            per_dealer_secret.push(secret);

            let theta = random_large_field(profile, &mut rng);
            let shares = dealer.share_secret(secret, &theta);
            // Lagrange-recover from t shares.
            let points: Vec<(usize, Gf2Element)> =
                shares.secret_shares.iter().take(t).copied().collect();
            let recovered = lagrange_recover_at_zero_ok(profile, &points);
            assert_eq!(recovered, secret);
            per_dealer_recovered.push(recovered);
        }

        let alpha: Vec<usize> = (1..=m).collect();
        let extractor = Gf2SuperInvExtractor::new(profile, alpha, r).unwrap();
        let outputs = extractor.extract(&per_dealer_recovered);
        assert_eq!(outputs.len(), r);
        // Outputs are in the small-field image (since inputs +
        // matrix entries both are).
        for (i, out) in outputs.iter().enumerate() {
            assert!(
                out.is_in_small_field(),
                "extracted output {} escaped small-field image",
                i
            );
        }
    }

    /// Wire-format roundtrip via the existing `Gf2Element` byte API:
    /// every share survives a `as_bytes` → `from_bytes` cycle, which
    /// is what later commits' wire path will do.
    #[test]
    fn shares_survive_wire_bytes_roundtrip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let dealer = make_dealer(64, 128, 3, 9);
        let profile = dealer.profile;
        let secret = small_random(profile, &mut rng);
        let theta = random_large_field(profile, &mut rng);
        let shares = dealer.share_secret(secret, &theta);
        for (i, share) in &shares.secret_shares {
            let bytes = *share.as_bytes();
            let recovered = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert_eq!(*share, recovered, "secret_share[{}] roundtrip failed", i);
        }
        for c in &shares.degree_test_coeffs {
            let bytes = *c.as_bytes();
            let recovered = Gf2Element::from_bytes(profile, bytes).unwrap();
            assert_eq!(*c, recovered, "h coeff roundtrip failed");
        }
    }
}
