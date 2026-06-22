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

impl Gf2TwoFieldDealer {
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
        Ok(Self {
            profile,
            threshold,
            share_amount,
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

        // f(i) for i = 1..=n. Computed in GF(2^w_q) on small-field
        // image inputs; by subfield closure the output stays in the
        // image. We expose two API-equivalent views.
        let mut secret_shares = Vec::with_capacity(self.share_amount);
        let mut f_large_shares = Vec::with_capacity(self.share_amount);
        for i in 1..=self.share_amount {
            let x = small_field_point(self.profile, i);
            let y = eval_poly_horner(self.profile, &f_poly, x);
            debug_assert!(
                y.is_in_small_field(),
                "subfield closure broken: f({}) escaped the GF(2^{}) image",
                i,
                self.profile.w_p
            );
            secret_shares.push((i, y));
            f_large_shares.push((i, y));
        }

        // g(i) for i = 1..=n. Evaluated at the same lifted x; full
        // large-field arithmetic, no closure required.
        let mut mask_shares = Vec::with_capacity(self.share_amount);
        for i in 1..=self.share_amount {
            let x = small_field_point(self.profile, i);
            let y = eval_poly_horner(self.profile, &g_poly, x);
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

    /// Compute `h(x) = g(x) + θ · f(x)` over `GF(2^w_q)`.
    ///
    /// In char 2 this is equal to the textbook `g(x) − θ · f(x)`
    /// (subtraction is XOR); we use the additive form for clarity.
    pub fn compute_degree_test_poly(
        &self,
        f_poly: &[Gf2Element],
        g_poly: &[Gf2Element],
        theta: &Gf2Element,
    ) -> Vec<Gf2Element> {
        let len = f_poly.len().max(g_poly.len());
        let zero = Gf2Element::zero(self.profile);
        let mut h = Vec::with_capacity(len);
        for i in 0..len {
            let g_i = g_poly.get(i).copied().unwrap_or(zero);
            let f_i = f_poly.get(i).copied().unwrap_or(zero);
            let theta_f = theta.mul(&f_i);
            h.push(g_i.add(&theta_f));
        }
        h
    }

    /// Verify one recipient's share pair against the publicly
    /// known `h(x)` coefficients and the degree-test challenge `θ`.
    ///
    /// Check: `g(i) + θ · f_large(i) == h(i)` over `GF(2^w_q)`.
    /// Returns `true` iff the recipient's share is consistent with
    /// the dealer-committed `h`, `g`, `f`.
    pub fn verify_share(
        &self,
        node_id: usize,
        f_large_share: &Gf2Element,
        g_share: &Gf2Element,
        h_coeffs: &[Gf2Element],
        theta: &Gf2Element,
    ) -> bool {
        debug_assert!(
            node_id >= 1 && node_id <= self.share_amount,
            "node_id {} not in 1..={}",
            node_id,
            self.share_amount
        );
        let x = small_field_point(self.profile, node_id);
        let h_at_x = eval_poly_horner(self.profile, h_coeffs, x);
        let theta_f = theta.mul(f_large_share);
        let lhs = g_share.add(&theta_f);
        lhs == h_at_x
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

/// Map an integer node id `1..=n` to its `GF(2^w_p) ↪ GF(2^w_q)`
/// evaluation point. The result is a `Gf2Element` whose low `w_p`
/// bits encode the little-endian byte representation of `node_id`
/// and whose remaining bits are zero (i.e. the element lies in the
/// small-field image).
///
/// Pre: caller has validated `node_id < 2^w_p` (the dealer's
/// `Gf2TwoFieldDealer::new` enforces this for `1..=share_amount`).
/// `node_id == 0` returns `Gf2Element::zero(profile)`, which would
/// produce a singular Vandermonde row; the dealer never uses 0 as
/// an evaluation point.
pub fn small_field_point(profile: Gf2Profile, node_id: usize) -> Gf2Element {
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

/// Recover `f(0)` from `t` (or more) `(node_id, share)` pairs via
/// Lagrange interpolation. Uses the **char-2-specialised** formula:
///
/// ```text
///     L_j(0) = Π_{k ≠ j} x_k / (x_j + x_k)
/// ```
///
/// (In char 2: `0 − x_k = x_k` and `x_j − x_k = x_j + x_k`.)
///
/// Returns `Gf2Element::zero(profile)` for an empty input. Panics
/// (via the underlying `inv`) if any pair of `node_id`s collides
/// in the small field, i.e. if the caller violated the dealer's
/// `share_amount < 2^w_p` invariant by passing equivalent points.
pub fn lagrange_recover_at_zero(
    profile: Gf2Profile,
    points: &[(usize, Gf2Element)],
) -> Gf2Element {
    let t = points.len();
    if t == 0 {
        return Gf2Element::zero(profile);
    }
    let xs: Vec<Gf2Element> = points
        .iter()
        .map(|(i, _)| small_field_point(profile, *i))
        .collect();
    let ys: Vec<Gf2Element> = points.iter().map(|(_, y)| *y).collect();

    let mut result = Gf2Element::zero(profile);
    let one = Gf2Element::one(profile);
    for j in 0..t {
        let mut num = one;
        let mut den = one;
        for k in 0..t {
            if k != j {
                num = num.mul(&xs[k]); // char 2: −x_k = x_k
                let diff = xs[j].add(&xs[k]); // char 2: x_j − x_k = x_j + x_k
                den = den.mul(&diff);
            }
        }
        let l_j = num.mul(&den.inv());
        result = result.add(&ys[j].mul(&l_j));
    }
    result
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
    /// `matrix[i][j] = L_j(β_i)` in `GF(2^w_p)` (small-field image).
    matrix: Vec<Vec<Gf2Element>>,
}

impl Gf2SuperInvExtractor {
    /// Build the extractor. `alpha_points` are 1-based integer node
    /// ids (sorted decided dealers' ids + 1, matching the BigUint
    /// path). `num_outputs` is the number of extracted beacon values
    /// per coin column (`m − f`).
    ///
    /// Pre: `alpha_points` are pairwise distinct, each in
    /// `1..=share_amount`. The dealer constructor's
    /// `share_amount < 2^w_p` capacity guarantee carries over: all
    /// `m + num_outputs` `small_field_point` values are distinct.
    pub fn new(profile: Gf2Profile, alpha_points: Vec<usize>, num_outputs: usize) -> Self {
        let m = alpha_points.len();
        let alphas: Vec<Gf2Element> = alpha_points
            .iter()
            .map(|&a| small_field_point(profile, a))
            .collect();

        let max_alpha = alpha_points.iter().copied().max().unwrap_or(0);
        let betas: Vec<Gf2Element> = (1..=num_outputs)
            .map(|i| small_field_point(profile, max_alpha + i))
            .collect();

        let one = Gf2Element::one(profile);
        let mut matrix = Vec::with_capacity(num_outputs);
        for beta in betas.iter() {
            let mut row = Vec::with_capacity(m);
            for j in 0..m {
                // L_j(β) = Π_{k ≠ j} (β + α_k) / (α_j + α_k)
                let mut num = one;
                let mut den = one;
                for k in 0..m {
                    if k != j {
                        num = num.mul(&beta.add(&alphas[k]));
                        den = den.mul(&alphas[j].add(&alphas[k]));
                    }
                }
                let lj = num.mul(&den.inv());
                row.push(lj);
            }
            matrix.push(row);
        }
        Self {
            profile,
            num_inputs: m,
            num_outputs,
            matrix,
        }
    }

    /// Extract `num_outputs` values from one column of `m` secrets
    /// (`inputs[j]` is the secret at evaluation point
    /// `alpha_points[j]`, in the SAME order passed to `new`).
    ///
    /// Output element `i` equals `P(β_i)` where `P` is the unique
    /// degree-`<m` polynomial interpolating `(α_j, inputs[j])`.
    pub fn extract(&self, inputs: &[Gf2Element]) -> Vec<Gf2Element> {
        let cols = self.num_inputs.min(inputs.len());
        let zero = Gf2Element::zero(self.profile);
        let mut out = Vec::with_capacity(self.num_outputs);
        for i in 0..self.num_outputs {
            let mut acc = zero;
            for j in 0..cols {
                acc = acc.add(&self.matrix[i][j].mul(&inputs[j]));
            }
            out.push(acc);
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
            let recovered = lagrange_recover_at_zero(profile, &shares.secret_shares[..t]);
            assert_eq!(
                recovered, secret,
                "recover failed at ({},{},t={},n={})",
                w_p, w_q, t, n
            );

            // (c) Recover from a DIFFERENT subset of t shares — should
            //     give the same result (polynomial uniqueness).
            if n >= t + 2 {
                let alt: Vec<_> = (0..t).map(|j| shares.secret_shares[n - 1 - j]).collect();
                let recovered_alt = lagrange_recover_at_zero(profile, &alt);
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
        let recovered_t = lagrange_recover_at_zero(profile, &shares.secret_shares[..5]);
        assert_eq!(recovered_t, secret);
        let recovered_tp1 = lagrange_recover_at_zero(profile, &shares.secret_shares[..6]);
        assert_eq!(recovered_tp1, secret, "t+1 shares must also recover");
        let recovered_tm1 = lagrange_recover_at_zero(profile, &shares.secret_shares[..4]);
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
        let recovered = lagrange_recover_at_zero(profile, &[(3, c)]);
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
            let recovered = lagrange_recover_at_zero(profile, &points);
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
            let c_d = lagrange_recover_at_zero(profile, &points);
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

            let extractor = Gf2SuperInvExtractor::new(profile, alpha.clone(), r);
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
        let extractor = Gf2SuperInvExtractor::new(profile, alpha, r);

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
            let recovered = lagrange_recover_at_zero(profile, &points);
            assert_eq!(recovered, secret);
            per_dealer_recovered.push(recovered);
        }

        let alpha: Vec<usize> = (1..=m).collect();
        let extractor = Gf2SuperInvExtractor::new(profile, alpha, r);
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
