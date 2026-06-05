/**
 * Phase 4B: Two-Field Optimization & Batch Randomness Extraction
 *
 * This module implements:
 * 1. Two-Field Secret Sharing: secrets in small field F_p, masks in large field F_q
 * 2. Degree Testing: h(x) = g(x) - θ·f(x) for verifiable share consistency
 * 3. Batch Extraction via Super Inverse Matrix: recover multiple secrets at once
 *    using precomputed Vandermonde inverse instead of per-secret Lagrange interpolation
 */

use num_bigint::{BigUint, BigInt};
use num_traits::{One, Zero};
use std::collections::HashMap;

use super::ShamirSecretSharing;

// ============================================================================
// Part 1: Two-Field Secret Sharing
// ============================================================================

/// TwoFieldDealer handles the dual-polynomial approach:
/// - f(x) over small field F_p encodes the real beacon secret
/// - g(x) over large field F_q serves as a random mask
/// - h(x) = g(x) - θ·f(x) is publicly broadcast for degree testing
///
/// IMPORTANT: For degree testing, h(x) is computed using f(x) coefficients
/// lifted to the large field (no mod p reduction on coefficients, only mod q).
/// Since all f(x) coefficients are < p < q, this is mathematically consistent.
/// However, f(i) mod p may differ from f(i) mod q when the polynomial evaluation
/// exceeds p. Therefore, we provide `f_large_shares` = f(i) mod q for verification.
#[derive(Clone, Debug)]
pub struct TwoFieldDealer {
    pub small_field: BigUint,   // p (secret domain)
    pub large_field: BigUint,   // q (nonce/mask domain)
    pub threshold: usize,       // t = f+1
    pub share_amount: usize,    // n = 3f+1
}

/// The result of a two-field share generation
#[derive(Clone, Debug)]
pub struct TwoFieldShares {
    /// f(i) for each node i, in small field (mod p) — used for secret reconstruction
    pub secret_shares: Vec<(usize, BigUint)>,
    /// f(i) for each node i, in large field (mod q) — used for degree test verification
    pub f_large_shares: Vec<(usize, BigUint)>,
    /// g(i) for each node i, in large field (mod q)
    pub mask_shares: Vec<(usize, BigUint)>,
    /// Coefficients of h(x) = g(x) - θ·f(x) mod q, publicly broadcast for degree testing
    pub degree_test_coeffs: Vec<BigUint>,
}

/// Sampled two-field shares WITHOUT the degree-test polynomial `h`
/// (which needs θ). Used by the Fiat-Shamir dealer path to commit
/// f and g before deriving θ from the commitment.
#[derive(Clone, Debug)]
pub struct TwoFieldSampled {
    pub secret_shares: Vec<(usize, BigUint)>,
    pub f_large_shares: Vec<(usize, BigUint)>,
    pub mask_shares: Vec<(usize, BigUint)>,
    pub f_poly: Vec<BigUint>,
    pub g_poly: Vec<BigUint>,
}

impl TwoFieldDealer {
    pub fn new(small_field: BigUint, large_field: BigUint, threshold: usize, share_amount: usize) -> Self {
        Self { small_field, large_field, threshold, share_amount }
    }

    /// Generate two-field shares for a single secret.
    /// theta is the degree-test challenge.
    ///
    /// Convenience wrapper kept for tests / call sites that already
    /// know θ. Production (Fiat-Shamir) uses `sample_shares` to commit
    /// f and g FIRST, derives θ from the commitment, then calls
    /// `compute_degree_test_poly_pub`.
    pub fn share_secret(&self, secret: BigUint, theta: &BigUint) -> TwoFieldShares {
        let sampled = self.sample_shares(secret);
        let h_coeffs =
            self.compute_degree_test_poly(&sampled.f_poly, &sampled.g_poly, theta);
        TwoFieldShares {
            secret_shares: sampled.secret_shares,
            f_large_shares: sampled.f_large_shares,
            mask_shares: sampled.mask_shares,
            degree_test_coeffs: h_coeffs,
        }
    }

    /// Sample f (encoding the secret) and the random mask g, returning
    /// all per-recipient shares PLUS the raw polynomials, WITHOUT
    /// computing the degree-test polynomial `h` (which needs θ). The
    /// Fiat-Shamir dealer path commits these shares first, derives θ
    /// from the commitment, then computes `h` via
    /// `compute_degree_test_poly_pub`.
    pub fn sample_shares(&self, secret: BigUint) -> TwoFieldSampled {
        let f_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.small_field.clone(),
        };
        let f_poly = f_ss.sample_polynomial_pub(secret);

        let secret_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, f_ss.mod_evaluate_at_pub(&f_poly, x)))
            .collect();

        let f_large_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.large_field.clone(),
        };
        let f_large_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, f_large_ss.mod_evaluate_at_pub(&f_poly, x)))
            .collect();

        let g_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.large_field.clone(),
        };
        let g_secret =
            rand::thread_rng().gen_biguint_range(&BigUint::from(0u32), &self.large_field);
        let g_poly = g_ss.sample_polynomial_pub(g_secret);
        let mask_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, g_ss.mod_evaluate_at_pub(&g_poly, x)))
            .collect();

        TwoFieldSampled {
            secret_shares,
            f_large_shares,
            mask_shares,
            f_poly,
            g_poly,
        }
    }

    /// Public wrapper around the degree-test polynomial computation
    /// `h(x) = g(x) - θ·f(x) mod q`, for the Fiat-Shamir dealer path.
    pub fn compute_degree_test_poly_pub(
        &self,
        f_coeffs: &[BigUint],
        g_coeffs: &[BigUint],
        theta: &BigUint,
    ) -> Vec<BigUint> {
        self.compute_degree_test_poly(f_coeffs, g_coeffs, theta)
    }

    /// Compute h(x) = g(x) - θ·f(x) mod q
    fn compute_degree_test_poly(
        &self,
        f_coeffs: &[BigUint],
        g_coeffs: &[BigUint],
        theta: &BigUint,
    ) -> Vec<BigUint> {
        let q = &self.large_field;
        let zero = BigUint::zero();
        let len = std::cmp::max(f_coeffs.len(), g_coeffs.len());
        let mut h = Vec::with_capacity(len);
        for i in 0..len {
            let g_i = if i < g_coeffs.len() { &g_coeffs[i] } else { &zero };
            let f_i = if i < f_coeffs.len() { &f_coeffs[i] } else { &zero };
            // h_i = g_i - θ·f_i mod q
            let theta_f = (theta * f_i) % q;
            let h_i = if g_i >= &theta_f {
                (g_i - &theta_f) % q
            } else {
                (q - (&theta_f - g_i) % q) % q
            };
            h.push(h_i);
        }
        h
    }

    /// Verify a share pair against the public h(x) coefficients.
    /// Check: g(i) - θ·f_large(i) == h(i) mod q
    ///
    /// f_large_share is f(i) evaluated in the LARGE field (mod q), NOT mod p.
    /// This is necessary because h(x) was computed from f(x) coefficients in F_q.
    pub fn verify_share(
        &self,
        node_id: usize,
        f_large_share: &BigUint,  // f(i) mod q
        g_share: &BigUint,        // g(i) mod q
        h_coeffs: &[BigUint],
        theta: &BigUint,
    ) -> bool {
        let q = &self.large_field;
        // Evaluate h(node_id) from public coefficients
        let x = BigUint::from(node_id);
        let h_eval = h_coeffs.iter().rev().fold(BigUint::zero(), |acc, coeff| {
            (&x * acc + coeff) % q
        });
        // Compute g(i) - θ·f_large(i) mod q
        let theta_f = (theta * f_large_share) % q;
        let lhs = if g_share >= &theta_f {
            (g_share - &theta_f) % q
        } else {
            (q - (&theta_f - g_share) % q) % q
        };
        lhs == h_eval
    }
}

use num_bigint::RandBigInt;

// Expose polynomial internals for two-field usage
impl ShamirSecretSharing {
    pub fn sample_polynomial_pub(&self, secret: BigUint) -> Vec<BigUint> {
        self.sample_polynomial(secret)
    }

    pub fn mod_evaluate_at_pub(&self, polynomial: &[BigUint], x: usize) -> BigUint {
        self.mod_evaluate_at(polynomial, x)
    }
}

// ============================================================================
// Part 2: Batch Extraction via Super Inverse Matrix
// ============================================================================

/// BatchExtractor precomputes the Lagrange basis coefficients for recovering f(0)
/// from shares at given evaluation points. This enables O(n·k) batch recovery
/// of k secrets from n shares, instead of k separate O(n²) Lagrange interpolations.
///
/// The "Super Inverse Matrix" approach:
/// Given evaluation points [x_1, ..., x_t], precompute L_j(0) for all j.
/// Then for any set of shares [y_1, ..., y_t], f(0) = Σ L_j(0) · y_j mod p.
/// This is a single row of the Vandermonde inverse matrix.
#[derive(Clone, Debug)]
pub struct BatchExtractor {
    /// The field modulus
    pub prime: BigUint,
    /// Precomputed Lagrange coefficients: L_j(0) for each evaluation point x_j
    pub lagrange_coeffs: Vec<BigInt>,
    /// The evaluation points used (1-indexed node IDs)
    pub eval_points: Vec<usize>,
}

impl BatchExtractor {
    /// Precompute Lagrange basis coefficients for recovering f(0)
    /// from shares at the given evaluation points.
    ///
    /// For points x_1, ..., x_t, the Lagrange coefficient for x_j is:
    /// L_j(0) = ∏_{k≠j} (0 - x_k) / (x_j - x_k) mod p
    pub fn new(eval_points: Vec<usize>, prime: BigUint) -> Self {
        let t = eval_points.len();
        let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, prime.clone());
        let xs: Vec<BigInt> = eval_points.iter().map(|&x| BigInt::from(x as i64)).collect();

        let mut lagrange_coeffs = Vec::with_capacity(t);
        for j in 0..t {
            let mut num = BigInt::one();
            let mut den = BigInt::one();
            for k in 0..t {
                if k != j {
                    // numerator: (0 - x_k) = -x_k
                    num = (num * (-xs[k].clone())) % &p_bi;
                    // denominator: (x_j - x_k)
                    den = (den * (&xs[j] - &xs[k])) % &p_bi;
                }
            }
            // L_j(0) = num * den^{-1} mod p
            let den_inv = Self::mod_inverse(&den, &p_bi);
            let coeff = (num * den_inv) % &p_bi;
            lagrange_coeffs.push(coeff);
        }

        Self { prime, lagrange_coeffs, eval_points }
    }

    /// Batch-recover multiple secrets at once.
    /// shares_matrix[coin_num] = HashMap<dealer_id -> share_value>
    /// Returns: Vec<(coin_num, recovered_secret)>
    pub fn batch_recover(
        &self,
        shares_matrix: &HashMap<usize, HashMap<usize, BigUint>>,
    ) -> Vec<(usize, BigUint)> {
        let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone());
        let mut results = Vec::new();

        for (&coin_num, dealer_shares) in shares_matrix.iter() {
            // Collect shares in the order of eval_points
            let mut shares_ordered: Vec<Option<&BigUint>> = Vec::with_capacity(self.eval_points.len());
            let mut all_present = true;
            for &pt in &self.eval_points {
                match dealer_shares.get(&pt) {
                    Some(s) => shares_ordered.push(Some(s)),
                    None => {
                        all_present = false;
                        break;
                    }
                }
            }
            if !all_present {
                continue;
            }

            // Compute f(0) = Σ L_j(0) · y_j mod p
            let mut secret = BigInt::zero();
            for (j, share) in shares_ordered.iter().enumerate() {
                let y_j = BigInt::from_biguint(num_bigint::Sign::Plus, share.unwrap().clone());
                secret = (secret + &self.lagrange_coeffs[j] * y_j) % &p_bi;
            }

            // Normalize to positive
            let secret_pos = if secret < BigInt::zero() {
                (secret + &p_bi).to_biguint().unwrap()
            } else {
                secret.to_biguint().unwrap()
            };

            results.push((coin_num, secret_pos));
        }

        results.sort_by_key(|(k, _)| *k);
        results
    }

    /// Recover a single secret f(0) from shares supplied in the same
    /// order as `self.eval_points`, reusing the precomputed Lagrange
    /// coefficients. `shares_in_order[j]` MUST be the share evaluated
    /// at `self.eval_points[j]`.
    ///
    /// Used by the PPT reconstruction path, which builds one small
    /// `BatchExtractor` per distinct provider-set (the f+1 lowest
    /// responding share-holders for a given dealer) instead of one
    /// global extractor pinned to the ACS-decided set. This is what
    /// restores reconstruction liveness: any f+1 valid shares from
    /// *any* providers suffice, so a Byzantine node that withholds
    /// its reconstruction share can no longer stall the round.
    pub fn recover_one(&self, shares_in_order: &[BigUint]) -> BigUint {
        let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, self.prime.clone());
        let mut secret = BigInt::zero();
        for (j, share) in shares_in_order.iter().enumerate() {
            if j >= self.lagrange_coeffs.len() {
                break;
            }
            let y_j = BigInt::from_biguint(num_bigint::Sign::Plus, share.clone());
            secret = (secret + &self.lagrange_coeffs[j] * y_j) % &p_bi;
        }
        if secret < BigInt::zero() {
            (secret + &p_bi).to_biguint().unwrap()
        } else {
            secret.to_biguint().unwrap()
        }
    }

    /// Extended Euclidean algorithm for modular inverse
    pub(crate) fn mod_inverse(a: &BigInt, modulus: &BigInt) -> BigInt {
        let a_pos = if a < &BigInt::zero() {
            a + modulus
        } else {
            a.clone()
        };
        let (mut r, mut next_r) = (modulus.clone(), a_pos);
        let (mut s, mut next_s) = (BigInt::zero(), BigInt::one());

        while next_r > BigInt::zero() {
            let quotient = &r / &next_r;
            let tmp_r = next_r.clone();
            next_r = &r - &next_r * &quotient;
            r = tmp_r;
            let tmp_s = next_s.clone();
            next_s = &s - &next_s * &quotient;
            s = tmp_s;
        }

        if s < BigInt::zero() {
            s + modulus
        } else {
            s
        }
    }
}

// ============================================================================
// Part 2b: Super-Invertible (Hyper-Invertible) Randomness Extraction
// ============================================================================

/// Super-invertible (a.k.a. hyper-invertible) randomness extractor
/// implementing the PPT "batch randomness extraction" step
/// (slides 8-10). It replaces the degenerate all-ones sum with a
/// genuine `R × m` super-invertible matrix.
///
/// Construction (Beerliová-Trubíniová & Hirt): given `m` distinct
/// input points `α_1..α_m` and `R` distinct output points
/// `β_1..β_R` (all `m + R` points distinct), the matrix
/// `M[i][j] = L_j(β_i)` — where `L_j` is the Lagrange basis polynomial
/// for the nodes `{α_j}` — is hyper-invertible: EVERY square submatrix
/// is invertible. Applying it to a column of `m` dealer secrets
/// `x = (x_1..x_m)` is exactly "interpolate the unique degree-(<m)
/// polynomial `P` with `P(α_j) = x_j`, then output `P(β_i)` for each
/// `i`".
///
/// Security: in one coin column, at most `f` of the `m` decided
/// dealers are Byzantine; their `x_j` are committed during AVSS,
/// independently of (and before) the `m - f ≥ f+1` honest, uniform,
/// secret inputs. Hyper-invertibility guarantees that for ANY choice
/// of which `f` columns are adversarial, the `R = m - f` outputs are a
/// bijective image of the `m - f` honest inputs (the honest-column
/// submatrix is square and invertible). Hence the `R` outputs are
/// uniformly random and independent — uniform extraction tolerating
/// `f` adversarial contributions, which a single summed output cannot
/// provide (it yields only one value).
#[derive(Clone, Debug)]
pub struct SuperInvExtractor {
    pub prime: BigUint,
    pub num_inputs: usize,
    pub num_outputs: usize,
    /// `matrix[i][j] = L_j(β_i) mod p`, reduced into `[0, p)`.
    matrix: Vec<Vec<BigUint>>,
}

impl SuperInvExtractor {
    /// Build the extractor for input evaluation points `alpha_points`
    /// (e.g. the sorted decided dealers' ids + 1) and `num_outputs`
    /// extracted values per column. The output points are chosen
    /// deterministically as `max(alpha)+1 .. max(alpha)+num_outputs`,
    /// guaranteeing they are distinct from every `alpha`.
    pub fn new(alpha_points: Vec<usize>, num_outputs: usize, prime: BigUint) -> Self {
        let m = alpha_points.len();
        let p_bi = BigInt::from_biguint(num_bigint::Sign::Plus, prime.clone());
        let alphas: Vec<BigInt> =
            alpha_points.iter().map(|&a| BigInt::from(a as i64)).collect();

        // β points strictly above the largest α so all m + num_outputs
        // points are distinct (α are dealer ids+1 in [1, n]).
        let max_alpha = alpha_points.iter().copied().max().unwrap_or(0);
        let betas: Vec<BigInt> = (1..=num_outputs)
            .map(|i| BigInt::from((max_alpha + i) as i64))
            .collect();

        let mut matrix = Vec::with_capacity(num_outputs);
        for beta in betas.iter() {
            let mut row = Vec::with_capacity(m);
            for j in 0..m {
                // L_j(β) = Π_{k != j} (β - α_k) / (α_j - α_k)
                let mut num = BigInt::one();
                let mut den = BigInt::one();
                for k in 0..m {
                    if k != j {
                        num = (num * (beta - &alphas[k])) % &p_bi;
                        den = (den * (&alphas[j] - &alphas[k])) % &p_bi;
                    }
                }
                let den_inv = BatchExtractor::mod_inverse(&den, &p_bi);
                let coeff = (((num * den_inv) % &p_bi) + &p_bi) % &p_bi;
                row.push(coeff.to_biguint().expect("coeff normalized to [0, p)"));
            }
            matrix.push(row);
        }

        Self {
            prime,
            num_inputs: m,
            num_outputs,
            matrix,
        }
    }

    /// Extract `num_outputs` values from one column of `m` secrets
    /// (`inputs[j]` is the secret at evaluation point `alpha_points[j]`,
    /// in the SAME order passed to `new`).
    pub fn extract(&self, inputs: &[BigUint]) -> Vec<BigUint> {
        let cols = self.num_inputs.min(inputs.len());
        let mut out = Vec::with_capacity(self.num_outputs);
        for i in 0..self.num_outputs {
            let mut acc = BigUint::zero();
            for j in 0..cols {
                acc = (acc + &self.matrix[i][j] * &inputs[j]) % &self.prime;
            }
            out.push(acc);
        }
        out
    }
}

// ============================================================================
// Part 3: Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;

    #[test]
    fn test_two_field_share_and_verify() {
        let small_p = BigUint::from(685373784908497u64);
        let large_q = BigUint::parse_bytes(
            b"57896044618658097711785492504343953926634992332820282019728792003956564819949", 10
        ).unwrap();

        let dealer = TwoFieldDealer::new(small_p.clone(), large_q.clone(), 2, 4);
        let theta = BigUint::from(42u32);
        let secret = BigUint::from(12345u32);

        let shares = dealer.share_secret(secret.clone(), &theta);

        // All shares should verify using f_large_shares (mod q)
        for i in 0..4 {
            let f_large = &shares.f_large_shares[i].1;
            let g_share = &shares.mask_shares[i].1;
            let node_id = shares.secret_shares[i].0;
            assert!(
                dealer.verify_share(node_id, f_large, g_share, &shares.degree_test_coeffs, &theta),
                "Share verification failed for node {}", node_id
            );
        }

        // Recover secret from t shares using small-field shares
        let ss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 4,
            prime: small_p.clone(),
        };
        let recovered = ss.recover(&shares.secret_shares[0..2]);
        assert_eq!(recovered, secret, "Secret recovery failed");
    }

    #[test]
    fn test_two_field_large_secret() {
        // Test with a secret close to the field boundary
        let small_p = BigUint::from(685373784908497u64);
        let large_q = BigUint::parse_bytes(
            b"57896044618658097711785492504343953926634992332820282019728792003956564819949", 10
        ).unwrap();

        let dealer = TwoFieldDealer::new(small_p.clone(), large_q.clone(), 2, 4);
        let theta = BigUint::from(999999u32);
        let secret = &small_p - BigUint::from(1u32);  // max possible secret

        let shares = dealer.share_secret(secret.clone(), &theta);

        for i in 0..4 {
            let f_large = &shares.f_large_shares[i].1;
            let g_share = &shares.mask_shares[i].1;
            let node_id = shares.secret_shares[i].0;
            assert!(
                dealer.verify_share(node_id, f_large, g_share, &shares.degree_test_coeffs, &theta),
                "Share verification failed for node {} with large secret", node_id
            );
        }

        let ss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 4,
            prime: small_p.clone(),
        };
        let recovered = ss.recover(&shares.secret_shares[0..2]);
        assert_eq!(recovered, secret, "Large secret recovery failed");
    }

    #[test]
    fn test_batch_extractor() {
        let prime = BigUint::from(685373784908497u64);
        let ss = ShamirSecretSharing {
            threshold: 2,
            share_amount: 4,
            prime: prime.clone(),
        };

        // Create 3 secrets and split them
        let secrets = vec![
            BigUint::from(111u32),
            BigUint::from(222u32),
            BigUint::from(333u32),
        ];

        let mut shares_matrix: HashMap<usize, HashMap<usize, BigUint>> = HashMap::new();
        for (coin, secret) in secrets.iter().enumerate() {
            let shares = ss.split(secret.clone());
            let mut dealer_shares = HashMap::new();
            for (id, val) in shares.iter().take(2) {
                dealer_shares.insert(*id, val.clone());
            }
            shares_matrix.insert(coin, dealer_shares);
        }

        // Batch recover
        let extractor = BatchExtractor::new(vec![1, 2], prime.clone());
        let recovered = extractor.batch_recover(&shares_matrix);

        assert_eq!(recovered.len(), 3);
        for (coin, rec_secret) in recovered {
            assert_eq!(rec_secret, secrets[coin], "Batch recovery failed for coin {}", coin);
        }
    }

    #[test]
    fn test_batch_extractor_larger() {
        let prime = BigUint::from(685373784908497u64);
        let n = 10;
        let f = 3;
        let t = f + 1;

        let ss = ShamirSecretSharing {
            threshold: t,
            share_amount: n,
            prime: prime.clone(),
        };

        let mut rng = rand::thread_rng();
        let num_coins = 20;
        let mut secrets = Vec::new();
        let mut shares_matrix: HashMap<usize, HashMap<usize, BigUint>> = HashMap::new();

        for coin in 0..num_coins {
            let secret = rng.gen_biguint_range(&BigUint::from(0u32), &prime);
            secrets.push(secret.clone());
            let shares = ss.split(secret);
            let mut dealer_shares = HashMap::new();
            for (id, val) in shares.iter().take(t) {
                dealer_shares.insert(*id, val.clone());
            }
            shares_matrix.insert(coin, dealer_shares);
        }

        let eval_points: Vec<usize> = (1..=t).collect();
        let extractor = BatchExtractor::new(eval_points, prime.clone());
        let recovered = extractor.batch_recover(&shares_matrix);

        assert_eq!(recovered.len(), num_coins);
        for (coin, rec_secret) in recovered {
            assert_eq!(rec_secret, secrets[coin], "Batch recovery failed for coin {}", coin);
        }
    }

    /// The extractor's output_i must equal P(β_i), where P is the
    /// degree-(<m) polynomial interpolating (α_j, x_j). We verify by
    /// recomputing P(β_i) via an independent Lagrange evaluation.
    #[test]
    fn super_inv_matches_polynomial_evaluation() {
        let prime = BigUint::from(685373784908497u64);
        let m = 7usize;
        let f = 2usize;
        let r = m - f; // 5 outputs
        let alpha: Vec<usize> = (1..=m).collect();

        let mut rng = rand::thread_rng();
        let inputs: Vec<BigUint> = (0..m)
            .map(|_| rng.gen_biguint_range(&BigUint::from(0u32), &prime))
            .collect();

        let extractor = SuperInvExtractor::new(alpha.clone(), r, prime.clone());
        let outputs = extractor.extract(&inputs);
        assert_eq!(outputs.len(), r);

        // Independent reference: interpolate P through (alpha_j, x_j)
        // and evaluate at beta_i = max(alpha)+1.. via a one-row
        // BatchExtractor trick (L_j(beta) = recover_one of unit basis).
        let max_alpha = *alpha.iter().max().unwrap();
        for i in 0..r {
            let beta = max_alpha + 1 + i;
            // P(beta) = Σ_j x_j * L_j(beta). Compute L_j(beta) by
            // interpolating the j-th unit vector through alpha and
            // evaluating at beta is overkill; instead reuse the
            // standard Lagrange formula directly.
            let p_bi = num_bigint::BigInt::from_biguint(
                num_bigint::Sign::Plus,
                prime.clone(),
            );
            let alphas: Vec<num_bigint::BigInt> =
                alpha.iter().map(|&a| num_bigint::BigInt::from(a as i64)).collect();
            let beta_bi = num_bigint::BigInt::from(beta as i64);
            let mut expected = num_bigint::BigInt::from(0);
            for j in 0..m {
                let mut num = num_bigint::BigInt::from(1);
                let mut den = num_bigint::BigInt::from(1);
                for k in 0..m {
                    if k != j {
                        num = (num * (&beta_bi - &alphas[k])) % &p_bi;
                        den = (den * (&alphas[j] - &alphas[k])) % &p_bi;
                    }
                }
                let den_inv = BatchExtractor::mod_inverse(&den, &p_bi);
                let lj = (((num * den_inv) % &p_bi) + &p_bi) % &p_bi;
                let xj = num_bigint::BigInt::from_biguint(
                    num_bigint::Sign::Plus,
                    inputs[j].clone(),
                );
                expected = (expected + lj * xj) % &p_bi;
            }
            let expected = ((expected % &p_bi) + &p_bi) % &p_bi;
            assert_eq!(
                outputs[i],
                expected.to_biguint().unwrap(),
                "output {} must equal P(beta_{})",
                i,
                i
            );
        }
    }

    /// Hyper-invertibility sanity: every output must depend on every
    /// input. Flipping a single (honest) input must change ALL outputs
    /// — this is what makes a single honest uniform input randomize the
    /// whole output vector, which the all-ones sum cannot do for more
    /// than one output.
    #[test]
    fn super_inv_every_output_depends_on_each_input() {
        let prime = BigUint::from(685373784908497u64);
        let m = 6usize;
        let f = 1usize;
        let r = m - f;
        let alpha: Vec<usize> = (1..=m).collect();
        let extractor = SuperInvExtractor::new(alpha, r, prime.clone());

        let base: Vec<BigUint> = (0..m).map(|j| BigUint::from((j as u64) + 1)).collect();
        let base_out = extractor.extract(&base);

        for flip in 0..m {
            let mut alt = base.clone();
            alt[flip] = (&alt[flip] + BigUint::from(12345u64)) % &prime;
            let alt_out = extractor.extract(&alt);
            for i in 0..r {
                assert_ne!(
                    base_out[i], alt_out[i],
                    "output {} did not change when input {} changed (matrix entry must be nonzero)",
                    i, flip
                );
            }
        }
    }
}
