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

impl TwoFieldDealer {
    pub fn new(small_field: BigUint, large_field: BigUint, threshold: usize, share_amount: usize) -> Self {
        Self { small_field, large_field, threshold, share_amount }
    }

    /// Generate two-field shares for a single secret.
    /// theta is the previous round's beacon output (used for degree testing).
    pub fn share_secret(&self, secret: BigUint, theta: &BigUint) -> TwoFieldShares {
        // 1. Generate f(x) over small field with f(0) = secret
        let f_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.small_field.clone(),
        };
        let f_poly = f_ss.sample_polynomial_pub(secret.clone());

        // Evaluate f(i) in small field (mod p) — for secret reconstruction
        let f_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, f_ss.mod_evaluate_at_pub(&f_poly, x)))
            .collect();

        // Evaluate f(i) in large field (mod q) — for degree test verification
        // Since f_poly coefficients are all < p < q, we can evaluate them mod q directly
        let f_large_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.large_field.clone(),
        };
        let f_large_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, f_large_ss.mod_evaluate_at_pub(&f_poly, x)))
            .collect();

        // 2. Generate g(x) over large field with random g(0)
        let g_ss = ShamirSecretSharing {
            threshold: self.threshold,
            share_amount: self.share_amount,
            prime: self.large_field.clone(),
        };
        let g_secret = rand::thread_rng().gen_biguint_range(
            &BigUint::from(0u32),
            &self.large_field,
        );
        let g_poly = g_ss.sample_polynomial_pub(g_secret);
        let g_shares: Vec<(usize, BigUint)> = (1..=self.share_amount)
            .map(|x| (x, g_ss.mod_evaluate_at_pub(&g_poly, x)))
            .collect();

        // 3. Compute h(x) = g(x) - θ·f(x) mod q
        // f_poly coefficients are used as-is (they're < p < q, so valid in F_q)
        let h_coeffs = self.compute_degree_test_poly(&f_poly, &g_poly, theta);

        TwoFieldShares {
            secret_shares: f_shares,
            f_large_shares,
            mask_shares: g_shares,
            degree_test_coeffs: h_coeffs,
        }
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

    /// Extended Euclidean algorithm for modular inverse
    fn mod_inverse(a: &BigInt, modulus: &BigInt) -> BigInt {
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
}
