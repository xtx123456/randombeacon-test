//! Π_SecKeyDst — Secret Key Distribution from Section 4.2 of:
//!
//!   Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//!   Verifiable Secret Sharing with Optimal Resilience", Journal of
//!   Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//!
//! ## What this protocol does
//!
//! A SENDER S holds a master key `k ∈ F_p` (a finite-field element)
//! and distributes it across `n` parties so that:
//!
//!   * Each party `P_j` ends up with a share `k_j = p(j+1)` where
//!     `p(X) = k + a_1 X + ... + a_t X^t` is a random degree-`t`
//!     polynomial sampled by S with `p(0) = k`.
//!   * Any `≤ t` corrupted parties learn no information about `k`
//!     (perfect, information-theoretic Shamir hiding).
//!   * Any `t+1` parties' shares uniquely reconstruct `k` via
//!     Lagrange interpolation.
//!
//! Reliable transport of the share vector `(k_1, ..., k_n)` is
//! delegated to the sibling `Π_RelMsgDst` (Sec 4.1). Two honest
//! recipients of an honest sender's distribution always end up
//! with the same `(k_j, π_j, r_j, r)` tuple, ready to be forwarded
//! via the unhappy-path forwarding sub-protocol if some other
//! honest party didn't receive its own dispersal.
//!
//! ## What this protocol does NOT do
//!
//! Π_SecKeyDst does NOT itself bind the dealer to a *single*
//! degree-`t` polynomial. A Byzantine sender could disperse a
//! share vector that does NOT lie on any single degree-`t`
//! polynomial; reconstruction from two different `t+1` subsets
//! would then yield two different "secrets". Detecting that
//! consistency violation is the responsibility of the higher-
//! level Π_SecMsgDst (Sec 4.3) — which composes Π_SecKeyDst with
//! a degree-test / commitment check — and ultimately of Π_avss1
//! (Sec 5). Those are commits 5 and 6/7 in this series.
//!
//! Linear-hiding-only in this module means: the **payload-level**
//! hiding (Shamir's perfect secrecy under ≤ t corruptions) is
//! provided here. Verifier-level binding is layered on top in
//! later commits.
//!
//! ## Wire format
//!
//! Each `m_j` carried by the underlying Π_RelMsgDst is the
//! big-endian byte representation of `k_j` zero-padded to exactly
//! `share_byte_len = ceil(prime.bits() / 8)` bytes. This makes
//! every distributed message in the vector the same size — which
//! the Reed-Solomon fragments inside `RelMsgDst` rely on for
//! deterministic Merkle commitments.
//!
//! The recipient parses its delivered `m_j` back into a `BigUint`
//! and emits `DeliveredShare { share: k_j }`.
//!
//! ## PQ-safety
//!
//! Pure finite-field arithmetic plus the underlying Π_RelMsgDst
//! layer (`do_hash` + Merkle + Reed-Solomon over GF(2^8)). No new
//! Cargo dependencies; no DL / pairing / RSA / threshold-sig
//! primitives.

use std::fmt;
use std::sync::Arc;

use crypto::aes_hash::HashState;
use crypto::hash::Hash;
use num_bigint::BigUint;
use num_traits::Zero;
use types::Replica;

use super::rel_msg_dst::{
    DispersalEntry, EchoPayload, ForwardPayload, ForwardReject, RelMsgDstAction,
    RelMsgDstError, RelMsgDstState,
};

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

#[derive(Debug)]
pub enum SecKeyDstError {
    /// Underlying Π_RelMsgDst rejected the configuration.
    InvalidConfig(RelMsgDstError),
    /// `set_input_as_sender` called by a non-sender.
    NotSender { myid: Replica, sender: Replica },
    /// `set_input_as_sender` was called with `secret >= prime`.
    SecretOutOfRange,
    /// Underlying Π_RelMsgDst error during `set_input_as_sender`.
    Underlying(RelMsgDstError),
    /// `prepare_forward_for` called before delivery.
    NotYetDelivered,
    /// `prepare_forward_for(self.myid)` is meaningless.
    SelfForwardRequest,
    /// Caller supplied a degenerate prime (`< 2`).
    DegeneratePrime,
}

impl fmt::Display for SecKeyDstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecKeyDstError::InvalidConfig(e) => write!(f, "invalid config: {}", e),
            SecKeyDstError::NotSender { myid, sender } => {
                write!(f, "node {} is not the sender ({})", myid, sender)
            }
            SecKeyDstError::SecretOutOfRange => write!(f, "secret >= prime"),
            SecKeyDstError::Underlying(e) => write!(f, "RelMsgDst error: {}", e),
            SecKeyDstError::NotYetDelivered => write!(f, "share not yet delivered"),
            SecKeyDstError::SelfForwardRequest => write!(f, "cannot forward to self"),
            SecKeyDstError::DegeneratePrime => write!(f, "prime must be >= 2"),
        }
    }
}

impl std::error::Error for SecKeyDstError {}

// ---------------------------------------------------------------------
// Action enum
// ---------------------------------------------------------------------

/// Side-effects emitted by `SecKeyDstState`. Almost a 1-1 wrapper
/// around `RelMsgDstAction`, except that `Delivered`/`ForwardDelivered`
/// are decoded into typed `BigUint` shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecKeyDstAction {
    SendDispersal {
        recipient_idx: usize,
        entries: Vec<DispersalEntry>,
    },
    SendEcho {
        recipient_idx: usize,
        echo: EchoPayload,
    },
    SendVote {
        meta_root: Hash,
    },
    SendForward {
        recipient: Replica,
        forward: ForwardPayload,
    },
    /// Local: this party has received its own Shamir share `k_myid`.
    DeliveredShare { share: BigUint },
    /// Local: a forwarded share `k_source = p(source + 1)` arrived
    /// from `source` (forward sub-protocol).
    ForwardDeliveredShare { source: Replica, share: BigUint },
    /// Local: a forwarded payload was rejected. Same as the
    /// underlying RelMsgDst rejection (forwarder or original
    /// sender provably misbehaved).
    ForwardRejected { source: Replica, reason: ForwardReject },
    /// Local: delivery happened in the underlying Π_RelMsgDst but
    /// the share bytes failed `parse_share` validation
    /// (`bytes.len() != share_byte_len`, or `parsed >= prime`).
    /// Indicates a Byzantine sender. Distinct from
    /// `ForwardRejected` (which is forwarder-level).
    DeliveryFailedMalformedShare,
}

// ---------------------------------------------------------------------
// Helpers: share serialization & reconstruction
// ---------------------------------------------------------------------

/// Number of bytes used by the canonical big-endian zero-padded
/// encoding of a share for a given prime. Always equals
/// `ceil(prime.bits() / 8)`, with a floor of 1 for the
/// degenerate `prime == 2` case.
pub fn share_byte_len(prime: &BigUint) -> usize {
    let bits = prime.bits();
    if bits == 0 {
        return 1;
    }
    ((bits + 7) / 8) as usize
}

/// Encode a Shamir share into a fixed-length big-endian byte
/// string suitable for transport via Π_RelMsgDst. The output is
/// always exactly `share_byte_len(prime)` bytes (zero-padded on
/// the high side).
///
/// Returns `None` if `share >= prime` (caller error: a valid
/// Shamir share over `F_p` always lies in `[0, p)`).
pub fn serialize_share(prime: &BigUint, share: &BigUint) -> Option<Vec<u8>> {
    if share >= prime {
        return None;
    }
    let target = share_byte_len(prime);
    let raw = share.to_bytes_be();
    if raw.len() > target {
        // Should be unreachable when share < prime.
        return None;
    }
    let mut out = vec![0u8; target - raw.len()];
    out.extend_from_slice(&raw);
    Some(out)
}

/// Parse a fixed-length big-endian byte string back into a
/// `BigUint` share. Rejects the decode if `bytes.len()` mismatches
/// the canonical `share_byte_len(prime)` or if the parsed value is
/// `>= prime`. Both rejections imply a Byzantine sender (or
/// truncated wire data) and the caller should treat the share as
/// non-existent.
pub fn parse_share(prime: &BigUint, bytes: &[u8]) -> Option<BigUint> {
    if bytes.len() != share_byte_len(prime) {
        return None;
    }
    let parsed = BigUint::from_bytes_be(bytes);
    if &parsed >= prime {
        return None;
    }
    Some(parsed)
}

/// Reconstruct the master key `k = p(0)` from at least `t+1`
/// distinct `(idx, share)` tuples using Lagrange interpolation
/// over `F_prime`. Party-id `i ∈ [0, n)` maps to evaluation
/// point `x = i + 1`, matching the dealer's `set_input_as_sender`
/// convention.
///
/// Returns `None` if:
///   * fewer than `threshold + 1` distinct `idx` values are
///     supplied;
///   * any `idx >= n` is supplied;
///   * the prime is degenerate (`< 2`);
///   * Lagrange computation fails (numerator or denominator
///     non-invertible — should be impossible for `prime` actually
///     prime and distinct evaluation points, included as defence
///     against caller misconfiguration).
pub fn reconstruct(
    prime: &BigUint,
    n: usize,
    threshold: usize,
    shares: &[(usize, BigUint)],
) -> Option<BigUint> {
    if prime < &BigUint::from(2u32) {
        return None;
    }
    let needed = threshold + 1;
    let mut seen = std::collections::HashSet::new();
    let mut deduped: Vec<(usize, BigUint)> = Vec::new();
    for (idx, share) in shares.iter() {
        if *idx >= n {
            return None;
        }
        if !seen.insert(*idx) {
            continue;
        }
        if share >= prime {
            return None;
        }
        deduped.push((*idx, share.clone()));
        if deduped.len() == needed {
            break;
        }
    }
    if deduped.len() < needed {
        return None;
    }
    // Take exactly `needed` distinct shares for interpolation.
    deduped.truncate(needed);

    use num_bigint::BigInt;
    use num_bigint::Sign;
    use num_traits::One;

    let prime_bi = BigInt::from_biguint(Sign::Plus, prime.clone());
    let mut result_bi = BigInt::zero();

    for (i, (idx_i, share_i)) in deduped.iter().enumerate() {
        let xi = BigInt::from((idx_i + 1) as i64);
        let yi = BigInt::from_biguint(Sign::Plus, share_i.clone());

        // Lagrange basis L_i(0) = ∏_{j != i} (-x_j) / (x_i - x_j) mod p.
        let mut num: BigInt = BigInt::one();
        let mut den: BigInt = BigInt::one();
        for (j, (idx_j, _)) in deduped.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = BigInt::from((idx_j + 1) as i64);
            num = (num * (-&xj)).modpow(&BigInt::one(), &prime_bi);
            den = (den * (&xi - &xj)).modpow(&BigInt::one(), &prime_bi);
        }
        // den^{-1} mod p via extended Euclid.
        let den_inv = match modinv(&den, &prime_bi) {
            Some(v) => v,
            None => return None,
        };
        let term = (yi * num * den_inv).modpow(&BigInt::one(), &prime_bi);
        result_bi = (result_bi + term).modpow(&BigInt::one(), &prime_bi);
    }

    if result_bi.sign() == Sign::Minus {
        result_bi += &prime_bi;
    }
    // After wrapping, result_bi is in [0, prime); to_biguint returns
    // Some when sign is non-negative.
    result_bi.to_biguint()
}

/// Modular inverse via extended Euclidean algorithm. Returns
/// `None` if `gcd(a, m) != 1`.
fn modinv(a: &num_bigint::BigInt, m: &num_bigint::BigInt) -> Option<num_bigint::BigInt> {
    use num_bigint::BigInt;
    use num_bigint::Sign;
    use num_traits::{One, Zero};
    let (mut old_r, mut r) = (a.clone(), m.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    while !r.is_zero() {
        let q = &old_r / &r;
        let new_r = &old_r - &q * &r;
        old_r = std::mem::replace(&mut r, new_r);
        let new_s = &old_s - &q * &s;
        old_s = std::mem::replace(&mut s, new_s);
    }
    // gcd(a, m) must be ±1 for the inverse to exist.
    let one_bi = BigInt::one();
    let neg_one_bi: BigInt = -BigInt::one();
    if old_r != one_bi && old_r != neg_one_bi {
        return None;
    }
    // If gcd came out as -1, flip the Bezout coefficient sign so
    // the inverse is well-defined.
    if old_r == neg_one_bi {
        old_s = -old_s;
    }
    // old_s may be negative; normalise into [0, m).
    let mut res = old_s.modpow(&BigInt::one(), m);
    if res.sign() == Sign::Minus {
        res += m;
    }
    Some(res)
}

// ---------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------

pub struct SecKeyDstState {
    pub myid: Replica,
    pub n: usize,
    pub t: usize,
    pub sender: Replica,
    /// Finite-field modulus. Caller is responsible for choosing a
    /// prime large enough for the security parameter (Sec 5 of the
    /// paper requires `|F| >= 2^λ`).
    pub prime: BigUint,
    /// Underlying Π_RelMsgDst transport.
    rmd: RelMsgDstState,
    /// Cached delivered share (`k_myid`), set once distribution
    /// completes successfully and the bytes parse cleanly.
    delivered_share: Option<BigUint>,
}

impl fmt::Debug for SecKeyDstState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecKeyDstState")
            .field("myid", &self.myid)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("sender", &self.sender)
            .field("prime_bits", &self.prime.bits())
            .field("delivered_share", &self.delivered_share.is_some())
            .finish()
    }
}

impl SecKeyDstState {
    pub fn new(
        myid: Replica,
        n: usize,
        t: usize,
        sender: Replica,
        prime: BigUint,
        hash_state: Arc<HashState>,
    ) -> Result<Self, SecKeyDstError> {
        if prime < BigUint::from(2u32) {
            return Err(SecKeyDstError::DegeneratePrime);
        }
        let rmd = RelMsgDstState::new(myid, n, t, sender, hash_state)
            .map_err(SecKeyDstError::InvalidConfig)?;
        Ok(Self {
            myid,
            n,
            t,
            sender,
            prime,
            rmd,
            delivered_share: None,
        })
    }

    pub fn delivered(&self) -> bool {
        self.delivered_share.is_some()
    }

    pub fn delivered_share(&self) -> Option<&BigUint> {
        self.delivered_share.as_ref()
    }

    /// Sender-side: sample a random degree-`t` polynomial with
    /// `p(0) = k`, evaluate `(k_1, ..., k_n) = (p(1), ..., p(n))`,
    /// serialize each `k_j` to fixed-length bytes, and hand the
    /// vector to the underlying `Π_RelMsgDst::set_input_as_sender`.
    ///
    /// `rng` is taken by mutable reference so callers can control
    /// determinism (e.g. seeded `ChaCha20Rng` in tests). The
    /// security analysis requires `rng` be cryptographically
    /// strong in production; this state machine just consumes it.
    pub fn set_input_as_sender<R>(
        &mut self,
        secret: BigUint,
        rng: &mut R,
    ) -> Result<Vec<SecKeyDstAction>, SecKeyDstError>
    where
        R: num_bigint::RandBigInt,
    {
        if self.myid != self.sender {
            return Err(SecKeyDstError::NotSender {
                myid: self.myid,
                sender: self.sender,
            });
        }
        if &secret >= &self.prime {
            return Err(SecKeyDstError::SecretOutOfRange);
        }

        // Sample t random coefficients `a_1, ..., a_t` in [0, prime).
        let low = BigUint::from(0u32);
        let high = self.prime.clone();
        let mut coeffs: Vec<BigUint> = Vec::with_capacity(self.t + 1);
        coeffs.push(secret);
        for _ in 0..self.t {
            coeffs.push(rng.gen_biguint_range(&low, &high));
        }

        // Evaluate p at x = j+1 for j ∈ [0, n).
        let mut shares: Vec<BigUint> = Vec::with_capacity(self.n);
        for j in 0..self.n {
            let x = BigUint::from((j + 1) as u64);
            shares.push(eval_poly(&coeffs, &x, &self.prime));
        }

        // Serialize each share into the canonical fixed-length
        // bytes. Every byte string is exactly the same length, so
        // Reed-Solomon fragmentation inside RelMsgDst yields
        // uniform-shape Merkle leaves.
        let messages: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| serialize_share(&self.prime, s).expect("share < prime by construction"))
            .collect();

        let actions = self
            .rmd
            .set_input_as_sender(messages)
            .map_err(SecKeyDstError::Underlying)?;
        Ok(self.lift_actions(actions))
    }

    pub fn handle_dispersal(
        &mut self,
        wire_sender: Replica,
        entries: Vec<DispersalEntry>,
    ) -> Vec<SecKeyDstAction> {
        let actions = self.rmd.handle_dispersal(wire_sender, entries);
        self.lift_actions(actions)
    }

    pub fn handle_echo(
        &mut self,
        wire_sender: Replica,
        echo: EchoPayload,
    ) -> Vec<SecKeyDstAction> {
        let actions = self.rmd.handle_echo(wire_sender, echo);
        self.lift_actions(actions)
    }

    pub fn handle_vote(&mut self, wire_sender: Replica, meta_root: Hash) -> Vec<SecKeyDstAction> {
        let actions = self.rmd.handle_vote(wire_sender, meta_root);
        self.lift_actions(actions)
    }

    pub fn handle_forward(
        &mut self,
        wire_sender: Replica,
        forward: ForwardPayload,
    ) -> Vec<SecKeyDstAction> {
        let actions = self.rmd.handle_forward(wire_sender, forward);
        self.lift_actions(actions)
    }

    pub fn prepare_forward_for(
        &self,
        recipient: Replica,
    ) -> Result<SecKeyDstAction, SecKeyDstError> {
        if recipient == self.myid {
            return Err(SecKeyDstError::SelfForwardRequest);
        }
        if self.delivered_share.is_none() {
            return Err(SecKeyDstError::NotYetDelivered);
        }
        let action = self
            .rmd
            .prepare_forward_for(recipient)
            .map_err(SecKeyDstError::Underlying)?;
        // RelMsgDst's prepare_forward_for always emits SendForward;
        // lift it.
        match action {
            RelMsgDstAction::SendForward { recipient, forward } => {
                Ok(SecKeyDstAction::SendForward { recipient, forward })
            }
            other => unreachable!(
                "RelMsgDstState::prepare_forward_for must return SendForward, got {:?}",
                other
            ),
        }
    }

    /// Translate the underlying `RelMsgDstAction`s to
    /// `SecKeyDstAction`s, decoding `Delivered` / `ForwardDelivered`
    /// payloads as Shamir shares. Caches our own share.
    fn lift_actions(&mut self, actions: Vec<RelMsgDstAction>) -> Vec<SecKeyDstAction> {
        let mut out = Vec::with_capacity(actions.len());
        for a in actions {
            match a {
                RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                    out.push(SecKeyDstAction::SendDispersal { recipient_idx, entries });
                }
                RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                    out.push(SecKeyDstAction::SendEcho { recipient_idx, echo });
                }
                RelMsgDstAction::SendVote { meta_root } => {
                    out.push(SecKeyDstAction::SendVote { meta_root });
                }
                RelMsgDstAction::SendForward { recipient, forward } => {
                    out.push(SecKeyDstAction::SendForward { recipient, forward });
                }
                RelMsgDstAction::Delivered { message } => {
                    match parse_share(&self.prime, &message) {
                        Some(share) => {
                            self.delivered_share = Some(share.clone());
                            out.push(SecKeyDstAction::DeliveredShare { share });
                        }
                        None => {
                            log::warn!(
                                "[ShoupSmart][SecKeyDst] node {} delivered malformed share \
                                 (len={}, expected {})",
                                self.myid,
                                message.len(),
                                share_byte_len(&self.prime),
                            );
                            out.push(SecKeyDstAction::DeliveryFailedMalformedShare);
                        }
                    }
                }
                RelMsgDstAction::ForwardDelivered { source, message } => {
                    match parse_share(&self.prime, &message) {
                        Some(share) => {
                            out.push(SecKeyDstAction::ForwardDeliveredShare { source, share });
                        }
                        None => {
                            // Treat malformed forwarded share like a forward rejection.
                            out.push(SecKeyDstAction::ForwardRejected {
                                source,
                                reason: ForwardReject::DecodeFailed(
                                    "share bytes failed parse_share".into(),
                                ),
                            });
                        }
                    }
                }
                RelMsgDstAction::ForwardRejected { source, reason } => {
                    out.push(SecKeyDstAction::ForwardRejected { source, reason });
                }
            }
        }
        out
    }
}

/// Horner-style evaluation of `poly` (low-to-high coefficients) at
/// `x` over `F_p`.
fn eval_poly(coeffs: &[BigUint], x: &BigUint, p: &BigUint) -> BigUint {
    let mut acc = BigUint::zero();
    for c in coeffs.iter().rev() {
        acc = (&acc * x + c) % p;
    }
    acc
}

// ---------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn hash_state() -> Arc<HashState> {
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        Arc::new(HashState::new(key0, key1, key2))
    }

    /// A tiny prime suitable for unit testing (16-bit, definitely
    /// big enough to fit secrets in [0, p) without overflow worries).
    /// The real PPT pipeline uses much larger primes; the field
    /// arithmetic is identical.
    fn small_prime() -> BigUint {
        // 2^61 - 1 — a Mersenne prime that fits in 8 bytes.
        BigUint::from((1u64 << 61) - 1)
    }

    fn large_prime() -> BigUint {
        // BLS12-381 scalar field prime: 255-bit, used by the rest
        // of the PPT codebase for the "large field".
        BigUint::parse_bytes(
            b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap()
    }

    fn make_state(
        myid: Replica,
        n: usize,
        t: usize,
        sender: Replica,
        prime: BigUint,
    ) -> SecKeyDstState {
        SecKeyDstState::new(myid, n, t, sender, prime, hash_state()).expect("valid config")
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xC0FFEE)
    }

    /// Drive a full Π_SecKeyDst across `n` honest replicas with
    /// synchronous reliable delivery. Returns each replica's
    /// delivered share (or `None`).
    fn drive_seckeydst(
        sender: Replica,
        secret: BigUint,
        n: usize,
        prime: BigUint,
    ) -> Vec<Option<BigUint>> {
        let t = (n - 1) / 3;
        let mut nodes: Vec<SecKeyDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, sender, prime.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecKeyDstAction)> = Vec::new();
        let mut rng = rng();
        let acts = nodes[sender as usize]
            .set_input_as_sender(secret, &mut rng)
            .expect("ok");
        for a in acts {
            pending.push((sender, a));
        }

        for _ in 0..2000 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, SecKeyDstAction)> = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecKeyDstAction::SendDispersal { recipient_idx, entries } => {
                        if recipient_idx < n {
                            for a in nodes[recipient_idx].handle_dispersal(sender_id, entries) {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    SecKeyDstAction::SendEcho { recipient_idx, echo } => {
                        if recipient_idx < n {
                            for a in nodes[recipient_idx].handle_echo(sender_id, echo) {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    SecKeyDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for a in node.handle_vote(sender_id, meta_root) {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        nodes
            .into_iter()
            .map(|n| n.delivered_share().cloned())
            .collect()
    }

    // ---- Basic reconstruction round-trip ----

    #[test]
    fn roundtrip_n4_t1_small_prime() {
        let p = small_prime();
        let secret = BigUint::from(0xDEADBEEFu64);
        let shares = drive_seckeydst(0, secret.clone(), 4, p.clone());
        // All 4 honest deliver.
        for s in &shares {
            assert!(s.is_some(), "every honest party must deliver its share");
        }
        // Reconstruct from any t+1=2 shares.
        let pairs: Vec<(usize, BigUint)> = shares
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (i, v.clone())))
            .take(2)
            .collect();
        let recovered = reconstruct(&p, 4, 1, &pairs).expect("reconstruct ok");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn roundtrip_n7_t2() {
        let p = small_prime();
        let secret = BigUint::from(0x123456789Au64);
        let shares = drive_seckeydst(2, secret.clone(), 7, p.clone());
        for s in &shares {
            assert!(s.is_some());
        }
        // Reconstruct from any 3 (t+1=3) shares — try several
        // disjoint triples.
        let collected: Vec<(usize, BigUint)> = shares
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (i, v.clone())))
            .collect();
        let triple1: Vec<_> = collected.iter().take(3).cloned().collect();
        let triple2: Vec<_> = collected.iter().rev().take(3).cloned().collect();
        let r1 = reconstruct(&p, 7, 2, &triple1).expect("triple1 ok");
        let r2 = reconstruct(&p, 7, 2, &triple2).expect("triple2 ok");
        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
    }

    #[test]
    fn roundtrip_n16_t5_large_prime() {
        // Realistic PPT-AVSS-sized parameters with the 255-bit
        // scalar prime PPT actually uses.
        let p = large_prime();
        let secret = BigUint::parse_bytes(b"112233445566778899AABBCCDDEEFF11", 16).unwrap();
        let shares = drive_seckeydst(0, secret.clone(), 16, p.clone());
        for s in &shares {
            assert!(s.is_some());
        }
        let pairs: Vec<(usize, BigUint)> = shares
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (i, v.clone())))
            .take(6) // t+1 = 6
            .collect();
        let recovered = reconstruct(&p, 16, 5, &pairs).expect("ok");
        assert_eq!(recovered, secret);
    }

    // ---- Error / edge cases on set_input_as_sender ----

    #[test]
    fn set_input_by_non_sender_errors() {
        let p = small_prime();
        let mut node = make_state(1, 4, 1, 0, p.clone()); // sender = 0, myid = 1
        let res = node.set_input_as_sender(BigUint::from(7u32), &mut rng());
        assert!(matches!(res, Err(SecKeyDstError::NotSender { .. })));
    }

    #[test]
    fn set_input_secret_out_of_range_errors() {
        let p = BigUint::from(7u32);
        let mut node = make_state(0, 4, 1, 0, p.clone());
        // secret == prime → out of range.
        let res = node.set_input_as_sender(p.clone(), &mut rng());
        assert!(matches!(res, Err(SecKeyDstError::SecretOutOfRange)));
        // secret > prime → out of range.
        let res2 = node.set_input_as_sender(BigUint::from(99u32), &mut rng());
        assert!(matches!(res2, Err(SecKeyDstError::SecretOutOfRange)));
    }

    #[test]
    fn degenerate_prime_is_rejected_at_construction() {
        let res = SecKeyDstState::new(
            0,
            4,
            1,
            0,
            BigUint::from(1u32), // prime < 2 → reject
            hash_state(),
        );
        assert!(matches!(res, Err(SecKeyDstError::DegeneratePrime)));
    }

    // ---- Hiding: any t-subset of shares carries no info about k ----

    #[test]
    fn t_shares_alone_cannot_reconstruct() {
        // Information-theoretically, any t shares are uniformly
        // distributed regardless of `k`. We assert reconstruct with
        // only `t` shares (instead of `t+1`) returns None.
        let p = small_prime();
        let secret = BigUint::from(42u64);
        let shares = drive_seckeydst(0, secret, 7, p.clone());
        let collected: Vec<(usize, BigUint)> = shares
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (i, v.clone())))
            .collect();
        // n=7, t=2 → need 3, give only 2.
        let too_few: Vec<_> = collected.iter().take(2).cloned().collect();
        let r = reconstruct(&p, 7, 2, &too_few);
        assert!(r.is_none(), "reconstruct must refuse fewer than t+1 shares");
    }

    // ---- Reconstruct edge cases ----

    #[test]
    fn reconstruct_rejects_idx_out_of_range() {
        let p = small_prime();
        // Out-of-range idx among the first `needed = t+1 = 2`
        // entries triggers the bounds check before we satisfy the
        // threshold. (Late out-of-range entries are silently
        // ignored once the threshold is reached — that's fine
        // semantically and consistent with first-seen-wins on
        // dedup; this test exercises the eager-rejection path.)
        let pairs = vec![
            (0usize, BigUint::from(1u32)),
            (99usize, BigUint::from(3u32)), // out of range for n=4
        ];
        let r = reconstruct(&p, 4, 1, &pairs);
        assert!(r.is_none());
    }

    #[test]
    fn reconstruct_dedups_repeated_indices() {
        let p = small_prime();
        let secret = BigUint::from(13u64);
        // Manual share set known to lie on a degree-1 polynomial:
        //   p(0) = 13, p(1) = 20, p(2) = 27, p(3) = 34, p(4) = 41
        // (slope 7).
        let shares = vec![
            (0usize, BigUint::from(20u64)),
            (0usize, BigUint::from(20u64)), // dup, dropped
            (1usize, BigUint::from(27u64)),
        ];
        let r = reconstruct(&p, 4, 1, &shares).expect("dedup ok");
        assert_eq!(r, secret);
    }

    // ---- Serialize / parse round-trip ----

    #[test]
    fn serialize_parse_roundtrip_small_prime() {
        let p = small_prime();
        for &v in &[0u64, 1, 7, 0xDEADBEEF, 0xFFFF_FFFF, (1u64 << 60) - 1] {
            let s = BigUint::from(v);
            let bytes = serialize_share(&p, &s).expect("ok");
            assert_eq!(bytes.len(), share_byte_len(&p));
            let parsed = parse_share(&p, &bytes).expect("parse ok");
            assert_eq!(parsed, s);
        }
    }

    #[test]
    fn serialize_rejects_share_at_or_above_prime() {
        let p = BigUint::from(7u32);
        // share == prime → reject.
        assert!(serialize_share(&p, &p).is_none());
        // share > prime → reject.
        assert!(serialize_share(&p, &BigUint::from(8u32)).is_none());
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let p = small_prime(); // 8-byte canonical
        // Length too short.
        assert!(parse_share(&p, &[0u8; 7]).is_none());
        // Length too long.
        assert!(parse_share(&p, &[0u8; 9]).is_none());
    }

    #[test]
    fn parse_rejects_value_geq_prime() {
        // Use a small but non-power-of-256 prime so we can craft
        // a byte string >= prime within the same byte length.
        let p = BigUint::from(257u32); // 9-bit prime → 2 bytes canonical
        let bad_bytes = [1u8, 2u8]; // 0x0102 = 258 > 257
        assert!(parse_share(&p, &bad_bytes).is_none());
        // valid share at 256 should decode (256 < 257).
        let good_bytes = [1u8, 0u8]; // 0x0100 = 256
        assert_eq!(parse_share(&p, &good_bytes), Some(BigUint::from(256u32)));
    }

    // ---- Distribution-phase Byzantine inputs ----

    #[test]
    fn handle_dispersal_dropped_from_non_sender() {
        let p = small_prime();
        let mut node = make_state(1, 4, 1, 0, p.clone());
        // Build a real dispersal addressed at recipient 1 from an
        // honest sender's perspective.
        let mut sender_state = make_state(0, 4, 1, 0, p.clone());
        let acts = sender_state
            .set_input_as_sender(BigUint::from(11u32), &mut rng())
            .unwrap();
        let entries = acts
            .into_iter()
            .find_map(|a| match a {
                SecKeyDstAction::SendDispersal { recipient_idx: 1, entries } => Some(entries),
                _ => None,
            })
            .expect("expected SendDispersal[1]");
        // wire_sender = 2 ≠ 0 → dropped by RelMsgDst.
        let result = node.handle_dispersal(2, entries);
        assert!(result.is_empty());
        assert!(!node.delivered());
    }

    // ---- Forwarding ----

    #[test]
    fn forwarding_delivers_share_to_third_party() {
        let p = small_prime();
        let secret = BigUint::from(0xCAFE_F00Du64);
        let n = 4;
        let t = 1;
        let mut nodes: Vec<SecKeyDstState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, 0, p.clone()))
            .collect();
        let mut pending: Vec<(Replica, SecKeyDstAction)> = Vec::new();
        let acts = nodes[0]
            .set_input_as_sender(secret.clone(), &mut rng())
            .unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..400 {
            if nodes.iter().all(|n| n.delivered()) { break; }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    SecKeyDstAction::SendDispersal { recipient_idx, entries } => {
                        for a in nodes[recipient_idx].handle_dispersal(sender_id, entries) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecKeyDstAction::SendEcho { recipient_idx, echo } => {
                        for a in nodes[recipient_idx].handle_echo(sender_id, echo) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    SecKeyDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for a in node.handle_vote(sender_id, meta_root) {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        // Distribution complete; node 1 forwards its share to a
        // fresh "node 99" (which doesn't have its own share).
        let fwd_action = nodes[1].prepare_forward_for(99).expect("ok");
        let fwd = match fwd_action {
            SecKeyDstAction::SendForward { forward, .. } => forward,
            _ => panic!("expected SendForward"),
        };
        let mut q = make_state(99, n, t, 0, p.clone());
        let result = q.handle_forward(1, fwd);
        // Find the ForwardDeliveredShare action.
        let delivered_share = result.iter().find_map(|a| match a {
            SecKeyDstAction::ForwardDeliveredShare { source, share } => Some((*source, share.clone())),
            _ => None,
        }).expect("forward should deliver share");
        assert_eq!(delivered_share.0, 1, "source should be node 1");
        // Q now has one foreign share (k_1). The actual share
        // value is whatever the dealer produced for x = 2.
        // Sanity: it must lie in [0, p).
        assert!(delivered_share.1 < p);
    }

    // ---- Determinism: same secret + rng = same shares ----

    #[test]
    fn deterministic_under_seeded_rng() {
        let p = small_prime();
        let secret = BigUint::from(0x1234u32);
        let shares1 = drive_seckeydst(0, secret.clone(), 4, p.clone());
        let shares2 = drive_seckeydst(0, secret.clone(), 4, p.clone());
        assert_eq!(shares1, shares2, "same seeded rng should produce same shares");
    }
}
