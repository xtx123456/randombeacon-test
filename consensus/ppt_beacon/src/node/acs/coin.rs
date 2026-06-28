//! Self-bootstrapping common coin for the PPT random beacon's ACS
//! pipeline.
//!
//! Each ACS round finishes by producing the next round's "previous
//! beacon" seed: the first reconstructed coin of the round (coin_num
//! == 0). The MMR ABA inside that ACS round needs a 1-bit common
//! coin per ABA round per ABA instance; we derive that bit by
//! hashing the previous beacon's bytes together with the ABA
//! instance ID and the ABA round counter.
//!
//! For round 0 there is no previous beacon, so we substitute a
//! fixed public genesis seed (`PPT_GENESIS_COIN_SEED`). This is
//! safe because the ABA termination property only requires the coin
//! to be unpredictable to the adversary BEFORE round 0's BVALs are
//! sent — and round 0 is the bootstrapping case where every honest
//! node enters with the same input bit unconditionally (see PPT
//! slide pg 17 "random beacon is a long running system": only the
//! genesis instance is bootstrapped, every later instance has a
//! prior beacon to seed off of).
//!
//! PQ-safety: this module uses only `crypto::hash::do_hash` (a
//! 256-bit hash family). No DL, no pairing, no RSA, no threshold
//! primitive, no external VRF — exactly what the PPT scheme allows.

use std::collections::{HashMap, HashSet};

use async_recursion::async_recursion;
use num_bigint::BigUint;

use crypto::aes_hash::Proof;
use crypto::hash::Hash;
use types::beacon::{BatchWSSReconMsg, CoinMsg, Val};
use types::{Replica, Round};

use crate::node::context::PPT_COIN_RESERVE;
use crate::node::shamir::two_field::BatchExtractor;
use crate::node::shoup_smart::proof_leaf_index;
use crate::node::Context;

/// Everything round `(R+1)`'s ACS needs to reconstruct the
/// unpredictable common coin from round `R`'s sealed coin-secrets:
///
///   - `decided`: round R's ACS-decided dealer set (agreed + stable),
///     the canonical set whose sealed coin-secrets are summed;
///   - `roots[d]`: dealer d's committed Merkle roots for the
///     `PPT_COIN_RESERVE` sealed coin indices (to validate revealed
///     shares);
///   - `my_shares[d]`: THIS node's own `(f_share, g_share, f_large,
///     nonce, proof)` for each of dealer d's sealed coin indices —
///     all four committed values are needed to recompute the
///     `avss_commit_leaf` when revealing, plus the Merkle proof.
#[derive(Clone, Debug)]
pub struct CoinMaterial {
    pub decided: Vec<Replica>,
    pub roots: HashMap<Replica, Vec<Hash>>,
    pub my_shares: HashMap<Replica, Vec<(Val, Val, Val, Val, Proof)>>,
}

const COIN_SECRET_DOMAIN: &[u8] = b"PPT_ACS_COIN_SECRET_v1::";

/// Derive ABA instance `j`'s coin bit from the reconstructed common
/// coin secret `C` for an ABA round. All honest nodes hold the same
/// `C` (it is the sum of fixed shared secrets), so the per-instance
/// bits are common; and `C` is unpredictable until f+1 honest reveals
/// land, so the bits are unpredictable.
pub fn coin_bit_from_secret(secret: &BigUint, instance: usize) -> bool {
    let mut buf = Vec::with_capacity(COIN_SECRET_DOMAIN.len() + 40);
    buf.extend_from_slice(COIN_SECRET_DOMAIN);
    let sbytes = secret.to_bytes_be();
    buf.extend_from_slice(&(sbytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(&sbytes);
    buf.extend_from_slice(&(instance as u64).to_be_bytes());
    let hash = crypto::hash::do_hash(buf.as_slice());
    (hash[hash.len() - 1] & 1u8) == 1
}

/// Public, deterministic seed used to derive the round-0 ABA common
/// coins. Every node uses this, so all ABA instances in round 0 see
/// the same coin bit. The byte string is intentionally distinct
/// from `PPT_GENESIS_THETA_SEED` so the two derivations never
/// produce correlated outputs.
pub const PPT_GENESIS_COIN_SEED: &[u8] = b"PPT_BEACON_GENESIS_COIN_v1";

/// Domain-separation prefix so the ACS coin derivation never
/// collides with other hash-based derivations elsewhere in the
/// protocol.
const COIN_DOMAIN: &[u8] = b"PPT_ACS_COIN_v1::";

impl Context {
    /// Return the bytes used to seed every ABA coin derivation in
    /// the ACS instance for `acs_round`.
    ///
    /// - For `acs_round == 0` we return `PPT_GENESIS_COIN_SEED`.
    /// - For `acs_round > 0` we look up the previous round's beacon
    ///   bytes that were recorded in `coin_per_round` at the moment
    ///   `record_beacon_output_for_coin(acs_round - 1, ...)` was
    ///   called from `self_coin_check_transmit` (coin_num == 0
    ///   path).
    ///
    /// Returns `None` for `acs_round > 0` when the previous round's
    /// beacon has not yet been recorded locally (transient async
    /// race, just like `theta_for_round`). The caller MUST handle
    /// `None` by deferring — never by dropping or silently picking
    /// a default value, since that would let a slow node disagree
    /// with everyone else on the coin bit.
    pub fn coin_seed_for_acs_round(&self, acs_round: Round) -> Option<Vec<u8>> {
        if acs_round == 0 {
            return Some(PPT_GENESIS_COIN_SEED.to_vec());
        }
        self.coin_per_round.get(&acs_round).cloned()
    }

    /// Derive the 1-bit common coin for `(acs_round, aba_instance_id,
    /// aba_round)`. All honest nodes derive the same bit because the
    /// inputs are deterministic protocol-level integers and the seed
    /// is either the public genesis seed or the previous round's
    /// reconstructed beacon (which is identical at every honest
    /// node by ACS / batch-recover safety).
    ///
    /// Returns `None` only when the previous-round beacon hasn't
    /// been recorded yet (caller defers — see
    /// `coin_seed_for_acs_round`).
    pub fn coin_bit_for(
        &self,
        acs_round: Round,
        aba_instance_id: usize,
        aba_round: u64,
    ) -> Option<bool> {
        let seed = self.coin_seed_for_acs_round(acs_round)?;
        Some(coin_bit_from_seed(&seed, aba_instance_id, aba_round))
    }

    /// Record the round-`acs_round` first-coin beacon output as the
    /// source of round-(acs_round + 1)'s ACS common-coin derivation.
    /// Called from `self_coin_check_transmit` in the `coin_num == 0`
    /// branch, immediately after `record_beacon_output_for_theta`.
    ///
    /// We store the raw bytes (not a hash) so the derivation in
    /// `coin_bit_for` can include domain-separated context (instance
    /// id, aba_round) and produce uncorrelated bits across instances.
    pub fn record_beacon_output_for_coin(&mut self, acs_round: Round, output_bytes: &[u8]) {
        self.coin_per_round.insert(acs_round + 1, output_bytes.to_vec());
    }
}

impl Context {
    /// Stash round `round`'s sealed coin material for use by round
    /// `round + 1`'s ACS common coin. Called from
    /// `finalize_acs_round(round)` once the decided set is fixed and
    /// the dealers' AVSS packets (commitments + this node's shares)
    /// are locally available.
    pub(crate) fn stash_coin_material(&mut self, round: Round, decided: &[Replica]) {
        let batch_size = self.batch_size;
        let total = batch_size + PPT_COIN_RESERVE;
        let mut roots: HashMap<Replica, Vec<Hash>> = HashMap::new();
        let mut my_shares: HashMap<Replica, Vec<(Val, Val, Val, Val, Proof)>> = HashMap::new();

        if let Some(state) = self.round_state.get(&round) {
            for &d in decided.iter() {
                if let Some(rv) = state.comm_vectors.get(&d) {
                    if rv.len() >= total {
                        roots.insert(d, rv[batch_size..total].to_vec());
                    }
                }
                // This node's own (f_share, g_share, f_large, nonce,
                // proof) for each sealed coin index — all four
                // committed values are needed to recompute the
                // combined `avss_commit_leaf` when revealing.
                let wss = state.node_secrets.get(&d);
                let masks = state.mask_shares.get(&d);
                let f_larges = state.f_large_shares.get(&d);
                if let (Some(wss), Some(masks), Some(f_larges)) = (wss, masks, f_larges) {
                    if wss.secrets.len() >= total
                        && wss.nonces.len() >= total
                        && wss.mps.len() >= total
                        && masks.len() >= total
                        && f_larges.len() >= total
                    {
                        let mut v = Vec::with_capacity(PPT_COIN_RESERVE);
                        for rr in 0..PPT_COIN_RESERVE {
                            let idx = batch_size + rr;
                            v.push((
                                wss.secrets[idx],
                                masks[idx],
                                f_larges[idx],
                                wss.nonces[idx],
                                wss.mps[idx].clone(),
                            ));
                        }
                        my_shares.insert(d, v);
                    }
                }
            }
        }

        log::debug!(
            "[PPT][COIN] node {} stashed coin material for round {} ({} dealers with roots, {} with my-shares)",
            self.myid,
            round,
            roots.len(),
            my_shares.len()
        );

        self.coin_material.insert(
            round,
            CoinMaterial {
                decided: decided.to_vec(),
                roots,
                my_shares,
            },
        );

        // Replay any coin reveals that arrived for acs_round = round+1
        // before this material was available.
        let acs_round = round + 1;
        let pending_keys: Vec<(Round, u64)> = self
            .coin_reveal_pending
            .keys()
            .copied()
            .filter(|(ar, _)| *ar == acs_round)
            .collect();
        for key in pending_keys {
            if let Some(list) = self.coin_reveal_pending.remove(&key) {
                for (packet, provider) in list.into_iter() {
                    let _ = self.ingest_coin_reveal_shares(key.0, key.1, &packet, provider);
                }
            }
        }
    }

    /// Drop coin state once round `acs_round`'s ACS has finalised:
    /// the per-round share/reconstruction caches for `acs_round` and
    /// the material `acs_round - 1` it consumed are no longer needed.
    pub(crate) fn cleanup_coin_state(&mut self, acs_round: Round) {
        self.coin_shares.retain(|(r, _), _| *r != acs_round);
        self.coin_reconstructed.retain(|(r, _), _| *r != acs_round);
        self.coin_reveal_sent.retain(|(r, _)| *r != acs_round);
        self.coin_reveal_pending.retain(|(r, _), _| *r != acs_round);
        if acs_round > 0 {
            self.coin_material.remove(&(acs_round - 1));
        }
    }

    /// Build this node's coin-share reveal packet for `aba_round`
    /// from the sealed coin material of `prev_round` (= acs_round-1).
    fn build_coin_reveal_packet(
        &self,
        prev_round: Round,
        aba_round: u64,
    ) -> Option<BatchWSSReconMsg> {
        let material = self.coin_material.get(&prev_round)?;
        let rr = aba_round as usize;
        let in_gf2_mode = self.gf2_profile.is_some();
        let mut origins = Vec::new();
        let mut secrets = Vec::new();
        let mut nonces = Vec::new();
        let mut mps = Vec::new();
        let mut mask_shares = Vec::new();
        let mut f_large_shares_vec: Vec<types::beacon::Val> = Vec::new();
        for &d in material.decided.iter() {
            if let Some(v) = material.my_shares.get(&d) {
                if let Some((share, g_share, f_large, nonce, proof)) = v.get(rr) {
                    origins.push(d);
                    secrets.push(*share);
                    mask_shares.push(*g_share);
                    if !in_gf2_mode {
                        f_large_shares_vec.push(*f_large);
                    }
                    nonces.push(*nonce);
                    mps.push(proof.clone());
                }
            }
        }
        if origins.is_empty() {
            return None;
        }
        Some(BatchWSSReconMsg {
            origin: self.myid,
            secrets,
            nonces,
            origins,
            mps,
            mask_shares,
            // GF(2^w) wire-format compaction (commit 7): drop the
            // redundant f_large channel; the receiver derives
            // f_large := share locally via subfield identity.
            f_large_shares: if in_gf2_mode {
                None
            } else {
                Some(f_large_shares_vec)
            },
            empty: false,
        })
    }

    /// Validate and store the coin-shares carried in `packet` from
    /// `provider`, then attempt to reconstruct the common coin secret
    /// `C = Σ_d c_{d,aba_round}`. Returns `true` iff `C` was newly
    /// reconstructed by this call.
    pub(crate) fn ingest_coin_reveal_shares(
        &mut self,
        acs_round: Round,
        aba_round: u64,
        packet: &BatchWSSReconMsg,
        provider: Replica,
    ) -> bool {
        if acs_round == 0 {
            return false;
        }
        let prev = acs_round - 1;

        // Snapshot the per-dealer committed root for this aba_round
        // from the (immutably borrowed) coin material, then drop the
        // borrow before mutating `coin_shares`.
        let (decided, roots): (Vec<Replica>, HashMap<Replica, Hash>) = {
            let material = match self.coin_material.get(&prev) {
                Some(m) => m,
                None => return false,
            };
            let rr = aba_round as usize;
            let roots = material
                .decided
                .iter()
                .filter_map(|d| {
                    material
                        .roots
                        .get(d)
                        .and_then(|v| v.get(rr))
                        .map(|h| (*d, *h))
                })
                .collect();
            (material.decided.clone(), roots)
        };
        let decided_set: HashSet<Replica> = decided.iter().copied().collect();

        let hc = self.hash_context.clone();
        let threshold = self.num_faults + 1;
        let secret_domain = self.secret_domain.clone();

        // Structurally validate all proofs in the packet in one batch
        // (the single-proof `Proof::validate` is inconsistent with this
        // codebase's `MerkleTree::build_trees`; `validate_batch` is the
        // trusted path, also used by the post-ACS audit / recon).
        let batch_ok = !packet.mps.is_empty()
            && Proof::validate_batch(&packet.mps, &hc);
        if batch_ok {
            let entry = self
                .coin_shares
                .entry((acs_round, aba_round))
                .or_default();
            for idx in 0..packet.origins.len() {
                let d = &packet.origins[idx];
                if !decided_set.contains(d) {
                    continue;
                }
                if idx >= packet.secrets.len()
                    || idx >= packet.nonces.len()
                    || idx >= packet.mps.len()
                    || idx >= packet.mask_shares.len()
                {
                    continue;
                }
                let f_large_ref = match packet.f_large_shares.as_ref() {
                    Some(fl) if idx < fl.len() => Some(&fl[idx]),
                    Some(_) => continue, // length mismatch is malformed
                    None => None,        // GF(2^w) mode — leaf is 3-field
                };
                let share = &packet.secrets[idx];
                let nonce = &packet.nonces[idx];
                let mp = &packet.mps[idx];
                let root = match roots.get(d) {
                    Some(r) => *r,
                    None => continue,
                };
                if proof_leaf_index(mp) != provider as usize {
                    continue;
                }
                if mp.root() != root {
                    continue;
                }
                // Combined leaf binds (f_share, g_share, [f_large,] nonce).
                // GF(2^w) mode (commit 7) uses the 3-field variant.
                let item = types::beacon::avss_commit_leaf_auto(
                    share,
                    &packet.mask_shares[idx],
                    f_large_ref,
                    nonce,
                );
                if item != mp.item() {
                    continue;
                }
                entry
                    .entry(*d)
                    .or_default()
                    .insert(provider, BigUint::from_bytes_be(share));
            }
        }

        if self.coin_reconstructed.contains_key(&(acs_round, aba_round)) {
            return false;
        }

        // Reconstruct each decided dealer's coin secret from f+1
        // validated providers; combine across dealers to obtain the
        // common coin C = Σ_d c_{d,aba_round}. Returns early if any
        // dealer is short of f+1 providers.
        //
        // Two field paths (commit 5 of the GF(2^w) migration):
        //   * BigUint (legacy default, gf2_profile == None) — per
        //     dealer: BatchExtractor + recover_one; accumulate
        //     `(sum + c_d) % secret_domain`.
        //   * GF(2^w) — per dealer: char-2 Lagrange via
        //     `gf2_two_field::lagrange_recover_at_zero`; accumulate
        //     by XOR (char-2 addition). The final XOR sum is wrapped
        //     into a BigUint via `from_bytes_be` so the storage type
        //     (`coin_reconstructed: HashMap<(.., ..), BigUint>`)
        //     stays unchanged. The integer value is arithmetically
        //     meaningless under GF(2^w); only its bytes (= the GF2
        //     element's canonical encoding) are. `coin_bit_from_secret`
        //     downstream consumes the bytes (`to_bytes_be` → hash →
        //     LSB) and is therefore field-agnostic at the byte
        //     level, so honest nodes derive identical coin bits.
        let gf2_profile = self.gf2_profile;
        let shares_map = match self.coin_shares.get(&(acs_round, aba_round)) {
            Some(m) => m,
            None => return false,
        };
        let sum: BigUint = match gf2_profile {
            None => {
                let mut sum = BigUint::from(0u32);
                for d in decided.iter() {
                    let pmap = match shares_map.get(d) {
                        Some(p) if p.len() >= threshold => p,
                        _ => return false,
                    };
                    let mut providers: Vec<usize> = pmap.keys().copied().collect();
                    providers.sort_unstable();
                    providers.truncate(threshold);
                    let eval_points: Vec<usize> = providers.iter().map(|p| p + 1).collect();
                    let shares: Vec<BigUint> =
                        providers.iter().map(|p| pmap.get(p).unwrap().clone()).collect();
                    let extractor = BatchExtractor::new(eval_points, secret_domain.clone());
                    let c_d = extractor.recover_one(&shares);
                    sum = (sum + c_d) % &secret_domain;
                }
                sum
            }
            Some(profile) => {
                use crate::node::shamir::gf2_two_field::lagrange_recover_at_zero;
                use crypto::gf2::Gf2Element;
                let mut acc = Gf2Element::zero(profile);
                for d in decided.iter() {
                    let pmap = match shares_map.get(d) {
                        Some(p) if p.len() >= threshold => p,
                        _ => return false,
                    };
                    let mut providers: Vec<usize> = pmap.keys().copied().collect();
                    providers.sort_unstable();
                    providers.truncate(threshold);
                    let mut points: Vec<(usize, Gf2Element)> = Vec::with_capacity(threshold);
                    let mut ok = true;
                    for p in providers.iter() {
                        let share_big = pmap.get(p).unwrap().clone();
                        let bytes = Context::pad_shares(share_big);
                        match Gf2Element::from_bytes(profile, bytes) {
                            Ok(elem) => points.push((p + 1, elem)),
                            Err(_) => {
                                log::error!(
                                    "[PPT][GF2-COIN] coin-share from dealer {} provider {} \
                                     has dirty bits beyond w_q in acs_round {} aba_round {}; \
                                     skipping reveal (this should never happen for a packet \
                                     that already passed `validate_batch` + commit-leaf binding)",
                                    d, p, acs_round, aba_round
                                );
                                ok = false;
                                break;
                            }
                        }
                    }
                    if !ok {
                        return false;
                    }
                    let c_d = lagrange_recover_at_zero(profile, &points);
                    // Char-2 sum: XOR each coordinate.
                    acc = acc.add(&c_d);
                }
                BigUint::from_bytes_be(acc.as_bytes())
            }
        };

        self.coin_reconstructed.insert((acs_round, aba_round), sum);
        log::debug!(
            "[PPT][COIN] node {} reconstructed ACS common coin for acs_round {} aba_round {} ({} decided dealers)",
            self.myid,
            acs_round,
            aba_round,
            decided.len()
        );
        true
    }

    /// Ensure this node has broadcast its coin-share reveal for
    /// `(acs_round, aba_round)` (releasing its share AFTER it has
    /// entered that ABA round, i.e. after its AUX is fixed), and
    /// return the reconstructed common coin secret if available.
    /// `None` ⇒ caller must defer feeding the coin.
    #[async_recursion]
    pub(crate) async fn ensure_coin_secret(
        &mut self,
        acs_round: Round,
        aba_round: u64,
    ) -> Option<BigUint> {
        if acs_round == 0 || (aba_round as usize) >= PPT_COIN_RESERVE {
            return None;
        }
        let prev = acs_round - 1;
        if !self.coin_material.contains_key(&prev) {
            return None;
        }

        if !self.coin_reveal_sent.contains(&(acs_round, aba_round)) {
            match self.build_coin_reveal_packet(prev, aba_round) {
                Some(packet) => {
                    self.coin_reveal_sent.insert((acs_round, aba_round));
                    log::debug!(
                        "[PPT][COIN] node {} broadcast coin reveal acs_round {} aba_round {} ({} dealer-shares)",
                        self.myid, acs_round, aba_round, packet.origins.len()
                    );
                    let msg = CoinMsg::ACSCoinReveal(acs_round, aba_round, packet.clone());
                    self.broadcast(msg, acs_round).await;
                    let myid = self.myid;
                    let _ = self.ingest_coin_reveal_shares(acs_round, aba_round, &packet, myid);
                }
                None => {
                    log::warn!(
                        "[PPT][COIN] node {} build_coin_reveal_packet returned None acs_round {} aba_round {} (prev material my_shares missing?)",
                        self.myid, acs_round, aba_round
                    );
                }
            }
        }

        self.coin_reconstructed.get(&(acs_round, aba_round)).cloned()
    }

    /// Common-coin bit for ACS `acs_round`, ABA instance `j`, ABA
    /// round `aba_round`. For `acs_round >= 1` within the reserve
    /// window this is the unpredictable AVSS-sealed coin; otherwise
    /// (genesis round 0, or beyond the reserve window) it falls back
    /// to the deterministic hash coin. Returns `None` only when the
    /// sealed coin is not yet reconstructed (caller defers).
    #[async_recursion]
    pub(crate) async fn acs_coin_bit(
        &mut self,
        acs_round: Round,
        j: usize,
        aba_round: u64,
    ) -> Option<bool> {
        let use_sealed = acs_round >= 1
            && (aba_round as usize) < PPT_COIN_RESERVE
            && self.coin_material.contains_key(&(acs_round - 1));
        if !use_sealed {
            // Genesis / out-of-window fallback: deterministic hash coin.
            return self.coin_bit_for(acs_round, j, aba_round);
        }
        match self.ensure_coin_secret(acs_round, aba_round).await {
            Some(c) => Some(coin_bit_from_secret(&c, j)),
            None => None,
        }
    }

    /// Inbound `ACSCoinReveal(acs_round, aba_round, packet)` from
    /// `provider`. Validates + stores the shares; if the coin becomes
    /// reconstructable, re-runs the ACS scan so the now-available coin
    /// is fed into the waiting ABA instances.
    #[async_recursion]
    pub(crate) async fn process_acs_coin_reveal(
        &mut self,
        acs_round: Round,
        aba_round: u64,
        packet: BatchWSSReconMsg,
        provider: Replica,
    ) {
        if acs_round == 0 {
            return;
        }
        let prev = acs_round - 1;
        if !self.coin_material.contains_key(&prev) {
            // Material not stashed yet (this node hasn't finalised the
            // previous round locally). Buffer for replay.
            log::debug!(
                "[PPT][COIN] node {} buffering coin reveal from {} acs_round {} aba_round {} (material[{}] missing)",
                self.myid, provider, acs_round, aba_round, prev
            );
            self.coin_reveal_pending
                .entry((acs_round, aba_round))
                .or_default()
                .push((packet, provider));
            return;
        }
        let newly = self.ingest_coin_reveal_shares(acs_round, aba_round, &packet, provider);
        if newly {
            self.acs_on_coin_ready(acs_round).await;
        }
    }
}

/// Pure function (no `&self`) for unit testing the coin derivation.
/// Hash inputs are length-prefixed so an adversary cannot collide
/// (`(round=10, aba=5, r=0)` vs `(round=1, aba=0, r=50)`) by
/// shifting bytes around.
pub fn coin_bit_from_seed(seed: &[u8], aba_instance_id: usize, aba_round: u64) -> bool {
    let mut buf = Vec::with_capacity(COIN_DOMAIN.len() + seed.len() + 8 + 8 + 8);
    buf.extend_from_slice(COIN_DOMAIN);
    let seed_len = seed.len() as u64;
    buf.extend_from_slice(&seed_len.to_be_bytes());
    buf.extend_from_slice(seed);
    buf.extend_from_slice(&(aba_instance_id as u64).to_be_bytes());
    buf.extend_from_slice(&aba_round.to_be_bytes());
    let hash = crypto::hash::do_hash(buf.as_slice());
    // Take the lowest bit of the last byte. Equivalent to "first
    // bit of any uniform byte from a CRH" which is uniform under
    // the random oracle assumption.
    let last = hash[hash.len() - 1];
    (last & 1u8) == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_coin_is_deterministic_per_instance_and_round() {
        // Two callers using the same genesis seed must derive the
        // exact same bit for the same (instance, round).
        let bit_a = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 0, 0);
        let bit_b = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 0, 0);
        assert_eq!(bit_a, bit_b);

        let bit_a = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 7, 13);
        let bit_b = coin_bit_from_seed(PPT_GENESIS_COIN_SEED, 7, 13);
        assert_eq!(bit_a, bit_b);
    }

    #[test]
    fn coin_bits_are_independent_across_instance_and_round() {
        // Different (instance_id, round) pairs MUST hash to
        // statistically uncorrelated bits. We sample a small bag
        // and require some variation in the first few outputs —
        // not a perfect uniformity test, but good enough to catch
        // a "constant 0" / "constant 1" / "round-only" regression.
        let seed = b"some-random-beacon-bytes";
        let mut zeros = 0usize;
        let mut ones = 0usize;
        let mut last: Option<bool> = None;
        let mut differences = 0usize;
        for inst in 0..16 {
            for r in 0..16u64 {
                let bit = coin_bit_from_seed(seed, inst, r);
                if bit { ones += 1; } else { zeros += 1; }
                if let Some(p) = last {
                    if p != bit { differences += 1; }
                }
                last = Some(bit);
            }
        }
        assert!(zeros > 0 && ones > 0, "coin not flipping across (inst, r): zeros={} ones={}", zeros, ones);
        assert!(differences > 16, "coin too sticky across (inst, r): {} flips out of 256", differences);
    }

    #[test]
    fn coin_bit_from_secret_is_deterministic_and_varies() {
        use num_bigint::BigUint;
        let c1 = BigUint::from(123456789u64);
        let c2 = BigUint::from(987654321u64);
        // Deterministic per (secret, instance).
        assert_eq!(coin_bit_from_secret(&c1, 0), coin_bit_from_secret(&c1, 0));
        assert_eq!(coin_bit_from_secret(&c1, 5), coin_bit_from_secret(&c1, 5));
        // Varies across instances and across secrets (statistically).
        let mut zeros = 0usize;
        let mut ones = 0usize;
        for j in 0..32 {
            if coin_bit_from_secret(&c1, j) { ones += 1; } else { zeros += 1; }
        }
        assert!(zeros > 0 && ones > 0, "coin too sticky across instances: z={} o={}", zeros, ones);
        let mut diff = 0usize;
        for j in 0..32 {
            if coin_bit_from_secret(&c1, j) != coin_bit_from_secret(&c2, j) { diff += 1; }
        }
        assert!(diff > 0, "two distinct coin secrets produced identical bit streams");
    }

    #[test]
    fn coin_changes_when_seed_changes() {
        // Two distinct seeds with the same (instance, round) must
        // produce statistically distinct outputs (probability of
        // accidental match for a single sample is 1/2 — but across
        // a small batch the chance of 100% match is 2^{-batch}).
        let seed_a = b"BEACON_OUTPUT_ROUND_3";
        let seed_b = b"BEACON_OUTPUT_ROUND_4";
        let mut differences = 0usize;
        for r in 0..32u64 {
            let bit_a = coin_bit_from_seed(seed_a, 0, r);
            let bit_b = coin_bit_from_seed(seed_b, 0, r);
            if bit_a != bit_b { differences += 1; }
        }
        assert!(differences > 0, "two distinct seeds produced identical coin bits");
    }
}
