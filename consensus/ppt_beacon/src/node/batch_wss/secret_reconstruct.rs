use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};

use async_recursion::async_recursion;
use num_bigint::BigUint;
use types::{
    beacon::{
        BatchBeaconConstructMsg,
        BatchWSSReconMsg,
        CoinMsg,
        MulticastRecoveredSharesMsg,
        RecoveredCoinSharesMsg,
        Val,
    },
    beacon::Round,
    Replica,
};

use crate::node::{Context, CTRBCState};
use crate::node::ctrbc::state::BlameReason;
use crate::node::shamir::two_field::BatchExtractor;
use crate::node::shoup_smart::proof_leaf_index;
use crypto::aes_hash::HashState;
use crypto::hash::Hash;
use std::time::UNIX_EPOCH;
use types::SyncMsg;
use types::SyncState;

fn packet_lengths_ok(packet: &BatchWSSReconMsg) -> bool {
    let l = packet.origins.len();
    let f_large_ok = match packet.f_large_shares.as_ref() {
        Some(fl) => fl.len() == l,
        None => true, // GF2 mode (commit 7): f_large derived locally
    };
    packet.secrets.len() == l
        && packet.nonces.len() == l
        && packet.mps.len() == l
        && packet.mask_shares.len() == l
        && f_large_ok
}

/// One coin-packet's pre-verified inputs, ready to be moved into
/// `tokio::task::spawn_blocking` together with all the other
/// coin-packets in the same `BatchBeaconConstruct` message.
///
/// `roots_for_dealer[dealer] = comm_vectors[dealer][coin_num]` is
/// pre-cloned out of `CTRBCState::comm_vectors` BEFORE the blocking
/// task starts, so the closure does not need to touch `&self` or any
/// shared state. A share is accepted iff it carries a Merkle proof
/// that chains to the dealer's committed root for this coin AND whose
/// leaf index equals the relaying provider's id (binding the share to
/// the correct evaluation point). This makes a relayed share
/// unforgeable: a Byzantine provider can only relay the dealer's
/// genuine committed share for its own slot, or withhold it.
///
/// `pub` so the Phase-D fire-and-forget recon-completion struct in
/// `context.rs` can carry these across the detached-task boundary.
pub struct CoinVerifyInputs {
    pub coin_num: usize,
    /// The relaying provider (== wire sender of the BeaconConstruct).
    pub provider: Replica,
    pub packet: BatchWSSReconMsg,
    pub roots_for_dealer: HashMap<Replica, Hash>,
}

/// inside a coin-packet, produced by `verify_recon_shares_pure`.
///
/// `pub` + `Debug` so the Phase-D fire-and-forget recon-completion
/// struct in `context.rs` can carry a `Vec<CoinVerifyOutcome>` across
/// the detached-task / main-loop channel boundary.
#[derive(Debug)]
pub enum CoinVerifyOutcome {
    /// Share verified successfully against the dealer's Merkle
    /// commitment. Caller writes it via
    /// `CTRBCState::add_secret_share(coin_num, dealer, provider, share)`.
    Accepted {
        coin_num: usize,
        dealer: Replica,
        provider: Replica,
        share: Val,
    },
}

/// CPU-heavy post-ACS audit loop. This is the body that used to
/// run inline on the consensus task's worker thread inside
/// `process_multicast_recovered_shares` once the n-f recovered-share
/// multicast quorum had arrived for a round. For `batch=100 / n=16`
/// the loop runs `n_decided_dealers × batch × n_audit_senders ≈
/// 16 × 100 × 11 = 17600` `Proof::validate_batch + hash_batch +
/// Merkle-root compare` operations — all serialised on one core
/// before this refactor.
///
/// Lifting it into a pure free function (no `&self`, no
/// `&CTRBCState`) lets `process_multicast_recovered_shares` move
/// the call into `tokio::task::spawn_blocking` (Level 2), so the
/// audit runs on the blocking pool in parallel with the consensus
/// task continuing to handle other messages.
///
/// **Contract identical to the previous inline audit body**:
/// returns the same `Vec<(Replica, BlameReason)>` blame events
/// the old code produced. The caller is responsible for actually
/// calling `blame_dealer` and `ban_dealer_global` on the blamed
/// dealers; this function only computes the evidence.
pub(crate) fn audit_post_complaint_pure(
    decided: Vec<Replica>,
    comm_vectors: HashMap<Replica, Vec<crypto::hash::Hash>, nohash_hasher::BuildNoHashHasher<Replica>>,
    post_packets: HashMap<Replica, MulticastRecoveredSharesMsg, nohash_hasher::BuildNoHashHasher<Replica>>,
    audit_senders: Vec<Replica>,
    batch_size: usize,
    hash_context: &crypto::aes_hash::HashState,
) -> Vec<(Replica, BlameReason)> {
    let mut blame_events: Vec<(Replica, BlameReason)> = Vec::new();

    for dealer in decided.into_iter() {
        let root_vec = match comm_vectors.get(&dealer) {
            Some(root_vec) => root_vec,
            None => {
                blame_events.push((dealer, BlameReason::MissingCommitmentVector));
                continue;
            }
        };

        for coin_num in 0..batch_size {
            if coin_num >= root_vec.len() {
                continue;
            }
            let expected_root = root_vec[coin_num];
            let mut complete = true;

            for share_owner in audit_senders.iter().copied() {
                let packet_bundle = match post_packets.get(&share_owner) {
                    Some(b) => b,
                    None => {
                        complete = false;
                        break;
                    }
                };

                let packet = match packet_bundle
                    .packets
                    .iter()
                    .find(|entry| entry.coin_num == coin_num)
                    .map(|entry| &entry.packet)
                {
                    Some(packet) => packet,
                    None => {
                        complete = false;
                        break;
                    }
                };

                if !crypto::aes_hash::Proof::validate_batch(&packet.mps, hash_context) {
                    complete = false;
                    break;
                }

                let idx = match packet.origins.iter().position(|origin| *origin == dealer) {
                    Some(idx) => idx,
                    None => {
                        complete = false;
                        break;
                    }
                };

                let share = packet.secrets[idx];
                let nonce = packet.nonces[idx];
                let proof = &packet.mps[idx];

                // Recompute the committed leaf binding f_share, g_share
                // (mask), f_large (BigUint only) and nonce. GF(2^w)
                // mode (commit 7): f_large channel dropped — the
                // 3-field `avss_commit_leaf_gf2` matches what the
                // dealer hashed.
                if idx >= packet.mask_shares.len() {
                    complete = false;
                    break;
                }
                let f_large_ref = match packet.f_large_shares.as_ref() {
                    Some(fl) if idx < fl.len() => Some(&fl[idx]),
                    Some(_) => {
                        complete = false;
                        break;
                    }
                    None => None,
                };
                let item = types::beacon::avss_commit_leaf_auto(
                    &share,
                    &packet.mask_shares[idx],
                    f_large_ref,
                    &nonce,
                );

                if item != proof.item() {
                    blame_events.push((
                        dealer,
                        BlameReason::CommitmentMismatch {
                            coin_num,
                            expected_root,
                            got_item: item,
                        },
                    ));
                    complete = false;
                    break;
                }

                if proof.root() != expected_root {
                    blame_events.push((
                        dealer,
                        BlameReason::MerkleRootMismatch {
                            coin_num,
                            expected_root,
                            got_root: proof.root(),
                        },
                    ));
                    complete = false;
                    break;
                }
            }

            if !complete {
                continue;
            }
        }
    }

    blame_events
}

/// CPU-heavy bulk verifier for a whole batch of coin-packets. The
/// previous implementation relied on the two-field per-share degree
/// test (`verify_share`) for integrity, but that check leaves the
/// relaying provider one degree of freedom: a Byzantine provider can
/// pick an arbitrary `f_large(i)` and set `g(i) = h(i) + θ·f_large(i)`
/// so the degree-test relation holds while the small-field `share`
/// it interpolates is garbage. Reconstruction then used a fixed set
/// of providers and required ALL of them, so a single Byzantine
/// provider could either corrupt the beacon or stall the round.
///
/// This verifier instead authenticates every relayed share against
/// the **dealer's Merkle commitment**:
///   - the dealer must be in the ACS-decided set and not banned,
///   - the proof's leaf index must equal the relaying `provider`
///     (binding the share to evaluation point `provider + 1`),
///   - `hash(share, nonce)` must equal the proof's leaf item,
///   - the proof must validate, and
///   - the proof's root must equal the dealer's committed
///     `root_vec[coin_num]` (supplied in `roots_for_dealer`).
///
/// Because the share is now bound to the dealer's canonical
/// committed value, a Byzantine provider can only relay the genuine
/// share for its own slot or withhold it — it can no longer inject a
/// wrong value or equivocate. Reconstruction can therefore safely
/// interpolate from ANY f+1 validated providers (see
/// `recover_and_emit_coin_set`).
///
/// Lifting it into a pure free function (no `&self`, no `&CTRBCState`)
/// lets the hot path call it inside `tokio::task::spawn_blocking`
/// (Phase D fire-and-forget recon ingest).
pub fn verify_recon_shares_pure(
    inputs: Vec<CoinVerifyInputs>,
    decided: &[Replica],
    banned: &HashSet<Replica>,
    hash_context: &HashState,
) -> Vec<CoinVerifyOutcome> {
    let decided_set: HashSet<Replica> = decided.iter().copied().collect();

    let mut outcomes = Vec::new();

    for input in inputs.into_iter() {
        let CoinVerifyInputs {
            coin_num,
            provider,
            packet,
            roots_for_dealer,
        } = input;

        // Structurally validate every Merkle proof in the packet in
        // one batch (matches the post-ACS audit, which is the trusted
        // Merkle-validation path in this codebase). A single bad proof
        // taints the whole packet from this provider; we simply skip
        // it and rely on the other >= 2f+1 honest providers.
        if packet.mps.is_empty() || !crypto::aes_hash::Proof::validate_batch(&packet.mps, hash_context) {
            continue;
        }

        for idx in 0..packet.origins.len() {
            let dealer = &packet.origins[idx];
            if !decided_set.contains(dealer) || banned.contains(dealer) {
                continue;
            }
            // All per-coin vectors must be aligned with origins. The
            // f_large_shares channel is optional (None in GF(2^w)
            // mode, commit 7); when Some, it must match length.
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
                None => None,
            };
            let share = &packet.secrets[idx];
            let nonce = &packet.nonces[idx];
            let mp = &packet.mps[idx];

            let expected_root = match roots_for_dealer.get(dealer) {
                Some(root) => *root,
                // No committed root locally yet: the assembly step
                // is responsible for buffering such packets, so this
                // should not normally be hit. Skip defensively.
                None => continue,
            };

            // Bind the share to evaluation point `provider + 1`.
            if proof_leaf_index(mp) != provider as usize {
                continue;
            }
            // Bind the proof to the dealer's committed root for this coin.
            if mp.root() != expected_root {
                continue;
            }
            // Bind (f_share, g_share, [f_large,] nonce) to the
            // committed leaf — 4-arg in BigUint mode, 3-arg in GF(2^w).
            let item = types::beacon::avss_commit_leaf_auto(
                share,
                &packet.mask_shares[idx],
                f_large_ref,
                nonce,
            );
            if item != mp.item() {
                continue;
            }

            outcomes.push(CoinVerifyOutcome::Accepted {
                coin_num,
                dealer: *dealer,
                provider,
                share: *share,
            });
        }
    }

    outcomes
}

/// Keep only ACS-decided dealers/messages inside a batch reconstruction packet.
/// This is the key alignment with the PPT requirement:
/// "We only reconstruct the secret chosen by ACS".
fn filter_packet_to_decided(
    packet: &BatchWSSReconMsg,
    decided: &[Replica],
) -> BatchWSSReconMsg {
    let decided_set: HashSet<Replica> = decided.iter().copied().collect();
    let mut filtered = packet.clone();
    filtered.origins.clear();
    filtered.secrets.clear();
    filtered.nonces.clear();
    filtered.mps.clear();
    filtered.mask_shares.clear();
    // f_large_shares is Option<Vec<Val>>: in GF(2^w) mode (commit 7)
    // the dealer ships None; preserve the variant when filtering. We
    // re-allocate the Some branch as an empty Vec ready for push.
    let mut filtered_f_large_vec: Option<Vec<types::beacon::Val>> =
        packet.f_large_shares.as_ref().map(|_| Vec::new());

    for idx in 0..packet.origins.len() {
        let dealer = packet.origins[idx];
        if decided_set.contains(&dealer) {
            filtered.origins.push(dealer);
            filtered.secrets.push(packet.secrets[idx].clone());
            filtered.nonces.push(packet.nonces[idx].clone());
            filtered.mps.push(packet.mps[idx].clone());
            filtered.mask_shares.push(packet.mask_shares[idx].clone());
            if let (Some(src), Some(dst)) =
                (packet.f_large_shares.as_ref(), filtered_f_large_vec.as_mut())
            {
                if idx < src.len() {
                    dst.push(src[idx].clone());
                }
            }
        }
    }
    filtered.f_large_shares = filtered_f_large_vec;

    filtered
}

/// A coin is ready to reconstruct once EVERY ACS-decided dealer has
/// at least `threshold = f+1` Merkle-validated provider shares
/// available for that coin. We no longer require a fixed set of
/// providers to all respond: any f+1 validated shares from any
/// providers determine the degree-f polynomial, so a Byzantine node
/// that withholds its reconstruction share can no longer prevent a
/// coin from becoming ready (there are >= 2f+1 honest providers).
fn ready_coins(state: &CTRBCState, batch_size: usize, threshold: usize) -> Vec<usize> {
    let decided = match state.acs_decided_set.as_ref() {
        Some(decided) => decided,
        None => return Vec::new(),
    };
    if decided.is_empty() {
        return Vec::new();
    }

    let mut ready = Vec::new();

    for coin in 0..batch_size {
        if state.recovered_coins.contains(&coin) {
            continue;
        }

        let coin_map = match state.secret_shares.get(&coin) {
            Some(coin_map) => coin_map,
            None => continue,
        };

        let mut coin_ready = true;

        for dealer in decided.iter().copied() {
            let have = coin_map.get(&dealer).map(|m| m.len()).unwrap_or(0);
            if have < threshold {
                coin_ready = false;
                break;
            }
        }

        if coin_ready {
            ready.push(coin);
        }
    }

    ready
}

/// One per-(coin, dealer) reconstruction task: the f+1 lowest-indexed
/// providers that supplied a validated share, packaged as the
/// evaluation points (`provider + 1`) and the share values in the
/// same order. Built on the async task before the heavy Lagrange
/// interpolation is moved into `spawn_blocking`.
struct DealerRecoverTask {
    coin: usize,
    dealer: Replica,
    eval_points: Vec<usize>,
    shares: Vec<BigUint>,
}

/// Build the per-(coin, dealer) reconstruction tasks for the given
/// ready coins. For each decided dealer we deterministically pick the
/// `threshold = f+1` lowest-indexed providers that have a validated
/// share. For an honest dealer (genuine degree-f sharing) any such
/// subset interpolates to the same f(0), so honest nodes that happen
/// to have different provider subsets available still agree on the
/// reconstructed secret.
fn build_dealer_recover_tasks(
    state: &CTRBCState,
    ready_coin_nums: &[usize],
    threshold: usize,
) -> Vec<DealerRecoverTask> {
    let decided = match state.acs_decided_set.as_ref() {
        Some(decided) => decided,
        None => return Vec::new(),
    };

    let mut tasks = Vec::new();

    for coin in ready_coin_nums.iter().copied() {
        let coin_map = match state.secret_shares.get(&coin) {
            Some(coin_map) => coin_map,
            None => continue,
        };

        for dealer in decided.iter().copied() {
            let provider_map = match coin_map.get(&dealer) {
                Some(provider_map) => provider_map,
                None => continue,
            };

            let mut providers: Vec<usize> = provider_map.keys().copied().collect();
            providers.sort_unstable();
            if providers.len() < threshold {
                continue;
            }
            providers.truncate(threshold);

            let eval_points: Vec<usize> = providers.iter().map(|p| p + 1).collect();
            let shares: Vec<BigUint> = providers
                .iter()
                .map(|p| provider_map.get(p).unwrap().clone())
                .collect();

            tasks.push(DealerRecoverTask {
                coin,
                dealer,
                eval_points,
                shares,
            });
        }
    }

    tasks
}

fn build_local_multicast_snapshot(
    state: &CTRBCState,
    round: Round,
    myid: Replica,
    decided: &[Replica],
    disclosed_coins: &[usize],
) -> MulticastRecoveredSharesMsg {
    let mut packets = Vec::with_capacity(disclosed_coins.len());

    for coin_num in disclosed_coins.iter().copied() {
        let packet = state.secret_shares(coin_num);
        let filtered = filter_packet_to_decided(&packet, decided);

        if !filtered.origins.is_empty() {
            packets.push(RecoveredCoinSharesMsg {
                coin_num,
                packet: filtered,
            });
        }
    }

    MulticastRecoveredSharesMsg {
        origin: myid,
        round,
        packets,
    }
}

fn build_local_batch_beacon_construct(
    state: &CTRBCState,
    round: Round,
    myid: Replica,
    batch_size: usize,
    decided: &[Replica],
) -> BatchBeaconConstructMsg {
    let mut packets = Vec::with_capacity(batch_size);

    for coin_num in 0..batch_size {
        let mut packet = state.secret_shares(coin_num);
        packet.origin = myid;
        let filtered = filter_packet_to_decided(&packet, decided);

        if !filtered.origins.is_empty() {
            packets.push(RecoveredCoinSharesMsg {
                coin_num,
                packet: filtered,
            });
        }
    }

    BatchBeaconConstructMsg {
        origin: myid,
        round,
        packets,
    }
}

impl Context {
    /// Release a round's transient state once it is fully done:
    ///   - every coin in the batch has emitted its beacon output
    ///     (`recon_secrets.contains(batch_size - 1)`), AND
    ///   - the post-ACS audit quorum (n-f recovered-share multicasts)
    ///     has completed (`post_complaint_complete == true`).
    ///
    /// Calling this in place (rather than removing the entry from
    /// `round_state`) keeps the `cleared` sentinel so any very-late
    /// arriving messages are safely ignored by the ingest paths.
    pub(crate) fn maybe_release_round(&mut self, round: Round) {
        let should_release = match self.round_state.get(&round) {
            Some(state) => {
                state.recon_secrets.contains(&(self.batch_size - 1))
                    && state.post_complaint_complete
                    && !state.cleared
            }
            None => false,
        };
        if !should_release {
            return;
        }

        if let Some(state) = self.round_state.get_mut(&round) {
            log::info!(
                "[PPT][ROUND-RELEASE] node {} round {} releasing transient state (batch + audit complete)",
                self.myid,
                round
            );
            state.clear();
        }

        // Commit-7 cutover added three per-(round, dealer) maps on
        // Context that hold the Shoup-Smart 2024 SecMsgDst transport
        // state (SecMsgDstState containing two RelMsgDstStates' worth
        // of caches + the cached AvssPublicCommitMsg + the decrypted
        // AvssRecipientPayload bytes). The previous version of this
        // function only called `state.clear()` on the CTRBCState and
        // left these three maps growing unboundedly with each round.
        //
        // Long-running beacons (max_rounds = 20000) would accumulate
        // ~20000 * n entries per map, eventually OOM-ing the
        // consensus node. Once `state.clear()` fires, every honest
        // round-r AVSS path has fully completed -- the SecMsgDst
        // transport caches for round r will never be referenced
        // again. Drop them.
        //
        // We use `retain` rather than `remove` because each map keys
        // by `(Round, Replica)` and may contain entries for several
        // dealers at the same round; we want to drop all entries
        // for *this* round in one pass without touching other
        // (still-active) rounds.
        let removed_state = {
            let before = self.avss_secmsg_state.len();
            self.avss_secmsg_state.retain(|(r, _), _| *r != round);
            before - self.avss_secmsg_state.len()
        };
        let removed_public = {
            let before = self.avss_secmsg_public.len();
            self.avss_secmsg_public.retain(|(r, _), _| *r != round);
            before - self.avss_secmsg_public.len()
        };
        let removed_delivered = {
            let before = self.avss_secmsg_delivered_bytes.len();
            self.avss_secmsg_delivered_bytes
                .retain(|(r, _), _| *r != round);
            before - self.avss_secmsg_delivered_bytes.len()
        };
        if removed_state + removed_public + removed_delivered > 0 {
            log::info!(
                "[PPT][ROUND-RELEASE] node {} round {} dropped SecMsgDst caches: \
                 state={} public={} delivered_bytes={}",
                self.myid,
                round,
                removed_state,
                removed_public,
                removed_delivered
            );
        }
    }

    #[async_recursion]
    async fn flush_pending_beacon_outputs(&mut self, round: Round, reason: &'static str) {
        let pending = {
            let rbc_state = match self.round_state.get_mut(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            std::mem::take(&mut rbc_state.pending_beacon_outputs)
        };

        for (coin_num, beacon) in pending.into_iter() {
            // Per-coin flush log demoted to debug: at batch=1000
            // this fires ~1000 times per round per node. Kept as
            // debug for forensics. The aggregate [STAGE][BEACON-OUT]
            // marker in `self_coin_check_transmit` plus the
            // round-level events still surface in INFO mode.
            log::debug!(
                "[PPT][BEACON-FLUSH] node {} round {} flushing coin {} via {}",
                self.myid,
                round,
                coin_num,
                reason,
            );
            self.self_coin_check_transmit(round, coin_num, beacon).await;
        }
    }

    /// Level 2 multi-core hot path. The previous version walked the
    /// incoming `BatchBeaconConstruct` packet-by-packet and called
    /// `ingest_secret_shares_only` for each coin; each of those calls
    /// ran `n_dealers × verify_share` of two-field degree-test work
    /// inline on the consensus task's worker thread. For
    /// `batch=100 / n=16` that's ~1600 verify_share calls per inbound
    /// BatchBeaconConstruct, all serialised on one core.
    ///
    /// This version:
    /// 1. Does the protocol-state preflight (banned sender / cleared
    ///    state / `acs_decided_set` ready / `θ` available) **once**
    ///    for the whole batch, not once per coin.
    /// 2. Snapshots the small slice of `degree_test_coeffs` that the
    ///    verifier actually needs into per-packet `HashMap`s, so the
    ///    blocking closure does not need to touch `CTRBCState`.
    /// 3. Moves the entire `batch_size × n_dealers` verify loop into
    ///    a single `tokio::task::spawn_blocking` call, so the
    ///    consensus task's worker can keep handling other inbound
    ///    messages while the heavy big-int / hash work runs on the
    ///    blocking pool (multi-core).
    /// 4. Re-acquires `&mut self` after the blocking task returns
    ///    and applies the verified shares (`add_secret_share`) and
    ///    blame events (`blame_dealer` + `ban_dealer_global`) on
    ///    one short, mutex-style window.
    ///
    /// Semantics are identical to the previous per-coin path: a share
    /// is accepted iff its dealer is in the ACS-decided set, not
    /// banned, has degree-test coefficients stored locally, and
    /// passes `verify_share(share_sender+1, ...)`. Missing-coeffs
    /// dealers in the decided set are permanently banned (the PPT
    /// "kick out corrupted leader" path).
    #[async_recursion]
    pub async fn process_batch_secret_shares(
        &mut self,
        recovered: BatchBeaconConstructMsg,
        sender: Replica,
        round: Round,
    ) {
        let now = SystemTime::now();
        log::info!(
            "[PPT][BATCH-RECV] node {} got batched BeaconConstruct from {} for round {} with {} coin-packets",
            self.myid,
            sender,
            round,
            recovered.packets.len()
        );

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        let banned = self.banned_dealers.clone();

        // (1) Preflight: cleared/complete + acs_decided_set + theta.
        //     If ACS hasn't decided yet, cache the whole batch for
        //     replay (kept compatible with the legacy per-coin
        //     `pre_acs_beacon_constructs` cache that
        //     `finalize_acs_round` drains).
        let decided: Vec<Replica> = {
            let rbc_state = self.round_state.get_mut(&round).unwrap();

            if rbc_state.cleared || rbc_state.batch_reconstruction_complete {
                self.add_benchmark(
                    String::from("process_batchreconstruct"),
                    now.elapsed().unwrap().as_nanos(),
                );
                return;
            }

            match rbc_state.acs_decided_set.clone() {
                Some(decided) => decided,
                None => {
                    log::warn!(
                        "[PPT][BATCH-CACHE] node {} caching {} coin-packets from {} for round {} until ACS finalization",
                        self.myid,
                        recovered.packets.len(),
                        sender,
                        round
                    );
                    for entry in recovered.packets.into_iter() {
                        if packet_lengths_ok(&entry.packet) {
                            rbc_state
                                .pre_acs_beacon_constructs
                                .push((entry.packet, sender, entry.coin_num));
                        }
                    }
                    self.add_benchmark(
                        String::from("process_batchreconstruct"),
                        now.elapsed().unwrap().as_nanos(),
                    );
                    return;
                }
            }
        };

        // (2) Assemble per-packet inputs. For each coin-packet we
        //     snapshot the committed Merkle root of every decided
        //     dealer present in the packet. If ANY decided dealer's
        //     commitment vector is not yet locally available (a
        //     transient async race where a reconstruction share
        //     overtook its dealer's AVSS commitment), we buffer the
        //     whole packet in `pending_recon_shares` for replay once
        //     the commitment lands, rather than dropping it.
        let mut verify_inputs: Vec<CoinVerifyInputs> =
            Vec::with_capacity(recovered.packets.len());
        let decided_set: HashSet<Replica> = decided.iter().copied().collect();
        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for entry in recovered.packets.into_iter() {
                if !packet_lengths_ok(&entry.packet) {
                    log::warn!(
                        "[PPT][BATCH-INGEST] dropping malformed packet from {} round {} coin {}",
                        sender,
                        round,
                        entry.coin_num
                    );
                    continue;
                }
                let coin_num = entry.coin_num;
                let packet = entry.packet;

                let mut roots_for_dealer: HashMap<Replica, Hash> = HashMap::new();
                let mut missing_commitment = false;
                for dealer in packet.origins.iter() {
                    if !decided_set.contains(dealer) || banned.contains(dealer) {
                        continue;
                    }
                    match rbc_state
                        .comm_vectors
                        .get(dealer)
                        .and_then(|roots| roots.get(coin_num))
                    {
                        Some(root) => {
                            roots_for_dealer.insert(*dealer, *root);
                        }
                        None => {
                            missing_commitment = true;
                        }
                    }
                }

                if missing_commitment {
                    log::info!(
                        "[PPT][RECON-DEFER] node {} buffering recon coin-packet from {} round {} coin {} until missing dealer commitment(s) arrive",
                        self.myid, sender, round, coin_num
                    );
                    rbc_state
                        .pending_recon_shares
                        .push((packet, sender, coin_num));
                    continue;
                }

                verify_inputs.push(CoinVerifyInputs {
                    coin_num,
                    provider: sender,
                    packet,
                    roots_for_dealer,
                });
            }
        }

        // (3) Phase D fire-and-forget (PR#6) + Merkle verifier (PR#5):
        //     detach the bulk Merkle-validation onto an independent
        //     tokio task that runs `verify_recon_shares_pure` on the
        //     blocking pool and publishes the outcomes back via
        //     `recon_tx`. Multiple inbound BatchBeaconConstructs for
        //     the same round therefore validate in PARALLEL on the
        //     blocking pool, instead of serialised on the consensus
        //     task's await point.
        let banned_clone = banned.clone();
        let decided_clone = decided.clone();
        let hash_context = Arc::clone(&self.hash_context);
        let share_sender = sender;
        let recon_tx = self.recon_tx.clone();

        tokio::spawn(async move {
            let outcomes = tokio::task::spawn_blocking(move || {
                verify_recon_shares_pure(
                    verify_inputs,
                    &decided_clone,
                    &banned_clone,
                    &hash_context,
                )
            })
            .await
            .unwrap_or_else(|e| {
                log::error!(
                    "[PPT][LEVEL2] bulk share-verify blocking task join error \
                     round {} sender {}: {}",
                    round, share_sender, e
                );
                Vec::new()
            });

            let _ = recon_tx.send(crate::node::context::ReconCompletion {
                round,
                share_sender,
                // PR#5 reconstruction binds each share to its proven
                // provider (any f+1 providers suffice), so the apply
                // path uses the per-outcome provider, not share_sender.
                // The flag is retained for the struct and always true.
                use_for_batch: true,
                outcomes,
            });
        });

        self.add_benchmark(
            String::from("process_batchreconstruct"),
            now.elapsed().unwrap().as_nanos(),
        );
        // NB: maybe_recover_ready_coins is triggered in
        // `finalize_recon_completion` once the detached
        // task publishes its outcomes back to the main loop.
    }

    /// Apply one completed reconstruct-ingest validation (from
    /// the detached task spawned in `process_batch_secret_shares`).
    /// Called from the main loop's `tokio::select!` arm on
    /// `recon_rx.recv()`. Runs on the consensus task's worker
    /// thread, so every Context mutation (secret_shares,
    /// banned_dealers) stays single-threaded.
    pub async fn finalize_recon_completion(
        &mut self,
        completion: crate::node::context::ReconCompletion,
    ) {
        let crate::node::context::ReconCompletion {
            round,
            share_sender: _share_sender,
            use_for_batch: _use_for_batch,
            outcomes,
        } = completion;

        // Late-arrival guard: the round may have been cleared
        // between spawn and finalize (e.g. all coins emitted +
        // audit done). Drop silently.
        let round_active = match self.round_state.get(&round) {
            Some(s) => !s.cleared,
            None => false,
        };
        if !round_active {
            return;
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for outcome in outcomes.into_iter() {
                match outcome {
                    CoinVerifyOutcome::Accepted {
                        coin_num,
                        dealer,
                        provider,
                        share,
                    } => {
                        rbc_state.add_secret_share(coin_num, dealer, provider, share);
                    }
                }
            }
        }

        // Trigger batch recovery exactly once per applied packet.
        // Multiple in-flight finalize_recon_completion calls each
        // trigger this; `maybe_recover_ready_coins` is idempotent
        // and only does work when the n-f share-quorum threshold
        // is crossed.
        self.maybe_recover_ready_coins(round).await;
    }

    /// Re-validate reconstruction coin-packets that were buffered in
    /// `pending_recon_shares` because a decided dealer's committed
    /// root vector was not yet locally available. Called from
    /// `maybe_recover_ready_coins` (which fires after every ingest)
    /// and from the AVSS path once a new dealer commitment lands.
    /// Packets whose commitments are still missing are kept buffered.
    fn drain_pending_recon_shares(&mut self, round: Round) {
        let (pending, decided, banned, hc) = {
            let rbc_state = match self.round_state.get_mut(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            if rbc_state.cleared || rbc_state.batch_reconstruction_complete {
                rbc_state.pending_recon_shares.clear();
                return;
            }
            let decided = match rbc_state.acs_decided_set.clone() {
                Some(d) => d,
                None => return,
            };
            if rbc_state.pending_recon_shares.is_empty() {
                return;
            }
            (
                std::mem::take(&mut rbc_state.pending_recon_shares),
                decided,
                self.banned_dealers.clone(),
                Arc::clone(&self.hash_context),
            )
        };

        let decided_set: HashSet<Replica> = decided.iter().copied().collect();
        let mut accepted: Vec<(usize, Replica, Replica, Val)> = Vec::new();
        let mut still_pending: Vec<(BatchWSSReconMsg, Replica, usize)> = Vec::new();

        for (packet, provider, coin_num) in pending.into_iter() {
            let mut roots_for_dealer: HashMap<Replica, Hash> = HashMap::new();
            let mut missing = false;
            {
                let rbc_state = self.round_state.get(&round).unwrap();
                for dealer in packet.origins.iter() {
                    if !decided_set.contains(dealer) || banned.contains(dealer) {
                        continue;
                    }
                    match rbc_state
                        .comm_vectors
                        .get(dealer)
                        .and_then(|roots| roots.get(coin_num))
                    {
                        Some(root) => {
                            roots_for_dealer.insert(*dealer, *root);
                        }
                        None => missing = true,
                    }
                }
            }

            if missing {
                still_pending.push((packet, provider, coin_num));
                continue;
            }

            let outcomes = verify_recon_shares_pure(
                vec![CoinVerifyInputs {
                    coin_num,
                    provider,
                    packet,
                    roots_for_dealer,
                }],
                &decided,
                &banned,
                &hc,
            );
            for outcome in outcomes.into_iter() {
                match outcome {
                    CoinVerifyOutcome::Accepted {
                        coin_num,
                        dealer,
                        provider,
                        share,
                    } => accepted.push((coin_num, dealer, provider, share)),
                }
            }
        }

        if let Some(rbc_state) = self.round_state.get_mut(&round) {
            for (coin_num, dealer, provider, share) in accepted.into_iter() {
                rbc_state.add_secret_share(coin_num, dealer, provider, share);
            }
            rbc_state.pending_recon_shares.extend(still_pending);
        }
    }
    
    /// Public entry: recover every ready coin for `round` and emit
    /// the resulting beacons. **Optimisation B (2026-05): coin-0
    /// fast path.** Coin-0's reconstructed beacon is the source of
    /// θ_{r+1} and the next-round ACS coin seed, so once it is
    /// emitted the local node can immediately broadcast the next
    /// round's AVSS as dealer and overlap the audit phase of round
    /// r with the AVSS phase of round r+1. The previous one-shot
    /// batch_recover delayed coin-0 emission until the entire batch
    /// finished interpolating, putting the round-r+1 dealer launch
    /// at ~70 % of round-r's wall clock and effectively serialising
    /// the protocol round-by-round.
    ///
    /// The new flow:
    ///   1. If coin-0 is ready and not yet emitted, recover ONLY
    ///      coin-0 in a small spawn_blocking call (a single
    ///      Lagrange interpolation, batch_size× cheaper than the
    ///      full batch). Emit coin-0 immediately, which fires
    ///      `record_beacon_output_for_theta` /
    ///      `record_beacon_output_for_coin` /
    ///      `ppt_try_start_round(round+1)` inside
    ///      `self_coin_check_transmit`. **Crucially, this fast-path
    ///      call passes `emit_audit_multicast = false`** — the
    ///      audit `MulticastRecoveredShares` broadcast is deferred
    ///      until the second pass below, so that audit always sees
    ///      the FULL batch of disclosures, not just coin-0.
    ///   2. Then recover all the remaining ready coins in one big
    ///      batch_recover (same code path as before), this time
    ///      with `emit_audit_multicast = true`. The audit
    ///      multicast carries the complete set of disclosed coins
    ///      (coin-0 ∪ remaining), so the post-ACS audit sees the
    ///      same evidence as the pre-fast-path implementation did.
    ///
    /// Both calls share the `recover_and_emit_coin_set` helper.
    ///
    /// Safety / liveness: identical to the old one-shot path.
    /// Coin-0's reconstruction uses the same shares_matrix subset
    /// as a one-shot batch_recover would have used; the resulting
    /// beacon value is byte-identical at every honest node, so
    /// θ_{r+1} and the ACS coin seed_{r+1} are also identical
    /// across honest nodes (preserving ACS Agreement). The audit
    /// `MulticastRecoveredShares` is sent **once per round** with
    /// the full disclosure set, so post-ACS audit completeness
    /// (every coin's commitment validation) is preserved verbatim.
    /// ACS three-property and PQ-safety are unchanged.
    #[async_recursion]
    pub(crate) async fn maybe_recover_ready_coins(&mut self, round: Round) {
        // First, retry any reconstruction packets that were buffered
        // because a decided dealer's commitment had not yet arrived.
        self.drain_pending_recon_shares(round);

        let threshold = self.num_faults + 1;
        let ready_initial = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            if rbc_state.batch_reconstruction_complete {
                return;
            }
            ready_coins(rbc_state, self.batch_size, threshold)
        };

        if ready_initial.is_empty() {
            return;
        }

        // Optimisation B coin-0 fast path: if coin-0 is ready and
        // not yet emitted, recover and emit it FIRST (small,
        // single-coin spawn_blocking call). This unblocks the
        // round-r+1 AVSS dealer launch ~2 seconds earlier than
        // the previous one-shot batch_recover did, which is the
        // single biggest win for cross-round pipelining.
        let coin0_pending = ready_initial.contains(&0)
            && !self
                .round_state
                .get(&round)
                .map(|s| s.emitted_beacon_coins.contains(&0))
                .unwrap_or(true);

        if coin0_pending {
            log::info!(
                "[PPT][COIN0-FAST] node {} round {} prioritising coin-0 recovery to unblock next-round AVSS pipeline",
                self.myid,
                round
            );
            // emit_audit_multicast = false: defer the audit
            // multicast to the second pass so it carries the full
            // batch of disclosures, not just coin-0. See doc above.
            self.recover_and_emit_coin_set(round, vec![0], false).await;

            // Re-snapshot ready set: coin-0 is now in recovered_coins,
            // ready_coins() will skip it on its next call.
            let remaining = {
                let rbc_state = match self.round_state.get(&round) {
                    Some(rbc_state) => rbc_state,
                    None => return,
                };
                if rbc_state.batch_reconstruction_complete {
                    return;
                }
                ready_coins(rbc_state, self.batch_size, threshold)
            };

            if remaining.is_empty() {
                // Edge case: only coin-0 was in the ready set. We
                // never sent the audit multicast in the fast-path
                // call (because we deferred it), so emit a
                // coin-0-only multicast now, matching what the
                // pre-fast-path code would have produced for a
                // batch_size = 1 round.
                self.send_audit_multicast_snapshot(round).await;
                return;
            }

            self.recover_and_emit_coin_set(round, remaining, true).await;
        } else {
            // Standard one-shot batch path (e.g. coin-0 already emitted
            // or coin-0 is not in this batch's ready set yet).
            self.recover_and_emit_coin_set(round, ready_initial, true).await;
        }
    }

    /// Stand-alone audit-multicast send used by the coin-0 fast
    /// path's degenerate "remaining is empty" edge case (e.g. the
    /// pathological batch_size = 1 case where only coin-0 ever
    /// gets recovered). Deliberately mirrors the multicast block
    /// of `recover_and_emit_coin_set` so audit semantics remain
    /// identical to the pre-fast-path implementation.
    #[async_recursion]
    async fn send_audit_multicast_snapshot(&mut self, round: Round) {
        let (multicast_msg, decided_dbg) = {
            let rbc_state = match self.round_state.get(&round) {
                Some(s) => s,
                None => return,
            };
            let decided = match rbc_state.acs_decided_set.clone() {
                Some(d) => d,
                None => return,
            };
            let mut disclosed: Vec<usize> =
                rbc_state.multicast_disclosed_coins.iter().copied().collect();
            disclosed.sort_unstable();
            if disclosed.is_empty() {
                return;
            }
            let msg = build_local_multicast_snapshot(
                rbc_state,
                round,
                self.myid,
                decided.as_slice(),
                disclosed.as_slice(),
            );
            (Some(msg), decided)
        };

        if let Some(msg) = multicast_msg {
            log::info!(
                "[PPT][POST-COMPLAINT-MULTICAST] node {} round {} (fast-path edge case, only coin-0 in batch) decided_set_len={}",
                self.myid,
                round,
                decided_dbg.len()
            );
            let coin_msg = CoinMsg::MulticastRecoveredShares(msg.clone(), self.myid, round);
            self.broadcast(coin_msg, round).await;
            self.process_multicast_recovered_shares(msg, self.myid, round).await;
        }
    }

    /// Pure helper: recover the secrets for `coin_set`, write them
    /// back to `reconstructed_secrets`, run `coin_check` to derive
    /// each beacon value, optionally broadcast a
    /// `MulticastRecoveredShares` snapshot, and emit each beacon
    /// via `flush_pending_beacon_outputs`.
    ///
    /// `emit_audit_multicast` controls whether the audit-side
    /// `MulticastRecoveredShares` broadcast is sent on this call.
    /// The coin-0 fast path passes `false` so that its single-coin
    /// disclosure is NOT sent prematurely (which would cause the
    /// post-ACS audit threshold to be reached on a partial
    /// disclosure set, allowing dealer commitments for
    /// coin-1..batch-1 to escape verification). The follow-up
    /// `remaining` pass passes `true` and carries the full
    /// disclosure (`multicast_disclosed_coins` accumulates across
    /// both passes), so audit semantics match the pre-fast-path
    /// one-shot code exactly.
    ///
    /// All non-multicast steps (recover, write back to
    /// `reconstructed_secrets`, `coin_check`, beacon emit, update
    /// `multicast_disclosed_coins`) are identical to the
    /// pre-fast-path body of this function.
    #[async_recursion]
    async fn recover_and_emit_coin_set(
        &mut self,
        round: Round,
        coin_set: Vec<usize>,
        emit_audit_multicast: bool,
    ) {
        if coin_set.is_empty() {
            return;
        }

        let (tasks, decided) = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            if rbc_state.batch_reconstruction_complete {
                return;
            }
            let decided = rbc_state
                .acs_decided_set
                .clone()
                .expect("ACS decided set missing during ready-coin recovery");
            let threshold = self.num_faults + 1;
            let tasks =
                build_dealer_recover_tasks(rbc_state, coin_set.as_slice(), threshold);
            (tasks, decided)
        };

        log::info!(
            "[PPT][BATCH-RECOVER] node {} round {} recovering coins {:?}",
            self.myid,
            round,
            coin_set
        );

        // Heavy Lagrange interpolation runs on tokio's blocking pool.
        // Each (coin, dealer) is reconstructed from its own f+1
        // lowest-indexed validated providers; in BigUint mode the
        // per-provider-set extractors are cached so the common case
        // (the same f+1 providers respond for every dealer) builds
        // the Lagrange coefficients only once.
        //
        // GF(2^w) mode (commit 5 of the migration) takes a parallel
        // branch: per-task it reinterprets the stored `BigUint`
        // bytes as `Gf2Element`s (the bytes round-trip exactly through
        // `Context::pad_shares` because `add_secret_share` ingested
        // them as `BigUint::from_bytes_be(&Val)` with `Val` always
        // 32 bytes) and runs the char-2-specialised
        // `lagrange_recover_at_zero` from `shamir::gf2_two_field`. The
        // recovered `Gf2Element`'s native LE bytes are then folded back
        // into a `BigUint::from_bytes_be(...)` slot so the downstream
        // storage type (`reconstructed_secrets: HashMap<.., BigUint>`)
        // is unchanged. The `BigUint` integer value in the slot is
        // arithmetically meaningless under GF(2^w) — it's a typed
        // envelope for the 32 GF2 element bytes — and the subsequent
        // `SuperInvExtractor` step in `coin_check` will be migrated to
        // its own GF(2^w) sibling in commit 6.
        let secret_domain = self.secret_domain.clone();
        let gf2_profile = self.gf2_profile;
        let recovered: Vec<(usize, Replica, BigUint)> = tokio::task::spawn_blocking(move || {
            match gf2_profile {
                None => {
                    let mut cache: HashMap<Vec<usize>, BatchExtractor> = HashMap::new();
                    let mut out = Vec::with_capacity(tasks.len());
                    for task in tasks.into_iter() {
                        let extractor = cache.entry(task.eval_points.clone()).or_insert_with(|| {
                            BatchExtractor::new(task.eval_points.clone(), secret_domain.clone())
                        });
                        let secret = extractor.recover_one(&task.shares);
                        out.push((task.coin, task.dealer, secret));
                    }
                    out
                }
                Some(profile) => {
                    use crate::node::shamir::gf2_two_field::lagrange_recover_at_zero;
                    use crypto::gf2::Gf2Element;

                    let mut out = Vec::with_capacity(tasks.len());
                    for task in tasks.into_iter() {
                        // `task.eval_points` contains 1-based node ids
                        // (provider + 1); the parallel `task.shares` are
                        // BigUint-wrapped GF2 element bytes.
                        let mut points: Vec<(usize, Gf2Element)> =
                            Vec::with_capacity(task.shares.len());
                        let mut ok = true;
                        for (idx, share_big) in task.shares.iter().enumerate() {
                            let bytes = Context::pad_shares(share_big.clone());
                            match Gf2Element::from_bytes(profile, bytes) {
                                Ok(elem) => points.push((task.eval_points[idx], elem)),
                                Err(_) => {
                                    log::error!(
                                        "[PPT][GF2-RECOVER] coin {} dealer {} provider \
                                         (1-based) {} share has dirty bits beyond w_q; \
                                         skipping (this should never happen on a packet \
                                         that already passed AVSS validation)",
                                        task.coin, task.dealer, task.eval_points[idx]
                                    );
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if !ok {
                            continue;
                        }
                        let secret_elem = lagrange_recover_at_zero(profile, &points);
                        // Wrap the GF2 element bytes inside a BigUint so
                        // the existing reconstructed_secrets storage
                        // shape is preserved. Commit 6 will replace this
                        // intermediate type with the native GF2
                        // SuperInvExtractor path.
                        let secret = BigUint::from_bytes_be(secret_elem.as_bytes());
                        out.push((task.coin, task.dealer, secret));
                    }
                    out
                }
            }
        })
        .await
        .unwrap_or_else(|e| {
            log::error!(
                "[PPT][LEVEL2] batch_recover blocking task join error round {}: {}",
                round, e
            );
            Vec::new()
        });

        let (multicast_msg, outputs) = {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            if rbc_state.batch_reconstruction_complete {
                return;
            }

            for (coin, dealer, secret) in recovered.into_iter() {
                rbc_state
                    .reconstructed_secrets
                    .entry(coin)
                    .or_default()
                    .insert(dealer, secret);
            }

            rbc_state.sync_secret_maps().await;

            let mut outputs = Vec::new();
            for coin in coin_set.iter().copied() {
                rbc_state.recovered_coins.insert(coin);

                if !rbc_state.emitted_beacon_coins.contains(&coin) {
                    if let Some(random) = rbc_state.coin_check(round, coin, self.num_nodes).await {
                        outputs.push((coin, random));
                    }
                    rbc_state.emitted_beacon_coins.insert(coin);
                }

                rbc_state.multicast_disclosed_coins.insert(coin);
            }

            let mut disclosed: Vec<usize> =
                rbc_state.multicast_disclosed_coins.iter().copied().collect();
            disclosed.sort_unstable();

            // Audit multicast is only built when the caller asked
            // for it. The coin-0 fast path passes
            // `emit_audit_multicast = false` so that its partial
            // disclosure (only `[0]`) is NOT broadcast — the
            // follow-up "remaining" pass with `true` carries the
            // full disclosure and ensures the post-ACS audit sees
            // every coin's commitment data, exactly as the
            // pre-fast-path one-shot code did.
            let multicast_msg = if !emit_audit_multicast || disclosed.is_empty() {
                None
            } else {
                Some(build_local_multicast_snapshot(
                    rbc_state,
                    round,
                    self.myid,
                    decided.as_slice(),
                    disclosed.as_slice(),
                ))
            };

            if rbc_state.recovered_coins.len() >= self.batch_size {
                rbc_state.batch_reconstruction_complete = true;
            }

            (multicast_msg, outputs)
        };

        if let Some(msg) = multicast_msg {
            let coin_msg = CoinMsg::MulticastRecoveredShares(msg.clone(), self.myid, round);
            self.broadcast(coin_msg, round).await;
            self.process_multicast_recovered_shares(msg, self.myid, round)
                .await;
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for (coin_num, beacon) in outputs.into_iter() {
                rbc_state.pending_beacon_outputs.insert(coin_num, beacon);
            }
        }

        self.flush_pending_beacon_outputs(round, "ready-coin fast-path")
            .await;
    }
    

    #[async_recursion]
    pub async fn reconstruct_beacon(&mut self, round: Round, _coin_number: usize) {
        let now = SystemTime::now();

        let maybe_msg = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            let decided = match rbc_state.acs_decided_set.clone() {
                Some(decided) => decided,
                None => return,
            };

            let msg = build_local_batch_beacon_construct(
                rbc_state,
                round,
                self.myid,
                self.batch_size,
                decided.as_slice(),
            );

            if msg.packets.is_empty() {
                None
            } else {
                Some(msg)
            }
        };

        if let Some(msg) = maybe_msg {
            let prot_msg = CoinMsg::BatchBeaconConstruct(msg.clone(), self.myid, round);
            self.broadcast(prot_msg, round).await;
            self.process_batch_secret_shares(msg, self.myid, round).await;
        }

        self.add_benchmark(
            String::from("reconstruct_beacon"),
            now.elapsed().unwrap().as_nanos(),
        );
    }

    pub async fn process_secret_shares(
        &mut self,
        recon_shares: BatchWSSReconMsg,
        share_sender: Replica,
        coin_num: usize,
        round: Round,
    ) {
        // Single-packet replay path (e.g. draining
        // `pre_acs_beacon_constructs` after ACS finalisation). Route
        // it through the same Merkle-validating batch ingest so there
        // is exactly one reconstruction code path.
        let batch = BatchBeaconConstructMsg {
            origin: share_sender,
            round,
            packets: vec![RecoveredCoinSharesMsg {
                coin_num,
                packet: recon_shares,
            }],
        };
        self.process_batch_secret_shares(batch, share_sender, round).await;
    }

    /// Inbound `MulticastRecoveredShares(round, sender, snapshot)`.
    ///
    /// **P0-A.1 fire-and-forget audit**: this handler used to await
    /// the spawn_blocking audit (~80–300 ms per round) and apply
    /// blame writes inline on the consensus task's main loop. That
    /// blocked every other inbound message (in particular round-r+1
    /// AVSSSend packets) for the audit duration, which empirically
    /// caused PPT b=500 / b=1000 to stall after only ~30 / ~20 s of
    /// an 80 s benchmark.
    ///
    /// The new flow:
    ///   1. Cheap inline writes (~µs): record this sender's snapshot
    ///      in `post_complaint_packets`, return early if we have
    ///      not yet reached the n-f threshold or the audit already
    ///      ran.
    ///   2. Once threshold hits, spawn a *detached* `tokio::spawn`
    ///      task that runs the full `audit_post_complaint_pure`
    ///      computation on the blocking pool. The detached task
    ///      sends the resulting `blame_events` back to the main
    ///      loop via `Context::audit_tx`.
    ///   3. The main loop's `tokio::select!` arm picks up the
    ///      `AuditCompletion` and calls `finalize_audit_completion`,
    ///      which performs the blame / ban / release writes. All
    ///      `Context` mutations therefore stay single-threaded and
    ///      sequential — no Mutex needed on the hot path.
    ///
    /// Safety / liveness preserved:
    ///   - The audit's correctness depends only on its inputs
    ///     (decided set, comm vectors, post packets, audit senders,
    ///     batch_size, hash_context), all of which are owned values
    ///     moved into the detached task. No shared mutable state.
    ///   - The blame writes (`ban_dealer_global`,
    ///     `maybe_release_round`) only affect future rounds; round-r
    ///     beacons have already been emitted before audit completes,
    ///     so deferring blame writes by the wall-clock duration of
    ///     the audit task does not change protocol output for any
    ///     committed round.
    pub async fn process_multicast_recovered_shares(
        &mut self,
        recovered: MulticastRecoveredSharesMsg,
        sender: Replica,
        round: Round,
    ) {
        if !self.round_state.contains_key(&round) {
            log::warn!(
                "[PPT][POST-COMPLAINT-DROP] node {} round {} missing round_state for sender {}",
                self.myid,
                round,
                sender
            );
            return;
        }

        let threshold = self.num_nodes - self.num_faults;

        log::info!(
            "[PPT][POST-COMPLAINT-RECV] node {} round {} got recovered-share multicast from {}",
            self.myid,
            round,
            sender
        );

        let detach_inputs = {
            let rbc_state = self.round_state.get_mut(&round).unwrap();

            if rbc_state.cleared {
                log::warn!(
                    "[PPT][POST-COMPLAINT-DROP] node {} round {} already cleared; dropping sender {}",
                    self.myid,
                    round,
                    sender
                );
                return;
            }

            // Phase F1 -- guard against late-arriving MulticastRecoveredShares:
            // once the audit task has fired (post_complaint_complete=true), any
            // additional inbound multicast for this round is unused (the audit's
            // n-f quorum already cleared, and audit_post_complaint_pure was
            // already invoked with the snapshot at that time). Pre-Phase-F1 we
            // would still `.insert(sender, recovered)` here, accumulating
            // ~4.5 MB per late arrival in a map that nobody consumes -- a
            // direct OOM contributor at batch=1000 / n=16 (~67 MB per round
            // just from stale insertions).
            if rbc_state.post_complaint_complete {
                log::debug!(
                    "[PPT][POST-COMPLAINT-SKIP] node {} round {} already completed; \
                     dropping late multicast from sender {}",
                    self.myid,
                    round,
                    sender
                );
                return;
            }

            // Latest snapshot from this sender overwrites previous one.
            rbc_state.post_complaint_packets.insert(sender, recovered);

            log::info!(
                "[PPT][POST-COMPLAINT-COUNT] node {} round {} now has {}/{} recovered-share multicasts (async threshold)",
                self.myid,
                round,
                rbc_state.post_complaint_packets.len(),
                threshold
            );

            // Asynchronous completion rule: n-f snapshots are enough to run the audit.
            if rbc_state.post_complaint_packets.len() < threshold {
                return;
            }

            let mut senders: Vec<Replica> = rbc_state.post_complaint_packets.keys().copied().collect();
            senders.sort_unstable();
            senders.truncate(threshold);

            rbc_state.post_complaint_complete = true;

            // Phase F1 -- MOVE (not clone) `comm_vectors` and
            // `post_complaint_packets` into the detached audit task. The
            // only consumer of either map for this round is
            // `audit_post_complaint_pure` inside the detached task; cloning
            // here used to double the in-flight memory footprint by ~67 MB
            // per round at batch=1000 / n=16, and the original copies in
            // `rbc_state` were never read again before
            // `maybe_release_round` cleared them. Using `mem::take` drops
            // the rbc_state copies the moment the audit task takes
            // ownership.
            //
            // Late-arriving AVSS validations that fire after this point
            // would call `store_avss_packet`, which writes into the
            // (now-empty) `comm_vectors` map. That is harmless: audit has
            // already used the pre-take snapshot, and the new entries are
            // small (one Hash per coin per dealer) and get cleared by
            // `maybe_release_round` at round end. Safety / correctness:
            // verified that no other code path reads either of these maps
            // for `round` after the audit fires.
            Some((
                rbc_state.acs_decided_set.clone().unwrap_or_default(),
                std::mem::take(&mut rbc_state.comm_vectors),
                std::mem::take(&mut rbc_state.post_complaint_packets),
                senders,
            ))
        };

        let (decided, comm_vectors, post_packets, audit_senders) = match detach_inputs {
            Some(v) => v,
            None => return,
        };

        // P0-A.1: detach the audit work into an independent
        // `tokio::spawn` task. The main loop returns immediately,
        // unblocking subsequent inbound messages (especially round-r+1
        // AVSSSend packets) instead of awaiting the ~80-300 ms
        // spawn_blocking audit synchronously.
        let hash_context = std::sync::Arc::clone(&self.hash_context);
        let batch_size = self.batch_size;
        let myid = self.myid;
        let audit_tx = self.audit_tx.clone();

        tokio::spawn(async move {
            let blame_events = tokio::task::spawn_blocking(move || {
                audit_post_complaint_pure(
                    decided,
                    comm_vectors,
                    post_packets,
                    audit_senders,
                    batch_size,
                    &hash_context,
                )
            })
            .await
            .unwrap_or_else(|e| {
                log::error!(
                    "[PPT][LEVEL2] post-complaint audit blocking task join error round {}: {}",
                    round, e
                );
                Vec::new()
            });

            log::info!(
                "[PPT][POST-COMPLAINT] node {} round {} async audit produced {} blame events; publishing to main loop",
                myid,
                round,
                blame_events.len()
            );

            let _ = audit_tx.send(crate::node::context::AuditCompletion {
                round,
                blame_events,
            });
        });
    }

    /// Apply the blame / ban / release writes from a completed
    /// fire-and-forget audit. Called from the main loop's
    /// `tokio::select!` arm on `audit_rx.recv()`.
    pub async fn finalize_audit_completion(
        &mut self,
        completion: crate::node::context::AuditCompletion,
    ) {
        let round = completion.round;
        let blame_events = completion.blame_events;
        let threshold = self.num_nodes - self.num_faults;

        if blame_events.is_empty() {
            log::info!(
                "[PPT][POST-COMPLAINT] node {} round {} async audit completed (n-f threshold {}) with no blame events",
                self.myid,
                round,
                threshold
            );
            // The audit just transitioned to complete; if every
            // coin was already emitted before audit completion,
            // release the round's transient state now.
            self.maybe_release_round(round);
            return;
        }

        let mut to_ban: HashSet<Replica> = HashSet::new();
        {
            let rbc_state = match self.round_state.get_mut(&round) {
                Some(rbc_state) => rbc_state,
                None => {
                    // round_state already released between the audit
                    // task spawning and finishing -- nothing to do.
                    return;
                }
            };
            for (dealer, reason) in blame_events.into_iter() {
                log::error!(
                    "[PPT][POST-BLAME] node {} round {} blaming dealer {}: {:?}",
                    self.myid,
                    round,
                    dealer,
                    reason
                );
                rbc_state.blame_dealer(dealer, round, reason);
                to_ban.insert(dealer);
            }
        }
        for dealer in to_ban.into_iter() {
            self.ban_dealer_global(dealer);
        }
        self.maybe_release_round(round);
    }

    /**
     * Pure-PPT beacon emit path:
     *   - record the round-r coin-0 beacon as the source of θ for round r+1
     *     (PPT slide pg 28: dealer must not be able to predict θ);
     *   - bootstrap round r+1 immediately (full-committee mode, no anytrust
     *     sampling — every honest node is always a dealer);
     *   - emit the beacon to the syncer for external consumption;
     *   - if `coin_num` is the canonical first-matched coin
     *     (see `Context::first_matched_coin_value`), additionally tag the
     *     emit so consumers that need a uniform [1,n] sample (slide pg 32)
     *     can pick it deterministically.
     *
     * We intentionally DO NOT clear round state here; the post-ACS audit
     * still needs the full disclosure data to remain available.
     */
    #[async_recursion]
    pub async fn self_coin_check_transmit(
        &mut self,
        round: Round,
        coin_num: usize,
        numbers: Vec<Vec<u8>>,
    ) {
        // `numbers` is the super-invertible extraction output for this
        // coin column: `R = |decided| - f` independent beacon values.
        // Each is emitted to the syncer under a distinct global index
        // `coin_num * R + i`. `R` is identical at every honest node
        // for this round (same ACS-decided set), so the per-index
        // agreement check on the syncer stays well-defined.
        let outputs_per_coin = numbers.len().max(1);

        // The canonical "coin-0 beacon" used to seed θ_{r+1} and the
        // next ACS round's common-coin derivation is sub-output 0 of
        // coin 0 (deterministic + agreed across honest nodes).
        let seed_value = numbers.first().cloned().unwrap_or_default();

        // Per-coin BEACON-OUT marker demoted to debug (Phase E): at
        // batch=1000 the per-coin INFO logs cost ~500 ms of
        // synchronous stderr work per round on the consensus main
        // task. The round-level markers + syncer BeaconRecon are
        // sufficient for production tracking.
        log::debug!(
            "[PPT][STAGE][BEACON-OUT] node {} round {} coin {} ({} extracted outputs)",
            self.myid,
            round,
            coin_num,
            numbers.len()
        );
        let is_last_coin = self.round_state
            .get(&round)
            .map(|state| state.recon_secrets.contains(&(self.batch_size - 1)))
            .unwrap_or(false);

        // Memory-bound: once every coin in the round has been emitted
        // AND the post-ACS audit quorum (n-f recovered-share
        // multicasts) has fired, this round is fully done. Wipe the
        // round's transient state in place so a long-running beacon
        // doesn't accumulate unbounded round_state entries.
        if is_last_coin {
            self.maybe_release_round(round);
        }

        if coin_num == 0 {
            // ACS common-coin fallback seed: the previous-round beacon
            // bytes seed the deterministic genesis/out-of-window hash
            // coin (`coin_bit_for`). The unpredictable in-window ACS
            // coin no longer uses this (it is AVSS-sealed), and the
            // degree-test θ no longer uses it either (Fiat-Shamir from
            // the dealer's commitment) — so the old per-round θ
            // recording + AVSS theta-buffer replay are gone.
            self.record_beacon_output_for_coin(round, seed_value.as_slice());

            // Pure PPT: every node is always a dealer in the next round.
            let next_round: Round = round + self.frequency;

            if next_round <= self.max_rounds {
                if !self.round_state.contains_key(&next_round) {
                    let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
                    self.round_state.insert(next_round, rbc_new_state);
                    log::info!(
                        "[PPT][ROUND-INIT] node {} round {} eagerly created future PPT round {}",
                        self.myid,
                        round,
                        next_round
                    );
                }

                self.ppt_try_start_round(next_round).await;
            }
        } else if is_last_coin {
            if let Some(state) = self.round_state.get_mut(&round) {
                state.ppt_round_finished = true;
            }
            log::info!(
                "Reconstruction ended for round {} at time {:?}",
                round,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            );
            log::info!("Number of messages passed between nodes: {}", self.num_messages);
        }

        // Emit each extracted beacon value under its own global index.
        for (i, number) in numbers.into_iter().enumerate() {
            let global_index = coin_num * outputs_per_coin + i;

            // PPT pg 30-32 first-match optimisation: report whether this
            // particular output lies in the rejection-sampling "good
            // range", so a downstream BFT consumer that wants a uniform
            // [1,n] beacon can deterministically pick the first matched
            // value in (coin, sub-output) order.
            if self.coin_value_matches_uniform_range(number.as_slice()) {
                log::info!(
                    "[PPT][FIRST-MATCH] node {} round {} coin {} sub {} (index {}) lies in the uniform-sample range [0, n*floor(p/n))",
                    self.myid,
                    round,
                    coin_num,
                    i,
                    global_index
                );
            }

            let cancel_handler = self.sync_send.send(
                0,
                SyncMsg {
                    sender: self.myid,
                    state: SyncState::BeaconRecon(round, self.myid, global_index, number),
                    value: 0,
                }
            ).await;
            self.add_cancel_handler(cancel_handler);
        }
    }
}

// ---------------------------------------------------------------------
// Tests for the problem-2 fix: reconstruction from ANY f+1 validated
// providers (liveness under withholding) + Merkle/leaf-index binding
// of relayed shares (a Byzantine provider cannot inject or mis-position
// a share).
// ---------------------------------------------------------------------
#[cfg(test)]
mod recon_fix_tests {
    use super::*;
    use crate::node::shamir::two_field::TwoFieldDealer;
    use crypto::aes_hash::{HashState, MerkleTree};
    use num_bigint::BigUint;
    use types::beacon::BatchWSSReconMsg;

    fn hash_state() -> HashState {
        HashState::new([5u8; 16], [29u8; 16], [23u8; 16])
    }

    fn small_prime() -> BigUint {
        BigUint::from(685373784908497u64)
    }

    fn large_prime() -> BigUint {
        BigUint::parse_bytes(
            b"57896044618658097711785492504343953926634992332820282019728792003956564819949",
            10,
        )
        .unwrap()
    }

    fn pad32(b: &BigUint) -> [u8; 32] {
        let mut bytes = b.to_bytes_be();
        assert!(bytes.len() <= 32);
        let mut out = vec![0u8; 32 - bytes.len()];
        out.append(&mut bytes);
        out.try_into().expect("padded to 32")
    }

    /// Build one honest dealer's coin-0 sharing for `n` nodes and
    /// return: the secret, the per-provider small-field shares, the
    /// per-provider Merkle proofs, the committed root, and the
    /// per-provider nonce. Provider `p` (0-based) holds the share at
    /// evaluation point `p + 1`.
    struct HonestSharing {
        secret: BigUint,
        shares: Vec<[u8; 32]>,
        masks: Vec<[u8; 32]>,
        f_larges: Vec<[u8; 32]>,
        nonces: Vec<[u8; 32]>,
        proofs: Vec<crypto::aes_hash::Proof>,
        root: Hash,
    }

    fn build_honest_sharing(n: usize, f: usize, seed: u64) -> HonestSharing {
        use num_bigint::RandBigInt;
        use rand::SeedableRng;

        let p = small_prime();
        let q = large_prime();
        let dealer = TwoFieldDealer::new(p.clone(), q.clone(), f + 1, n);
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let secret = rng.gen_biguint_range(&BigUint::from(0u32), &p);
        let sampled = dealer.sample_shares(secret.clone());

        let mut shares: Vec<[u8; 32]> = Vec::with_capacity(n);
        let mut masks: Vec<[u8; 32]> = Vec::with_capacity(n);
        let mut f_larges: Vec<[u8; 32]> = Vec::with_capacity(n);
        let mut nonces: Vec<[u8; 32]> = Vec::with_capacity(n);
        let hc = hash_state();
        let mut leaf_hashes: Vec<Hash> = Vec::with_capacity(n);
        for i in 0..n {
            let f_share = pad32(&sampled.secret_shares[i].1);
            let g_share = pad32(&sampled.mask_shares[i].1);
            let f_large = pad32(&sampled.f_large_shares[i].1);
            let nonce = pad32(&rng.gen_biguint_range(&BigUint::from(0u32), &q));
            leaf_hashes.push(types::beacon::avss_commit_leaf(&f_share, &g_share, &f_large, &nonce));
            shares.push(f_share);
            masks.push(g_share);
            f_larges.push(f_large);
            nonces.push(nonce);
        }

        let trees = MerkleTree::build_trees(vec![leaf_hashes], &hc);
        let mt = &trees[0];
        let proofs: Vec<crypto::aes_hash::Proof> = (0..n).map(|i| mt.gen_proof(i)).collect();
        let root = mt.root();

        HonestSharing {
            secret,
            shares,
            masks,
            f_larges,
            nonces,
            proofs,
            root,
        }
    }

    /// One provider's coin-0 reconstruction packet for a single dealer.
    fn provider_packet(s: &HonestSharing, dealer: Replica, provider: usize) -> BatchWSSReconMsg {
        BatchWSSReconMsg {
            origin: provider as Replica,
            secrets: vec![s.shares[provider]],
            nonces: vec![s.nonces[provider]],
            origins: vec![dealer],
            mps: vec![s.proofs[provider].clone()],
            mask_shares: vec![s.masks[provider]],
            // BigUint test fixture — Some channel.
            f_large_shares: Some(vec![s.f_larges[provider]]),
            empty: false,
        }
    }

    fn accept_one(
        s: &HonestSharing,
        dealer: Replica,
        provider: usize,
    ) -> Vec<CoinVerifyOutcome> {
        let mut roots = HashMap::new();
        roots.insert(dealer, s.root);
        let decided = vec![dealer];
        let banned: HashSet<Replica> = HashSet::new();
        verify_recon_shares_pure(
            vec![CoinVerifyInputs {
                coin_num: 0,
                provider: provider as Replica,
                packet: provider_packet(s, dealer, provider),
                roots_for_dealer: roots,
            }],
            &decided,
            &banned,
            &hash_state(),
        )
    }

    /// Liveness: any f+1 validated providers reconstruct the secret,
    /// even when the other (n - f - 1) providers withhold. Every
    /// distinct f+1 subset must yield the SAME secret.
    #[test]
    fn any_f_plus_one_providers_reconstruct_same_secret() {
        let (n, f) = (4usize, 1usize);
        let s = build_honest_sharing(n, f, 0x1234);
        let threshold = f + 1;
        let p = small_prime();

        // Try several distinct provider subsets of size f+1, including
        // ones that EXCLUDE specific nodes (simulating withholding).
        let subsets = vec![
            vec![0usize, 1],
            vec![1, 2],
            vec![2, 3],
            vec![0, 3],
        ];
        for subset in subsets {
            assert_eq!(subset.len(), threshold);
            let eval_points: Vec<usize> = subset.iter().map(|p| p + 1).collect();
            let shares: Vec<BigUint> = subset
                .iter()
                .map(|p| BigUint::from_bytes_be(&s.shares[*p]))
                .collect();
            let extractor = BatchExtractor::new(eval_points, p.clone());
            let recovered = extractor.recover_one(&shares);
            assert_eq!(
                recovered, s.secret,
                "subset {:?} must reconstruct the dealer's secret",
                subset
            );
        }
    }

    /// Integrity: an honest provider's share validates against the
    /// dealer's committed Merkle root with the correct leaf index.
    #[test]
    fn honest_provider_share_validates() {
        let (n, f) = (4usize, 1usize);
        let s = build_honest_sharing(n, f, 0xABCD);
        for provider in 0..n {
            let outcomes = accept_one(&s, 0, provider);
            assert_eq!(outcomes.len(), 1, "provider {} share must be accepted", provider);
            match &outcomes[0] {
                CoinVerifyOutcome::Accepted {
                    coin_num,
                    dealer,
                    provider: pv,
                    share,
                } => {
                    assert_eq!(*coin_num, 0);
                    assert_eq!(*dealer, 0);
                    assert_eq!(*pv, provider as Replica);
                    assert_eq!(*share, s.shares[provider]);
                }
            }
        }
    }

    /// Integrity: a Byzantine provider that relays ANOTHER node's
    /// share+proof (correct Merkle proof, but for the wrong leaf
    /// index) must be rejected by the leaf-index binding. Without
    /// this, the share would be interpolated at the wrong evaluation
    /// point and corrupt the result.
    #[test]
    fn wrong_leaf_index_is_rejected() {
        let (n, f) = (4usize, 1usize);
        let s = build_honest_sharing(n, f, 0x5555);
        let dealer = 0 as Replica;
        let mut roots = HashMap::new();
        roots.insert(dealer, s.root);

        // Provider claims to be node 2 but relays node 0's share+proof.
        let mut packet = provider_packet(&s, dealer, 0);
        packet.origin = 2;
        let outcomes = verify_recon_shares_pure(
            vec![CoinVerifyInputs {
                coin_num: 0,
                provider: 2, // wire sender / claimed slot
                packet,
                roots_for_dealer: roots,
            }],
            &[dealer],
            &HashSet::new(),
            &hash_state(),
        );
        assert!(
            outcomes.is_empty(),
            "share whose Merkle leaf-index != claimed provider must be rejected"
        );
    }

    /// Integrity: a tampered share (does not match the committed leaf)
    /// is rejected even though it is presented with the dealer's real
    /// root and the correct leaf index.
    #[test]
    fn tampered_share_is_rejected() {
        let (n, f) = (4usize, 1usize);
        let s = build_honest_sharing(n, f, 0x9999);
        let dealer = 0 as Replica;
        let mut roots = HashMap::new();
        roots.insert(dealer, s.root);

        let mut packet = provider_packet(&s, dealer, 1);
        // Flip the share so hash(share, nonce) != committed leaf.
        let mut garbage = packet.secrets[0];
        garbage[31] ^= 0x01;
        packet.secrets[0] = garbage;

        let outcomes = verify_recon_shares_pure(
            vec![CoinVerifyInputs {
                coin_num: 0,
                provider: 1,
                packet,
                roots_for_dealer: roots,
            }],
            &[dealer],
            &HashSet::new(),
            &hash_state(),
        );
        assert!(
            outcomes.is_empty(),
            "share that does not hash to the committed Merkle leaf must be rejected"
        );
    }

    /// Integrity: a share presented against the WRONG dealer root
    /// (e.g. a Byzantine provider re-roots a self-built tree) is
    /// rejected.
    #[test]
    fn wrong_root_is_rejected() {
        let (n, f) = (4usize, 1usize);
        let s = build_honest_sharing(n, f, 0x4242);
        let dealer = 0 as Replica;

        let mut bad_root = s.root;
        bad_root[0] ^= 0x01;
        let mut roots = HashMap::new();
        roots.insert(dealer, bad_root);

        let outcomes = verify_recon_shares_pure(
            vec![CoinVerifyInputs {
                coin_num: 0,
                provider: 0,
                packet: provider_packet(&s, dealer, 0),
                roots_for_dealer: roots,
            }],
            &[dealer],
            &HashSet::new(),
            &hash_state(),
        );
        assert!(
            outcomes.is_empty(),
            "share whose proof root != dealer's committed root must be rejected"
        );
    }

    /// End-to-end (pure layer): validate shares from only f+1 providers
    /// via `verify_recon_shares_pure`, feed the accepted shares into a
    /// `BatchExtractor`, and confirm the dealer's secret is recovered —
    /// the other providers withholding entirely.
    #[test]
    fn validate_then_reconstruct_from_f_plus_one_only() {
        let (n, f) = (7usize, 2usize);
        let s = build_honest_sharing(n, f, 0x0F0F);
        let dealer = 0 as Replica;
        let threshold = f + 1;

        // Only providers {1, 3, 5} respond; the rest withhold.
        let responding = vec![1usize, 3, 5];
        assert_eq!(responding.len(), threshold);

        let mut accepted_shares: HashMap<usize, BigUint> = HashMap::new();
        for &provider in &responding {
            let outcomes = accept_one(&s, dealer, provider);
            assert_eq!(outcomes.len(), 1);
            if let CoinVerifyOutcome::Accepted { provider: pv, share, .. } = &outcomes[0] {
                accepted_shares.insert(*pv as usize, BigUint::from_bytes_be(share));
            }
        }

        let mut providers: Vec<usize> = accepted_shares.keys().copied().collect();
        providers.sort_unstable();
        let eval_points: Vec<usize> = providers.iter().map(|p| p + 1).collect();
        let shares: Vec<BigUint> = providers
            .iter()
            .map(|p| accepted_shares.get(p).unwrap().clone())
            .collect();

        let extractor = BatchExtractor::new(eval_points, small_prime());
        let recovered = extractor.recover_one(&shares);
        assert_eq!(
            recovered, s.secret,
            "secret must reconstruct from f+1 responding providers while the rest withhold"
        );
    }
}
