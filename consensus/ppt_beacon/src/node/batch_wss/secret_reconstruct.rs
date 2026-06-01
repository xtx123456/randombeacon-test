use std::{
    collections::{HashMap, HashSet},
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
use crate::node::shamir::two_field::TwoFieldDealer;
use std::time::UNIX_EPOCH;
use types::SyncMsg;
use types::SyncState;

fn packet_lengths_ok(packet: &BatchWSSReconMsg) -> bool {
    let l = packet.origins.len();
    packet.secrets.len() == l
        && packet.nonces.len() == l
        && packet.mps.len() == l
        && packet.mask_shares.len() == l
        && packet.f_large_shares.len() == l
}

/// One coin-packet's pre-verified inputs, ready to be moved into
/// `tokio::task::spawn_blocking` together with all the other
/// coin-packets in the same `BatchBeaconConstruct` message.
///
/// `coeffs_for_dealer[dealer] = degree_test_coeffs[dealer][coin_num]`
/// is pre-cloned out of `CTRBCState::degree_test_coeffs` BEFORE the
/// blocking task starts, so the closure does not need to touch
/// `&self` or any shared state.
pub(crate) struct CoinVerifyInputs {
    pub coin_num: usize,
    pub packet: BatchWSSReconMsg,
    pub coeffs_for_dealer: HashMap<Replica, Vec<Val>>,
}

/// One verification outcome of a single `(coin_num, dealer)` pair
/// inside a coin-packet, produced by `verify_batch_shares_pure`.
pub(crate) enum CoinVerifyOutcome {
    /// Share verified successfully. Caller (back on the async task)
    /// should write it via `CTRBCState::add_secret_share`.
    Accepted {
        coin_num: usize,
        dealer: Replica,
        share: Val,
    },
    /// Dealer is in the decided set but has no degree-test
    /// coefficients stored locally for this coin → permanent ban
    /// (matches the pre-Level-2 `MissingDegreeTestCoeffs` blame
    /// path).
    MissingMaterial {
        coin_num: usize,
        dealer: Replica,
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

                let item = hash_context
                    .hash_batch(vec![share], vec![nonce])
                    .into_iter()
                    .next()
                    .expect("hash_batch returned no item");

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

/// CPU-heavy bulk verifier for a whole batch of coin-packets. This
/// is the body that used to run inline on the consensus task's
/// worker thread for every `BatchBeaconConstruct` message it
/// received. Lifting it into a pure free function (no `&self`,
/// no `&CTRBCState`) lets the Level 2 hot path call it inside
/// `tokio::task::spawn_blocking`, so the heavy degree-test +
/// big-int arithmetic loop runs in tokio's blocking pool on
/// another core in parallel with consensus message handling.
///
/// **Contract identical to the previous inline loop in
/// `ingest_secret_shares_only`**: a share is accepted iff
///   - its dealer is in the ACS-decided set,
///   - the dealer is not in the banned set,
///   - degree-test coefficients for `(dealer, coin_num)` are
///     locally available,
///   - `verify_share(share_sender + 1, f_large, g_share, h_coeffs, theta)`
///     returns true.
/// Missing-coeffs dealers in the decided set are surfaced as
/// `MissingMaterial` outcomes for the caller to ban; all other
/// failures (filter mismatch, verify_share false) are silent drops.
pub(crate) fn verify_batch_shares_pure(
    inputs: Vec<CoinVerifyInputs>,
    theta: &BigUint,
    decided: &[Replica],
    banned: &HashSet<Replica>,
    share_sender: Replica,
    secret_domain: &BigUint,
    nonce_domain: &BigUint,
    num_faults: usize,
    num_nodes: usize,
) -> Vec<CoinVerifyOutcome> {
    let verifier = TwoFieldDealer::new(
        secret_domain.clone(),
        nonce_domain.clone(),
        num_faults + 1,
        num_nodes,
    );
    let decided_set: HashSet<Replica> = decided.iter().copied().collect();

    let mut outcomes = Vec::new();

    for input in inputs.into_iter() {
        let CoinVerifyInputs {
            coin_num,
            packet,
            coeffs_for_dealer,
        } = input;

        for ((((dealer, share), _nonce), mask_share), f_large_share) in packet
            .origins
            .iter()
            .zip(packet.secrets.iter())
            .zip(packet.nonces.iter())
            .zip(packet.mask_shares.iter())
            .zip(packet.f_large_shares.iter())
        {
            if !decided_set.contains(dealer) || banned.contains(dealer) {
                continue;
            }

            let coeffs = match coeffs_for_dealer.get(dealer) {
                Some(coeffs) => coeffs,
                None => {
                    outcomes.push(CoinVerifyOutcome::MissingMaterial {
                        coin_num,
                        dealer: *dealer,
                    });
                    continue;
                }
            };

            let f_large = BigUint::from_bytes_be(f_large_share);
            let g_share = BigUint::from_bytes_be(mask_share);
            let h_coeffs: Vec<BigUint> = coeffs
                .iter()
                .map(|bytes| BigUint::from_bytes_be(bytes.as_slice()))
                .collect();

            if !verifier.verify_share(share_sender + 1, &f_large, &g_share, &h_coeffs, theta) {
                continue;
            }

            outcomes.push(CoinVerifyOutcome::Accepted {
                coin_num,
                dealer: *dealer,
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
    filtered.f_large_shares.clear();

    for idx in 0..packet.origins.len() {
        let dealer = packet.origins[idx];
        if decided_set.contains(&dealer) {
            filtered.origins.push(dealer);
            filtered.secrets.push(packet.secrets[idx].clone());
            filtered.nonces.push(packet.nonces[idx].clone());
            filtered.mps.push(packet.mps[idx].clone());
            filtered.mask_shares.push(packet.mask_shares[idx].clone());
            filtered
                .f_large_shares
                .push(packet.f_large_shares[idx].clone());
        }
    }

    filtered
}

fn ready_coins(state: &CTRBCState, batch_size: usize) -> Vec<usize> {
    let extractor = match state.batch_extractor.as_ref() {
        Some(extractor) => extractor,
        None => return Vec::new(),
    };
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
            let provider_map = match coin_map.get(&dealer) {
                Some(provider_map) => provider_map,
                None => {
                    coin_ready = false;
                    break;
                }
            };

            for eval_point in extractor.eval_points.iter().copied() {
                let provider = eval_point - 1;
                if !provider_map.contains_key(&provider) {
                    coin_ready = false;
                    break;
                }
            }

            if !coin_ready {
                break;
            }
        }

        if coin_ready {
            ready.push(coin);
        }
    }

    ready
}

fn build_batch_matrix_for_coins(
    state: &CTRBCState,
    ready_coin_nums: &[usize],
    num_nodes: usize,
) -> HashMap<usize, HashMap<usize, BigUint>> {
    let extractor = state
        .batch_extractor
        .as_ref()
        .expect("batch_extractor missing");
    let decided = state
        .acs_decided_set
        .as_ref()
        .expect("acs_decided_set missing");

    let mut shares_matrix: HashMap<usize, HashMap<usize, BigUint>> = HashMap::new();

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

            let mut entry: HashMap<usize, BigUint> = HashMap::new();

            for eval_point in extractor.eval_points.iter().copied() {
                let provider = eval_point - 1;
                if let Some(share) = provider_map.get(&provider) {
                    entry.insert(eval_point, share.clone());
                }
            }

            if !entry.is_empty() {
                shares_matrix.insert(coin * num_nodes + dealer, entry);
            }
        }
    }

    shares_matrix
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
            log::info!(
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

        let theta = match self.theta_for_round(round) {
            Some(t) => t,
            None => {
                log::error!(
                    "[PPT][THETA-MISS] node {} process_batch_secret_shares: θ for round {} not yet recorded; dropping whole batch from {}",
                    self.myid,
                    round,
                    sender,
                );
                self.add_benchmark(
                    String::from("process_batchreconstruct"),
                    now.elapsed().unwrap().as_nanos(),
                );
                return;
            }
        };

        // (2) Assemble per-packet inputs. Snapshot only the slice of
        //     degree_test_coeffs the verifier actually needs, so the
        //     blocking closure stays self-contained.
        let mut verify_inputs: Vec<CoinVerifyInputs> =
            Vec::with_capacity(recovered.packets.len());
        let decided_set: HashSet<Replica> = decided.iter().copied().collect();
        {
            let rbc_state = self.round_state.get(&round).unwrap();
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
                let mut coeffs_for_dealer: HashMap<Replica, Vec<Val>> = HashMap::new();
                for dealer in packet.origins.iter() {
                    if !decided_set.contains(dealer) || banned.contains(dealer) {
                        continue;
                    }
                    if let Some(coeffs) = rbc_state
                        .degree_test_coeffs
                        .get(dealer)
                        .and_then(|cs| cs.get(coin_num))
                    {
                        coeffs_for_dealer.insert(*dealer, coeffs.clone());
                    }
                    // Else: leave coeffs_for_dealer empty for this dealer
                    // → verify_batch_shares_pure will surface it as a
                    // MissingMaterial outcome and we'll ban below.
                }
                verify_inputs.push(CoinVerifyInputs {
                    coin_num,
                    packet,
                    coeffs_for_dealer,
                });
            }
        }

        // (3) Level 2: bulk degree-test on tokio blocking pool.
        let use_for_batch = decided.contains(&sender) && !banned.contains(&sender);
        let secret_domain = self.secret_domain.clone();
        let nonce_domain = self.nonce_domain.clone();
        let num_faults = self.num_faults;
        let num_nodes = self.num_nodes;
        let banned_clone = banned.clone();
        let decided_clone = decided.clone();
        let share_sender = sender;

        let outcomes = tokio::task::spawn_blocking(move || {
            verify_batch_shares_pure(
                verify_inputs,
                &theta,
                &decided_clone,
                &banned_clone,
                share_sender,
                &secret_domain,
                &nonce_domain,
                num_faults,
                num_nodes,
            )
        })
        .await
        .unwrap_or_else(|e| {
            log::error!(
                "[PPT][LEVEL2] bulk share-verify blocking task join error round {} sender {}: {}",
                round, sender, e
            );
            Vec::new()
        });

        // (4) Apply outcomes back to state in a single short window.
        let mut missing_dealers: HashSet<Replica> = HashSet::new();
        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for outcome in outcomes.into_iter() {
                match outcome {
                    CoinVerifyOutcome::Accepted {
                        coin_num,
                        dealer,
                        share,
                    } => {
                        if use_for_batch {
                            rbc_state.add_secret_share(coin_num, dealer, share_sender, share);
                        }
                    }
                    CoinVerifyOutcome::MissingMaterial { coin_num, dealer } => {
                        if missing_dealers.insert(dealer) {
                            log::error!(
                                "[PPT][TWO-FIELD-BLAME] missing degree-test coeffs for decided dealer {} round {} coin {}; blaming dealer and rejecting this share path",
                                dealer, round, coin_num
                            );
                        }
                        rbc_state.blame_dealer(
                            dealer,
                            round,
                            BlameReason::MissingDegreeTestCoeffs { coin_num },
                        );
                    }
                }
            }
        }
        for dealer in missing_dealers.into_iter() {
            self.ban_dealer_global(dealer);
        }

        self.add_benchmark(
            String::from("process_batchreconstruct"),
            now.elapsed().unwrap().as_nanos(),
        );

        // (5) Trigger batch recovery exactly once for the whole batch.
        self.maybe_recover_ready_coins(round).await;
    }

    fn ingest_secret_shares_only(
        &mut self,
        recon_shares: BatchWSSReconMsg,
        share_sender: Replica,
        coin_num: usize,
        round: Round,
    ) {
        let now = SystemTime::now();
        log::info!(
            "[PPT][BATCH-INGEST] node {} ingesting coin-packet from {} for round {} coin {} origins {:?}",
            self.myid,
            share_sender,
            round,
            coin_num,
            recon_shares.origins
        );

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        if !packet_lengths_ok(&recon_shares) {
            log::warn!(
                "[PPT][BATCH-INGEST] dropping malformed packet from {} round {} coin {}",
                share_sender,
                round,
                coin_num
            );
            self.add_benchmark(
                String::from("process_batchreconstruct"),
                now.elapsed().unwrap().as_nanos(),
            );
            return;
        }

        let decided = {
            let rbc_state = self.round_state.get_mut(&round).unwrap();

            if rbc_state.cleared {
                self.add_benchmark(
                    String::from("process_batchreconstruct"),
                    now.elapsed().unwrap().as_nanos(),
                );
                return;
            }

            if rbc_state.batch_reconstruction_complete {
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
                        "[PPT][BATCH-CACHE] node {} caching BeaconConstruct from {} for round {} coin {} until ACS finalization",
                        self.myid,
                        share_sender,
                        round,
                        coin_num
                    );
                    rbc_state
                        .pre_acs_beacon_constructs
                        .push((recon_shares, share_sender, coin_num));

                    self.add_benchmark(
                        String::from("process_batchreconstruct"),
                        now.elapsed().unwrap().as_nanos(),
                    );
                    return;
                }
            }
        };

        // θ for this round MUST be available by the time we reach
        // ingest: ACS-decide implies AVSS-validate, which implies
        // theta_for_round(round) was Some at AVSS time, which is
        // monotone (θ is only ever inserted, never removed). If it
        // is somehow None here, refuse to validate any share rather
        // than panicking — dropping the packet is safe (the dealer
        // can re-announce later via the recovered-share multicast)
        // and we surface the anomaly via [PPT][THETA-MISS].
        let theta = match self.theta_for_round(round) {
            Some(t) => t,
            None => {
                log::error!(
                    "[PPT][THETA-MISS] node {} ingest_secret_shares_only: θ for round {} not yet recorded; dropping packet from {} coin {}",
                    self.myid,
                    round,
                    share_sender,
                    coin_num
                );
                self.add_benchmark(
                    String::from("process_batchreconstruct"),
                    now.elapsed().unwrap().as_nanos(),
                );
                return;
            }
        };
        let verifier = TwoFieldDealer::new(
            self.secret_domain.clone(),
            self.nonce_domain.clone(),
            self.num_faults + 1,
            self.num_nodes,
        );

        let mut missing_material_dealers: HashSet<Replica> = HashSet::new();
        let banned = self.banned_dealers.clone();

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            let use_for_batch = decided.contains(&share_sender) && !banned.contains(&share_sender);

            for ((((dealer, share), _nonce), mask_share), f_large_share) in recon_shares
                .origins
                .iter()
                .zip(recon_shares.secrets.iter())
                .zip(recon_shares.nonces.iter())
                .zip(recon_shares.mask_shares.iter())
                .zip(recon_shares.f_large_shares.iter())
            {
                if !decided.contains(dealer) || banned.contains(dealer) {
                    continue;
                }

                let coeffs = match rbc_state
                    .degree_test_coeffs
                    .get(dealer)
                    .and_then(|coins| coins.get(coin_num))
                {
                    Some(coeffs) => coeffs,
                    None => {
                        log::error!(
                            "[PPT][TWO-FIELD-BLAME] missing degree-test coeffs for decided dealer {} round {} coin {}; blaming dealer and rejecting this share path",
                            dealer,
                            round,
                            coin_num
                        );
                        missing_material_dealers.insert(*dealer);
                        continue;
                    }
                };

                let f_large = BigUint::from_bytes_be(f_large_share);
                let g_share = BigUint::from_bytes_be(mask_share);
                let h_coeffs: Vec<BigUint> = coeffs
                    .iter()
                    .map(|bytes| BigUint::from_bytes_be(bytes.as_slice()))
                    .collect();

                if !verifier.verify_share(share_sender + 1, &f_large, &g_share, &h_coeffs, &theta) {
                    log::warn!(
                        "[PPT][TWO-FIELD] dropped share_sender {} -> dealer {} round {} coin {} due to degree-test failure",
                        share_sender,
                        dealer,
                        round,
                        coin_num
                    );
                    continue;
                }

                if use_for_batch {
                    rbc_state.add_secret_share(coin_num, *dealer, share_sender, *share);
                }
            }

            // Apply blame once per dealer for this packet/coin, instead of silently continuing.
            for dealer in missing_material_dealers.iter().copied() {
                rbc_state.blame_dealer(
                    dealer,
                    round,
                    BlameReason::MissingDegreeTestCoeffs { coin_num },
                );
            }
        }
        for dealer in missing_material_dealers.into_iter() {
            self.ban_dealer_global(dealer);
        }

        self.add_benchmark(
            String::from("process_batchreconstruct"),
            now.elapsed().unwrap().as_nanos(),
        );
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
    async fn maybe_recover_ready_coins(&mut self, round: Round) {
        let ready_initial = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            if rbc_state.batch_reconstruction_complete {
                return;
            }
            ready_coins(rbc_state, self.batch_size)
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
                ready_coins(rbc_state, self.batch_size)
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

        let (extractor, shares_matrix, decided) = {
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
            let extractor = rbc_state
                .batch_extractor
                .clone()
                .expect("ACS-decided BatchExtractor missing");
            let shares_matrix =
                build_batch_matrix_for_coins(rbc_state, coin_set.as_slice(), self.num_nodes);
            (extractor, shares_matrix, decided)
        };

        log::info!(
            "[PPT][BATCH-RECOVER] node {} round {} recovering coins {:?}",
            self.myid,
            round,
            coin_set
        );

        // Heavy Lagrange interpolation runs on tokio's blocking pool.
        let recovered = tokio::task::spawn_blocking(move || {
            extractor.batch_recover(&shares_matrix)
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

            for (composite_key, secret) in recovered.into_iter() {
                let coin = composite_key / self.num_nodes;
                let dealer = composite_key % self.num_nodes;

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
        // Legacy / compatibility path:
        // single packet ingest, then one recovery attempt.
        self.ingest_secret_shares_only(recon_shares, share_sender, coin_num, round);
        self.maybe_recover_ready_coins(round).await;
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

            // Latest snapshot from this sender overwrites previous one.
            rbc_state.post_complaint_packets.insert(sender, recovered);

            log::info!(
                "[PPT][POST-COMPLAINT-COUNT] node {} round {} now has {}/{} recovered-share multicasts (async threshold)",
                self.myid,
                round,
                rbc_state.post_complaint_packets.len(),
                threshold
            );

            if rbc_state.post_complaint_complete {
                log::info!(
                    "[PPT][POST-COMPLAINT-SKIP] node {} round {} already completed",
                    self.myid,
                    round
                );
                return;
            }

            // Asynchronous completion rule: n-f snapshots are enough to run the audit.
            if rbc_state.post_complaint_packets.len() < threshold {
                return;
            }

            let mut senders: Vec<Replica> = rbc_state.post_complaint_packets.keys().copied().collect();
            senders.sort_unstable();
            senders.truncate(threshold);

            rbc_state.post_complaint_complete = true;

            Some((
                rbc_state.acs_decided_set.clone().unwrap_or_default(),
                rbc_state.comm_vectors.clone(),
                rbc_state.post_complaint_packets.clone(),
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
    pub async fn self_coin_check_transmit(&mut self, round: Round, coin_num: usize, number: Vec<u8>) {
        log::info!(
            "[PPT][STAGE][BEACON-OUT] node {} round {} coin {}",
            self.myid,
            round,
            coin_num
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
            // PPT pg 28: θ for the next round is derived from this round's
            // coin-0 beacon, which the next round's dealer cannot influence.
            self.record_beacon_output_for_theta(round, number.as_slice());

            // Self-bootstrap MMR ABA common coin: store the same
            // beacon output as the seed for the *next* ACS round's
            // coin derivation. Honest nodes agree on `number` bit-
            // for-bit (ACS + batch-recover safety) so every node's
            // coin_bit_for(round+1, ..) returns the identical bit.
            self.record_beacon_output_for_coin(round, number.as_slice());

            // Pure PPT: every node is always a dealer in the next round.
            let next_round: Round = round + self.frequency;

            // Now that θ(next_round) is in the cache, replay any
            // AVSSSend packets that arrived for `next_round` BEFORE
            // we had θ available (the async race window between fast
            // and slow peers). This is the live-path fix for the
            // "[PPT][THETA] requested theta but no previous-round
            // beacon recorded" panic that used to crash slow nodes.
            self.drain_pending_avss_for(next_round).await;

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

        // PPT pg 30-32 first-match optimisation: report whether this
        // particular coin lies in the rejection-sampling "good range",
        // so a downstream BFT consumer that wants a uniform [1,n] beacon
        // can deterministically pick the first matched coin in batch
        // order across all reconstructed coins.
        let matched_in_range = self.coin_value_matches_uniform_range(number.as_slice());
        if matched_in_range {
            log::info!(
                "[PPT][FIRST-MATCH] node {} round {} coin {} value lies in the uniform-sample range [0, n*floor(p/n))",
                self.myid,
                round,
                coin_num
            );
        }

        let cancel_handler = self.sync_send.send(
            0,
            SyncMsg {
                sender: self.myid,
                state: SyncState::BeaconRecon(round, self.myid, coin_num, number),
                value: 0,
            }
        ).await;
        self.add_cancel_handler(cancel_handler);
    }
}
