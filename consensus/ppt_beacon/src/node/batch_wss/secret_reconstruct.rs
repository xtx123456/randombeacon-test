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

    #[async_recursion]
    pub async fn process_batch_secret_shares(
        &mut self,
        recovered: BatchBeaconConstructMsg,
        sender: Replica,
        round: Round,
    ) {
        log::info!(
            "[PPT][BATCH-RECV] node {} got batched BeaconConstruct from {} for round {} with {} coin-packets",
            self.myid,
            sender,
            round,
            recovered.packets.len()
        );

        // Important:
        // ingest the whole batched packet first, and only then trigger recovery ONCE.
        // This avoids turning one batched message into 20 singleton recoveries.
        for entry in recovered.packets.into_iter() {
            self.ingest_secret_shares_only(entry.packet, sender, entry.coin_num, round);
        }

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

        let theta = self.get_previous_theta(round.saturating_sub(1));
        let verifier = TwoFieldDealer::new(
            self.secret_domain.clone(),
            self.nonce_domain.clone(),
            self.num_faults + 1,
            self.num_nodes,
        );

        let mut missing_material_dealers: HashSet<Replica> = HashSet::new();

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            let use_for_batch = decided.contains(&share_sender);

            for ((((dealer, share), _nonce), mask_share), f_large_share) in recon_shares
                .origins
                .iter()
                .zip(recon_shares.secrets.iter())
                .zip(recon_shares.nonces.iter())
                .zip(recon_shares.mask_shares.iter())
                .zip(recon_shares.f_large_shares.iter())
            {
                if !decided.contains(dealer) {
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

        self.add_benchmark(
            String::from("process_batchreconstruct"),
            now.elapsed().unwrap().as_nanos(),
        );
    }
    
    #[async_recursion]
    async fn maybe_recover_ready_coins(&mut self, round: Round) {
        let ready = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };
            if rbc_state.batch_reconstruction_complete {
                return;
            }
            ready_coins(rbc_state, self.batch_size)
        };

        if ready.is_empty() {
            return;
        }

        let (multicast_msg, outputs) = {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            if rbc_state.batch_reconstruction_complete {
                return;
            }

            let decided = rbc_state
                .acs_decided_set
                .clone()
                .expect("ACS decided set missing during ready-coin recovery");

            log::info!(
                "[PPT][BATCH-RECOVER] node {} round {} recovering ready coins {:?}",
                self.myid,
                round,
                ready
            );

            let extractor = rbc_state
                .batch_extractor
                .clone()
                .expect("ACS-decided BatchExtractor missing");

            let shares_matrix =
                build_batch_matrix_for_coins(rbc_state, ready.as_slice(), self.num_nodes);
            let recovered = extractor.batch_recover(&shares_matrix);

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
            for coin in ready.iter().copied() {
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

            let multicast_msg = if disclosed.is_empty() {
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

        let (decided, comm_vectors, post_packets, audit_senders) = {
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

            (
                rbc_state.acs_decided_set.clone().unwrap_or_default(),
                rbc_state.comm_vectors.clone(),
                rbc_state.post_complaint_packets.clone(),
                senders,
            )
        };

        let mut blame_events: Vec<(Replica, BlameReason)> = Vec::new();

        for dealer in decided.into_iter() {
            let root_vec = match comm_vectors.get(&dealer) {
                Some(root_vec) => root_vec,
                None => {
                    log::error!(
                        "[PPT][POST-COMPLAINT-BLAME] node {} round {} missing commitment vector for decided dealer {}; blaming dealer",
                        self.myid,
                        round,
                        dealer
                    );
                    blame_events.push((dealer, BlameReason::MissingCommitmentVector));
                    continue;
                }
            };

            for coin_num in 0..self.batch_size {
                if coin_num >= root_vec.len() {
                    continue;
                }

                let expected_root = root_vec[coin_num];
                let mut complete = true;

                for share_owner in audit_senders.iter().copied() {
                    let packet_bundle = match post_packets.get(&share_owner) {
                        Some(packet_bundle) => packet_bundle,
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

                    if !crypto::aes_hash::Proof::validate_batch(&packet.mps, &self.hash_context) {
                        log::warn!(
                            "[PPT][POST-COMPLAINT-DROP] node {} round {} got invalid proof batch in multicast packet from share_owner {} for coin {}",
                            self.myid,
                            round,
                            share_owner,
                            coin_num
                        );
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

                    let item = self
                        .hash_context
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

        if blame_events.is_empty() {
            log::info!(
                "[PPT][POST-COMPLAINT] node {} round {} completed at async threshold {} with no blame events",
                self.myid,
                round,
                threshold
            );
            return;
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            for (dealer, reason) in blame_events.into_iter() {
                log::error!(
                    "[PPT][POST-BLAME] node {} round {} blaming dealer {}: {:?}",
                    self.myid,
                    round,
                    dealer,
                    reason
                );
                rbc_state.blame_dealer(dealer, round, reason);
            }
        }
    }

    /**
     * Beacons can be reconstructed in HashRand for two reasons:
     * a) For external consumption (which are sent to the syncer)
     * b) For internal consumption (for AnyTrust sampling and efficiency)
     *
     * We intentionally DO NOT clear round state here anymore; post-ACS complaint
     * needs the full disclosure data to remain available after batch recovery.
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

        if coin_num == 0 {
            if let Some(state) = self.round_state.get_mut(&round) {
                state.committee_elected = true;
            }

            let committee = self.elect_committee(number.clone()).await;

            // Pure PPT:
            // the committee of round r directly bootstraps the next frequency round.
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

                {
                    let next_state = self.round_state.get_mut(&next_round).unwrap();
                    next_state.set_committee(committee.clone());
                    next_state.ppt_round_started = false;
                    log::info!(
                        "[PPT][COMMITTEE-HANDOFF] node {} round {} stored committee {:?} into future PPT round {}",
                        self.myid,
                        round,
                        committee,
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
