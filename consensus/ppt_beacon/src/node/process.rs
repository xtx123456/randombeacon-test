use std::{collections::HashSet, sync::Arc};

use async_recursion::async_recursion;
use crypto::hash::verf_mac;
use num_bigint::BigUint;
use types::{
    beacon::{CoinMsg, WrapperMsg},
    Replica, Round, SyncMsg, SyncState,
};

use crate::node::acs::state::ACSInstanceState;
use crate::node::acs::init::build_local_proposal;

use super::Context;

impl Context {
    fn replicas_to_set(dealers: &[Replica]) -> HashSet<usize> {
        dealers.iter().map(|x| *x as usize).collect()
    }

    fn set_to_sorted_replicas(dealers: &HashSet<usize>) -> Vec<Replica> {
        let mut v: Vec<Replica> = dealers.iter().copied().map(|x| x as Replica).collect();
        v.sort_unstable();
        v
    }

    pub fn check_proposal(self: &Context, wrapper_msg: Arc<WrapperMsg>) -> bool {
        let byte_val =
            bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");

        let sec_key = match self.sec_key_map.get(&wrapper_msg.sender) {
            Some(val) => val,
            None => panic!("Secret key not available, this shouldn't happen"),
        };

        if !verf_mac(&byte_val, sec_key.as_slice(), &wrapper_msg.mac) {
            log::warn!("MAC Verification failed.");
            return false;
        }

        true
    }

    pub(crate) async fn process_msg(self: &mut Context, wrapper_msg: WrapperMsg) {
        log::debug!("Received protocol msg: {:?}", wrapper_msg);

        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg) {
            self.num_messages += 1;
            self.choose_fn(wrapper_msg).await;
        } else {
            log::warn!(
                "MAC Verification failed for message {:?}",
                wrapper_msg.protmsg
            );
        }
    }

    pub(crate) async fn choose_fn(self: &mut Context, wrapper_msg: WrapperMsg) {
        match wrapper_msg.clone().protmsg {
            CoinMsg::AVSSSend(beaconmsg, transcript_root, dealer, round) => {
                self.process_avss_send(beaconmsg, transcript_root, dealer, round).await;
            }
            CoinMsg::AVSSReady(dealer, transcript_root, sender, round) => {
                self.process_avss_ready(dealer, transcript_root, sender, round).await;
            }
            CoinMsg::AVSSComplete(dealer, transcript_root, sender, round) => {
                self.process_avss_complete(dealer, transcript_root, sender, round).await;
            }
            CoinMsg::CTRBCInit(beaconmsg, ctr) => {
                self.process_rbcinit(beaconmsg, ctr).await;
            }
            CoinMsg::CTRBCEcho(ctr, root, echo_sender) => {
                self.process_echo(ctr, root, echo_sender).await;
            }
            CoinMsg::CTRBCReady(ctr, root, ready_sender) => {
                self.process_ready(ctr, root, ready_sender).await;
            }
            CoinMsg::CTRBCReconstruct(ctr, root, recon_sender) => {
                self.process_reconstruct(ctr, root, recon_sender).await;
            }
            CoinMsg::BinaryAAEcho(_, echo_sender, round) => {
                log::error!(
                    "[PPT][PURE] rejecting legacy BinaryAAEcho from {} for round {}",
                    echo_sender,
                    round
                );
            }
            CoinMsg::BinaryAAEcho2(_, echo2_sender, round) => {
                log::error!(
                    "[PPT][PURE] rejecting legacy BinaryAAEcho2 from {} for round {}",
                    echo2_sender,
                    round
                );
            }
            CoinMsg::BeaconConstruct(shares, share_sender, coin_num, round) => {
                log::debug!(
                    "[PPT][LEGACY-BEACON-CONSTRUCT] received per-coin BeaconConstruct from node {} for coin {} in round {}",
                    share_sender, coin_num, round
                );
                self.process_secret_shares(shares, share_sender, coin_num, round).await;
            }

            CoinMsg::BatchBeaconConstruct(msg, share_sender, round) => {
                log::debug!(
                    "[PPT][BATCH-BEACON-CONSTRUCT] received batched BeaconConstruct from node {} with {} coin-packets in round {}",
                    share_sender,
                    msg.packets.len(),
                    round
                );
                self.process_batch_secret_shares(msg, share_sender, round).await;
            }

            CoinMsg::MulticastRecoveredShares(msg, sender, round) => {
                log::info!(
                    "[PPT][MULTICAST-DISPATCH] node {} dispatching recovered-share multicast from {} for round {}",
                    self.myid,
                    sender,
                    round
                );
                self.process_multicast_recovered_shares(msg, sender, round).await;
            }
            CoinMsg::GatherEcho(_, sender, round) => {
                log::warn!(
                    "[PPT][GATHER-OFF] dropping legacy GatherEcho from {} for round {}",
                    sender,
                    round
                );
            }
            CoinMsg::GatherEcho2(_, sender, round) => {
                log::warn!(
                    "[PPT][GATHER-OFF] dropping legacy GatherEcho2 from {} for round {}",
                    sender,
                    round
                );
            }
            CoinMsg::ACSInit((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSInit from {} for round {} dealers {:?}",
                    self.myid,
                    sender,
                    round,
                    dealers
                );
                self.process_acs_init(sender, round, dealers).await;
            }
            CoinMsg::ACSOutput((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSOutput from {} for round {} dealers {:?}",
                    self.myid,
                    sender,
                    round,
                    dealers
                );
                self.process_acs_output(sender, round, dealers).await;
            }
            _ => {}
        }
    }

    pub(crate) async fn increment_round(&mut self, round: u32) {
        if round >= self.curr_round {
            self.curr_round = round + 1;
        }
    }

    #[async_recursion]
    pub(crate) async fn maybe_broadcast_acs_init_from_avss(&mut self, round: Round) {
        let threshold = self.num_nodes - self.num_faults;
        let support_threshold = self.num_faults + 1;
        let support_threshold = self.num_faults + 1;
        let support_threshold = self.num_faults + 1;

        let maybe_payload = {
            let rbc_state = match self.round_state.get(&round) {
                Some(rbc_state) => rbc_state,
                None => return,
            };

            if rbc_state.avss_completed_dealers.len() < threshold {
                return;
            }

            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

            if st.init_sent {
                return;
            }

            st.completed_dealers.clear();
            for dealer in rbc_state.avss_completed_dealers.iter().copied() {
                st.mark_completed(dealer);
            }

            let local_dealers: Vec<Replica> = {
                let mut dealers: Vec<Replica> = build_local_proposal(st)
                    .into_iter()
                    .map(|dealer| dealer as Replica)
                    .collect();
                dealers.sort_unstable();
                dealers
            };

            st.init_sent = true;
            Some(local_dealers)
        };

        let local_dealers = match maybe_payload {
            Some(local_dealers) => local_dealers,
            None => return,
        };

        log::info!(
            "[PPT][ACS-FASTPATH] node {} round {} AVSS completed for {} dealers; broadcasting ACSInit directly from completed dealer set {:?}",
            self.myid,
            round,
            local_dealers.len(),
            local_dealers
        );

        let init_msg = CoinMsg::ACSInit((self.myid, round, local_dealers.clone()));
        self.broadcast(init_msg, round).await;
        self.process_acs_init(self.myid, round, local_dealers).await;
    }

    fn avss_local_packet_valid(
        &self,
        beacon_msg: &types::beacon::BeaconMsg,
        transcript_root: &crypto::hash::Hash,
        dealer: Replica,
        round: Round,
    ) -> bool {
        let public_root = crypto::hash::do_hash(beacon_msg.serialize_ctrbc().as_slice());
        if public_root != *transcript_root {
            log::warn!(
                "[PPT][AVSS] transcript root mismatch for dealer {} round {}",
                dealer,
                round
            );
            return false;
        }

        if !beacon_msg.verify_proofs(&self.hash_context) {
            log::warn!(
                "[PPT][AVSS] invalid Merkle/share proof for dealer {} round {}",
                dealer,
                round
            );
            return false;
        }

        let degree_test_coeffs = match beacon_msg.degree_test_coeffs.as_ref() {
            Some(coeffs) => coeffs,
            None => return false,
        };
        let mask_shares = match beacon_msg.mask_shares.as_ref() {
            Some(mask_shares) => mask_shares,
            None => return false,
        };
        let f_large_shares = match beacon_msg.f_large_shares.as_ref() {
            Some(f_large_shares) => f_large_shares,
            None => return false,
        };

        if degree_test_coeffs.len() != self.batch_size
            || mask_shares.len() != self.batch_size
            || f_large_shares.len() != self.batch_size
        {
            log::warn!(
                "[PPT][AVSS] malformed two-field batch lengths from dealer {} round {}",
                dealer,
                round
            );
            return false;
        }

        let verifier = crate::node::shamir::two_field::TwoFieldDealer::new(
            self.secret_domain.clone(),
            self.nonce_domain.clone(),
            self.num_faults + 1,
            self.num_nodes,
        );
        let theta = self.get_previous_theta(round.saturating_sub(1));

        for coin_num in 0..self.batch_size {
            let coeffs = &degree_test_coeffs[coin_num];
            let h_coeffs: Vec<BigUint> = coeffs
                .iter()
                .map(|bytes| BigUint::from_bytes_be(bytes.as_slice()))
                .collect();
            let f_large = BigUint::from_bytes_be(f_large_shares[coin_num].as_slice());
            let g_share = BigUint::from_bytes_be(mask_shares[coin_num].as_slice());

            if !verifier.verify_share(self.myid + 1, &f_large, &g_share, &h_coeffs, &theta) {
                log::warn!(
                    "[PPT][AVSS] degree-test failed for dealer {} round {} coin {} at node {}",
                    dealer,
                    round,
                    coin_num,
                    self.myid
                );
                return false;
            }
        }

        true
    }

    fn maybe_mark_dealer_completed(&mut self, round: Round, dealer: Replica) -> bool {
        let threshold = self.num_nodes - self.num_faults;
        let rbc_state = match self.round_state.get_mut(&round) {
            Some(rbc_state) => rbc_state,
            None => return false,
        };

        if rbc_state.avss_completed_dealers.contains(&dealer) {
            return false;
        }

        if !rbc_state.avss_local_valid.contains(&dealer) {
            return false;
        }

        if rbc_state.matching_avss_complete_count(dealer) < threshold {
            return false;
        }

        rbc_state.avss_completed_dealers.insert(dealer);
        true
    }

    fn maybe_prepare_avss_complete(
        &mut self,
        round: Round,
        dealer: Replica,
    ) -> Option<crypto::hash::Hash> {
        let threshold = self.num_nodes - self.num_faults;
        let rbc_state = match self.round_state.get_mut(&round) {
            Some(rbc_state) => rbc_state,
            None => return None,
        };

        if !rbc_state.avss_local_valid.contains(&dealer) {
            return None;
        }

        if rbc_state.avss_complete_sent.contains(&dealer) {
            return None;
        }

        if rbc_state.matching_avss_ready_count(dealer) < threshold {
            return None;
        }

        let transcript_root = match rbc_state.avss_transcript_roots.get(&dealer) {
            Some(root) => *root,
            None => return None,
        };

        rbc_state.avss_complete_sent.insert(dealer);
        Some(transcript_root)
    }

    #[async_recursion]
    pub async fn process_avss_send(
        &mut self,
        beacon_msg: types::beacon::BeaconMsg,
        transcript_root: crypto::hash::Hash,
        dealer: Replica,
        round: Round,
    ) {
        if !self.round_state.contains_key(&round) {
            let rbc_new_state = crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        if !self.avss_local_packet_valid(&beacon_msg, &transcript_root, dealer, round) {
            return;
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            if rbc_state.avss_local_valid.contains(&dealer) {
                return;
            }
            rbc_state.store_avss_packet(dealer, beacon_msg, transcript_root);
            rbc_state.avss_local_valid.insert(dealer);
            rbc_state.add_avss_ready_vote(dealer, self.myid, transcript_root);
        }

        let ready_msg = CoinMsg::AVSSReady(dealer, transcript_root, self.myid, round);
        self.broadcast(ready_msg, round).await;

        if let Some(complete_root) = self.maybe_prepare_avss_complete(round, dealer) {
            let complete_msg = CoinMsg::AVSSComplete(dealer, complete_root, self.myid, round);
            self.broadcast(complete_msg, round).await;
            self.process_avss_complete(dealer, complete_root, self.myid, round).await;
        }

        if self.maybe_mark_dealer_completed(round, dealer) {
            self.maybe_broadcast_acs_init_from_avss(round).await;
        }
    }

    #[async_recursion]
    pub async fn process_avss_ready(
        &mut self,
        dealer: Replica,
        transcript_root: crypto::hash::Hash,
        sender: Replica,
        round: Round,
    ) {
        if !self.round_state.contains_key(&round) {
            let rbc_new_state = crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            rbc_state.add_avss_ready_vote(dealer, sender, transcript_root);
        }

        if let Some(complete_root) = self.maybe_prepare_avss_complete(round, dealer) {
            let complete_msg = CoinMsg::AVSSComplete(dealer, complete_root, self.myid, round);
            self.broadcast(complete_msg, round).await;
            self.process_avss_complete(dealer, complete_root, self.myid, round).await;
        }
    }

    #[async_recursion]
    pub async fn process_avss_complete(
        &mut self,
        dealer: Replica,
        transcript_root: crypto::hash::Hash,
        sender: Replica,
        round: Round,
    ) {
        if !self.round_state.contains_key(&round) {
            let rbc_new_state = crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            rbc_state.add_avss_complete_vote(dealer, sender, transcript_root);
        }

        if self.maybe_mark_dealer_completed(round, dealer) {
            log::info!(
                "[PPT][AVSS-COMPLETE] node {} round {} dealer {} marked completed",
                self.myid,
                round,
                dealer
            );
            self.maybe_broadcast_acs_init_from_avss(round).await;
        }
    }
}

impl Context {
    #[async_recursion]
    pub async fn process_acs_init(
        &mut self,
        sender: Replica,
        round: Round,
        dealers: Vec<Replica>,
    ) {
        log::info!(
            "[PPT][ACS-INIT] node {} got ACSInit from {} for round {} with {} dealers",
            self.myid,
            sender,
            round,
            dealers.len()
        );

        let threshold = self.num_nodes - self.num_faults;

        let maybe_output = {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

            let dealer_set = Self::replicas_to_set(&dealers);
            st.record_init(sender as usize, dealer_set);

            let maybe = st.maybe_build_output(threshold, support_threshold);
            if maybe.is_some() && !st.output_sent {
                st.mark_output_sent();
                maybe
            } else {
                None
            }
        };

        if let Some(decided_set) = maybe_output {
            let decided_replicas = Self::set_to_sorted_replicas(&decided_set);

            log::info!(
                "[PPT][ACS-OUTPUT] node {} round {} broadcasting ACSOutput {:?}",
                self.myid,
                round,
                decided_replicas
            );

            let out_msg = CoinMsg::ACSOutput((self.myid, round, decided_replicas.clone()));
            self.broadcast(out_msg, round).await;
            self.process_acs_output(self.myid, round, decided_replicas)
                .await;
        }
    }

    #[async_recursion]
    pub async fn process_acs_output(
        &mut self,
        sender: Replica,
        round: Round,
        dealers: Vec<Replica>,
    ) {
        log::info!(
            "[PPT][ACS-OUT] node {} got ACSOutput from {} for round {} dealers {:?}",
            self.myid,
            sender,
            round,
            dealers
        );

        let threshold = self.num_nodes - self.num_faults;

        let final_decision = {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

            let dealer_set = Self::replicas_to_set(&dealers);
            st.record_final_output(sender as usize, dealer_set);
            st.try_finalize_from_outputs(threshold)
        };

        if let Some(decided_set) = final_decision {
            let decided_vec = Self::set_to_sorted_replicas(&decided_set);
            self.finalize_acs_round(round, decided_vec).await;
        }
    }

    #[async_recursion]
    async fn finalize_acs_round(&mut self, round: Round, mut decided_vec: Vec<Replica>) {
        decided_vec.sort_unstable();

        log::error!(
            "[PPT][ACS-DECIDE] node {} round {} FINAL ACS decision = {:?}",
            self.myid,
            round,
            decided_vec
        );

        let replay_packets = {
            let rbc_state = self
                .round_state
                .entry(round)
                .or_insert_with(|| crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes));

            rbc_state.acs_decided_set = Some(decided_vec.clone());
            rbc_state.batch_reconstruction_complete = false;
            rbc_state.recovered_shares_multicast_sent = false;
            rbc_state.post_complaint_complete = false;
            rbc_state.post_complaint_packets.clear();
            rbc_state.pending_beacon_outputs.clear();
            rbc_state.ppt_round_finished = false;

            use crate::node::shamir::two_field::BatchExtractor;
            let eval_points: Vec<usize> = decided_vec.iter().map(|dealer| *dealer + 1).collect();

            rbc_state.batch_extractor = if eval_points.is_empty() {
                None
            } else {
                Some(BatchExtractor::new(
                    eval_points.clone(),
                    rbc_state.secret_domain.clone(),
                ))
            };

            log::error!(
                "[PPT][ACS-RECON] node {} round {} immutable decided_set = {:?}, eval_points = {:?}",
                self.myid,
                round,
                decided_vec,
                eval_points
            );

            std::mem::take(&mut rbc_state.pre_acs_beacon_constructs)
        };

        self.reconstruct_beacon(round, 0).await;

        if !replay_packets.is_empty() {
            log::info!(
                "[PPT][BATCH-REPLAY] node {} round {} replaying {} cached BeaconConstruct packets after ACS finalization",
                self.myid,
                round,
                replay_packets.len()
            );
        }

        for (packet, share_sender, coin_num) in replay_packets.into_iter() {
            self.process_secret_shares(packet, share_sender, coin_num, round)
                .await;
        }

        let cancel_handler = self
            .sync_send
            .send(
                0,
                SyncMsg {
                    sender: self.myid,
                    state: SyncState::BeaconFin(round, self.myid),
                    value: 0,
                },
            )
            .await;

        self.add_cancel_handler(cancel_handler);
    }
}
