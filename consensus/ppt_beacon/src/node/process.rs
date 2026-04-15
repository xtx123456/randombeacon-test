use types::{Replica, Round};
use crate::node::acs::state::ACSInstanceState;
use std::sync::Arc;

use crypto::hash::verf_mac;
use types::{
    beacon::{WrapperMsg, CoinMsg},
    SyncMsg, SyncState,
};

use super::Context;

impl Context {
    pub fn check_proposal(self: &Context, wrapper_msg: Arc<WrapperMsg>) -> bool {
        let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => val,
            None => panic!("Secret key not available, this shouldn't happen"),
        };
        if !verf_mac(&byte_val, &sec_key.as_slice(), &wrapper_msg.mac) {
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
            log::warn!("MAC Verification failed for message {:?}", wrapper_msg.protmsg);
        }
    }

    pub(crate) async fn choose_fn(self: &mut Context, wrapper_msg: WrapperMsg) {
        match wrapper_msg.clone().protmsg {
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
            CoinMsg::GatherEcho(gather, sender, round) => {
                self.process_gatherecho(gather.nodes, sender, round).await;
            }
            CoinMsg::GatherEcho2(gather, sender, round) => {
                self.process_gatherecho2(gather.nodes, sender, round).await;
            }
            CoinMsg::BinaryAAEcho(_, echo_sender, round) => {
                log::warn!(
                    "[PPT][LEGACY-OFF] dropping BinaryAAEcho from {} for round {}",
                    echo_sender,
                    round
                );
            }
            CoinMsg::BinaryAAEcho2(_, echo2_sender, round) => {
                log::warn!(
                    "[PPT][LEGACY-OFF] dropping BinaryAAEcho2 from {} for round {}",
                    echo2_sender,
                    round
                );
            }
            CoinMsg::BeaconConstruct(shares, share_sender, coin_num, round) => {
                log::debug!(
                    "Received Beacon Construct message from node {} for coin number {} in round {}",
                    share_sender, coin_num, round
                );
                self.process_secret_shares(shares, share_sender, coin_num, round).await;
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
            CoinMsg::ACSInit((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSInit from {} for round {} dealers {:?}",
                    self.myid, sender, round, dealers
                );
                self.process_acs_init(sender, round, dealers).await;
            }
            CoinMsg::ACSOutput((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSOutput from {} for round {} dealers {:?}",
                    self.myid, sender, round, dealers
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
}

impl Context {
    pub async fn process_acs_init(&mut self, sender: Replica, round: Round, dealers: Vec<Replica>) {
        log::info!(
            "[PPT][ACS-INIT] node {} got ACSInit from {} for round {} with {} dealers",
            self.myid, sender, round, dealers.len()
        );

        let threshold = self.num_nodes - self.num_faults;
        let st = self.acs_state
            .entry(round)
            .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

        let dealer_set: std::collections::HashSet<usize> =
            dealers.iter().map(|x| *x as usize).collect();

        st.record_output(sender, dealer_set);

        if st.try_decide_union(threshold) {
            if let Some(decided) = st.decided_set.clone() {
                let mut decided_vec: Vec<usize> = decided.iter().copied().collect();
                decided_vec.sort_unstable();

                if !st.output_sent {
                    st.output_sent = true;
                    let decided_replicas: Vec<Replica> =
                        decided_vec.iter().map(|x| *x as Replica).collect();
                    let out_msg = CoinMsg::ACSOutput((self.myid, round, decided_replicas.clone()));
                    self.broadcast(out_msg.clone(), round).await;
                    self.process_acs_output(self.myid, round, decided_replicas).await;
                }
            }
        }
    }

    pub async fn process_acs_output(&mut self, sender: Replica, round: Round, dealers: Vec<Replica>) {
        log::info!(
            "[PPT][ACS-OUT] node {} got ACSOutput from {} for round {} dealers {:?}",
            self.myid, sender, round, dealers
        );

        let threshold = self.num_nodes - self.num_faults;
        let st = self.acs_state
            .entry(round)
            .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

        let dealer_set: std::collections::HashSet<usize> =
            dealers.iter().map(|x| *x as usize).collect();

        st.record_final_output(sender, dealer_set);

        let recv_count = st.final_outputs_seen.len();
        if recv_count < threshold || st.final_decided {
            return;
        }

        st.final_decided = true;

        let mut union_set = std::collections::HashSet::new();
        for s in st.final_outputs_seen.values() {
            union_set.extend(s.iter().copied());
        }
        let mut decided_vec: Vec<Replica> = union_set.iter().copied().map(|x| x as Replica).collect();
        decided_vec.sort_unstable();
        st.final_decided_set = Some(union_set);

        log::error!(
            "[PPT][ACS-DECIDE] node {} round {} FINAL ACS decision = {:?}",
            self.myid, round, decided_vec
        );

        let replay_packets = {
            let rbc_state = self.round_state
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
                Some(BatchExtractor::new(eval_points.clone(), rbc_state.secret_domain.clone()))
            };

            log::error!(
                "[PPT][ACS-RECON] node {} round {} immutable decided_set = {:?}, eval_points = {:?}",
                self.myid, round, decided_vec, eval_points
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
            self.process_secret_shares(packet, share_sender, coin_num, round).await;
        }

        let cancel_handler = self.sync_send.send(
            0,
            SyncMsg {
                sender: self.myid,
                state: SyncState::BeaconFin(round, self.myid),
                value: 0,
            }
        ).await;
        self.add_cancel_handler(cancel_handler);
    }
}