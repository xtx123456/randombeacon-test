use types::{Replica, Round};
use crate::node::acs::state::ACSInstanceState;
use std::{sync::Arc};

use crypto::hash::{verf_mac};
use num_bigint::BigUint;
use num_traits::pow;
use types::{beacon::{WrapperMsg, CoinMsg}, SyncMsg, SyncState};

use super::Context;

/*
    PPT Beacon protocol with deferred-complaint control flow.

    New control flow (Phase 2 rewrite):
    1. Dealers share secrets via BAwVSS + CT-RBC (unchanged)
    2. Gather (W1 → W2) collects terminated dealer sets (unchanged)
    3. After W2 completes, nodes broadcast ACSInit with their local terminated_secrets
    4. ACS decides the final dealer set via union of n-f ACSOutput messages
    5. ACS final decision DIRECTLY drives reconstruction — no Binary AA needed for frequency rounds
    6. Binary AA is retained only for non-frequency rounds (lightweight consensus)

    Key change: reconstruction is gated by ACS decision, not by Binary AA termination.
*/
impl Context{
    pub fn check_proposal(self:&Context,wrapper_msg: Arc<WrapperMsg>) -> bool {
        // validate MAC
        let byte_val = bincode::serialize(&wrapper_msg.protmsg).expect("Failed to serialize object");
        let sec_key = match self.sec_key_map.get(&wrapper_msg.clone().sender) {
            Some(val) => {val},
            None => {panic!("Secret key not available, this shouldn't happen")},
        };
        if !verf_mac(&byte_val,&sec_key.as_slice(),&wrapper_msg.mac){
            log::warn!("MAC Verification failed.");
            return false;
        }
        true
    }
    
    pub(crate) async fn process_msg(self: &mut Context, wrapper_msg: WrapperMsg){
        log::debug!("Received protocol msg: {:?}",wrapper_msg);
        let msg = Arc::new(wrapper_msg.clone());
        if self.check_proposal(msg){
            self.num_messages += 1;
            self.choose_fn(wrapper_msg).await;
        }
        else {
            log::warn!("MAC Verification failed for message {:?}",wrapper_msg.protmsg);
        }
    }

    pub(crate) async fn choose_fn(self: &mut Context, wrapper_msg: WrapperMsg){
        match wrapper_msg.clone().protmsg {
            // Messages related to Cachin-Tessaro's Reliable Broadcast
            CoinMsg::CTRBCInit(beaconmsg,ctr ) =>{
                self.process_rbcinit(beaconmsg, ctr).await;
            },
            CoinMsg::CTRBCEcho(ctr, root, echo_sender) => {
                self.process_echo(ctr, root, echo_sender).await;
            },
            CoinMsg::CTRBCReady(ctr, root, ready_sender) => {
                self.process_ready(ctr, root, ready_sender).await;
            },
            CoinMsg::CTRBCReconstruct(ctr, root, recon_sender)=>{
                self.process_reconstruct(ctr, root, recon_sender).await;
            },
            // Messages related to the Gather protocol
            CoinMsg::GatherEcho(gather,sender,round) =>{
                self.process_gatherecho(gather.nodes, sender, round).await;
            },
            CoinMsg::GatherEcho2(gather,sender,round) =>{
                self.process_gatherecho2(gather.nodes, sender, round).await;
            },
            // Messages related to Binary Approximate Agreement (retained for non-frequency rounds)
            CoinMsg::BinaryAAEcho(msgs, echo_sender, round) =>{
                log::debug!("Received Binary AA Echo1 from node {}",echo_sender);
                self.process_baa_echo(msgs, echo_sender, round).await;
            },
            CoinMsg::BinaryAAEcho2(msgs, echo2_sender, round) =>{
                log::debug!("Received Binary AA Echo2 from node {}",echo2_sender);
                self.process_baa_echo2(msgs, echo2_sender, round).await;
            },
            // Messages related to Beacon Reconstruction
            CoinMsg::BeaconConstruct(shares, share_sender, coin_num, round)=>{
                log::debug!("Received Beacon Construct message from node {} for coin number {} in round {}",share_sender,coin_num,round);
                self.process_secret_shares(shares, share_sender, coin_num, round).await;
            },
            // ACS messages — the NEW primary path for frequency rounds
            CoinMsg::ACSInit((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSInit from {} for round {} dealers {:?}",
                    self.myid, sender, round, dealers
                );
                self.process_acs_init(sender, round, dealers).await;
            },
            CoinMsg::ACSOutput((sender, round, dealers)) => {
                log::info!(
                    "[PPT][ACS] node {} received ACSOutput from {} for round {} dealers {:?}",
                    self.myid, sender, round, dealers
                );
                self.process_acs_output(sender, round, dealers).await;
            },
            _ => {}
        }
    }

    pub(crate) async fn increment_round(&mut self,round:u32){
        if round>=self.curr_round{
            self.curr_round = round+1;
        }
        else{
            return;
        }
    }
}


/// =====================================================================
/// ACS-driven reconstruction (Phase 2: Deferred Complaint)
///
/// When ACS reaches final decision (n-f matching ACSOutput messages),
/// the decided dealer set DIRECTLY drives beacon reconstruction.
/// This bypasses the old Binary AA → reconstruct_beacon path for
/// frequency rounds, achieving the "deferred complaint" design.
/// =====================================================================
impl Context {
    pub async fn process_acs_init(&mut self, sender: Replica, round: Round, dealers: Vec<Replica>) {
        log::info!("[PPT][ACS-INIT] node {} got ACSInit from {} for round {} with {} dealers",
            self.myid, sender, round, dealers.len());

        let threshold = self.num_nodes - self.num_faults;
        let st = self.acs_state
            .entry(round)
            .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

        let dealer_set: std::collections::HashSet<usize> =
            dealers.iter().map(|x| *x as usize).collect();

        st.record_output(sender, dealer_set);

        log::info!(
            "[PPT][ACS-INIT] node {} round {} has {}/{} ACSInit proposals",
            self.myid, round, st.outputs_seen.len(), threshold
        );

        let had_output = st.output_sent;
        if st.try_decide_union(threshold) {
            if let Some(decided) = st.decided_set.clone() {
                let mut decided_vec: Vec<usize> = decided.iter().copied().collect();
                decided_vec.sort_unstable();

                log::info!(
                    "[PPT][ACS-UNION] node {} round {} local union = {:?}",
                    self.myid, round, decided_vec
                );

                if !had_output {
                    st.output_sent = true;
                    let out_msg = CoinMsg::ACSOutput((
                        self.myid, round,
                        decided_vec.iter().map(|x| *x as Replica).collect()
                    ));
                    self.broadcast(out_msg.clone(), round).await;
                    self.process_acs_output(
                        self.myid, round,
                        decided_vec.iter().map(|x| *x as Replica).collect()
                    ).await;
                }
            }
        }
    }

    /// Core Phase 2 change: ACS final decision triggers reconstruction directly.
    pub async fn process_acs_output(&mut self, sender: Replica, round: Round, dealers: Vec<Replica>) {
        log::info!("[PPT][ACS-OUT] node {} got ACSOutput from {} for round {} dealers {:?}",
            self.myid, sender, round, dealers);

        let threshold = self.num_nodes - self.num_faults;
        let st = self.acs_state
            .entry(round)
            .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

        let dealer_set: std::collections::HashSet<usize> =
            dealers.iter().map(|x| *x as usize).collect();

        st.record_final_output(sender, dealer_set);

        let recv_count = st.final_outputs_seen.len();
        log::info!(
            "[PPT][ACS-OUT] node {} round {} has {}/{} ACSOutput messages",
            self.myid, round, recv_count, threshold
        );

        if recv_count >= threshold && !st.final_decided {
            st.final_decided = true;

            // Compute final union of all received ACSOutput dealer sets
            let mut union_set = std::collections::HashSet::new();
            for s in st.final_outputs_seen.values() {
                union_set.extend(s.iter().copied());
            }
            let mut decided_vec: Vec<usize> = union_set.iter().copied().collect();
            decided_vec.sort_unstable();
            st.final_decided_set = Some(union_set.clone());

            log::error!(
                "[PPT][ACS-DECIDE] node {} round {} FINAL ACS decision = {:?}",
                self.myid, round, decided_vec
            );

            // ============================================================
            // PHASE 2 CORE: ACS decision directly drives reconstruction
            // Instead of waiting for Binary AA to terminate and then
            // calling reconstruct_beacon, we immediately:
            // 1. Set appx_con_term_vals from ACS decided dealers
            // 2. Sync secret maps
            // 3. Notify syncer
            // 4. Start reconstruction
            // ============================================================
            if self.round_state.contains_key(&round) {
                let max_weight = {
                    let max = BigUint::from(2u32);
                    pow(max, self.rounds_aa as usize)
                };

                let rbc_state = self.round_state.get_mut(&round).unwrap();

                // Phase 3: Filter out malicious dealers from ACS decision
                let blamed_count = rbc_state.malicious_dealers.len();
                if blamed_count > 0 {
                    log::error!(
                        "[PPT][ACS-BLAME] node {} round {} excluding {} malicious dealers: {:?}",
                        self.myid, round, blamed_count,
                        rbc_state.malicious_dealers.iter().collect::<Vec<_>>()
                    );
                }

                // Set equal weight for all ACS-decided dealers (excluding malicious ones)
                for dealer in decided_vec.iter() {
                    let dealer_rep = *dealer as Replica;
                    if rbc_state.malicious_dealers.contains(&dealer_rep) {
                        log::warn!("[PPT][ACS-BLAME] Excluding malicious dealer {} from reconstruction in round {}", dealer_rep, round);
                        continue;
                    }
                    if rbc_state.terminated_secrets.contains(&dealer_rep) {
                        rbc_state.appx_con_term_vals.insert(dealer_rep, max_weight.clone());
                    }
                }

                // Phase 4B: Precompute BatchExtractor for this ACS decision.
                // The evaluation points are the ACS-decided dealer IDs + 1 (since shares
                // are evaluated at points 1..n). We use the first t+1 available share
                // providers as evaluation points.
                {
                    use crate::node::shamir::two_field::BatchExtractor;
                    let t = self.num_faults + 1;
                    // Collect the evaluation points that will be used for reconstruction.
                    // These are the replica IDs + 1 (since shares are at points 1..n).
                    let eval_points: Vec<usize> = (0..self.num_nodes)
                        .map(|i| i + 1)
                        .take(t)
                        .collect();
                    let extractor = BatchExtractor::new(
                        eval_points,
                        rbc_state.secret_domain.clone(),
                    );
                    rbc_state.batch_extractor = Some(extractor);
                    log::info!(
                        "[PPT][BATCH-EXTRACT] node {} round {} precomputed BatchExtractor with t={} eval points",
                        self.myid, round, t
                    );
                }

                rbc_state.sync_secret_maps().await;

                log::error!(
                    "[PPT][ACS-RECON] node {} round {} ACS-driven reconstruction with {} dealers, appx_con_term_vals keys: {:?}",
                    self.myid, round, decided_vec.len(),
                    rbc_state.appx_con_term_vals.keys().collect::<Vec<_>>()
                );

                // Notify syncer that this round's beacon is finalized
                let cancel_handler = self.sync_send.send(
                    0,
                    SyncMsg {
                        sender: self.myid,
                        state: SyncState::BeaconFin(round, self.myid),
                        value: 0
                    }
                ).await;
                self.add_cancel_handler(cancel_handler);

                // Start reconstruction — skip coin 0 (reserved for committee election)
                self.reconstruct_beacon(round, 1).await;
            } else {
                log::warn!(
                    "[PPT][ACS-RECON] node {} round {} ACS decided but no round_state exists",
                    self.myid, round
                );
            }
        }
    }
}
