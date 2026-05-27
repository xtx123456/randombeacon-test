use std::sync::Arc;

use async_recursion::async_recursion;
use crypto::aes_hash::HashState;
use crypto::hash::{verf_mac, Hash};
use num_bigint::BigUint;
use types::{
    beacon::{BeaconMsg, CoinMsg, WrapperMsg},
    Replica, Round, SyncMsg, SyncState,
};

use crate::node::shamir::two_field::TwoFieldDealer;

use super::Context;

/// Pure verifier for one dealer's AVSS packet under the PPT
/// two-field scheme. This is the **CPU-heavy** body of the
/// validation: it runs `batch_size` per-coin `verify_share`
/// degree-tests plus a full Merkle / commitment check on the AVSS
/// payload. Lifting it into a free function (no `&self`) lets the
/// hot path move the call into `tokio::task::spawn_blocking`, so
/// the consensus task's worker thread is not occupied for the
/// duration of the degree-test loop.
///
/// **Contract identical to the previous `Context::avss_local_packet_valid`**:
/// returns `Ok(())` on success, `Err(reason)` on any
/// protocol-level violation (transcript mismatch, bad Merkle
/// proof, missing two-field material, degree-test failure). The
/// caller MUST permanently ban the dealer on `Err(_)`.
///
/// Inputs that used to be read from `&self` (`hash_context`,
/// `secret_domain`, `nonce_domain`, `num_faults`, `num_nodes`,
/// `batch_size`, `myid`) are now explicit parameters, so this
/// function is `'static`-callable from `spawn_blocking`.
pub(crate) fn avss_local_packet_valid_pure(
    beacon_msg: &BeaconMsg,
    transcript_root: &Hash,
    dealer: Replica,
    round: Round,
    theta: &BigUint,
    hash_context: &HashState,
    secret_domain: &BigUint,
    nonce_domain: &BigUint,
    num_faults: usize,
    num_nodes: usize,
    batch_size: usize,
    myid: usize,
) -> Result<(), &'static str> {
    let public_root = crypto::hash::do_hash(beacon_msg.serialize_ctrbc().as_slice());
    if public_root != *transcript_root {
        log::warn!(
            "[PPT][AVSS] transcript root mismatch for dealer {} round {}",
            dealer,
            round
        );
        return Err("transcript root mismatch");
    }

    if !beacon_msg.verify_proofs(hash_context) {
        log::warn!(
            "[PPT][AVSS] invalid Merkle/share proof for dealer {} round {}",
            dealer,
            round
        );
        return Err("merkle proof invalid");
    }

    let degree_test_coeffs = match beacon_msg.degree_test_coeffs.as_ref() {
        Some(coeffs) => coeffs,
        None => return Err("missing degree-test coeffs"),
    };
    let mask_shares = match beacon_msg.mask_shares.as_ref() {
        Some(mask_shares) => mask_shares,
        None => return Err("missing mask shares"),
    };
    let f_large_shares = match beacon_msg.f_large_shares.as_ref() {
        Some(f_large_shares) => f_large_shares,
        None => return Err("missing f_large shares"),
    };

    if degree_test_coeffs.len() != batch_size
        || mask_shares.len() != batch_size
        || f_large_shares.len() != batch_size
    {
        log::warn!(
            "[PPT][AVSS] malformed two-field batch lengths from dealer {} round {}",
            dealer,
            round
        );
        return Err("malformed two-field lengths");
    }

    let verifier = TwoFieldDealer::new(
        secret_domain.clone(),
        nonce_domain.clone(),
        num_faults + 1,
        num_nodes,
    );

    for coin_num in 0..batch_size {
        let coeffs = &degree_test_coeffs[coin_num];
        let h_coeffs: Vec<BigUint> = coeffs
            .iter()
            .map(|bytes| BigUint::from_bytes_be(bytes.as_slice()))
            .collect();
        let f_large = BigUint::from_bytes_be(f_large_shares[coin_num].as_slice());
        let g_share = BigUint::from_bytes_be(mask_shares[coin_num].as_slice());

        if !verifier.verify_share(myid + 1, &f_large, &g_share, &h_coeffs, theta) {
            log::warn!(
                "[PPT][AVSS] degree-test failed for dealer {} round {} coin {} at node {}",
                dealer,
                round,
                coin_num,
                myid
            );
            return Err("degree test failed");
        }
    }

    Ok(())
}

impl Context {
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
            CoinMsg::CTRBCInit(_, ctr) => {
                log::debug!(
                    "[PPT][CTRBC-OFF] dropping legacy CTRBCInit for round {}",
                    ctr.round
                );
            }
            CoinMsg::CTRBCEcho(ctr, _, echo_sender) => {
                log::debug!(
                    "[PPT][CTRBC-OFF] dropping legacy CTRBCEcho from {} for round {}",
                    echo_sender,
                    ctr.round
                );
            }
            CoinMsg::CTRBCReady(ctr, _, ready_sender) => {
                log::debug!(
                    "[PPT][CTRBC-OFF] dropping legacy CTRBCReady from {} for round {}",
                    ready_sender,
                    ctr.round
                );
            }
            CoinMsg::CTRBCReconstruct(ctr, _, recon_sender) => {
                log::debug!(
                    "[PPT][CTRBC-OFF] dropping legacy CTRBCReconstruct from {} for round {}",
                    recon_sender,
                    ctr.round
                );
            }
            CoinMsg::BinaryAAEcho(_, echo_sender, round) => {
                log::debug!(
                    "[PPT][PURE] rejecting legacy BinaryAAEcho from {} for round {}",
                    echo_sender,
                    round
                );
            }
            CoinMsg::BinaryAAEcho2(_, echo2_sender, round) => {
                log::debug!(
                    "[PPT][PURE] rejecting legacy BinaryAAEcho2 from {} for round {}",
                    echo2_sender,
                    round
                );
            }
            CoinMsg::BeaconConstruct(_, share_sender, coin_num, round) => {
                log::debug!(
                    "[PPT][LEGACY-DROP] ignoring per-coin BeaconConstruct from node {} for coin {} in round {}; pure PPT only accepts BatchBeaconConstruct",
                    share_sender, coin_num, round
                );
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
                log::debug!(
                    "[PPT][GATHER-OFF] dropping legacy GatherEcho from {} for round {}",
                    sender,
                    round
                );
            }
            CoinMsg::GatherEcho2(_, sender, round) => {
                log::debug!(
                    "[PPT][GATHER-OFF] dropping legacy GatherEcho2 from {} for round {}",
                    sender,
                    round
                );
            }
            CoinMsg::ACSInit((sender, round, _dealers)) => {
                log::warn!(
                    "[PPT][ACS-LEGACY] dropping legacy ACSInit from {} for round {}; pure PPT uses ACSPropose/Witness1/Witness2",
                    sender,
                    round
                );
            }
            CoinMsg::ACSOutput((sender, round, _dealers)) => {
                log::warn!(
                    "[PPT][ACS-LEGACY] dropping legacy ACSOutput from {} for round {}; pure PPT uses ACSPropose/Witness1/Witness2",
                    sender,
                    round
                );
            }
            CoinMsg::ACSPropose(round, sender, dealers) => {
                log::warn!(
                    "[PPT][ACS-LEGACY] dropping legacy ACSPropose from {} round {} ({} dealers); pure PPT now uses RBC + MMR ABA",
                    sender,
                    round,
                    dealers.len()
                );
            }
            CoinMsg::ACSWitness1(round, sender, validated) => {
                log::warn!(
                    "[PPT][ACS-LEGACY] dropping legacy ACSWitness1 from {} round {} ({} proposers); pure PPT now uses RBC + MMR ABA",
                    sender,
                    round,
                    validated.len()
                );
            }
            CoinMsg::ACSWitness2(round, sender, witnessed) => {
                log::warn!(
                    "[PPT][ACS-LEGACY] dropping legacy ACSWitness2 from {} round {} ({} senders); pure PPT now uses RBC + MMR ABA",
                    sender,
                    round,
                    witnessed.len()
                );
            }
            CoinMsg::ACSRbcSend(round, proposer, payload) => {
                log::info!(
                    "[PPT][ACS-RBC] node {} got ACSRbcSend round {} proposer {} (|payload|={} bytes, wire-sender={})",
                    self.myid,
                    round,
                    proposer,
                    payload.len(),
                    wrapper_msg.sender
                );
                if wrapper_msg.sender != proposer {
                    log::warn!(
                        "[PPT][ACS-RBC] dropping ACSRbcSend round {} proposer {} sent by wire {} (sender mismatch)",
                        round, proposer, wrapper_msg.sender
                    );
                } else {
                    self.process_acs_rbc_send(round, proposer, payload).await;
                }
            }
            CoinMsg::ACSRbcEcho(round, proposer, payload_hash) => {
                self.process_acs_rbc_echo(round, proposer, wrapper_msg.sender, payload_hash).await;
            }
            CoinMsg::ACSRbcReady(round, proposer, payload_hash) => {
                self.process_acs_rbc_ready(round, proposer, wrapper_msg.sender, payload_hash).await;
            }
            CoinMsg::ACSAbaBval(round, aba_instance_id, aba_round, value) => {
                self.process_acs_aba_bval(round, aba_instance_id, aba_round, value, wrapper_msg.sender).await;
            }
            CoinMsg::ACSAbaAux(round, aba_instance_id, aba_round, value) => {
                self.process_acs_aba_aux(round, aba_instance_id, aba_round, value, wrapper_msg.sender).await;
            }
            _ => {}
        }
    }

    pub(crate) async fn increment_round(&mut self, round: u32) {
        if round >= self.curr_round {
            self.curr_round = round + 1;
        }
    }

    /// Public hook used by the AVSS path: a dealer just transitioned
    /// to AVSS-completed locally; let the ACS driver re-evaluate
    /// every phase that became eligible (Propose, Witness1,
    /// Witness2, Decide).
    #[async_recursion]
    pub(crate) async fn maybe_broadcast_acs_init_from_avss(&mut self, round: Round) {
        self.acs_note_local_change(round).await;
    }

    /// Validate a dealer's AVSS packet under the PPT two-field
    /// scheme. Returns `Ok(())` on success or `Err(reason)` on
    /// failure. On failure the caller MUST permanently ban the
    /// dealer: by definition, only a Byzantine dealer can produce
    /// an invalid packet, so banning is safe and required for the
    /// "kick out corrupted leader" path described in the PPT
    /// scheme.
    ///
    /// `theta` is supplied by the caller (typically via
    /// `theta_for_round(round)`). The caller MUST resolve `theta`
    /// before calling this method; if `theta_for_round` returns
    /// `None` the caller MUST defer the packet (via
    /// `Context::buffer_avss_for_theta`) instead of calling this
    /// method, because "θ not yet available" is a transient async
    /// race condition and is NOT a protocol-level violation.
    ///
    /// This method is a thin wrapper around the pure free function
    /// `avss_local_packet_valid_pure`; the wrapper is kept so
    /// existing test code that calls the method form still compiles.
    /// Production hot paths should call the pure function inside
    /// `tokio::task::spawn_blocking` so that the heavy degree-test
    /// loop runs in tokio's blocking pool (multi-core) instead of
    /// hogging the consensus task's worker thread.
    #[allow(dead_code)]
    fn avss_local_packet_valid(
        &self,
        beacon_msg: &types::beacon::BeaconMsg,
        transcript_root: &crypto::hash::Hash,
        dealer: Replica,
        round: Round,
        theta: &BigUint,
    ) -> Result<(), &'static str> {
        avss_local_packet_valid_pure(
            beacon_msg,
            transcript_root,
            dealer,
            round,
            theta,
            &self.hash_context,
            &self.secret_domain,
            &self.nonce_domain,
            self.num_faults,
            self.num_nodes,
            self.batch_size,
            self.myid,
        )
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
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][BAN] dropping AVSSSend from banned dealer {} round {}",
                dealer,
                round
            );
            return;
        }

        // PPT slide pg 28: θ for round r is derived from round (r-1)'s
        // reconstructed beacon. In an asynchronous network a fast peer
        // may broadcast its round-(r+1) AVSSSend before this node has
        // finished reconstructing round-r's coin 0. In that case
        // `theta_for_round(round)` returns None — this is NOT a
        // protocol violation, so we MUST NOT ban the dealer or drop
        // the packet. Instead, buffer it and replay once
        // `record_beacon_output_for_theta` populates θ (which the
        // beacon-emit path does inside `self_coin_check_transmit`).
        let theta = match self.theta_for_round(round) {
            Some(t) => t,
            None => {
                self.buffer_avss_for_theta(round, beacon_msg, transcript_root, dealer);
                return;
            }
        };

        if !self.round_state.contains_key(&round) {
            let rbc_new_state = crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        // ---- Level 2 multi-core: move the CPU-heavy AVSS validation
        // (hash transcript, verify_proofs Merkle batch, batch_size
        // degree-tests over BigUint arithmetic) into tokio's blocking
        // pool so the consensus task's worker thread is free to keep
        // handling other inbound messages while validation runs in
        // parallel on another core.
        //
        // We move `beacon_msg` and `theta` into the blocking closure
        // and return them back out, so no large clones happen along
        // the hot path. Everything else copied into the closure is
        // small and/or cheaply cloned.
        let hash_context = Arc::clone(&self.hash_context);
        let secret_domain = self.secret_domain.clone();
        let nonce_domain = self.nonce_domain.clone();
        let num_faults = self.num_faults;
        let num_nodes = self.num_nodes;
        let batch_size = self.batch_size;
        let myid = self.myid;
        let transcript_root_owned = transcript_root;

        let (validation_result, beacon_msg, _theta) =
            tokio::task::spawn_blocking(move || {
                let result = avss_local_packet_valid_pure(
                    &beacon_msg,
                    &transcript_root_owned,
                    dealer,
                    round,
                    &theta,
                    &hash_context,
                    &secret_domain,
                    &nonce_domain,
                    num_faults,
                    num_nodes,
                    batch_size,
                    myid,
                );
                (result, beacon_msg, theta)
            })
            .await
            .unwrap_or_else(|e| {
                log::error!(
                    "[PPT][LEVEL2] AVSS validation blocking task join error round {} dealer {}: {}",
                    round, dealer, e
                );
                // Failsafe: treat join error as transient (no ban). Recreate
                // a dummy BeaconMsg / theta won't be used because we early-return.
                (
                    Err("blocking task join error"),
                    types::beacon::BeaconMsg::new_with_appx(0, 0, Vec::new()),
                    BigUint::from(0u32),
                )
            });

        match validation_result {
            Ok(()) => {}
            Err(reason) => {
                log::error!(
                    "[PPT][AVSS-BAN] banning dealer {} for invalid AVSS packet round {} reason={}",
                    dealer,
                    round,
                    reason
                );
                self.ban_dealer_global(dealer);
                return;
            }
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

    /// Replay every AVSSSend that was buffered waiting for θ(round)
    /// to become available. Idempotent — re-processed packets that
    /// are already valid go through the normal `process_avss_send`
    /// pipeline and the "already validated" guard short-circuits
    /// duplicates.
    #[async_recursion]
    pub async fn drain_pending_avss_for(&mut self, round: Round) {
        let pending = self.take_pending_avss_for(round);
        if pending.is_empty() {
            return;
        }
        log::info!(
            "[PPT][THETA-REPLAY] node {} replaying {} buffered AVSSSend(s) for round {} now that θ is available",
            self.myid,
            pending.len(),
            round
        );
        for (beacon_msg, transcript_root, dealer) in pending.into_iter() {
            self.process_avss_send(beacon_msg, transcript_root, dealer, round)
                .await;
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
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][BAN] dropping AVSSReady for banned dealer {} round {}",
                dealer,
                round
            );
            return;
        }

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
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][BAN] dropping AVSSComplete for banned dealer {} round {}",
                dealer,
                round
            );
            return;
        }

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
    async fn start_reconstruction_after_acs(
        &mut self,
        round: Round,
        decided_vec: &[Replica],
    ) {
        log::info!(
            "[PPT][STAGE][ACS-DECIDE] node {} round {} dealers {:?}",
            self.myid,
            round,
            decided_vec
        );
        log::info!(
            "[PPT][ACS->RECON] node {} round {} immediately starting reconstruction for decided dealers {:?}",
            self.myid,
            round,
            decided_vec
        );
        log::info!(
            "[PPT][STAGE][RECON-START] node {} round {}",
            self.myid,
            round
        );

        self.reconstruct_beacon(round, 0).await;
    }

    /// Called by the ACS driver once an `ACSInstanceState` has
    /// finalised. `decided_vec` is the deterministic dealer set
    /// computed from `state::finalize_decision` — every honest
    /// finaliser receives the SAME `decided_vec` for this round,
    /// which is what beacon-output safety depends on.
    #[async_recursion]
    pub async fn finalize_acs_round(&mut self, round: Round, mut decided_vec: Vec<Replica>) {
        decided_vec.sort_unstable();
        decided_vec.retain(|d| !self.banned_dealers.contains(d));

        if decided_vec.is_empty() {
            log::error!(
                "[PPT][ACS-DECIDE] node {} round {} ACS decided an empty dealer set after ban filter; aborting round",
                self.myid,
                round
            );
            return;
        }

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
            rbc_state.recovered_coins.clear();
            rbc_state.multicast_disclosed_coins.clear();
            rbc_state.emitted_beacon_coins.clear();
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

        self.start_reconstruction_after_acs(round, decided_vec.as_slice())
            .await;

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
