use std::{ time::SystemTime};

use async_recursion::async_recursion;
use crypto::{hash::{do_hash, Hash}, aes_hash::MerkleTree};
use num_bigint::{BigUint, RandBigInt};
use types::{beacon::{BatchWSSMsg, CoinMsg, WrapperMsg, Val}, Replica, beacon::{Round, BeaconMsg}};

use crate::node::{Context, ShamirSecretSharing, CTRBCState};
use crate::node::shamir::two_field::TwoFieldDealer;

/**
 * Phase B:
 * PPT-native round bootstrap using SS-AVSS only.
 *
 * This file no longer serves as a legacy "next_round_begin" companion for PPT.
 * Instead:
 *   - round 0 is bootstrapped with the full committee
 *   - future frequency rounds are started directly from committee handoff
 *   - only committee members actively launch local SS-AVSS dealer instances
 *   - non-committee nodes create/passively hold the round state and receive RBC
 */
impl Context {
    /// Legacy-compatible entry point, now redirected to PPT-native bootstrap.
    ///
    /// The caller may still use the old convention:
    ///   - round == 20000 => bootstrap logical round 0
    ///   - otherwise      => bootstrap exact round (round + 1)
    ///
    /// In pure PPT mode we only start frequency rounds (and round 0).
    #[async_recursion]
    pub async fn start_new_round(
        &mut self,
        round: Round,
        _vec_round_vals: Vec<(Round,Vec<(Replica,BigUint)>)>
    ) {
        let target_round = if round == 20000 { 0 } else { round + 1 };
        self.ppt_try_start_round(target_round).await;
    }

    /// PPT-native bootstrap gate.
    ///
    /// A round may start when:
    ///   - it is round 0 (bootstrap with all nodes as committee), or
    ///   - its committee has already been handed off by a previous beacon round.
    ///
    /// Only committee members actively launch a local dealer instance.
    /// Other nodes mark the round as started passively and only receive/process messages.
    pub async fn ppt_try_start_round(&mut self, target_round: Round) {
        if target_round > self.max_rounds {
            log::warn!(
                "[PPT][ROUND-START] node {} refusing to start round {} because it exceeds max_rounds={}",
                self.myid,
                target_round,
                self.max_rounds
            );
            return;
        }

        if target_round != 0 && target_round % self.frequency != 0 {
            log::warn!(
                "[PPT][ROUND-START] node {} refusing to start non-frequency round {} in pure PPT mode",
                self.myid,
                target_round
            );
            return;
        }

        if !self.round_state.contains_key(&target_round) {
            let rbc_new_state = CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(target_round, rbc_new_state);
        }

        let launch_as_dealer = {
            let st = self.round_state.get_mut(&target_round).unwrap();

            if st.ppt_round_started {
                log::info!(
                    "[PPT][ROUND-START] node {} round {} already started; skip duplicate bootstrap",
                    self.myid,
                    target_round
                );
                return;
            }

            if target_round == 0 {
                st.committee = (0..self.num_nodes).collect();
                st.committee_elected = true;
            }

            if !st.committee_elected {
                log::info!(
                    "[PPT][ROUND-START] node {} round {} not ready yet; committee not handed off",
                    self.myid,
                    target_round
                );
                return;
            }

            st.ppt_round_started = true;
            st.ppt_round_finished = false;

            // Reset only the PPT runtime flags for this round.
            st.send_w1 = false;
            st.send_w2 = false;
            st.ppt_acs_init_sent = false; // pure-PPT ACSInit one-shot guard // reused as ACS-trigger one-shot guard only
            st.accepted_witnesses1.clear();
            st.accepted_witnesses2.clear();
            st.witness1.clear();
            st.witness2.clear();

            st.acs_decided_set = None;
            st.batch_extractor = None;
            st.recovered_shares_multicast_sent = false;
            st.batch_reconstruction_complete = false;
            st.post_complaint_complete = false;
            st.post_complaint_packets.clear();
            st.pending_beacon_outputs.clear();
            st.malicious_dealers.clear();
            st.blame_log.clear();

            let committee = st.committee.clone();
            committee.contains(&self.myid)
        };

        if launch_as_dealer {
            log::info!(
                "[PPT][ROUND-START] node {} actively launching round {} as committee member",
                self.myid,
                target_round
            );
            self.ppt_launch_exact_round(target_round).await;
        } else {
            log::info!(
                "[PPT][ROUND-START] node {} passively opened round {} (not in committee)",
                self.myid,
                target_round
            );
        }
    }

    /// Launch one exact PPT frequency round using SS-AVSS / Two-Field sharing.
    ///
    /// This is the PPT-native replacement for the legacy "next_round_begin" pipeline.
    /// It intentionally carries no appxcon payload.
    async fn ppt_launch_exact_round(&mut self, new_round: Round) {
        let now = SystemTime::now();

        if new_round != 0 && new_round % self.frequency != 0 {
            log::warn!(
                "[PPT][ROUND-START] node {} refusing to launch exact non-frequency round {}",
                self.myid,
                new_round
            );
            return;
        }

        log::info!(
            "[PPT][ROUND-START] node {} launching exact PPT round {}",
            self.myid,
            new_round
        );

        let mut beacon_msgs = Vec::new();

        // Pure PPT: no legacy appxcon payload.
        let vec_round_msgs: Vec<(Round,Vec<(Replica,Val)>)> = Vec::new();

        let faults = self.num_faults;
        let batch_size = self.batch_size;
        let low_r = BigUint::from(0u32);
        let prime = self.secret_domain.clone();
        let nonce_prime = self.nonce_domain.clone();

        let two_field_dealer = TwoFieldDealer::new(
            prime.clone(),
            nonce_prime.clone(),
            faults + 1,      // threshold t = f+1
            3 * faults + 1,  // share_amount n = 3f+1
        );

        let theta = self.get_previous_theta(new_round.saturating_sub(1));

        let mut share_vec: Vec<[u8;32]> = Vec::new();
        let mut nonce_share_vec: Vec<[u8;32]> = Vec::new();

        let mut degree_test_batch: Vec<Vec<Val>> = Vec::with_capacity(batch_size);
        let mut mask_shares_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); self.num_nodes];
        let mut f_large_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); self.num_nodes];

        for _ in 0..batch_size {
            let secret = rand::thread_rng().gen_biguint_range(&low_r, &prime);

            let two_field_shares = two_field_dealer.share_secret(secret, &theta);

            let nonce_ss = ShamirSecretSharing{
                threshold: faults + 1,
                share_amount: 3 * faults + 1,
                prime: nonce_prime.clone(),
            };
            let nonce = rand::thread_rng().gen_biguint_range(&low_r, &nonce_prime);
            let nonce_shares = nonce_ss.split(nonce);

            let h_coeffs_as_val: Vec<Val> = two_field_shares.degree_test_coeffs.iter()
                .map(|c| Self::pad_shares(c.clone()))
                .collect();
            degree_test_batch.push(h_coeffs_as_val);

            for node_idx in 0..self.num_nodes {
                let g_share = &two_field_shares.mask_shares[node_idx].1;
                mask_shares_per_node[node_idx].push(Self::pad_shares(g_share.clone()));

                let f_large = &two_field_shares.f_large_shares[node_idx].1;
                f_large_per_node[node_idx].push(Self::pad_shares(f_large.clone()));
            }

            for (share, nonce_share) in two_field_shares.secret_shares.into_iter().zip(nonce_shares.into_iter()) {
                share_vec.push(Self::pad_shares(share.1));
                nonce_share_vec.push(Self::pad_shares(nonce_share.1));
            }
        }

        let commitments = self.hash_context.hash_batch(share_vec.clone(), nonce_share_vec.clone());
        let triplets: Vec<(Val, Val, Hash)> = share_vec
            .into_iter()
            .zip(nonce_share_vec.into_iter())
            .zip(commitments.into_iter())
            .map(|((share, nonce), comm)| (share, nonce, comm))
            .collect();

        assert_eq!(
            triplets.len(),
            batch_size * self.num_nodes,
            "two-field packing mismatch: got {} triplets for batch_size={} num_nodes={}",
            triplets.len(),
            batch_size,
            self.num_nodes
        );

        let share_comm_hash: Vec<Vec<(Val, Val, Hash)>> = triplets
            .chunks(self.num_nodes)
            .map(|chunk| chunk.iter().cloned().collect())
            .collect();

        assert_eq!(
            share_comm_hash.len(),
            batch_size,
            "expected {} per-coin groups, got {}",
            batch_size,
            share_comm_hash.len()
        );

        let hashes_vec: Vec<Vec<Hash>> = share_comm_hash
            .iter()
            .map(|secret_chunk| secret_chunk.iter().map(|(_, _, h)| *h).collect())
            .collect();

        let mt_vec = MerkleTree::build_trees(hashes_vec, &self.hash_context);

        let mut vec_msgs_to_be_sent: Vec<(Replica, BatchWSSMsg)> = (0..self.num_nodes)
            .map(|i| (i + 1, BatchWSSMsg::new(self.myid, Vec::new(), Vec::new(), Vec::new())))
            .collect();

        let mut roots_vec: Vec<Hash> = Vec::with_capacity(batch_size);
        for (secret_chunk, mt) in share_comm_hash.into_iter().zip(mt_vec.into_iter()) {
            for (i, (share, nonce, _comm)) in secret_chunk.into_iter().enumerate() {
                vec_msgs_to_be_sent[i].1.secrets.push(share);
                vec_msgs_to_be_sent[i].1.nonces.push(nonce);
                vec_msgs_to_be_sent[i].1.mps.push(mt.gen_proof(i));
            }
            roots_vec.push(mt.root());
        }

        assert_eq!(roots_vec.len(), batch_size);
        assert_eq!(degree_test_batch.len(), batch_size);

        for (idx, (rep, batchwss)) in vec_msgs_to_be_sent.into_iter().enumerate() {
            let beacon_msg = BeaconMsg::new_two_field(
                self.myid,
                new_round,
                batchwss,
                roots_vec.clone(),
                vec_round_msgs.clone(),
                degree_test_batch.clone(),
                mask_shares_per_node[idx].clone(),
                f_large_per_node[idx].clone(),
            );
            beacon_msgs.push((rep, beacon_msg));
        }

        for (rep, beacon_msg) in beacon_msgs.into_iter() {
            let replica = rep - 1;
            let sec_key = self.sec_key_map.get(&replica).unwrap().clone();
            let transcript_root = do_hash(beacon_msg.serialize_ctrbc().as_slice());
            if replica != self.myid {
                let beacon_init = CoinMsg::AVSSSend(beacon_msg, transcript_root, self.myid, new_round);
                let wrapper_msg = WrapperMsg::new(beacon_init, self.myid, &sec_key, new_round);
                self.send(replica, wrapper_msg).await;
            } else {
                self.process_avss_send(beacon_msg, transcript_root, self.myid, new_round).await;
            }
        }

        self.increment_round(new_round).await;
        self.add_benchmark(String::from("ppt_start_round"), now.elapsed().unwrap().as_nanos());
    }

    /// Phase 4B: Get theta (previous round's beacon output) for degree testing.
    /// Returns 0 if no previous beacon is available.
    pub(crate) fn get_previous_theta(&self, round: Round) -> BigUint {
        if round == 0 {
            BigUint::from(0u32)
        } else {
            let round_bytes = round.to_be_bytes();
            let hash = crypto::hash::do_hash(&round_bytes);
            BigUint::from_bytes_be(&hash) % &self.secret_domain
        }
    }

    pub fn pad_shares(inp:BigUint)->[u8;32]{
        let mut byte_arr = inp.to_bytes_be();
        if byte_arr.len() > 32{
            panic!("All inputs must be within 32 bytes");
        }
        else {
            let mut vec_zeros = vec![0u8;32-byte_arr.len()];
            vec_zeros.append(&mut byte_arr);
            vec_zeros.try_into().unwrap_or_else(
                |v: Vec<u8>| panic!("Expected a Vec of length {} but it was {}", 32, v.len())
            )
        }
    }
}
