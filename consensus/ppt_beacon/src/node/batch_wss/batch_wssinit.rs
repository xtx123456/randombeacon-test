use std::time::SystemTime;

use async_recursion::async_recursion;
use crypto::{aes_hash::MerkleTree, hash::Hash};
use num_bigint::{BigUint, RandBigInt};
use types::{
    beacon::{BatchWSSMsg, BeaconMsg, CoinMsg, Round, Val, WrapperMsg},
    Replica,
};

use crate::node::shamir::two_field::TwoFieldDealer;
use crate::node::{CTRBCState, Context, ShamirSecretSharing};

/**
 * Phase B:
 * PPT-native round bootstrap using SS-AVSS only.
 *
 * Pure-PPT mode (this file):
 *   - every honest node is *always* a dealer; there is no anytrust
 *     committee selection;
 *   - banned dealers (i.e. those that previously sent an invalid
 *     AVSS packet, equivocated in ACS, or failed the post-ACS audit)
 *     do not launch their own AVSS instance and are rejected from
 *     every receiver's view (see Context::ban_dealer_global).
 */
impl Context {
    /// Legacy-compatible entry point, now redirected to PPT-native bootstrap.
    ///
    /// The caller may still use the old convention:
    ///   - round == 20000 => bootstrap logical round 0
    ///   - otherwise      => bootstrap exact round (round + 1)
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
    /// In pure PPT mode every node is a dealer in every round, so
    /// the only blocker is whether this node has already started
    /// the round (idempotency) and whether it is itself banned
    /// (refuse to act as a dealer once banned).
    #[async_recursion]
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

        let already_started = {
            let st = self.round_state.get_mut(&target_round).unwrap();
            if st.ppt_round_started {
                log::info!(
                    "[PPT][ROUND-START] node {} round {} already started; skip duplicate bootstrap",
                    self.myid,
                    target_round
                );
                true
            } else {
                // Pure PPT: every honest node is always a dealer in
                // every round. There is no per-round committee field
                // anymore -- the dealer set comes directly from
                // Context (filtered against banned_dealers).
                st.ppt_round_started = true;
                st.ppt_round_finished = false;
                st.acs_decided_set = None;
                st.batch_extractor = None;
                st.recovered_shares_multicast_sent = false;
                st.batch_reconstruction_complete = false;
                st.post_complaint_complete = false;
                st.post_complaint_packets.clear();
                st.pending_beacon_outputs.clear();
                st.blame_log.clear();
                false
            }
        };

        if already_started {
            return;
        }

        if self.banned_dealers.contains(&self.myid) {
            log::error!(
                "[PPT][ROUND-START] node {} is permanently banned; not launching round {} as dealer",
                self.myid,
                target_round
            );
            return;
        }

        log::info!(
            "[PPT][ROUND-START] node {} launching round {} as PPT dealer (full-committee mode)",
            self.myid,
            target_round
        );
        self.ppt_launch_exact_round(target_round).await;
    }

    /// Launch one exact PPT frequency round using SS-AVSS / Two-Field sharing.
    ///
    /// This is the PPT-native replacement for the legacy "next_round_begin" pipeline.
    /// It intentionally carries no appxcon payload.
    #[async_recursion]
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
        log::info!(
            "[PPT][STAGE][BATCH-START] node {} round {}",
            self.myid,
            new_round
        );

        // Pure PPT: no legacy appxcon payload.
        let vec_round_msgs: Vec<(Round,Vec<(Replica,Val)>)> = Vec::new();

        let faults = self.num_faults;
        let batch_size = self.batch_size;
        // Share `batch_size` beacon coins PLUS `PPT_COIN_RESERVE`
        // sealed coin-secrets (used by the NEXT round's ACS common
        // coin). They are dealt + validated identically to beacon
        // coins but live at coin indices [batch_size, total_coins).
        let total_coins = batch_size + crate::node::context::PPT_COIN_RESERVE;
        let low_r = BigUint::from(0u32);
        let prime = self.secret_domain.clone();
        let nonce_prime = self.nonce_domain.clone();

        let two_field_dealer = TwoFieldDealer::new(
            prime.clone(),
            nonce_prime.clone(),
            faults + 1,      // threshold t = f+1
            3 * faults + 1,  // share_amount n = 3f+1
        );

        let n = self.num_nodes;

        // ---- Fiat-Shamir degree test (problem-3 fix) ----
        //
        // (1) Sample f (encoding the secret) and the random mask g for
        //     every coin, WITHOUT computing h yet (h needs θ).
        // (2) Commit: build a Merkle tree per coin whose leaves bind
        //     EACH recipient's (f_share, g_share, f_large, nonce) via
        //     `avss_commit_leaf`. This pins both f and g BEFORE θ.
        // (3) Derive θ = H(round‖dealer‖root_vec) from the commitment
        //     (Fiat-Shamir) — the dealer cannot pick g to cancel a
        //     high-degree f after seeing θ.
        // (4) Compute h(x) = g(x) − θ·f(x) for every coin.
        let mut f_polys: Vec<Vec<BigUint>> = Vec::with_capacity(total_coins);
        let mut g_polys: Vec<Vec<BigUint>> = Vec::with_capacity(total_coins);
        let mut mask_shares_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut f_large_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut secret_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut nonce_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        // Per-coin leaf hashes for the Merkle trees.
        let mut hashes_vec: Vec<Vec<Hash>> = Vec::with_capacity(total_coins);

        for _ in 0..total_coins {
            let secret = rand::thread_rng().gen_biguint_range(&low_r, &prime);
            let sampled = two_field_dealer.sample_shares(secret);
            f_polys.push(sampled.f_poly.clone());
            g_polys.push(sampled.g_poly.clone());

            let nonce_ss = ShamirSecretSharing {
                threshold: faults + 1,
                share_amount: 3 * faults + 1,
                prime: nonce_prime.clone(),
            };
            let nonce = rand::thread_rng().gen_biguint_range(&low_r, &nonce_prime);
            let nonce_shares = nonce_ss.split(nonce);

            let mut coin_leaves: Vec<Hash> = Vec::with_capacity(n);
            for i in 0..n {
                let f_share = Self::pad_shares(sampled.secret_shares[i].1.clone());
                let g_share = Self::pad_shares(sampled.mask_shares[i].1.clone());
                let f_large = Self::pad_shares(sampled.f_large_shares[i].1.clone());
                let nonce_share = Self::pad_shares(nonce_shares[i].1.clone());
                let leaf = types::beacon::avss_commit_leaf(
                    &f_share, &g_share, &f_large, &nonce_share,
                );
                coin_leaves.push(leaf);
                secret_per_node[i].push(f_share);
                nonce_per_node[i].push(nonce_share);
                mask_shares_per_node[i].push(g_share);
                f_large_per_node[i].push(f_large);
            }
            hashes_vec.push(coin_leaves);
        }

        let mt_vec = MerkleTree::build_trees(hashes_vec, &self.hash_context);
        let roots_vec: Vec<Hash> = mt_vec.iter().map(|mt| mt.root()).collect();

        // (3) Fiat-Shamir challenge from the dealer's own commitment.
        let theta = Self::theta_from_commitment(new_round, self.myid, &roots_vec, &nonce_prime);

        // (4) Degree-test polynomial h per coin, under the bound θ.
        let mut degree_test_batch: Vec<Vec<Val>> = Vec::with_capacity(total_coins);
        for coin in 0..total_coins {
            let h = two_field_dealer.compute_degree_test_poly_pub(
                &f_polys[coin],
                &g_polys[coin],
                &theta,
            );
            degree_test_batch.push(h.iter().map(|c| Self::pad_shares(c.clone())).collect());
        }

        // Assemble per-recipient BatchWSSMsg (f-share, nonce, proof).
        let mut vec_msgs_to_be_sent: Vec<(Replica, BatchWSSMsg)> = (0..n)
            .map(|i| (i + 1, BatchWSSMsg::new(self.myid, Vec::new(), Vec::new(), Vec::new())))
            .collect();
        for coin in 0..total_coins {
            let mt = &mt_vec[coin];
            for i in 0..n {
                vec_msgs_to_be_sent[i].1.secrets.push(secret_per_node[i][coin]);
                vec_msgs_to_be_sent[i].1.nonces.push(nonce_per_node[i][coin]);
                vec_msgs_to_be_sent[i].1.mps.push(mt.gen_proof(i));
            }
        }

        assert_eq!(roots_vec.len(), total_coins);
        assert_eq!(degree_test_batch.len(), total_coins);

        // ============================================================
        // AVSS share-distribution dispatch.
        //
        // Step 1 (common to both transports): broadcast a single
        // AvssPublicCommitMsg carrying root_vec + degree_test_coeffs
        // + transcript-binding hash. Same wire payload regardless
        // of transport; saves (n-1)x bytes vs the historical per-
        // recipient duplication of these public fields.
        //
        // Step 2 (transport-specific): ship the per-recipient
        // AvssRecipientPayload (secrets, nonces, mask_shares,
        // f_large_shares, mps) to every other node. Two transports:
        //
        //   * AvssTransport::Lite (default): single AVSSPrivatePayload
        //     unicast per recipient. O(n) wire messages per dealer
        //     per round. Wire-layer confidentiality is provided by
        //     the existing WrapperMsg HMAC + (typically) TLS, plus
        //     the PPT-design observation that the post-ACS
        //     MulticastRecoveredShares phase reveals these same
        //     share bytes in cleartext anyway -- so application-
        //     layer encryption only delays the leak by a few
        //     hundred milliseconds and does not change any
        //     adversary's information set in the steady-state PPT
        //     beacon protocol.
        //
        //   * AvssTransport::SecMsg: full Shoup-Smart 2024 Sec 4.3
        //     Pi_SecMsgDst dispersal (Shamir-shared master key +
        //     per-recipient hash-chain PRG + RBC-style key &
        //     cipher channels with Bracha echo / vote). O(n^2)
        //     wire messages per dealer per round. Suitable for
        //     paper-compliance benchmarks and for deployments
        //     that cannot rely on wire-layer confidentiality.
        //
        // Step 3 (common): the receiver's try_finalize_avss_secmsg
        // reconstructs an equivalent-shaped BeaconMsg and feeds it
        // into the same process_avss_send pipeline the legacy
        // cleartext AVSSSend path used. Every P0/P1/Level fix
        // (theta buffering, banned_dealers, spawn_blocking,
        // audit fire-and-forget, coin-0 fast-path) remains in
        // force regardless of which transport delivered the bytes.
        //
        // appx_con is empty (Vec::new()) on the pure-PPT path
        // (see vec_round_msgs above) so the BeaconMsg
        // reconstruction on the receiver side does not need the
        // dealer to ship appx_con explicitly.
        // ============================================================
        let _ = vec_round_msgs;

        // ----- Step 1: shared public commit broadcast -----
        let public_commit = types::beacon::AvssPublicCommitMsg::new(
            self.myid,
            new_round,
            roots_vec.clone(),
            degree_test_batch.clone(),
        );
        let public_commit_for_self = public_commit.clone();
        self.broadcast(
            CoinMsg::AVSSSecMsgPublicCommit(public_commit),
            new_round,
        )
        .await;
        // Broadcast skips self; deliver our own commit synchronously.
        // wire_sender on the self-deliver path equals self.myid
        // (== public_commit.origin), so the sender-binding check
        // inside `process_avss_secmsg_public_commit` passes.
        let myid = self.myid;
        self.process_avss_secmsg_public_commit(public_commit_for_self, myid)
            .await;

        // ----- Step 2: build per-recipient AvssRecipientPayload byte vectors -----
        // The ordering matches the SecMsgDst recipient_idx convention
        // (recipient j in [0, n) -> payload[j]) so both transports
        // reuse the same per-recipient byte vector.
        let mut recipient_payload_bytes: Vec<Vec<u8>> = Vec::with_capacity(self.num_nodes);
        for (idx, (_rep, batchwss)) in vec_msgs_to_be_sent.into_iter().enumerate() {
            let payload = types::beacon::AvssRecipientPayload::new(
                batchwss.secrets,
                batchwss.nonces,
                mask_shares_per_node[idx].clone(),
                f_large_per_node[idx].clone(),
                batchwss.mps,
            );
            recipient_payload_bytes.push(payload.serialize_bytes());
        }
        debug_assert_eq!(recipient_payload_bytes.len(), self.num_nodes);

        // ----- Step 3: transport-specific dispatch -----
        match self.transport {
            crate::node::context::AvssTransport::Lite => {
                log::info!(
                    "[PPT][AVSS-LITE] node {} dispatching {} per-recipient \
                     AVSSPrivatePayload unicasts for round {} (transport=lite)",
                    self.myid,
                    self.num_nodes,
                    new_round
                );
                // One direct unicast per recipient. The byte vector
                // for recipient `j` is recipient_payload_bytes[j].
                // The self-deliver path (j == self.myid) re-enters
                // process_avss_private_payload synchronously below,
                // which mirrors the broadcast-skips-self pattern
                // used by Context::broadcast.
                for (j, bytes) in recipient_payload_bytes.into_iter().enumerate() {
                    let recipient = j as Replica;
                    if recipient == self.myid {
                        // Self-deliver: wire_sender = self.myid
                        // == dealer, so the sender-binding check
                        // inside process_avss_private_payload passes.
                        self.process_avss_private_payload(
                            new_round,
                            self.myid,
                            bytes,
                            self.myid,
                        )
                        .await;
                    } else {
                        let coin_msg =
                            CoinMsg::AVSSPrivatePayload(new_round, self.myid, bytes);
                        let sec_key = self
                            .sec_key_map
                            .get(&recipient)
                            .cloned()
                            .expect("sec_key for recipient must exist");
                        let wrapper = types::beacon::WrapperMsg::new(
                            coin_msg,
                            self.myid,
                            &sec_key,
                            new_round,
                        );
                        let cancel = self.net_send.send(recipient, wrapper).await;
                        self.add_cancel_handler(cancel);
                    }
                }
            }
            crate::node::context::AvssTransport::SecMsg => {
                log::info!(
                    "[PPT][AVSS-SECMSG] node {} dispatching Pi_SecMsgDst Sec 4.3 \
                     transport for round {} (transport=secmsg)",
                    self.myid,
                    new_round
                );
                let actions = {
                    let secmsg_state =
                        self.get_or_init_avss_secmsg(new_round, self.myid);
                    let mut rng = rand::thread_rng();
                    secmsg_state
                        .set_input_as_sender(recipient_payload_bytes, &mut rng)
                        .expect(
                            "[PPT][SECMSG-AVSS] dealer set_input_as_sender failed -- \
                             this should be impossible on the live path \
                             (only fails on degenerate prime/n/t configs)",
                        )
                };
                self.dispatch_avss_secmsg_actions(new_round, self.myid, actions)
                    .await;
            }
        }

        // Suppress unused-binding warnings for the local variables
        // that the lite path's match-arm closure moves out of scope.
        let _ = roots_vec;
        let _ = degree_test_batch;
        let _ = mask_shares_per_node;
        let _ = f_large_per_node;
        // Keep the legacy-path types referenced via PhantomData
        // so cargo-fix / future imports stay stable. Nothing here
        // executes at runtime.
        let _phantom_legacy: std::marker::PhantomData<(BeaconMsg, Hash, WrapperMsg)> =
            std::marker::PhantomData;

        self.increment_round(new_round).await;
        self.add_benchmark(String::from("ppt_start_round"), now.elapsed().unwrap().as_nanos());
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
