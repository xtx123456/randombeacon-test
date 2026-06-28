use std::time::SystemTime;

use async_recursion::async_recursion;
use crypto::gf2::{Gf2Element, Gf2Profile};
use crypto::{aes_hash::MerkleTree, hash::Hash};
use num_bigint::{BigUint, RandBigInt};
use rand::Rng;
use types::{
    beacon::{BatchWSSMsg, BeaconMsg, CoinMsg, Round, Val, WrapperMsg},
    Replica,
};

use crate::node::shamir::gf2_two_field::Gf2TwoFieldDealer;
use crate::node::shamir::two_field::TwoFieldDealer;
use crate::node::{CTRBCState, Context, ShamirSecretSharing};

// ============================================================================
// AVSS dealer field-adapter (commit 4 of the GF(2^w) migration)
//
// `ppt_try_start_round_exact` originally hardcoded a `TwoFieldDealer`
// (BigUint). This adapter lets the same round-bootstrap routine run
// against either the legacy BigUint dealer or the new
// `Gf2TwoFieldDealer` (parametrised by `Context::gf2_profile`),
// without duplicating the ~250-line wire-assembly + broadcast block.
//
// The contract is "bytes in, bytes out": all per-recipient share
// material is exposed as `Val = [u8; 32]`, and the Fiat-Shamir θ is
// derived as 32 bytes. The wire format (Val slots) is therefore
// unchanged; only the **interpretation** of those bytes differs by
// field. A receiver on the *matching* profile decodes them with
// `Gf2Element::from_bytes(profile, ..)`; a receiver on the wrong
// profile would parse garbage. Cluster-wide configuration agreement
// is the user's responsibility (the same assumption as
// `--transport`).
// ============================================================================

/// Field-agnostic AVSS dealer adapter for `ppt_try_start_round_exact`.
enum DealerAdapter {
    BigUint {
        dealer: TwoFieldDealer,
        secret_domain: BigUint,
        nonce_domain: BigUint,
    },
    Gf2 {
        dealer: Gf2TwoFieldDealer,
        profile: Gf2Profile,
        nonce_domain: BigUint,
    },
}

/// Per-coin polynomial state retained between `sample_coin` and
/// `compute_h_bytes`. The dealer commits to f and g (via the Merkle
/// trees built over per-recipient share material) *before* θ is
/// derived (Fiat-Shamir); this enum keeps the field-native f / g
/// polynomials around for the post-θ `h(x) = g(x) + θ·f(x)` step.
enum CoinPolyBlob {
    BigUint {
        f_poly: Vec<BigUint>,
        g_poly: Vec<BigUint>,
    },
    Gf2 {
        profile: Gf2Profile,
        f_poly: Vec<Gf2Element>,
        g_poly: Vec<Gf2Element>,
    },
}

impl DealerAdapter {
    /// Build the appropriate adapter for the current `Context`
    /// configuration. Falls back to the BigUint dealer when no
    /// GF(2^w) profile is configured (the historical default).
    fn build(ctx: &Context, threshold: usize, share_amount: usize) -> Self {
        match ctx.gf2_profile {
            Some(profile) => DealerAdapter::Gf2 {
                dealer: Gf2TwoFieldDealer::new(profile, threshold, share_amount).expect(
                    "Gf2Profile + share_amount validated at CLI parse time / Context construction",
                ),
                profile,
                nonce_domain: ctx.nonce_domain.clone(),
            },
            None => DealerAdapter::BigUint {
                dealer: TwoFieldDealer::new(
                    ctx.secret_domain.clone(),
                    ctx.nonce_domain.clone(),
                    threshold,
                    share_amount,
                ),
                secret_domain: ctx.secret_domain.clone(),
                nonce_domain: ctx.nonce_domain.clone(),
            },
        }
    }

    /// Large-field domain. Used by the per-coin nonce sampler
    /// (BigUint commitment salt, unchanged in both modes).
    fn nonce_domain(&self) -> &BigUint {
        match self {
            Self::BigUint { nonce_domain, .. } | Self::Gf2 { nonce_domain, .. } => nonce_domain,
        }
    }

    /// Sample one coin's f-polynomial + g-polynomial and per-
    /// recipient shares. Returns the per-recipient share Vals
    /// (recipient i corresponds to node id i+1) plus a polynomial
    /// blob retained for the post-θ degree-test computation.
    fn sample_coin(&self) -> (Vec<Val>, Vec<Val>, Vec<Val>, CoinPolyBlob) {
        match self {
            Self::BigUint {
                dealer,
                secret_domain,
                ..
            } => {
                let low = BigUint::from(0u32);
                let secret = rand::thread_rng().gen_biguint_range(&low, secret_domain);
                let sampled = dealer.sample_shares(secret);
                let secrets = sampled
                    .secret_shares
                    .iter()
                    .map(|(_, v)| Context::pad_shares(v.clone()))
                    .collect();
                let f_larges = sampled
                    .f_large_shares
                    .iter()
                    .map(|(_, v)| Context::pad_shares(v.clone()))
                    .collect();
                let masks = sampled
                    .mask_shares
                    .iter()
                    .map(|(_, v)| Context::pad_shares(v.clone()))
                    .collect();
                (
                    secrets,
                    f_larges,
                    masks,
                    CoinPolyBlob::BigUint {
                        f_poly: sampled.f_poly,
                        g_poly: sampled.g_poly,
                    },
                )
            }
            Self::Gf2 { dealer, profile, .. } => {
                // Uniform small-field secret in GF(2^w_p): sample
                // `small_byte_len` random bytes and lift into the
                // tower envelope. `lift_small` masks any bits beyond
                // `w_p` to zero.
                let small_len = profile.small_byte_len();
                let mut small_bytes = vec![0u8; small_len];
                rand::thread_rng().fill(&mut small_bytes[..]);
                let secret = Gf2Element::lift_small(*profile, &small_bytes);
                let sampled = dealer.sample_shares(secret);
                let secrets = sampled
                    .secret_shares
                    .iter()
                    .map(|(_, v)| *v.as_bytes())
                    .collect();
                let f_larges = sampled
                    .f_large_shares
                    .iter()
                    .map(|(_, v)| *v.as_bytes())
                    .collect();
                let masks = sampled
                    .mask_shares
                    .iter()
                    .map(|(_, v)| *v.as_bytes())
                    .collect();
                (
                    secrets,
                    f_larges,
                    masks,
                    CoinPolyBlob::Gf2 {
                        profile: *profile,
                        f_poly: sampled.f_poly,
                        g_poly: sampled.g_poly,
                    },
                )
            }
        }
    }

    /// Derive the Fiat-Shamir degree-test challenge θ as 32 bytes.
    /// Both modes share the same `theta_seed_bytes` transcript so
    /// honest verifiers on the matching profile recompute the
    /// identical value.
    fn derive_theta_bytes(&self, round: Round, dealer_id: Replica, roots: &[Hash]) -> [u8; 32] {
        match self {
            Self::BigUint { nonce_domain, .. } => {
                let theta = Context::theta_from_commitment(round, dealer_id, roots, nonce_domain);
                Context::pad_shares(theta)
            }
            Self::Gf2 { profile, .. } => {
                let theta = Context::theta_from_commitment_gf2(round, dealer_id, roots, *profile);
                *theta.as_bytes()
            }
        }
    }
}

impl CoinPolyBlob {
    /// Compute the degree-test polynomial `h(x) = g(x) ± θ · f(x)`
    /// for this coin and return its coefficients as on-wire Vals.
    /// (The sign drops in char 2: `+` and `−` are XOR.)
    fn compute_h_bytes(&self, theta_bytes: &[u8; 32], dealer: &DealerAdapter) -> Vec<Val> {
        match (self, dealer) {
            (
                Self::BigUint { f_poly, g_poly },
                DealerAdapter::BigUint { dealer, .. },
            ) => {
                let theta = BigUint::from_bytes_be(theta_bytes);
                let h = dealer.compute_degree_test_poly_pub(f_poly, g_poly, &theta);
                h.into_iter().map(Context::pad_shares).collect()
            }
            (
                Self::Gf2 {
                    profile,
                    f_poly,
                    g_poly,
                },
                DealerAdapter::Gf2 { dealer, .. },
            ) => {
                let theta = Gf2Element::from_bytes(*profile, *theta_bytes)
                    .expect("theta_bytes always canonical via from_random_bytes");
                let h = dealer.compute_degree_test_poly(f_poly, g_poly, &theta);
                h.iter().map(|c| *c.as_bytes()).collect()
            }
            _ => unreachable!(
                "DealerAdapter and CoinPolyBlob variants must match (programmer bug)"
            ),
        }
    }
}

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

        // Field-agnostic AVSS dealer adapter (see DealerAdapter at the
        // top of this file). Dispatches to either the BigUint
        // `TwoFieldDealer` (default, ctx.gf2_profile == None) or the
        // GF(2^w) `Gf2TwoFieldDealer` based on the runtime profile
        // selector. All per-recipient share material below flows as
        // 32-byte `Val` slots regardless of the underlying field —
        // wire format is unchanged.
        let dealer = DealerAdapter::build(self, faults + 1, 3 * faults + 1);
        let nonce_prime = dealer.nonce_domain().clone();

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
        // (4) Compute h(x) = g(x) − θ·f(x) for every coin. (In char 2,
        //     i.e. the GF(2^w) profile, this is g(x) + θ·f(x); both
        //     forms are byte-equivalent.)
        let mut coin_blobs: Vec<CoinPolyBlob> = Vec::with_capacity(total_coins);
        let mut mask_shares_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut f_large_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut secret_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        let mut nonce_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(total_coins); n];
        // Per-coin leaf hashes for the Merkle trees.
        let mut hashes_vec: Vec<Vec<Hash>> = Vec::with_capacity(total_coins);

        for _ in 0..total_coins {
            let (secret_shares, f_large_shares, mask_shares, blob) = dealer.sample_coin();

            // Per-coin nonce: BigUint Shamir salt in BOTH modes
            // (nonces are commit-binding only, don't participate in
            // field arithmetic, no need to migrate them).
            let nonce_ss = ShamirSecretSharing {
                threshold: faults + 1,
                share_amount: 3 * faults + 1,
                prime: nonce_prime.clone(),
            };
            let nonce = rand::thread_rng().gen_biguint_range(&low_r, &nonce_prime);
            let nonce_shares = nonce_ss.split(nonce);

            let mut coin_leaves: Vec<Hash> = Vec::with_capacity(n);
            // GF(2^w) mode (commit 7): f_large == f_share byte-for-byte
            // (subfield closure), so the leaf hash binds only
            // (f_share, g_share, nonce) — saves 32 bytes of input per
            // leaf. Producer-side `f_large_per_node` is still
            // populated for storage symmetry but is NOT shipped on
            // the wire (see Step 2 below where `f_large_shares`
            // becomes `None` in GF2 mode).
            let in_gf2_mode = self.gf2_profile.is_some();
            for i in 0..n {
                let f_share = secret_shares[i];
                let g_share = mask_shares[i];
                let f_large = f_large_shares[i];
                let nonce_share = Self::pad_shares(nonce_shares[i].1.clone());
                let leaf = if in_gf2_mode {
                    types::beacon::avss_commit_leaf_gf2(&f_share, &g_share, &nonce_share)
                } else {
                    types::beacon::avss_commit_leaf(
                        &f_share, &g_share, &f_large, &nonce_share,
                    )
                };
                coin_leaves.push(leaf);
                secret_per_node[i].push(f_share);
                nonce_per_node[i].push(nonce_share);
                mask_shares_per_node[i].push(g_share);
                f_large_per_node[i].push(f_large);
            }
            hashes_vec.push(coin_leaves);
            coin_blobs.push(blob);
        }

        let mt_vec = MerkleTree::build_trees(hashes_vec, &self.hash_context);
        let roots_vec: Vec<Hash> = mt_vec.iter().map(|mt| mt.root()).collect();

        // (3) Fiat-Shamir challenge from the dealer's own commitment.
        //     Returned as 32 raw bytes; each field interprets them via
        //     its own canonicalisation inside `compute_h_bytes`.
        let theta_bytes = dealer.derive_theta_bytes(new_round, self.myid, &roots_vec);

        // (4) Degree-test polynomial h per coin, under the bound θ.
        let mut degree_test_batch: Vec<Vec<Val>> = Vec::with_capacity(total_coins);
        for blob in &coin_blobs {
            degree_test_batch.push(blob.compute_h_bytes(&theta_bytes, &dealer));
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
        //
        // GF(2^w) wire-format compaction (commit 7): the f_large
        // channel is dropped in GF2 mode since `f_large == secrets`
        // byte-for-byte under the subfield embedding. The dealer
        // ships `f_large_shares = None`; the receiver derives
        // `f_large := secrets` locally before running the degree
        // test. Saves 32 bytes per (recipient, coin) on the wire
        // AND 32 bytes per leaf in the Merkle hash input.
        let dealer_in_gf2_mode = self.gf2_profile.is_some();
        let mut recipient_payload_bytes: Vec<Vec<u8>> = Vec::with_capacity(self.num_nodes);
        for (idx, (_rep, batchwss)) in vec_msgs_to_be_sent.into_iter().enumerate() {
            let f_large_opt = if dealer_in_gf2_mode {
                None
            } else {
                Some(f_large_per_node[idx].clone())
            };
            let payload = types::beacon::AvssRecipientPayload::new(
                batchwss.secrets,
                batchwss.nonces,
                mask_shares_per_node[idx].clone(),
                f_large_opt,
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
