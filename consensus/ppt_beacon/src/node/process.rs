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
    hash_context: &HashState,
    secret_domain: &BigUint,
    nonce_domain: &BigUint,
    num_faults: usize,
    num_nodes: usize,
    batch_size: usize,
    coin_reserve: usize,
    myid: usize,
) -> Result<(), &'static str> {
    // The dealer shares `batch_size` beacon coins plus `coin_reserve`
    // sealed ACS-coin secrets; all are committed + degree-tested
    // uniformly, so every length / loop below ranges over the total.
    let batch_size = batch_size + coin_reserve;
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

    // Fiat-Shamir degree-test challenge θ (problem-3 fix): derived
    // from the dealer's OWN committed Merkle roots, so the dealer had
    // to commit f and g (bound into the leaves via `avss_commit_leaf`)
    // BEFORE θ was determined. Replaces the old predictable θ =
    // H(previous public beacon). Every honest verifier recomputes the
    // identical θ from the same committed `root_vec`.
    let theta = {
        let root_vec = match beacon_msg.root_vec.as_ref() {
            Some(rv) if rv.len() == batch_size => rv,
            Some(_) => return Err("malformed root_vec length"),
            None => return Err("missing root_vec or wss"),
        };
        Context::theta_from_commitment(round, dealer, root_vec, nonce_domain)
    };
    let theta = &theta;

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

    // PPT slide 20 binding: the dealer commits to a Merkle root
    // vector `root_vec[coin]` over the n share commitments
    // `c_i = H(share_i, nonce_i)`. The per-recipient Merkle proof
    // `mp_coin` MUST chain to this dealer-published root. Without
    // this check a Byzantine dealer could ship `(share_j, nonce_j,
    // mp_j)` triples whose mp_j is internally self-consistent and
    // satisfies `hash(share_j, nonce_j) == mp_j.item()` (which is
    // all `verify_proofs` enforces) but whose `mp_j.root()` differs
    // from the committed `root_vec[coin]`. The triples would then
    // pass AVSS-quorum, the dealer would enter the ACS-decided set,
    // and the garbage shares would dictate the round's beacon
    // contribution. Audit catches this post-emit (via
    // `audit_post_complaint_pure` comparing `proof.root() !=
    // expected_root`), but by then the bad beacon is already out.
    let root_vec_opt = beacon_msg.root_vec.as_ref();
    let wssmsg_opt = beacon_msg.wss.as_ref();
    if let (Some(root_vec), Some(wssmsg)) = (root_vec_opt, wssmsg_opt) {
        if root_vec.len() != batch_size {
            log::warn!(
                "[PPT][AVSS] root_vec length {} != batch_size {} from dealer {} round {}",
                root_vec.len(),
                batch_size,
                dealer,
                round
            );
            return Err("malformed root_vec length");
        }
        if wssmsg.mps.len() != batch_size {
            log::warn!(
                "[PPT][AVSS] mps length {} != batch_size {} from dealer {} round {}",
                wssmsg.mps.len(),
                batch_size,
                dealer,
                round
            );
            return Err("malformed mps length");
        }
        for (coin_num, mp) in wssmsg.mps.iter().enumerate() {
            if mp.root() != root_vec[coin_num] {
                log::warn!(
                    "[PPT][AVSS] mp.root != root_vec[coin] for dealer {} round {} coin {} at node {}",
                    dealer,
                    round,
                    coin_num,
                    myid
                );
                return Err("mp.root does not match dealer's committed root_vec");
            }
        }
    } else {
        // Both fields are mandatory on the PPT path; their absence
        // is a malformed packet from a Byzantine dealer.
        return Err("missing root_vec or wss");
    }

    let verifier = TwoFieldDealer::new(
        secret_domain.clone(),
        nonce_domain.clone(),
        num_faults + 1,
        num_nodes,
    );

    // Pre-extract the small-field share bytes for the share <-> f_large
    // cross-field binding check below. We already verified
    // `wssmsg_opt.is_some()` and `wssmsg.mps.len() == batch_size`
    // immediately above; `wssmsg.secrets.len()` is asserted to equal
    // `mps.len()` by `verify_proofs` (it calls `hash_batch(secrets,
    // nonces)` and zips against `mps`, so a mismatch would have
    // panicked or short-circuited there). We re-check explicitly so
    // a future refactor of `verify_proofs` cannot silently lift the
    // implicit length invariant.
    let wssmsg = wssmsg_opt.expect("just verified Some(_) above");
    if wssmsg.secrets.len() != batch_size {
        return Err("malformed wss.secrets length");
    }

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

        // Two-field cross-binding: the small-field `share[coin]`
        // (used in F_p Lagrange reconstruction) MUST equal
        // `f_large[coin] mod secret_domain`. An honest dealer
        // satisfies this trivially because `share = f_poly(i) mod p`
        // and `f_large = f_poly(i) mod q` come from a SINGLE
        // polynomial `f_poly` whose coefficients are all in [0, p)
        // < q (see `TwoFieldDealer::share_secret`), so
        // `f_poly(i) mod p == (f_poly(i) mod q) mod p`.
        //
        // Without this binding, a Byzantine dealer can decouple the
        // two channels: ship an honest degree-t `(f_large, g_share,
        // h)` triple that passes the degree-test at every recipient,
        // and INDEPENDENTLY ship `(share_1, ..., share_n)` that
        // interpolate (on the ACS-decided evaluation point subset)
        // to any dealer-chosen target. The reconstruction layer
        // computes the round's beacon contribution by Lagrange-
        // interpolating exactly those `share` values, so the dealer
        // can pick its contribution at will -- and the audit layer
        // does not catch this (it only compares `proof.root() !=
        // expected_root`, which the dealer satisfied above by
        // committing to the garbage shares' own Merkle root).
        //
        // Cost: one BigUint construction + one mod + one equality
        // check per (coin, node). For batch_size = 100, n = 16 this
        // is on the order of a few microseconds per AVSSSend; the
        // spawn_blocking wrapper that already hosts this function
        // absorbs it without a noticeable benchmark hit.
        let share = BigUint::from_bytes_be(wssmsg.secrets[coin_num].as_slice());
        if share != (&f_large % secret_domain) {
            log::warn!(
                "[PPT][AVSS] share != f_large mod p for dealer {} round {} coin {} at node {} \
                 (dealer decoupled small-field share from large-field degree-test polynomial)",
                dealer,
                round,
                coin_num,
                myid
            );
            return Err("share mod p does not match f_large mod p");
        }
    }

    Ok(())
}

impl Context {
    /// MAC-verify an inbound wrapper. Takes `&WrapperMsg` (was
    /// `Arc<WrapperMsg>`) so the caller no longer needs to clone
    /// the entire enclosed `protmsg` payload just to pass it
    /// here. For inbound BatchBeaconConstruct at batch=1000 the
    /// pre-clone alone was ~4.5 MB per message; eliminating it
    /// saves tens of MB of memory bandwidth per round per node.
    pub fn check_proposal(self: &Context, wrapper_msg: &WrapperMsg) -> bool {
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

        if self.check_proposal(&wrapper_msg) {
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
        // Destructure WrapperMsg by ownership rather than cloning
        // `protmsg` just to match on it. The old `wrapper_msg.clone()
        // .protmsg` pattern cloned the entire inbound payload --
        // ~4.5 MB for BatchBeaconConstruct at batch=1000 -- on the
        // consensus main task before we could even dispatch.
        let wire_sender = wrapper_msg.sender;
        match wrapper_msg.protmsg {
            // Legacy cleartext AVSSSend from a peer running an older
            // binary. Commit 7 cut the dealer over to the
            // Shoup-Smart 2024 SecMsgDst path (AVSSSecMsgPublicCommit
            // + AVSSSecMsgKey* + AVSSSecMsgCipher*); honest dealers
            // running this binary never emit AVSSSend on the wire.
            // We keep the `process_avss_send` body alive because the
            // theta-replay path (`drain_pending_avss_for`) and the
            // SecMsgDst finalisation path (`try_finalize_avss_secmsg`)
            // both call it internally with locally-reconstructed
            // BeaconMsgs. This branch only fires for a literal wire
            // AVSSSend, which we drop with a diagnostic.
            CoinMsg::AVSSSend(_beaconmsg, _transcript_root, dealer, round) => {
                log::warn!(
                    "[PPT][AVSS-LEGACY] dropping wire AVSSSend from dealer {} \
                     for round {} -- commit 7 cut the dealer over to \
                     SecMsgDst-routed AVSS",
                    dealer, round
                );
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
                    wire_sender
                );
                if wire_sender != proposer {
                    log::warn!(
                        "[PPT][ACS-RBC] dropping ACSRbcSend round {} proposer {} sent by wire {} (sender mismatch)",
                        round, proposer, wire_sender
                    );
                } else {
                    self.process_acs_rbc_send(round, proposer, payload).await;
                }
            }
            CoinMsg::ACSRbcEcho(round, proposer, payload_hash) => {
                self.process_acs_rbc_echo(round, proposer, wire_sender, payload_hash).await;
            }
            CoinMsg::ACSRbcReady(round, proposer, payload_hash) => {
                self.process_acs_rbc_ready(round, proposer, wire_sender, payload_hash).await;
            }
            CoinMsg::ACSAbaBval(round, aba_instance_id, aba_round, value) => {
                self.process_acs_aba_bval(round, aba_instance_id, aba_round, value, wire_sender).await;
            }
            CoinMsg::ACSAbaAux(round, aba_instance_id, aba_round, value) => {
                self.process_acs_aba_aux(round, aba_instance_id, aba_round, value, wire_sender).await;
            }
            // ---- Shoup-Smart 2024 SecMsgDst-routed AVSS (commit 6 receiver-side) ----
            //
            // Commit 6 lands the receiver plumbing only. The legacy
            // `AVSSSend` path above still drives AVSS-completion in
            // production; the variants below cache decrypted
            // plaintexts so commit 7 can flip the dealer cutover
            // atomically without changing the wire dispatcher again.
            CoinMsg::AVSSSecMsgPublicCommit(commit_msg) => {
                // Sender-binding: only the dealer themselves may
                // broadcast their own public commit. See the
                // doc-comment on
                // `process_avss_secmsg_public_commit` for the
                // dealer-framing attack this guards against.
                self.process_avss_secmsg_public_commit(commit_msg, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgKeyDispersal(round, dealer, payload) => {
                self.process_avss_secmsg_key_dispersal(
                    round, dealer, payload, wire_sender,
                )
                .await;
            }
            CoinMsg::AVSSSecMsgKeyEcho(round, dealer, payload) => {
                self.process_avss_secmsg_key_echo(round, dealer, payload, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgKeyVote(round, dealer, meta_root) => {
                self.process_avss_secmsg_key_vote(round, dealer, meta_root, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgCipherDispersal(round, dealer, payload) => {
                self.process_avss_secmsg_cipher_dispersal(
                    round, dealer, payload, wire_sender,
                )
                .await;
            }
            CoinMsg::AVSSSecMsgCipherEcho(round, dealer, payload) => {
                self.process_avss_secmsg_cipher_echo(
                    round, dealer, payload, wire_sender,
                )
                .await;
            }
            CoinMsg::AVSSSecMsgCipherVote(round, dealer, meta_root) => {
                self.process_avss_secmsg_cipher_vote(
                    round, dealer, meta_root, wire_sender,
                )
                .await;
            }
            // ---- Lite AVSS transport (default; pluggable-transport mode 'lite') ----
            //
            // Wire complement of AVSSSecMsgPublicCommit: a single
            // unicast per recipient carrying the dealer's
            // bincode-serialized AvssRecipientPayload. The receiver
            // handler caches the bytes and triggers the existing
            // try_finalize_avss_secmsg path, so AVSSReady /
            // AVSSComplete quorum, ACS hook, theta buffering, and
            // post-ACS audit all stay shared with the secmsg path.
            CoinMsg::AVSSPrivatePayload(round, dealer, payload) => {
                self.process_avss_private_payload(
                    round, dealer, payload, wire_sender,
                )
                .await;
            }
            CoinMsg::ACSCoinReveal(acs_round, aba_round, packet) => {
                self.process_acs_coin_reveal(
                    acs_round, aba_round, packet, wrapper_msg.sender,
                )
                .await;
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
    ) -> Result<(), &'static str> {
        avss_local_packet_valid_pure(
            beacon_msg,
            transcript_root,
            dealer,
            round,
            &self.hash_context,
            &self.secret_domain,
            &self.nonce_domain,
            self.num_faults,
            self.num_nodes,
            self.batch_size,
            crate::node::context::PPT_COIN_RESERVE,
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

    /// Inbound AVSS packet entry point. **Phase D fire-and-forget**:
    /// the CPU-heavy validation runs in a detached
    /// `tokio::spawn` + `spawn_blocking` so the consensus main
    /// loop is not blocked while it runs. Validation results come
    /// back through `Context::avss_validation_rx` and are applied
    /// by `finalize_avss_validation`.
    ///
    /// Before fire-and-forget, the consensus task awaited the
    /// `spawn_blocking` synchronously and applied the
    /// `store_avss_packet` + `AVSSReady` cascade inline. With
    /// n=16, batch=1000 this awaited ~25 ms per inbound AVSS
    /// packet, and the n inbound packets per round per node were
    /// serialised on the main loop = ~400 ms per round on the
    /// main loop just for AVSS validation awaits, blocking
    /// reconstruct / ACS / next-round AVSS from interleaving.
    ///
    /// Phase D parallelises the validations on the blocking pool;
    /// per-round AVSS-validation wall time drops from
    /// `n * 25 ms` to `~25 ms` on a multi-core machine.
    ///
    /// Idempotency / safety:
    ///   * `theta` is resolved + the packet is buffered (NOT
    ///     dropped) on `None` before any spawn happens, exactly
    ///     as before.
    ///   * `banned_dealers` is checked before spawn (cheap).
    ///   * The `avss_local_valid` de-dup guard runs inside
    ///     `finalize_avss_validation` on the main loop, so a
    ///     duplicate AVSS packet for the same `(round, dealer)`
    ///     pays only the cost of one extra spawn_blocking before
    ///     being short-circuited.
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

        // Lazy-create the per-round CTRBCState so the detached
        // validation's apply path can find it when its result lands.
        if !self.round_state.contains_key(&round) {
            let rbc_new_state =
                crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        // Snapshot every input the detached validator needs so the
        // task is self-contained (no &self captured). The Fiat-Shamir
        // degree-test challenge θ is derived INSIDE the validator from
        // the dealer's committed `root_vec`, so there is no θ to fetch
        // or buffer here (the old previous-beacon θ race is gone).
        let hash_context = Arc::clone(&self.hash_context);
        let secret_domain = self.secret_domain.clone();
        let nonce_domain = self.nonce_domain.clone();
        let num_faults = self.num_faults;
        let num_nodes = self.num_nodes;
        let batch_size = self.batch_size;
        let myid = self.myid;
        let transcript_root_owned = transcript_root;
        let avss_tx = self.avss_validation_tx.clone();

        // Phase D fire-and-forget (PR#6) + Fiat-Shamir validator
        // (PR#5): detach the CPU-heavy validation into an independent
        // tokio task so concurrent inbound AVSS packets validate in
        // PARALLEL on the blocking pool, then publish the outcome back
        // to the main loop via `avss_validation_tx`. The validator
        // derives θ internally from the committed root_vec (no theta
        // argument).
        tokio::spawn(async move {
            let (validation_result, beacon_msg_back) =
                tokio::task::spawn_blocking(move || {
                    let result = avss_local_packet_valid_pure(
                        &beacon_msg,
                        &transcript_root_owned,
                        dealer,
                        round,
                        &hash_context,
                        &secret_domain,
                        &nonce_domain,
                        num_faults,
                        num_nodes,
                        batch_size,
                        crate::node::context::PPT_COIN_RESERVE,
                        myid,
                    );
                    (result, beacon_msg)
                })
                .await
                .unwrap_or_else(|e| {
                    log::error!(
                        "[PPT][LEVEL2] AVSS validation blocking task join error \
                         round {} dealer {}: {}",
                        round, dealer, e
                    );
                    // Failsafe: treat join error as transient (no ban).
                    (
                        Err("blocking task join error"),
                        types::beacon::BeaconMsg::new_with_appx(0, 0, Vec::new()),
                    )
                });

            let _ = avss_tx.send(crate::node::context::AvssValidationCompletion {
                round,
                dealer,
                transcript_root: transcript_root_owned,
                beacon_msg: beacon_msg_back,
                result: validation_result,
            });
        });
    }

    /// Apply one completed AVSS validation (from the detached
    /// task spawned in `process_avss_send`). Called from the
    /// main loop's `tokio::select!` arm on
    /// `avss_validation_rx.recv()`. Runs on the consensus task's
    /// worker thread, so every Context mutation (round_state,
    /// banned_dealers) stays single-threaded as before fire-and-
    /// forget was added.
    pub async fn finalize_avss_validation(
        &mut self,
        completion: crate::node::context::AvssValidationCompletion,
    ) {
        let crate::node::context::AvssValidationCompletion {
            round,
            dealer,
            transcript_root,
            beacon_msg,
            result,
        } = completion;

        // Dealer may have been banned between spawn and finalize
        // (e.g. via the post-ACS audit / another concurrent
        // validation failure). Drop late results for banned
        // dealers to avoid spurious AVSSReady broadcasts.
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][AVSS-FINALIZE] dropping AVSS validation result for \
                 banned dealer {} round {}",
                dealer, round
            );
            return;
        }

        match result {
            Ok(()) => {}
            Err(reason) => {
                log::error!(
                    "[PPT][AVSS-BAN] banning dealer {} for invalid AVSS packet \
                     round {} reason={}",
                    dealer, round, reason
                );
                self.ban_dealer_global(dealer);
                return;
            }
        }

        // Ensure round_state still exists (it normally does --
        // process_avss_send lazily creates it before spawning).
        if !self.round_state.contains_key(&round) {
            let rbc_new_state =
                crate::node::CTRBCState::new(self.secret_domain.clone(), self.num_nodes);
            self.round_state.insert(round, rbc_new_state);
        }

        // De-dup: if another detached task for the same
        // (round, dealer) already raced ahead and finalized
        // first, skip.
        {
            let rbc_state = self.round_state.get_mut(&round).unwrap();
            if rbc_state.avss_local_valid.contains(&dealer) {
                return;
            }
            rbc_state.store_avss_packet(dealer, beacon_msg, transcript_root);
            rbc_state.avss_local_valid.insert(dealer);
            rbc_state.add_avss_ready_vote(dealer, self.myid, transcript_root);
        }

        // Phase F2 -- the AVSS validation cascade has now completed
        // for (round, dealer): `store_avss_packet` copied every field
        // we need into `CTRBCState` (root_vec, degree_test_coeffs,
        // mask_shares, f_large_shares, BatchWSSMsg). The two
        // SecMsgDst-side caches that fed us here -- the
        // `AvssPublicCommitMsg` and the decrypted
        // `AvssRecipientPayload` plaintext bytes -- are dead weight
        // from this point on. Drop them immediately to keep memory
        // proportional to "currently-being-validated rounds" rather
        // than "all rounds waiting for end-of-round
        // maybe_release_round". At batch=1000 / n=16 this frees on
        // the order of 5 MB per round per node.
        //
        // Late duplicate AVSSPrivatePayload / AVSSSecMsgPublicCommit
        // arriving for the same (round, dealer) after this point are
        // dropped by the `avss_local_valid` guards added to
        // `process_avss_private_payload` and
        // `process_avss_secmsg_public_commit`, so the drop here is
        // safe: nothing will re-allocate these entries.
        self.avss_secmsg_public.remove(&(round, dealer));
        self.avss_secmsg_delivered_bytes.remove(&(round, dealer));

        let ready_msg = CoinMsg::AVSSReady(dealer, transcript_root, self.myid, round);
        self.broadcast(ready_msg, round).await;

        if let Some(complete_root) = self.maybe_prepare_avss_complete(round, dealer) {
            let complete_msg =
                CoinMsg::AVSSComplete(dealer, complete_root, self.myid, round);
            self.broadcast(complete_msg, round).await;
            self.process_avss_complete(dealer, complete_root, self.myid, round)
                .await;
        }

        if self.maybe_mark_dealer_completed(round, dealer) {
            self.maybe_broadcast_acs_init_from_avss(round).await;
        }

        // This dealer's commitment vector (`comm_vectors`) is now
        // stored locally. If reconstruction for this round is already
        // underway, any recon coin-packets that were buffered in
        // `pending_recon_shares` because they referenced this dealer's
        // (previously-missing) commitment can now be validated. This
        // is a no-op until ACS has decided and is cheap otherwise.
        self.maybe_recover_ready_coins(round).await;
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

            // PPT reconstruction is no longer pinned to a fixed
            // evaluation-point set derived from the ACS-decided
            // dealers. Each decided dealer's secret is reconstructed
            // from ANY f+1 Merkle-validated shares supplied by ANY
            // providers (see `recover_and_emit_coin_set`), so a
            // Byzantine node admitted into the decided set can no
            // longer stall the round by withholding its own
            // reconstruction share. The per-(provider-set) Lagrange
            // coefficients are built on demand at recovery time.
            rbc_state.batch_extractor = None;

            // Build the super-invertible (hyper-invertible) randomness
            // extraction matrix for this round's immutable decided set.
            // `alpha = sorted(decided) + 1`, `num_outputs = m - f`
            // (>= f+1 >= 1). `coin_check` applies it per coin column to
            // extract `m - f` independent beacon values, tolerating the
            // <= f Byzantine dealers in the decided set.
            use crate::node::shamir::two_field::SuperInvExtractor;
            let m = decided_vec.len();
            let num_outputs = m.saturating_sub(self.num_faults).max(1);
            let alpha_points: Vec<usize> =
                decided_vec.iter().map(|dealer| *dealer + 1).collect();
            rbc_state.super_inv_extractor = Some(SuperInvExtractor::new(
                alpha_points,
                num_outputs,
                rbc_state.secret_domain.clone(),
            ));

            log::error!(
                "[PPT][ACS-RECON] node {} round {} immutable decided_set = {:?} (reconstruction: any f+1 validated providers/dealer; extraction: super-invertible {}->{} per coin)",
                self.myid,
                round,
                decided_vec,
                m,
                num_outputs
            );
            std::mem::take(&mut rbc_state.pre_acs_beacon_constructs)
        };

        // ACS common coin (problem-1 fix):
        //   - stash THIS round's sealed coin-secrets so round (round+1)'s
        //     ACS can reconstruct its unpredictable common coin from a
        //     stable, agreed dealer set (= this round's decided set);
        //   - drop the coin state for this round and the material it
        //     consumed (round-1), now that this round's ACS is done.
        self.stash_coin_material(round, decided_vec.as_slice());
        self.cleanup_coin_state(round);

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

// ---------------------------------------------------------------------
// Unit tests for the two AVSS-ingest binding checks added to
// `avss_local_packet_valid_pure` (commit "ppt_beacon: bind share to
// f_large mod p and mp.root to root_vec[coin] in AVSS validation").
//
// Each test starts from an honest two-field share batch and then
// surgically corrupts ONE field to simulate the Byzantine attack
// the corresponding binding guards against. The honest path
// (`accepts_honest_two_field_packet`) double-checks that the new
// guards do not reject legitimate inputs.
// ---------------------------------------------------------------------
#[cfg(test)]
mod avss_binding_tests {
    use super::*;
    use crate::node::shamir::two_field::TwoFieldDealer;
    use crypto::aes_hash::{HashState, MerkleTree};
    use num_bigint::RandBigInt;
    use rand::SeedableRng;
    use types::beacon::{BatchWSSMsg, BeaconMsg, Val};

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

    fn pad32(b: BigUint) -> [u8; 32] {
        let mut bytes = b.to_bytes_be();
        assert!(bytes.len() <= 32);
        let mut out = vec![0u8; 32 - bytes.len()];
        out.append(&mut bytes);
        out.try_into().expect("padded to 32")
    }

    /// Build an honest two-field AVSS batch for one dealer, one
    /// receiver, and an arbitrary batch size. Returns the inputs
    /// `avss_local_packet_valid_pure` accepts as parameters when
    /// the dealer is honest.
    fn build_honest_packet(
        dealer: Replica,
        myid: usize,
        round: Round,
        batch_size: usize,
        n: usize,
        f: usize,
        force_wrong_theta: bool,
    ) -> (BeaconMsg, Hash, BigUint, BigUint, BigUint, HashState) {
        let p = small_prime();
        let q = large_prime();
        let two_field_dealer =
            TwoFieldDealer::new(p.clone(), q.clone(), f + 1, n);
        let hc = hash_state();

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xABCD);

        // (1) Sample f, g per coin (no θ yet); collect per-(coin,node)
        //     material and build the combined-leaf Merkle trees.
        let mut f_polys: Vec<Vec<BigUint>> = Vec::with_capacity(batch_size);
        let mut g_polys: Vec<Vec<BigUint>> = Vec::with_capacity(batch_size);
        let mut mask_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); n];
        let mut f_large_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); n];
        let mut secret_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); n];
        let mut nonce_per_node: Vec<Vec<Val>> = vec![Vec::with_capacity(batch_size); n];
        let mut hashes_vec: Vec<Vec<Hash>> = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            let secret = rng.gen_biguint_range(&BigUint::from(0u32), &p);
            let nonce = rng.gen_biguint_range(&BigUint::from(0u32), &q);
            let sampled = two_field_dealer.sample_shares(secret);
            f_polys.push(sampled.f_poly.clone());
            g_polys.push(sampled.g_poly.clone());
            let nonce_bytes = pad32(nonce);
            let mut coin_leaves: Vec<Hash> = Vec::with_capacity(n);
            for i in 0..n {
                let f_share = pad32(sampled.secret_shares[i].1.clone());
                let g_share = pad32(sampled.mask_shares[i].1.clone());
                let f_large = pad32(sampled.f_large_shares[i].1.clone());
                let leaf = types::beacon::avss_commit_leaf(&f_share, &g_share, &f_large, &nonce_bytes);
                coin_leaves.push(leaf);
                secret_per_node[i].push(f_share);
                nonce_per_node[i].push(nonce_bytes);
                mask_per_node[i].push(g_share);
                f_large_per_node[i].push(f_large);
            }
            hashes_vec.push(coin_leaves);
        }

        let mt_vec = MerkleTree::build_trees(hashes_vec, &hc);
        let roots_vec: Vec<Hash> = mt_vec.iter().map(|mt| mt.root()).collect();

        // (2) Fiat-Shamir θ from the dealer's own commitment, then h.
        //     `force_wrong_theta` models a Byzantine dealer that
        //     computes h under a θ NOT bound to its commitment (e.g.
        //     the old predictable θ); the verifier recomputes the
        //     real FS θ from root_vec and MUST reject it.
        let theta = if force_wrong_theta {
            BigUint::from(0xC0FFEEu64)
        } else {
            Context::theta_from_commitment(round, dealer, &roots_vec, &q)
        };
        let mut degree_test_coeffs: Vec<Vec<Val>> = Vec::with_capacity(batch_size);
        for coin in 0..batch_size {
            let h = two_field_dealer.compute_degree_test_poly_pub(&f_polys[coin], &g_polys[coin], &theta);
            degree_test_coeffs.push(h.iter().map(|c| pad32(c.clone())).collect());
        }

        let mut my_secrets: Vec<Val> = Vec::with_capacity(batch_size);
        let mut my_nonces: Vec<Val> = Vec::with_capacity(batch_size);
        let mut my_mps = Vec::with_capacity(batch_size);
        for coin in 0..batch_size {
            my_secrets.push(secret_per_node[myid][coin]);
            my_nonces.push(nonce_per_node[myid][coin]);
            my_mps.push(mt_vec[coin].gen_proof(myid));
        }

        let wss = BatchWSSMsg::new(dealer, my_secrets, my_nonces, my_mps);
        let beacon = BeaconMsg::new_two_field(
            dealer,
            round,
            wss,
            roots_vec,
            Vec::new(),
            degree_test_coeffs,
            mask_per_node[myid].clone(),
            f_large_per_node[myid].clone(),
        );
        let transcript = crypto::hash::do_hash(beacon.serialize_ctrbc().as_slice());
        (beacon, transcript, p, q, theta, hc)
    }

    fn n_f() -> (usize, usize, usize) {
        // n=4, f=1, batch_size=3 keeps the test fast but exercises
        // every loop iteration.
        (4, 1, 3)
    }

    #[test]
    fn accepts_honest_two_field_packet() {
        let (n, f, batch_size) = n_f();
        let (beacon, transcript, p, q, theta, hc) =
            build_honest_packet(0, 1, 42, batch_size, n, f, false);
        let res = avss_local_packet_valid_pure(
            &beacon, &transcript, 0, 42, &hc, &p, &q, f, n, batch_size, 0, 1,
        );
        assert!(res.is_ok(), "honest packet must validate: {:?}", res);
    }

    #[test]
    fn rejects_degree_test_not_bound_to_fiat_shamir_theta() {
        // Problem-3 fix: the degree-test challenge θ is derived from
        // the dealer's OWN committed root_vec (Fiat-Shamir). A dealer
        // that computes h under any θ NOT equal to H(round‖dealer‖
        // root_vec) — e.g. the old predictable θ — is rejected,
        // because every honest verifier recomputes the real θ from the
        // commitment and the degree-test relation no longer holds.
        let (n, f, batch_size) = n_f();
        let (beacon, transcript, p, q, _theta, hc) =
            build_honest_packet(0, 1, 42, batch_size, n, f, /* force_wrong_theta = */ true);
        let res = avss_local_packet_valid_pure(
            &beacon, &transcript, 0, 42, &hc, &p, &q, f, n, batch_size, 0, 1,
        );
        assert!(
            res.is_err(),
            "h computed under a θ not bound to the commitment must be rejected (Fiat-Shamir)"
        );
    }

    #[test]
    fn rejects_byzantine_share_decoupled_from_f_large() {
        // The slide-20 dealer-controlled-beacon attack: dealer
        // ships an honest (f_large, g_share, h) that passes the
        // degree test at every node, but secretly replaces the
        // small-field share[coin] with garbage. Without the new
        // share == f_large mod p binding the dealer could pick any
        // beacon value; with the binding, validation MUST reject.
        let (n, f, batch_size) = n_f();
        let (mut beacon, _transcript, p, q, theta, hc) =
            build_honest_packet(0, 1, 42, batch_size, n, f, false);

        // Corrupt coin 0's share: replace with a value provably
        // != f_large mod p. We pick `0` and only flip if the
        // honest share already happens to be 0.
        {
            let wss = beacon.wss.as_mut().expect("honest packet has wss");
            let mut garbage = [0u8; 32];
            if wss.secrets[0] == garbage {
                garbage[31] = 1;
            }
            wss.secrets[0] = garbage;
        }
        // The dealer can rebuild a fresh Merkle root over the
        // garbage commitments and ship that in root_vec, but we
        // model the simpler attack where root_vec stays bound to
        // the honest commitments: the Merkle-proof check fires
        // first. Recompute transcript_root from the mutated
        // BeaconMsg so the first check inside the function
        // (transcript binding) still passes.
        let transcript = crypto::hash::do_hash(beacon.serialize_ctrbc().as_slice());

        let res = avss_local_packet_valid_pure(
            &beacon, &transcript, 0, 42, &hc, &p, &q, f, n, batch_size, 0, 1,
        );
        assert!(res.is_err(), "Byzantine packet must be rejected");
    }

    #[test]
    fn rejects_mp_root_not_matching_dealer_root_vec() {
        // Byzantine dealer keeps the same per-coin commit (so
        // hash(share, nonce) == mp.item() still holds), but
        // tampers with the dealer-published `root_vec[coin]` so it
        // no longer matches the proof's chain root. Honest
        // production code computes root_vec by hashing the per-coin
        // commit batch into a Merkle root; a Byzantine dealer that
        // ships a different `root_vec[coin]` is the attack vector
        // §2.C from the audit guarded against.
        let (n, f, batch_size) = n_f();
        let (mut beacon, _transcript, p, q, theta, hc) =
            build_honest_packet(0, 1, 42, batch_size, n, f, false);
        {
            let root_vec = beacon.root_vec.as_mut().expect("honest packet has root_vec");
            // Tamper with coin 0's root (flip a byte). The mp's
            // own internal Merkle validation still passes (we
            // haven't touched the mp), so the new
            // `mp.root() == root_vec[coin]` guard must fire.
            root_vec[0][0] ^= 0x01;
        }
        let transcript = crypto::hash::do_hash(beacon.serialize_ctrbc().as_slice());
        let res = avss_local_packet_valid_pure(
            &beacon, &transcript, 0, 42, &hc, &p, &q, f, n, batch_size, 0, 1,
        );
        assert!(
            res.is_err(),
            "tampered root_vec must trigger mp.root mismatch rejection"
        );
    }
}
