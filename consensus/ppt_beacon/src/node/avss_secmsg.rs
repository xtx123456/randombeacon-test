//! Receiver-side plumbing for the new Π_SecMsgDst-routed AVSS
//! dealer path (Shoup-Smart 2024 Sec 4.3 + commits 1-5 in
//! `shoup_smart/`).
//!
//! ## What this module does (commit 6 — strictly additive)
//!
//! Provides `Context` methods that:
//!
//!   1. Cache the public AVSS commitment broadcast by the dealer
//!      (`AvssPublicCommitMsg`) — Merkle roots, h(x) coefficients,
//!      and a transcript-binding hash that replaces the duplicated
//!      public fields previously stuffed into n cleartext
//!      `AVSSSend` packets.
//!
//!   2. Route inbound `AVSSSecMsgKey*` and `AVSSSecMsgCipher*` wire
//!      messages into the per-(round, dealer) `SecMsgDstState`
//!      instance, lazily creating it on first arrival.
//!
//!   3. Translate the channel-tagged outbound actions emitted by
//!      `SecMsgDstState` (its sender-side `set_input_as_sender`
//!      output, plus echo / vote responses on the receiver side)
//!      back into wire `CoinMsg` variants for `Context::send` /
//!      `Context::broadcast`.
//!
//!   4. On `SecMsgDstAction::DeliveredMessage` — i.e. the receiver
//!      has fully recovered its own per-recipient AVSS payload —
//!      cache the decrypted plaintext bytes in
//!      `Context::avss_secmsg_delivered_bytes`. **Commit 6 stops
//!      here**: it does NOT yet validate the payload against the
//!      cached public commit, store it in `CTRBCState`, or
//!      broadcast `AVSSReady`. Those steps belong to commit 7
//!      (the dealer-side cutover) so commit 6 is a strictly
//!      additive landing — the legacy `AVSSSend` cleartext path
//!      still drives the live AVSS quorum.
//!
//! ## PQ-safety
//!
//! Pure routing + caching + bincode serialise of wire payloads.
//! The underlying SecMsgDst state machine itself is hash-only
//! (commit 1-5), so no new crypto assumptions are introduced.

use std::collections::hash_map::Entry;

use async_recursion::async_recursion;
use bincode;
use types::beacon::{AvssPublicCommitMsg, CoinMsg};
use types::{Replica, Round};

use crate::node::context::Context;
use crate::node::shoup_smart::rel_msg_dst::{
    DispersalEntry, EchoPayload,
};
use crate::node::shoup_smart::sec_msg_dst::{
    SecMsgChannel, SecMsgDstAction, SecMsgDstState,
};
use crypto::hash::Hash;

impl Context {
    /// Lazily construct the per-(round, dealer) SecMsgDst-AVSS
    /// state machine on first message arrival. Returns a mutable
    /// borrow of the entry.
    ///
    /// `pub(crate)` so the dealer-side launch in `batch_wssinit`
    /// can install the local SecMsgDstState before calling
    /// `set_input_as_sender`.
    pub(crate) fn get_or_init_avss_secmsg(
        &mut self,
        round: Round,
        dealer: Replica,
    ) -> &mut SecMsgDstState {
        if !self.avss_secmsg_state.contains_key(&(round, dealer)) {
            let state = self.fresh_avss_secmsg_state(dealer);
            self.avss_secmsg_state.insert((round, dealer), state);
        }
        self.avss_secmsg_state
            .get_mut(&(round, dealer))
            .expect("just inserted above")
    }

    /// Allocate a fresh `SecMsgDstState` for `(round, dealer)`
    /// without touching `avss_secmsg_state`. Used by the
    /// secmsg-handler spawn_blocking shim: we `remove` the
    /// existing state, move it into the blocking closure, then
    /// `insert` the (possibly mutated) state back. On a
    /// first-message-for-(round, dealer) path the `remove`
    /// returns `None`, so this helper bootstraps the initial
    /// state independently from the lazy-create path inside
    /// `get_or_init_avss_secmsg`.
    fn fresh_avss_secmsg_state(&self, dealer: Replica) -> SecMsgDstState {
        let prime = self.secret_domain.clone();
        let n = self.num_nodes;
        let t = self.num_faults;
        let myid = self.myid;
        let hash_state = self.hash_context.clone();
        // SecMsgDstState::new only fails on degenerate
        // configuration (prime < 2 / n < 4 / t == 0 / 3t >= n);
        // the parent Context already validates these, so the
        // unwrap below is panic-free in any production config.
        SecMsgDstState::new(myid, n, t, dealer, prime, hash_state)
            .expect("SecMsgDstState::new given a Context-validated config")
    }

    /// Take-process-put-back helper that lets a SecMsgDst-side
    /// handler run its bincode deserialize + Merkle / Bracha
    /// validation on tokio's blocking pool instead of on the
    /// consensus task's worker thread.
    ///
    /// Semantics:
    ///   1. Take ownership of the per-(round, dealer)
    ///      `SecMsgDstState` (or freshly allocate one if this is
    ///      the first inbound for that AVSS instance).
    ///   2. Move both the state and the caller-provided closure
    ///      into a `spawn_blocking` task. The closure receives
    ///      `SecMsgDstState` by ownership and returns the
    ///      (mutated state, dispatch actions) pair.
    ///   3. `await` the blocking task. The consensus task is
    ///      suspended during the await, so other tokio tasks
    ///      (audit fire-and-forget, network sender's per-
    ///      connection tasks, sync receiver) are no longer
    ///      starved by the heavy hash work that the SecMsgDst
    ///      handlers used to do synchronously on the main thread.
    ///   4. Reinstate the state and return the actions.
    ///
    /// Safety: the take-process-put-back is safe under tokio's
    /// single-task consensus model because between `remove` and
    /// `insert` no other handler can run on the same task. The
    /// `await` point hands control back to the runtime, but only
    /// non-consensus tasks make progress -- the next
    /// `process_msg` call waits at `self.net_recv.recv()` for
    /// the current handler to finish.
    async fn with_avss_secmsg_state<F, R>(
        &mut self,
        round: Round,
        dealer: Replica,
        f: F,
    ) -> R
    where
        F: FnOnce(SecMsgDstState) -> (SecMsgDstState, R) + Send + 'static,
        R: Send + 'static,
    {
        let state = self
            .avss_secmsg_state
            .remove(&(round, dealer))
            .unwrap_or_else(|| self.fresh_avss_secmsg_state(dealer));

        let (new_state, result) = tokio::task::spawn_blocking(move || f(state))
            .await
            .expect(
                "[PPT][SECMSG-AVSS] spawn_blocking handler must not panic; \
                 SecMsgDstState operations are pure + bounded",
            );

        self.avss_secmsg_state.insert((round, dealer), new_state);
        result
    }

    /// Receiver entry point for a broadcast `AVSSSecMsgPublicCommit`
    /// from `dealer`. Verifies the transcript-binding hash, caches
    /// the commit, and triggers `try_finalize_avss_secmsg` (which
    /// is a no-op until the matching SecMsgDst delivery also lands).
    ///
    /// `wire_sender` is the WrapperMsg-level sender that ferried
    /// this commit. We MUST require `wire_sender == msg.origin`:
    /// the commit's `transcript_root` is a public hash of the
    /// (origin, round, root_vec, degree_test_coeffs) tuple, so
    /// **any** node can compute a valid `transcript_root` for any
    /// `origin` they choose. Without the sender-binding check a
    /// single Byzantine node X could broadcast a fake commit with
    /// `origin = Y` (some honest dealer) that arrives before Y's
    /// real one; honest receivers would cache X's fake commit,
    /// drop Y's real one as duplicate ("first-seen-wins"), then
    /// when Y's SecMsgDst payload finally delivers
    /// `try_finalize_avss_secmsg` would reconstruct a BeaconMsg
    /// with X's fake `root_vec` + `degree_test_coeffs` and Y's
    /// honest per-recipient share material. The two-field
    /// degree-test would fail against the fake h(x) coefficients,
    /// causing `process_avss_send` to `ban_dealer_global(Y)`. A
    /// single Byzantine peer could thus frame every other honest
    /// dealer simultaneously, ban them all in round 0, and stall
    /// liveness permanently.
    #[async_recursion]
    pub async fn process_avss_secmsg_public_commit(
        &mut self,
        msg: AvssPublicCommitMsg,
        wire_sender: Replica,
    ) {
        if wire_sender != msg.origin {
            log::warn!(
                "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} dropping public-commit \
                 with wire_sender={} != origin={} (round={}) -- attempted dealer \
                 framing",
                self.myid, wire_sender, msg.origin, msg.round
            );
            return;
        }
        if !msg.verify_transcript_root() {
            log::warn!(
                "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} rejecting public-commit \
                 from dealer {} for round {} -- transcript_root mismatch",
                self.myid, msg.origin, msg.round
            );
            return;
        }
        let round = msg.round;
        let dealer = msg.origin;
        // Idempotent: first-seen-wins. Byzantine dealer that
        // re-broadcasts a different commit is silently dropped.
        let newly_cached = match self.avss_secmsg_public.entry((round, dealer)) {
            Entry::Occupied(_) => {
                log::debug!(
                    "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} dropping duplicate \
                     public-commit from dealer {} for round {} (already cached)",
                    self.myid, dealer, round
                );
                false
            }
            Entry::Vacant(e) => {
                log::info!(
                    "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} cached public-commit \
                     from dealer {} for round {} (#roots={}, #h-coeffs={})",
                    self.myid,
                    dealer,
                    round,
                    msg.root_vec.len(),
                    msg.degree_test_coeffs.len(),
                );
                e.insert(msg);
                true
            }
        };
        if newly_cached {
            self.try_finalize_avss_secmsg(round, dealer).await;
        }
    }

    // ------- Key channel -------

    #[async_recursion]
    pub async fn process_avss_secmsg_key_dispersal(
        &mut self,
        round: Round,
        dealer: Replica,
        payload: Vec<u8>,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let entries: Vec<DispersalEntry> = match bincode::deserialize(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "[PPT][SECMSG-AVSS][KEY-DISP] dropping malformed \
                             key-dispersal from {} for (round={}, dealer={}): {}",
                            wire_sender, round, dealer, e
                        );
                        return (state, Vec::new());
                    }
                };
                let acts = state.handle_key_dispersal(wire_sender, entries);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    #[async_recursion]
    pub async fn process_avss_secmsg_key_echo(
        &mut self,
        round: Round,
        dealer: Replica,
        payload: Vec<u8>,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let echo: EchoPayload = match bincode::deserialize(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "[PPT][SECMSG-AVSS][KEY-ECHO] dropping malformed \
                             key-echo from {} for (round={}, dealer={}): {}",
                            wire_sender, round, dealer, e
                        );
                        return (state, Vec::new());
                    }
                };
                let acts = state.handle_key_echo(wire_sender, echo);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    #[async_recursion]
    pub async fn process_avss_secmsg_key_vote(
        &mut self,
        round: Round,
        dealer: Replica,
        meta_root: Hash,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let acts = state.handle_key_vote(wire_sender, meta_root);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    // ------- Cipher channel -------

    #[async_recursion]
    pub async fn process_avss_secmsg_cipher_dispersal(
        &mut self,
        round: Round,
        dealer: Replica,
        payload: Vec<u8>,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let entries: Vec<DispersalEntry> = match bincode::deserialize(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "[PPT][SECMSG-AVSS][CIPHER-DISP] dropping malformed \
                             cipher-dispersal from {} for (round={}, dealer={}): {}",
                            wire_sender, round, dealer, e
                        );
                        return (state, Vec::new());
                    }
                };
                let acts = state.handle_cipher_dispersal(wire_sender, entries);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    #[async_recursion]
    pub async fn process_avss_secmsg_cipher_echo(
        &mut self,
        round: Round,
        dealer: Replica,
        payload: Vec<u8>,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let echo: EchoPayload = match bincode::deserialize(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!(
                            "[PPT][SECMSG-AVSS][CIPHER-ECHO] dropping malformed \
                             cipher-echo from {} for (round={}, dealer={}): {}",
                            wire_sender, round, dealer, e
                        );
                        return (state, Vec::new());
                    }
                };
                let acts = state.handle_cipher_echo(wire_sender, echo);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    #[async_recursion]
    pub async fn process_avss_secmsg_cipher_vote(
        &mut self,
        round: Round,
        dealer: Replica,
        meta_root: Hash,
        wire_sender: Replica,
    ) {
        let actions = self
            .with_avss_secmsg_state(round, dealer, move |mut state| {
                let acts = state.handle_cipher_vote(wire_sender, meta_root);
                (state, acts)
            })
            .await;
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    /// Translate channel-tagged actions emitted by the per-(round,
    /// dealer) `SecMsgDstState` into wire `CoinMsg` variants and
    /// send / broadcast them through `Context`'s networking.
    /// `Delivered` and `*Rejected` outcomes are handled locally.
    /// `pub(crate)` so the dealer-side launch can pump the
    /// `SecMsgDstAction`s emitted by `set_input_as_sender` through
    /// the same wire-routing pipeline as receiver-side responses.
    #[async_recursion]
    pub(crate) async fn dispatch_avss_secmsg_actions(
        &mut self,
        round: Round,
        dealer: Replica,
        actions: Vec<SecMsgDstAction>,
    ) {
        for action in actions {
            match action {
                SecMsgDstAction::SendDispersal {
                    channel,
                    recipient_idx,
                    entries,
                } => {
                    let bytes = match bincode::serialize(&entries) {
                        Ok(b) => b,
                        Err(e) => {
                            log::error!(
                                "[PPT][SECMSG-AVSS] failed to bincode dispersal \
                                 entries (round={}, dealer={}, channel={:?}): {}",
                                round, dealer, channel, e
                            );
                            continue;
                        }
                    };
                    let coin_msg = match channel {
                        SecMsgChannel::Key => {
                            CoinMsg::AVSSSecMsgKeyDispersal(round, dealer, bytes)
                        }
                        SecMsgChannel::Cipher => {
                            CoinMsg::AVSSSecMsgCipherDispersal(round, dealer, bytes)
                        }
                    };
                    self.send_avss_secmsg_unicast(recipient_idx as Replica, coin_msg, round)
                        .await;
                }
                SecMsgDstAction::SendEcho {
                    channel,
                    recipient_idx,
                    echo,
                } => {
                    let bytes = match bincode::serialize(&echo) {
                        Ok(b) => b,
                        Err(e) => {
                            log::error!(
                                "[PPT][SECMSG-AVSS] failed to bincode echo \
                                 (round={}, dealer={}, channel={:?}): {}",
                                round, dealer, channel, e
                            );
                            continue;
                        }
                    };
                    let coin_msg = match channel {
                        SecMsgChannel::Key => {
                            CoinMsg::AVSSSecMsgKeyEcho(round, dealer, bytes)
                        }
                        SecMsgChannel::Cipher => {
                            CoinMsg::AVSSSecMsgCipherEcho(round, dealer, bytes)
                        }
                    };
                    self.send_avss_secmsg_unicast(recipient_idx as Replica, coin_msg, round)
                        .await;
                }
                SecMsgDstAction::SendVote { channel, meta_root } => {
                    let coin_msg = match channel {
                        SecMsgChannel::Key => {
                            CoinMsg::AVSSSecMsgKeyVote(round, dealer, meta_root)
                        }
                        SecMsgChannel::Cipher => {
                            CoinMsg::AVSSSecMsgCipherVote(round, dealer, meta_root)
                        }
                    };
                    self.broadcast(coin_msg, round).await;
                }
                SecMsgDstAction::SendForward { .. }
                | SecMsgDstAction::SendMessageForward { .. } => {
                    // Forward sub-protocol is not exercised in
                    // commit 6; commit 7 will route these to a
                    // dedicated `AVSSSecMsgForward*` wire variant.
                    // For now, log and drop so we can detect any
                    // accidental emission during testing.
                    log::warn!(
                        "[PPT][SECMSG-AVSS] dropping SendForward/SendMessageForward \
                         emitted in commit 6 (forwards are commit-7 territory) for \
                         (round={}, dealer={})",
                        round, dealer
                    );
                }
                SecMsgDstAction::DeliveredMessage { message } => {
                    self.on_avss_secmsg_delivered(round, dealer, message).await;
                }
                SecMsgDstAction::ForwardDeliveredMessage { source, message } => {
                    log::info!(
                        "[PPT][SECMSG-AVSS] node {} forward-delivered message from \
                         source {} (round={}, dealer={}) -- {} plaintext bytes \
                         (commit 6 ignores forward-delivery)",
                        self.myid,
                        source,
                        round,
                        dealer,
                        message.len()
                    );
                }
                SecMsgDstAction::ForwardRejected { source, reason } => {
                    log::warn!(
                        "[PPT][SECMSG-AVSS] forward-rejected from source {} for \
                         (round={}, dealer={}): {:?}",
                        source, round, dealer, reason
                    );
                }
                SecMsgDstAction::DeliveryFailedDecrypt { reason } => {
                    log::warn!(
                        "[PPT][SECMSG-AVSS] delivery-failed-decrypt for \
                         (round={}, dealer={}): {:?}",
                        round, dealer, reason
                    );
                }
            }
        }
    }

    /// Send a single SecMsgDst-AVSS wire message unicast to one
    /// recipient, taking care to handle the self-delivery loop-back
    /// (recipient == self.myid) that the receiver's own dispersal
    /// → echo response generates.
    #[async_recursion]
    async fn send_avss_secmsg_unicast(
        &mut self,
        recipient: Replica,
        coin_msg: CoinMsg,
        round: Round,
    ) {
        if recipient == self.myid {
            // Self-deliver: re-enter the appropriate handler. The
            // wrapper-level wire-sender for self-loops is
            // `self.myid`; this matches exactly what the network
            // layer would deliver.
            let myid = self.myid;
            self.dispatch_self_avss_secmsg(coin_msg, myid).await;
            return;
        }
        if let Some(sec_key) = self.sec_key_map.get(&recipient).cloned() {
            let wrapper = types::beacon::WrapperMsg::new(coin_msg, self.myid, &sec_key, round);
            let cancel_handler = self.net_send.send(recipient, wrapper).await;
            self.add_cancel_handler(cancel_handler);
        } else {
            log::error!(
                "[PPT][SECMSG-AVSS] no sec_key for recipient {} -- dropping \
                 SecMsgDst-AVSS unicast (round={})",
                recipient, round
            );
        }
    }

    /// Re-dispatch a self-loop wire message back into the matching
    /// receiver handler. Mirrors the existing `process_avss_send`
    /// self-delivery pattern.
    #[async_recursion]
    async fn dispatch_self_avss_secmsg(&mut self, coin_msg: CoinMsg, wire_sender: Replica) {
        match coin_msg {
            CoinMsg::AVSSSecMsgKeyDispersal(round, dealer, bytes) => {
                self.process_avss_secmsg_key_dispersal(round, dealer, bytes, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgKeyEcho(round, dealer, bytes) => {
                self.process_avss_secmsg_key_echo(round, dealer, bytes, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgKeyVote(round, dealer, meta_root) => {
                self.process_avss_secmsg_key_vote(round, dealer, meta_root, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgCipherDispersal(round, dealer, bytes) => {
                self.process_avss_secmsg_cipher_dispersal(round, dealer, bytes, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgCipherEcho(round, dealer, bytes) => {
                self.process_avss_secmsg_cipher_echo(round, dealer, bytes, wire_sender)
                    .await;
            }
            CoinMsg::AVSSSecMsgCipherVote(round, dealer, meta_root) => {
                self.process_avss_secmsg_cipher_vote(round, dealer, meta_root, wire_sender)
                    .await;
            }
            other => {
                log::error!(
                    "[PPT][SECMSG-AVSS] dispatch_self_avss_secmsg got unexpected \
                     CoinMsg variant: {:?}",
                    std::mem::discriminant(&other)
                );
            }
        }
    }

    /// Receiver entry point for an `AVSSPrivatePayload` wire
    /// message (the `Lite` transport's per-recipient unicast).
    ///
    /// Mirrors the role `on_avss_secmsg_delivered` plays for the
    /// `SecMsg` transport: caches the cleartext bytes in
    /// `avss_secmsg_delivered_bytes` and triggers
    /// `try_finalize_avss_secmsg`, which validates the payload
    /// against the cached `AvssPublicCommitMsg` and feeds the
    /// reconstructed `BeaconMsg` into the legacy
    /// `process_avss_send` quorum / ACS pipeline.
    ///
    /// Sender-binding: only the dealer themselves may ship their
    /// own `AVSSPrivatePayload`. We MUST verify
    /// `wire_sender == dealer` here -- otherwise a Byzantine peer X
    /// could fabricate a payload "from dealer Y" containing
    /// arbitrary garbage; honest receivers would cache it,
    /// `try_finalize_avss_secmsg` would reconstruct a BeaconMsg
    /// against Y's legitimate cached public commit, the two-field
    /// degree test would fail, and Y would be banned. This mirrors
    /// the framing-via-PublicCommit guard introduced in fix
    /// `26e1995`; the lite transport's per-recipient unicast is
    /// the second window the same attack class could exploit
    /// without this check.
    #[async_recursion]
    pub async fn process_avss_private_payload(
        &mut self,
        round: Round,
        dealer: Replica,
        plaintext: Vec<u8>,
        wire_sender: Replica,
    ) {
        if wire_sender != dealer {
            log::warn!(
                "[PPT][AVSS-LITE][PRIVATE] node {} dropping AVSSPrivatePayload \
                 with wire_sender={} != dealer={} (round={}, |payload|={}) -- \
                 attempted dealer framing",
                self.myid,
                wire_sender,
                dealer,
                round,
                plaintext.len()
            );
            return;
        }
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][AVSS-LITE][PRIVATE] dropping AVSSPrivatePayload from \
                 banned dealer {} for round {}",
                dealer,
                round
            );
            return;
        }
        let public_cached = self.avss_secmsg_public.contains_key(&(round, dealer));
        log::info!(
            "[PPT][AVSS-LITE][PRIVATE] node {} received AVSSPrivatePayload from \
             dealer {} for round {} -- {} plaintext bytes (public-commit cached={})",
            self.myid,
            dealer,
            round,
            plaintext.len(),
            public_cached
        );
        // Idempotent: if we already cached a payload for this
        // (round, dealer), drop the duplicate. Honest dealers send
        // exactly one AVSSPrivatePayload per recipient per round.
        // A Byzantine dealer that ships a different payload after
        // the first one is silently ignored at this layer; the
        // first-cached value remains the one
        // `try_finalize_avss_secmsg` validates against the cached
        // public commit (this matches the first-cached-wins
        // pattern of `avss_secmsg_public`).
        if self
            .avss_secmsg_delivered_bytes
            .contains_key(&(round, dealer))
        {
            log::debug!(
                "[PPT][AVSS-LITE][PRIVATE] dropping duplicate AVSSPrivatePayload \
                 from dealer {} for round {} (first-cached-wins)",
                dealer,
                round
            );
            return;
        }
        self.avss_secmsg_delivered_bytes
            .insert((round, dealer), plaintext);
        self.try_finalize_avss_secmsg(round, dealer).await;
    }

    /// Called when the per-(round, dealer) SecMsgDst state has
    /// fully delivered our own per-recipient AVSS payload. Caches
    /// the decrypted plaintext bytes and triggers
    /// `try_finalize_avss_secmsg` (which proceeds only when the
    /// public-commit broadcast has also been cached).
    #[async_recursion]
    async fn on_avss_secmsg_delivered(
        &mut self,
        round: Round,
        dealer: Replica,
        plaintext: Vec<u8>,
    ) {
        let public_cached = self.avss_secmsg_public.contains_key(&(round, dealer));
        log::info!(
            "[PPT][SECMSG-AVSS][DELIVERED] node {} delivered SecMsgDst-AVSS \
             payload from dealer {} for round {} -- {} plaintext bytes \
             (public-commit cached={})",
            self.myid,
            dealer,
            round,
            plaintext.len(),
            public_cached
        );
        // Idempotent: first-seen-wins. SecMsgDst delivery is
        // already idempotent at the state-machine level (latches
        // on first XOR), but defensive guard here costs nothing.
        if self
            .avss_secmsg_delivered_bytes
            .contains_key(&(round, dealer))
        {
            return;
        }
        self.avss_secmsg_delivered_bytes
            .insert((round, dealer), plaintext);
        self.try_finalize_avss_secmsg(round, dealer).await;
    }

    /// Once both the public-commit broadcast and the SecMsgDst
    /// delivery for `(round, dealer)` have landed locally,
    /// reconstruct the equivalent legacy-shape `BeaconMsg +
    /// transcript_root` pair and feed it into the existing
    /// `process_avss_send` pipeline.
    ///
    /// `process_avss_send` performs every step the live AVSS
    /// pipeline requires (theta gating + buffering, spawn_blocking
    /// validation via `avss_local_packet_valid_pure`,
    /// `ban_dealer_global` on failure, `store_avss_packet`,
    /// AVSSReady broadcast, AVSSComplete threshold + broadcast,
    /// AVSS-completion + ACS hook). Reusing it preserves every
    /// P0/P1/Level fix automatically — the only thing that
    /// changes between the legacy and SecMsgDst paths is HOW the
    /// dealer's per-recipient payload arrived.
    ///
    /// Idempotent: returns early if either prerequisite is
    /// missing or if the dealer has already been validated for
    /// this round.
    #[async_recursion]
    pub(crate) async fn try_finalize_avss_secmsg(
        &mut self,
        round: Round,
        dealer: Replica,
    ) {
        // Need both inputs.
        if !self.avss_secmsg_public.contains_key(&(round, dealer)) {
            return;
        }
        if !self.avss_secmsg_delivered_bytes.contains_key(&(round, dealer)) {
            return;
        }
        // Skip if banned.
        if self.banned_dealers.contains(&dealer) {
            log::warn!(
                "[PPT][SECMSG-AVSS][FINALIZE] dropping finalize for banned \
                 dealer {} round {}",
                dealer, round
            );
            return;
        }
        // Skip if already finalized through this or any earlier path.
        if let Some(rs) = self.round_state.get(&round) {
            if rs.avss_local_valid.contains(&dealer) {
                return;
            }
        }
        // Take ownership of the cached pieces. We `clone` rather than
        // `remove` so a duplicate trigger (idempotent re-entry) still
        // sees the same data — the `avss_local_valid` guard above
        // prevents double-processing into the AVSS quorum.
        let public = self
            .avss_secmsg_public
            .get(&(round, dealer))
            .expect("just verified contains_key")
            .clone();
        let plaintext = self
            .avss_secmsg_delivered_bytes
            .get(&(round, dealer))
            .expect("just verified contains_key")
            .clone();
        let myid = self.myid;

        let payload = match types::beacon::AvssRecipientPayload::deserialize_bytes(&plaintext) {
            Some(p) => p,
            None => {
                log::error!(
                    "[PPT][SECMSG-AVSS][FINALIZE] node {} got malformed \
                     AvssRecipientPayload bytes from dealer {} round {} -- \
                     banning dealer",
                    myid, dealer, round
                );
                self.ban_dealer_global(dealer);
                return;
            }
        };

        // Reconstruct a BeaconMsg with the same field layout as
        // the legacy AVSSSend would have carried. Public fields
        // come from the cached AvssPublicCommitMsg (identical at
        // every honest receiver by construction); per-recipient
        // fields come from the decrypted AvssRecipientPayload.
        // `appx_con` is empty in the pure-PPT path (legacy dealer
        // also passes Vec::new() — see batch_wssinit.rs:154).
        let wss = types::beacon::BatchWSSMsg::new(
            dealer,
            payload.secrets,
            payload.nonces,
            payload.mps,
        );
        let beacon_msg = types::beacon::BeaconMsg::new_two_field(
            dealer,
            round,
            wss,
            public.root_vec.clone(),
            Vec::new(),
            public.degree_test_coeffs.clone(),
            payload.mask_shares,
            payload.f_large_shares,
        );
        // Use the *same* transcript-root derivation as the legacy
        // path: do_hash(BeaconMsg::serialize_ctrbc()). Because
        // every honest receiver reconstructs BeaconMsg from the
        // same public commit and the same canonical empty
        // appx_con, this hash is bit-identical at every honest
        // node — which is exactly what the AVSSReady / AVSSComplete
        // quorum requires.
        let transcript_root =
            crypto::hash::do_hash(beacon_msg.serialize_ctrbc().as_slice());

        log::info!(
            "[PPT][SECMSG-AVSS][FINALIZE] node {} feeding reconstructed \
             BeaconMsg into process_avss_send for dealer {} round {} \
             (transcript_root prefix={:02x}{:02x}{:02x}{:02x})",
            myid,
            dealer,
            round,
            transcript_root[0],
            transcript_root[1],
            transcript_root[2],
            transcript_root[3]
        );
        self.process_avss_send(beacon_msg, transcript_root, dealer, round)
            .await;
    }
}
