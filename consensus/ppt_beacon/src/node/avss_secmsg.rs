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
    fn get_or_init_avss_secmsg(
        &mut self,
        round: Round,
        dealer: Replica,
    ) -> &mut SecMsgDstState {
        if !self.avss_secmsg_state.contains_key(&(round, dealer)) {
            let prime = self.secret_domain.clone();
            let n = self.num_nodes;
            let t = self.num_faults;
            let myid = self.myid;
            let hash_state = self.hash_context.clone();
            // SecMsgDstState::new only fails on degenerate
            // configuration (prime < 2 / n < 4 / t == 0 / 3t >= n);
            // the parent Context already validates these, so the
            // unwrap below is panic-free in any production config.
            let state =
                SecMsgDstState::new(myid, n, t, dealer, prime, hash_state)
                    .expect("SecMsgDstState::new given a Context-validated config");
            self.avss_secmsg_state.insert((round, dealer), state);
        }
        self.avss_secmsg_state
            .get_mut(&(round, dealer))
            .expect("just inserted above")
    }

    /// Receiver entry point for a broadcast `AVSSSecMsgPublicCommit`
    /// from `dealer`. Verifies the transcript-binding hash and
    /// caches the commit so commit 7's payload-verifier can chain
    /// per-recipient Merkle proofs against `root_vec` and run the
    /// degree test against `degree_test_coeffs`.
    pub async fn process_avss_secmsg_public_commit(
        &mut self,
        msg: AvssPublicCommitMsg,
    ) {
        if !msg.verify_transcript_root() {
            log::warn!(
                "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} rejecting public-commit \
                 from dealer {} for round {} -- transcript_root mismatch",
                self.myid, msg.origin, msg.round
            );
            return;
        }
        // Idempotent: first-seen-wins. Byzantine dealer that
        // re-broadcasts a different commit is silently dropped.
        match self.avss_secmsg_public.entry((msg.round, msg.origin)) {
            Entry::Occupied(_) => {
                log::debug!(
                    "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} dropping duplicate \
                     public-commit from dealer {} for round {} (already cached)",
                    self.myid, msg.origin, msg.round
                );
            }
            Entry::Vacant(e) => {
                log::info!(
                    "[PPT][SECMSG-AVSS][PUB-COMMIT] node {} cached public-commit \
                     from dealer {} for round {} (#roots={}, #h-coeffs={})",
                    self.myid,
                    msg.origin,
                    msg.round,
                    msg.root_vec.len(),
                    msg.degree_test_coeffs.len(),
                );
                e.insert(msg);
            }
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
        let entries: Vec<DispersalEntry> = match bincode::deserialize(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[PPT][SECMSG-AVSS][KEY-DISP] dropping malformed key-dispersal \
                     from {} for (round={}, dealer={}): {}",
                    wire_sender, round, dealer, e
                );
                return;
            }
        };
        let actions = self
            .get_or_init_avss_secmsg(round, dealer)
            .handle_key_dispersal(wire_sender, entries);
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
        let echo: EchoPayload = match bincode::deserialize(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[PPT][SECMSG-AVSS][KEY-ECHO] dropping malformed key-echo \
                     from {} for (round={}, dealer={}): {}",
                    wire_sender, round, dealer, e
                );
                return;
            }
        };
        let actions = self
            .get_or_init_avss_secmsg(round, dealer)
            .handle_key_echo(wire_sender, echo);
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
            .get_or_init_avss_secmsg(round, dealer)
            .handle_key_vote(wire_sender, meta_root);
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
        let entries: Vec<DispersalEntry> = match bincode::deserialize(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[PPT][SECMSG-AVSS][CIPHER-DISP] dropping malformed \
                     cipher-dispersal from {} for (round={}, dealer={}): {}",
                    wire_sender, round, dealer, e
                );
                return;
            }
        };
        let actions = self
            .get_or_init_avss_secmsg(round, dealer)
            .handle_cipher_dispersal(wire_sender, entries);
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
        let echo: EchoPayload = match bincode::deserialize(&payload) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "[PPT][SECMSG-AVSS][CIPHER-ECHO] dropping malformed cipher-echo \
                     from {} for (round={}, dealer={}): {}",
                    wire_sender, round, dealer, e
                );
                return;
            }
        };
        let actions = self
            .get_or_init_avss_secmsg(round, dealer)
            .handle_cipher_echo(wire_sender, echo);
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
            .get_or_init_avss_secmsg(round, dealer)
            .handle_cipher_vote(wire_sender, meta_root);
        self.dispatch_avss_secmsg_actions(round, dealer, actions).await;
    }

    /// Translate channel-tagged actions emitted by the per-(round,
    /// dealer) `SecMsgDstState` into wire `CoinMsg` variants and
    /// send / broadcast them through `Context`'s networking.
    /// `Delivered` and `*Rejected` outcomes are handled locally.
    #[async_recursion]
    async fn dispatch_avss_secmsg_actions(
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

    /// Called when the per-(round, dealer) SecMsgDst state has
    /// fully delivered our own per-recipient AVSS payload. Caches
    /// the decrypted plaintext bytes.
    ///
    /// Commit 6 stops here; commit 7 will deserialize these bytes
    /// into `AvssRecipientPayload`, validate Merkle proofs against
    /// `avss_secmsg_public[(round, dealer)]`, run the two-field
    /// degree test, and trigger AVSS-completion.
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
             (public-commit cached={}). Commit 6 caches only; AVSS-completion \
             still flows through legacy AVSSSend path.",
            self.myid,
            dealer,
            round,
            plaintext.len(),
            public_cached
        );
        self.avss_secmsg_delivered_bytes
            .insert((round, dealer), plaintext);
    }
}
