//! New PPT ACS pipeline: Bracha RBC + n parallel Mostefaoui-Moumen-
//! Raynal ABA + self-bootstrap common coin.
//!
//! This module replaces the previous 4-phase witness-gathering ACS,
//! which did not satisfy Agreement under asynchrony. The pipeline is:
//!
//! Phase 1 (RBC):
//!     Each node `i` runs a Bracha RBC instance as proposer with
//!     payload `V_i = bytes(local AVSS-completed dealers)`. RBC
//!     guarantees that every honest node delivers the same payload
//!     bytes for sender `i` (or the proposer is silent / Byzantine
//!     and no honest node delivers).
//!
//! Phase 2 (n parallel ABAs):
//!     For each proposer index `j ∈ [0, n)`, run one MMR ABA
//!     instance with the following input rule:
//!
//!       - if RBC for `j` has delivered AND dealer `j` is locally
//!         AVSS-completed AND `j` is not banned: input = 1.
//!       - if `j` is banned: input = 0.
//!       - otherwise: defer; do not feed an input yet.
//!
//!     Once `n-f` ABA instances have decided 1, every remaining
//!     instance that hasn't been fed an input gets `input = 0`. This
//!     is the standard MMR-ACS / Ben-Or-Kelmer-Rabin "force 0 after
//!     enough 1s" rule.
//!
//!     The MMR ABA needs a 1-bit common coin per ABA round. We use
//!     the self-bootstrap coin `Context::coin_bit_for(round, j, r)`
//!     which derives from the previous PPT round's beacon (or the
//!     fixed genesis seed for round 0).
//!
//! Phase 3 (output):
//!     ACS output = `{ j : ABA(j) decided 1 }`. Size ≥ n-f by MMR
//!     ABA validity + the totality argument above. Every honest
//!     node receives the SAME index set because every ABA's
//!     decision is identical at every honest node (Agreement).
//!
//! PQ-safety: only `crypto::hash::do_hash` is used; everything else
//! is pure boolean / set logic. No DL, no MAC threshold, no VRF.

use std::collections::HashSet;

use async_recursion::async_recursion;

use types::{
    beacon::{CoinMsg, Replica},
    Round,
};

use super::aba_driver::AbaDriverAction;
use super::rbc::RbcAction;
use super::state::AcsRound;
use crate::node::Context;

impl Context {
    /// Local quorum threshold n-f.
    fn acs_threshold(&self) -> usize {
        self.num_nodes - self.num_faults
    }

    /// Get-or-create the per-round ACS state.
    fn acs_round_mut(&mut self, round: Round) -> &mut AcsRound {
        let myid = self.myid;
        let n = self.num_nodes;
        let f = self.num_faults;
        self.acs_state
            .entry(round)
            .or_insert_with(|| AcsRound::new(round, myid, n, f))
    }

    /// Build the local AVSS-completed dealer set as a sorted byte
    /// payload. This is exactly `V_i` from the PPT brief.
    fn build_local_proposal_bytes(&self, round: Round) -> Vec<u8> {
        let mut local: Vec<Replica> = self.local_completed_dealers(round).into_iter().collect();
        local.sort_unstable();
        // Compact length-prefixed serialisation: 4-byte BE count then
        // the per-dealer Replica IDs as BE u32. We don't need bincode
        // since the contents are just sorted u32s and we want the
        // bytes to be identical at every honest node for RBC byte-
        // equality.
        let mut buf = Vec::with_capacity(4 + 4 * local.len());
        buf.extend_from_slice(&(local.len() as u32).to_be_bytes());
        for d in local {
            buf.extend_from_slice(&d.to_be_bytes());
        }
        buf
    }

    /// Public hook called by the AVSS path after a dealer transitions
    /// to AVSS-completed (or after a dealer becomes banned). The hook
    /// drives the new ACS pipeline forward: it (re-)tries to start
    /// our own RBC, re-evaluates deferred inputs, and cascades any
    /// follow-up ABA / RBC actions.
    #[async_recursion]
    pub async fn acs_note_local_change(&mut self, round: Round) {
        // Apply the global ban list to the per-round ACS state.
        let banned: HashSet<Replica> = self.permanently_banned_dealers();
        {
            let st = self.acs_round_mut(round);
            for d in banned.iter().copied() {
                st.ban_dealer(d);
            }
        }

        self.acs_try_start_self_rbc(round).await;
        self.acs_try_feed_deferred_inputs(round).await;
        // AVSS-hook path covers both ABA-input-changing events
        // (via acs_try_feed_deferred_inputs) and round-bootstrap, so
        // it needs the FULL scan. The two specialised RBC vs ABA
        // outer scans below are used for inbound network-message
        // cascade tails.
        self.acs_external_scan_full(round).await;
    }

    /// Full external-boundary scan: pump every (j, aba_round) coin
    /// that hasn't been fed, fire the n-f-decided-1 force-zero rule
    /// if applicable, and finalise the round if every ABA decided.
    ///
    /// Used at the cascade boundary by the **ABA inbound handlers**
    /// (`process_acs_aba_bval` / `process_acs_aba_aux`) and by the
    /// AVSS hook (`acs_note_local_change`). The RBC inbound
    /// handlers use the cheaper `acs_external_scan_finalize_only`
    /// instead, because RBC ECHO/READY counter updates can never
    /// directly enable a `pump_coins` or `force_zero` transition --
    /// only ABA state changes (and AVSS-completion changes that
    /// arrive through `acs_note_local_change`) can. RBC delivery
    /// *can* feed a fresh ABA input via `on_rbc_delivered`, but
    /// once that input is fed, the resulting BVAL is broadcast to
    /// peers and their ABA outer handlers will trigger
    /// `acs_external_scan_full` within the next network round-trip
    /// to pump the new ABA(j) round-0 coin. This avoids the per-
    /// inbound-RBC-message scan overhead that regressed batch=100
    /// throughput by 23 % in the first version of experiment A.
    ///
    /// The three helpers are idempotent + monotone so running them
    /// at the cascade boundary preserves Validity / Agreement /
    /// Termination — see PR description for the formal argument.
    #[async_recursion]
    async fn acs_external_scan_full(&mut self, round: Round) {
        self.acs_pump_coins(round).await;
        self.acs_maybe_force_zero_inputs(round).await;
        self.acs_maybe_finalize(round).await;
    }

    /// Cheaper external-boundary scan: only checks whether the
    /// round can finalise. Used by the RBC inbound handlers
    /// (`process_acs_rbc_send` / `echo` / `ready`) because their
    /// state changes (ECHO/READY counters and SEND payload caching)
    /// cannot directly enable a `pump_coins` / `force_zero`
    /// transition; only ABA state changes can.
    #[async_recursion]
    async fn acs_external_scan_finalize_only(&mut self, round: Round) {
        self.acs_maybe_finalize(round).await;
    }

    /// Try to start our own Bracha RBC instance with the local
    /// AVSS-completed dealer set as the proposal. Idempotent: only
    /// fires once per round, and only after we have ≥ n-f locally
    /// completed dealers (ensures the proposal carries non-trivial
    /// content; banned dealers are excluded by
    /// `local_completed_dealers`).
    #[async_recursion]
    async fn acs_try_start_self_rbc(&mut self, round: Round) {
        let threshold = self.acs_threshold();
        let myid = self.myid;
        let payload = self.build_local_proposal_bytes(round);
        let local_len = if payload.len() < 4 {
            0
        } else {
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize
        };
        if local_len < threshold {
            return;
        }

        let fire_actions: Option<Vec<RbcAction>> = {
            let st = self.acs_round_mut(round);
            if st.rbc_self_send_done {
                None
            } else {
                st.rbc_self_send_done = true;
                let acts = st.rbc[myid as usize].proposer_send(payload.clone());
                Some(acts)
            }
        };

        let acts = match fire_actions {
            Some(a) => a,
            None => return,
        };

        log::info!(
            "[PPT][ACS-RBC] node {} round {} broadcasting RBC SEND (proposer={}, |V_i|={} bytes)",
            self.myid,
            round,
            self.myid,
            payload.len()
        );

        for a in acts {
            self.dispatch_rbc_action(round, myid, a).await;
        }
    }

    /// Re-evaluate deferred ABA inputs (RBC-delivered V_j whose
    /// external validity check still failed at the time of delivery).
    #[async_recursion]
    async fn acs_try_feed_deferred_inputs(&mut self, round: Round) {
        let banned = self.permanently_banned_dealers();
        let local_complete = self.local_completed_dealers(round);

        let pending_proposers: Vec<usize> = {
            let st = self.acs_round_mut(round);
            st.deferred_inputs.iter().copied().collect()
        };

        for j in pending_proposers {
            let dealer_id = j as Replica;
            let already_fed = self
                .acs_state
                .get(&round)
                .map(|s| s.aba_input_fed.get(j).copied().unwrap_or(true))
                .unwrap_or(true);
            if already_fed {
                let st = self.acs_round_mut(round);
                st.deferred_inputs.remove(&j);
                continue;
            }

            let bit = if banned.contains(&dealer_id) {
                Some(false)
            } else if local_complete.contains(&dealer_id) {
                Some(true)
            } else {
                None
            };

            if let Some(b) = bit {
                let acts = {
                    let st = self.acs_round_mut(round);
                    st.aba_input_fed[j] = true;
                    st.deferred_inputs.remove(&j);
                    st.aba.set_input(j, b)
                };
                log::info!(
                    "[PPT][ACS-ABA] node {} round {} feeding ABA(j={}) input={} (deferred path)",
                    self.myid,
                    round,
                    j,
                    b as u32
                );
                for a in acts {
                    self.dispatch_aba_action(round, self.myid, a).await;
                }
            }
        }
    }

    /// MMR-ACS / BKR rule: once n-f instances decide 1, every
    /// remaining un-fed instance gets input=0. Without this rule
    /// the "stalled" ABAs never make progress because their
    /// proposer is silent / Byzantine and no honest node is
    /// motivated to feed them anything.
    #[async_recursion]
    async fn acs_maybe_force_zero_inputs(&mut self, round: Round) {
        let threshold = self.acs_threshold();

        let (should_force, undecided_to_force) = {
            let st = match self.acs_state.get(&round) {
                Some(s) => s,
                None => return,
            };
            if st.forced_zero_round_started {
                return;
            }
            let ones = st.aba.count_decisions_one();
            let should_force = ones >= threshold;
            let mut undecided: Vec<usize> = Vec::new();
            if should_force {
                for j in 0..st.n {
                    if !st.aba_input_fed[j] {
                        undecided.push(j);
                    }
                }
            }
            (should_force, undecided)
        };

        if !should_force {
            return;
        }

        {
            let st = self.acs_round_mut(round);
            st.forced_zero_round_started = true;
        }

        for j in undecided_to_force {
            let acts = {
                let st = self.acs_round_mut(round);
                st.aba_input_fed[j] = true;
                st.deferred_inputs.remove(&j);
                st.aba.set_input(j, false)
            };
            log::info!(
                "[PPT][ACS-ABA] node {} round {} forcing ABA(j={}) input=0 (n-f decided 1 fast-path)",
                self.myid,
                round,
                j
            );
            for a in acts {
                self.dispatch_aba_action(round, self.myid, a).await;
            }
        }
    }

    /// Feed the common coin into every (j, current_aba_round) pair
    /// that hasn't been fed yet. Idempotent. Iterates internally
    /// until a fixed point is reached, so that feeding coin r at
    /// instance j (which can advance instance j into round r+1) is
    /// followed in the *same* outer scan by feeding coin r+1, etc.
    ///
    /// Without this fixed-point loop, the experiment-A "scan once
    /// at the cascade boundary" design would cost one extra network
    /// round-trip of latency per ABA round of advancement, because
    /// each newly-advanced round's coin would only be pumped after
    /// the next inbound BVAL/AUX from a peer triggered another
    /// outer scan. The loop is bounded by `MAX_PUMP_PASSES` to
    /// defend against any pathological infinite advancement (in
    /// practice MMR ABA terminates in O(1) expected ABA rounds, so
    /// 16 is well above any realistic upper bound).
    #[async_recursion]
    async fn acs_pump_coins(&mut self, round: Round) {
        // We may not have the seed yet (round > 0 with previous
        // beacon not yet recorded). In that case we cannot derive
        // any coin; the caller will retry on the next state change.
        if self.coin_seed_for_acs_round(round).is_none() {
            return;
        }

        const MAX_PUMP_PASSES: usize = 16;
        for _ in 0..MAX_PUMP_PASSES {
            let needed: Vec<(usize, u64)> = {
                let st = match self.acs_state.get(&round) {
                    Some(s) => s,
                    None => return,
                };
                let mut needed = Vec::new();
                for j in 0..st.n {
                    if !st.aba_input_fed[j] {
                        // Cannot advance until input is fed — coin
                        // is useless before that.
                        continue;
                    }
                    let curr = st.aba.current_aba_round(j).unwrap_or(0);
                    for r in 0..=curr {
                        if !st.coin_fed_for.contains(&(j, r)) {
                            needed.push((j, r));
                        }
                    }
                }
                needed
            };

            if needed.is_empty() {
                return;
            }

            for (j, r) in needed {
                let bit = match self.coin_bit_for(round, j, r) {
                    Some(b) => b,
                    None => continue,
                };
                let acts = {
                    let st = self.acs_round_mut(round);
                    st.coin_fed_for.insert((j, r));
                    st.aba.handle_coin(j, r, bit)
                };
                for a in acts {
                    self.dispatch_aba_action(round, self.myid, a).await;
                }
            }
        }
    }

    /// Once every ABA has decided, compute the dealer set output
    /// `{ j : ABA(j) = 1 }` and call `finalize_acs_round`.
    #[async_recursion]
    async fn acs_maybe_finalize(&mut self, round: Round) {
        let banned = self.permanently_banned_dealers();

        let dealers_to_finalize: Option<Vec<Replica>> = {
            let st = match self.acs_state.get(&round) {
                Some(s) => s,
                None => return,
            };
            if st.finalized {
                None
            } else {
                st.compute_decided_dealers(&banned)
            }
        };

        let dealers = match dealers_to_finalize {
            Some(d) => d,
            None => return,
        };

        {
            let st = self.acs_round_mut(round);
            st.finalized = true;
        }

        log::error!(
            "[PPT][ACS-DECIDE] node {} round {} new-pipeline ACS decided dealers = {:?}",
            self.myid,
            round,
            dealers
        );

        self.finalize_acs_round(round, dealers).await;
    }

    // ---- RBC dispatch ----

    /// Dispatch one `RbcAction` produced by `acs_state[round].rbc[*]`.
    /// Maps:
    ///   - `SendSend(payload)` → broadcast `ACSRbcSend` + self-deliver
    ///   - `SendEcho(h)`       → broadcast `ACSRbcEcho` + self-deliver
    ///   - `SendReady(h)`      → broadcast `ACSRbcReady` + self-deliver
    ///   - `Delivered(payload)`→ record locally and feed ABA(j) input
    ///
    /// Self-deliver paths intentionally call the **`*_inner`**
    /// variants of the inbound handlers, which skip the external
    /// scan (`acs_external_scan_once`). The scan happens once at
    /// the outer cascade boundary, not on every recursive
    /// self-deliver step.
    #[async_recursion]
    async fn dispatch_rbc_action(
        &mut self,
        round: Round,
        proposer: Replica,
        action: RbcAction,
    ) {
        match action {
            RbcAction::SendSend { payload } => {
                let msg = CoinMsg::ACSRbcSend(round, proposer, payload.clone());
                self.broadcast(msg, round).await;
                // Self-deliver inner: feed our own SEND into our local
                // RBC state so the ECHO/READY thresholds count us.
                // No scan here -- it runs once at the outer boundary.
                self.process_acs_rbc_send_inner(round, proposer, payload).await;
            }
            RbcAction::SendEcho { payload_hash } => {
                let msg = CoinMsg::ACSRbcEcho(round, proposer, payload_hash);
                self.broadcast(msg, round).await;
                self.process_acs_rbc_echo_inner(round, proposer, self.myid, payload_hash).await;
            }
            RbcAction::SendReady { payload_hash } => {
                let msg = CoinMsg::ACSRbcReady(round, proposer, payload_hash);
                self.broadcast(msg, round).await;
                self.process_acs_rbc_ready_inner(round, proposer, self.myid, payload_hash).await;
            }
            RbcAction::Delivered { payload } => {
                self.on_rbc_delivered(round, proposer, payload).await;
            }
        }
    }

    /// Local RBC delivery: try to feed ABA(proposer) input=1 if
    /// dealer `proposer` is AVSS-completed locally; otherwise defer.
    #[async_recursion]
    async fn on_rbc_delivered(&mut self, round: Round, proposer: Replica, payload: Vec<u8>) {
        let banned = self.permanently_banned_dealers();
        let local_complete = self.local_completed_dealers(round);
        let j = proposer as usize;

        let already_fed = self
            .acs_state
            .get(&round)
            .map(|s| s.aba_input_fed.get(j).copied().unwrap_or(true))
            .unwrap_or(true);

        log::info!(
            "[PPT][ACS-RBC] node {} round {} RBC delivered for proposer {} (|payload|={} bytes, already_fed={})",
            self.myid,
            round,
            proposer,
            payload.len(),
            already_fed
        );

        // Cache the payload regardless of input decision.
        {
            let st = self.acs_round_mut(round);
            st.rbc_delivered_payload.insert(j, payload);
        }

        if already_fed {
            return;
        }

        // External validity: dealer j must be AVSS-completed locally
        // and not banned. If not, defer (NOT abstain) — AVSS totality
        // guarantees that an honest proposer's dealer eventually
        // becomes locally AVSS-completed.
        let bit_opt: Option<bool> = if banned.contains(&proposer) {
            Some(false)
        } else if local_complete.contains(&proposer) {
            Some(true)
        } else {
            None
        };

        match bit_opt {
            Some(b) => {
                let acts = {
                    let st = self.acs_round_mut(round);
                    st.aba_input_fed[j] = true;
                    st.deferred_inputs.remove(&j);
                    st.aba.set_input(j, b)
                };
                log::info!(
                    "[PPT][ACS-ABA] node {} round {} feeding ABA(j={}) input={} (RBC-delivery path)",
                    self.myid,
                    round,
                    j,
                    b as u32
                );
                for a in acts {
                    self.dispatch_aba_action(round, self.myid, a).await;
                }
            }
            None => {
                let st = self.acs_round_mut(round);
                st.deferred_inputs.insert(j);
                log::info!(
                    "[PPT][ACS-ABA] node {} round {} deferring ABA(j={}) input — dealer {} not yet AVSS-completed",
                    self.myid,
                    round,
                    j,
                    proposer
                );
            }
        }
    }

    /// Dispatch one `AbaDriverAction`. Maps:
    ///   - `Bval`     → broadcast + self-deliver (inner)
    ///   - `Aux`      → broadcast + self-deliver (inner)
    ///   - `Decided`  → log; finalisation happens at the outer scan.
    ///
    /// As with `dispatch_rbc_action`, self-deliver uses the `*_inner`
    /// handler variants which skip the external scan.
    #[async_recursion]
    async fn dispatch_aba_action(
        &mut self,
        round: Round,
        sender: Replica,
        action: AbaDriverAction,
    ) {
        match action {
            AbaDriverAction::Bval { aba_instance_id, aba_round, value } => {
                let msg = CoinMsg::ACSAbaBval(
                    round,
                    aba_instance_id as Replica,
                    aba_round,
                    value,
                );
                self.broadcast(msg, round).await;
                self.process_acs_aba_bval_inner(round, aba_instance_id as Replica, aba_round, value, sender).await;
            }
            AbaDriverAction::Aux { aba_instance_id, aba_round, value } => {
                let msg = CoinMsg::ACSAbaAux(
                    round,
                    aba_instance_id as Replica,
                    aba_round,
                    value,
                );
                self.broadcast(msg, round).await;
                self.process_acs_aba_aux_inner(round, aba_instance_id as Replica, aba_round, value, sender).await;
            }
            AbaDriverAction::Decided { aba_instance_id, value } => {
                log::info!(
                    "[PPT][ACS-ABA-DECIDE] node {} round {} ABA(j={}) decided={}",
                    self.myid,
                    round,
                    aba_instance_id,
                    value as u32
                );
            }
        }
    }

    // ---- Inbound message handlers ----
    //
    // Each handler comes in two flavours:
    //
    //   * `process_acs_*`        -- OUTER entry: called by the
    //     network dispatcher in `process.rs` for each received
    //     wire message. Runs the inner cascade and then triggers
    //     **exactly one** external scan at the cascade boundary.
    //     RBC handlers use the cheap `acs_external_scan_finalize_only`,
    //     ABA handlers use the full `acs_external_scan_full`.
    //
    //   * `process_acs_*_inner`  -- INNER entry: called from
    //     `dispatch_rbc_action` / `dispatch_aba_action` along the
    //     self-deliver path. Runs the state-machine update + any
    //     resulting cascade actions. **Does not scan**, because
    //     the enclosing outer entry will scan at the cascade
    //     boundary anyway, and the three scan helpers
    //     (`acs_pump_coins` / `acs_maybe_force_zero_inputs` /
    //     `acs_maybe_finalize`) are idempotent + monotone, so
    //     deferring them to the boundary preserves Validity /
    //     Agreement / Termination at significantly lower CPU cost.
    //
    // Why specialised scans for RBC vs ABA? The RBC state machine
    // only updates ECHO/READY counters and SEND payload bytes -- it
    // never directly enables a `pump_coins` or `force_zero`
    // transition (those depend on ABA state). RBC delivery *does*
    // feed an ABA input via `on_rbc_delivered`, but the resulting
    // BVAL is broadcast to peers, who then run their own ABA outer
    // scan within ~1 RTT and pump the new ABA(j) round-0 coin.
    // Skipping pump_coins on the RBC path avoided a 23 % batch=100
    // throughput regression in the first version of experiment A
    // (where every RBC ECHO/READY also triggered a full pump scan).
    //
    // Termination intuition: every inbound ACS message arrives
    // through one of the OUTER entries (the network dispatcher in
    // `process.rs` only ever calls the outer variants), and every
    // outer entry concludes with at least `acs_maybe_finalize`.
    // ABA inbound messages additionally trigger pump_coins +
    // force_zero, which are exactly the events that can require
    // them. Every state mutation that could enable a new scan-
    // driven transition is therefore followed by an appropriate
    // scan before control returns to the network event loop.

    /// `ACSRbcSend(round, proposer, payload)`. The dispatcher in
    /// `process.rs` already checked that the wrapper-level sender
    /// matches `proposer` (Bracha RBC SENDs are only authoritative
    /// from the proposer themselves).
    #[async_recursion]
    pub async fn process_acs_rbc_send(
        &mut self,
        round: Round,
        proposer: Replica,
        payload: Vec<u8>,
    ) {
        self.process_acs_rbc_send_inner(round, proposer, payload).await;
        self.acs_external_scan_finalize_only(round).await;
    }

    #[async_recursion]
    async fn process_acs_rbc_send_inner(
        &mut self,
        round: Round,
        proposer: Replica,
        payload: Vec<u8>,
    ) {
        if self.permanently_banned_dealers().contains(&proposer) {
            log::warn!(
                "[PPT][BAN] dropping ACSRbcSend from banned proposer {} round {}",
                proposer,
                round
            );
            return;
        }
        if (proposer as usize) >= self.num_nodes {
            return;
        }

        let acts = {
            let st = self.acs_round_mut(round);
            st.rbc[proposer as usize].handle_send(proposer, payload)
        };

        for a in acts {
            self.dispatch_rbc_action(round, proposer, a).await;
        }
    }

    #[async_recursion]
    pub async fn process_acs_rbc_echo(
        &mut self,
        round: Round,
        proposer: Replica,
        sender: Replica,
        payload_hash: crypto::hash::Hash,
    ) {
        self.process_acs_rbc_echo_inner(round, proposer, sender, payload_hash).await;
        self.acs_external_scan_finalize_only(round).await;
    }

    #[async_recursion]
    async fn process_acs_rbc_echo_inner(
        &mut self,
        round: Round,
        proposer: Replica,
        sender: Replica,
        payload_hash: crypto::hash::Hash,
    ) {
        if self.permanently_banned_dealers().contains(&proposer) {
            return;
        }
        if (proposer as usize) >= self.num_nodes {
            return;
        }

        let acts = {
            let st = self.acs_round_mut(round);
            st.rbc[proposer as usize].handle_echo(sender, payload_hash)
        };

        for a in acts {
            self.dispatch_rbc_action(round, proposer, a).await;
        }
    }

    #[async_recursion]
    pub async fn process_acs_rbc_ready(
        &mut self,
        round: Round,
        proposer: Replica,
        sender: Replica,
        payload_hash: crypto::hash::Hash,
    ) {
        self.process_acs_rbc_ready_inner(round, proposer, sender, payload_hash).await;
        self.acs_external_scan_finalize_only(round).await;
    }

    #[async_recursion]
    async fn process_acs_rbc_ready_inner(
        &mut self,
        round: Round,
        proposer: Replica,
        sender: Replica,
        payload_hash: crypto::hash::Hash,
    ) {
        if self.permanently_banned_dealers().contains(&proposer) {
            return;
        }
        if (proposer as usize) >= self.num_nodes {
            return;
        }

        let acts = {
            let st = self.acs_round_mut(round);
            st.rbc[proposer as usize].handle_ready(sender, payload_hash)
        };

        for a in acts {
            self.dispatch_rbc_action(round, proposer, a).await;
        }
    }

    #[async_recursion]
    pub async fn process_acs_aba_bval(
        &mut self,
        round: Round,
        aba_instance_id: Replica,
        aba_round: u64,
        value: bool,
        sender: Replica,
    ) {
        self.process_acs_aba_bval_inner(round, aba_instance_id, aba_round, value, sender).await;
        self.acs_external_scan_full(round).await;
    }

    #[async_recursion]
    async fn process_acs_aba_bval_inner(
        &mut self,
        round: Round,
        aba_instance_id: Replica,
        aba_round: u64,
        value: bool,
        sender: Replica,
    ) {
        let j = aba_instance_id as usize;
        if j >= self.num_nodes {
            return;
        }

        let acts = {
            let st = self.acs_round_mut(round);
            st.aba.handle_bval(j, aba_round, value, sender)
        };

        for a in acts {
            self.dispatch_aba_action(round, self.myid, a).await;
        }
    }

    #[async_recursion]
    pub async fn process_acs_aba_aux(
        &mut self,
        round: Round,
        aba_instance_id: Replica,
        aba_round: u64,
        value: bool,
        sender: Replica,
    ) {
        self.process_acs_aba_aux_inner(round, aba_instance_id, aba_round, value, sender).await;
        self.acs_external_scan_full(round).await;
    }

    #[async_recursion]
    async fn process_acs_aba_aux_inner(
        &mut self,
        round: Round,
        aba_instance_id: Replica,
        aba_round: u64,
        value: bool,
        sender: Replica,
    ) {
        let j = aba_instance_id as usize;
        if j >= self.num_nodes {
            return;
        }

        let acts = {
            let st = self.acs_round_mut(round);
            st.aba.handle_aux(j, aba_round, value, sender)
        };

        for a in acts {
            self.dispatch_aba_action(round, self.myid, a).await;
        }
    }
}
