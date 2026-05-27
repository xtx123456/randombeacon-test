//! Driver for the PPT ACS protocol. See `state.rs` for the
//! protocol description; this module wires the state machine into
//! `Context` and handles network egress/ingress.
//!
//! The driver enforces the following invariants:
//!
//! 1. A node sends its `ACSPropose` exactly once, only after it
//!    locally has at least n-f AVSS-completed dealers (this is
//!    monotone: AVSS-completed grows only).
//! 2. A node sends `ACSWitness1` exactly once, only after it has
//!    validated at least n-f distinct proposals.
//! 3. A node sends `ACSWitness2` exactly once, only after it has
//!    ratified at least n-f Witness1 senders.
//! 4. A node finalises the decision exactly once, only after it
//!    has ratified at least n-f Witness2 senders. The finalised
//!    dealer set is deterministic given the ratified set
//!    (see `ACSInstanceState::finalize_decision`).
//! 5. Every time the local AVSS-completion view changes (a new
//!    dealer transitions to AVSS-complete or a dealer is banned),
//!    we re-validate buffered proposals, then cascade to W1, W2,
//!    DECIDE in case the new validations unblock progress.

use async_recursion::async_recursion;

use types::{
    beacon::{CoinMsg, Replica},
    Round,
};

use super::state::ACSInstanceState;
use crate::node::Context;

impl Context {
    /// Local quorum threshold n-f.
    fn acs_threshold(&self) -> usize {
        self.num_nodes - self.num_faults
    }

    /// Public entry from the AVSS path: a dealer just became
    /// AVSS-completed locally, or has been freshly banned. The
    /// driver reflects that into the ACS state machine and runs a
    /// full cascade so any downstream phase that became eligible
    /// fires immediately.
    ///
    /// Order matters here:
    /// 1. Apply bans / new completions.
    /// 2. Re-validate buffered proposals (can grow `validated_proposers`).
    /// 3. Re-rate cached W1 senders against the new
    ///    `validated_proposers` (can grow `w1_ratified`).
    /// 4. Re-rate cached W2 senders against the new `w1_ratified`
    ///    (can grow `w2_ratified`).
    /// 5. Cascade — try to send our own Propose / W1 / W2 / Decide.
    ///
    /// Without steps 3 and 4, cached W1 / W2 messages from peers
    /// that arrived BEFORE we had validated the proposers they
    /// reference would never be re-evaluated, and ACS would stall
    /// forever in any execution where some dealer's AVSS completes
    /// at one node noticeably later than at another.
    #[async_recursion]
    pub async fn acs_note_local_change(&mut self, round: Round) {
        let local_completed = self.local_completed_dealers(round);
        let banned: Vec<Replica> = self.permanently_banned_dealers().into_iter().collect();

        {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));
            for d in banned.into_iter() {
                st.ban_dealer(d);
            }
            for d in local_completed.into_iter() {
                st.note_completed(d);
            }
            st.revalidate_pending();
            st.rerate_w1();
            st.rerate_w2();
        }

        self.acs_try_send_propose(round).await;
        self.acs_cascade(round).await;
    }

    /// Drive the ACS state forward as far as the local view
    /// allows. Each phase only sends once.
    #[async_recursion]
    async fn acs_cascade(&mut self, round: Round) {
        let threshold = self.acs_threshold();

        // Witness1 -- sent once we have validated n-f proposals.
        let w1_payload = {
            let st = match self.acs_state.get_mut(&round) {
                Some(st) => st,
                None => return,
            };
            if st.ready_to_send_w1(threshold) {
                let v: Vec<Replica> = st.validated_proposers.iter().copied().collect();
                st.w1_sent = true;
                Some(v)
            } else {
                None
            }
        };
        if let Some(v) = w1_payload {
            log::info!(
                "[PPT][ACS] node {} round {} sending Witness1 with {} validated proposers: {:?}",
                self.myid,
                round,
                v.len(),
                v
            );
            self.broadcast(CoinMsg::ACSWitness1(round, self.myid, v.clone()), round)
                .await;
            self.process_acs_witness1(round, self.myid, v).await;
        }

        // Witness2 -- sent once we have ratified n-f Witness1 senders.
        let w2_payload = {
            let st = match self.acs_state.get_mut(&round) {
                Some(st) => st,
                None => return,
            };
            if st.ready_to_send_w2(threshold) {
                let v: Vec<Replica> = st.w1_ratified.iter().copied().collect();
                st.w2_sent = true;
                Some(v)
            } else {
                None
            }
        };
        if let Some(v) = w2_payload {
            log::info!(
                "[PPT][ACS] node {} round {} sending Witness2 with {} ratified W1 senders: {:?}",
                self.myid,
                round,
                v.len(),
                v
            );
            self.broadcast(CoinMsg::ACSWitness2(round, self.myid, v.clone()), round)
                .await;
            self.process_acs_witness2(round, self.myid, v).await;
        }

        // DECIDE.
        let decision = {
            let st = match self.acs_state.get_mut(&round) {
                Some(st) => st,
                None => return,
            };
            if st.ready_to_decide(threshold) {
                st.finalize_decision()
            } else {
                None
            }
        };
        if let Some((proposers, dealers)) = decision {
            log::error!(
                "[PPT][ACS-DECIDE] node {} round {} finalised proposers={:?} dealers={:?}",
                self.myid,
                round,
                proposers,
                dealers
            );
            self.finalize_acs_round(round, dealers).await;
        }
    }

    /// Try to broadcast our local `ACSPropose` if the AVSS path
    /// has produced n-f locally completed dealers.
    #[async_recursion]
    async fn acs_try_send_propose(&mut self, round: Round) {
        let threshold = self.acs_threshold();

        let payload = {
            let st = match self.acs_state.get_mut(&round) {
                Some(st) => st,
                None => return,
            };
            if st.propose_sent {
                return;
            }
            match st.build_local_proposal(threshold) {
                Some(p) => {
                    st.propose_sent = true;
                    p
                }
                None => return,
            }
        };

        log::info!(
            "[PPT][ACS] node {} round {} broadcasting ACSPropose with {} dealers: {:?}",
            self.myid,
            round,
            payload.len(),
            payload
        );
        self.broadcast(CoinMsg::ACSPropose(round, self.myid, payload.clone()), round)
            .await;
        self.process_acs_propose(round, self.myid, payload).await;
    }

    /// Ingress: `ACSPropose(round, sender, dealers)`.
    #[async_recursion]
    pub async fn process_acs_propose(
        &mut self,
        round: Round,
        sender: Replica,
        dealers: Vec<Replica>,
    ) {
        if self.permanently_banned_dealers().contains(&sender) {
            log::warn!(
                "[PPT][ACS] dropping ACSPropose from banned sender {} round {}",
                sender,
                round
            );
            return;
        }

        // Make sure the local AVSS view is reflected before we
        // attempt to validate this proposal.
        let local_completed = self.local_completed_dealers(round);
        let banned: Vec<Replica> = self.permanently_banned_dealers().into_iter().collect();

        {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));
            for d in banned.into_iter() {
                st.ban_dealer(d);
            }
            for d in local_completed.into_iter() {
                st.note_completed(d);
            }

            // If `record_propose` newly validates `sender`, it grows
            // `validated_proposers`. Re-rate cached W1 / W2 messages
            // so any peer that previously couldn't be ratified
            // (because they referenced this proposer) becomes
            // ratifiable now. Without this, peers that sent W1
            // referencing `sender` BEFORE we received `sender`'s
            // proposal would stay un-ratified and ACS would stall.
            let newly_validated = st.record_propose(sender, dealers);
            if newly_validated {
                st.rerate_w1();
                st.rerate_w2();
            }
        }

        self.acs_cascade(round).await;
    }

    /// Ingress: `ACSWitness1(round, sender, validated_proposers)`.
    #[async_recursion]
    pub async fn process_acs_witness1(
        &mut self,
        round: Round,
        sender: Replica,
        validated: Vec<Replica>,
    ) {
        if self.permanently_banned_dealers().contains(&sender) {
            log::warn!(
                "[PPT][ACS] dropping ACSWitness1 from banned sender {} round {}",
                sender,
                round
            );
            return;
        }

        {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));

            // If this Witness1 is newly ratifiable, `w1_ratified`
            // grows; re-rate cached W2 messages because a peer that
            // previously couldn't be ratified (because they
            // referenced this W1 sender) becomes ratifiable now.
            let newly_ratified = st.record_w1(sender, validated);
            if newly_ratified {
                st.rerate_w2();
            }
        }

        self.acs_cascade(round).await;
    }

    /// Ingress: `ACSWitness2(round, sender, witnessed_w1_senders)`.
    #[async_recursion]
    pub async fn process_acs_witness2(
        &mut self,
        round: Round,
        sender: Replica,
        witnessed: Vec<Replica>,
    ) {
        if self.permanently_banned_dealers().contains(&sender) {
            log::warn!(
                "[PPT][ACS] dropping ACSWitness2 from banned sender {} round {}",
                sender,
                round
            );
            return;
        }

        {
            let st = self
                .acs_state
                .entry(round)
                .or_insert_with(|| ACSInstanceState::new(round as usize, self.myid));
            st.record_w2(sender, witnessed);
        }

        self.acs_cascade(round).await;
    }
}
