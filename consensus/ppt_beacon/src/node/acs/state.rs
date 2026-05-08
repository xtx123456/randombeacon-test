//! Asynchronous Common Subset state for one PPT round.
//!
//! Protocol summary (see `acs/protocol.rs` for the driver):
//!
//! 1. PROPOSE  — every node broadcasts `ACSPropose(i, S_i)` where
//!    `S_i = local AVSS-completed dealers, |S_i| ≥ n-f`.
//!    Receivers validate the proposal under *external validity*:
//!    every dealer in `S_i` must also be AVSS-completed in the
//!    receiver's local view. Invalid proposals are buffered, never
//!    silently dropped, because AVSS totality guarantees that any
//!    honest proposal becomes valid eventually.
//!
//! 2. WITNESS1 — once a node has validated n-f distinct proposals
//!    it broadcasts `ACSWitness1(V)` with the *proposer IDs* whose
//!    proposals it has validated.
//!
//! 3. WITNESS2 — once a node has received n-f `ACSWitness1`
//!    messages whose `V_k ⊆ local_validated`, it broadcasts
//!    `ACSWitness2(W1)` with the *Witness1 senders* it ratified.
//!
//! 4. DECIDE   — once a node has received n-f `ACSWitness2`
//!    messages whose `W2_k ⊆ local_W1_ratified`, it computes the
//!    deterministic decided proposer set:
//!
//!       decided_proposers = sorted_union over k ∈ W2_ratified of W1[k].validated
//!       decided_dealers   = sorted_union over j ∈ decided_proposers of proposal[j].dealers
//!
//!    Both unions are sorted (canonical) so all honest finalisers
//!    obtain the *exact same* dealer set, which is required for
//!    beacon safety (every honest node must reconstruct the same
//!    secret sum in `coin_check`).
//!
//! Safety: a finaliser only commits when it sees n-f matching
//! ratifications at each phase. Two honest finalisers therefore
//! share f+1 ratifying senders at every phase, which by AVSS
//! totality and proposal binding (each proposer is bound to a
//! single proposal — Byzantine equivocators are caught by the
//! validation step in `record_propose`) forces both finalisers
//! onto the same `decided_proposers` and hence the same
//! `decided_dealers`.
//!
//! Liveness: Witness1/Witness2 ratification is monotone (only
//! grows with more deliveries). Honest proposals are delivered
//! everywhere by AVSS totality, so every honest node eventually
//! collects n-f matching Witness1, then n-f matching Witness2.

use std::collections::{BTreeSet, HashMap, HashSet};

use types::Replica;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ACSPhase {
    Proposing,
    Witness1Sent,
    Witness2Sent,
    Decided,
}

impl Default for ACSPhase {
    fn default() -> Self {
        ACSPhase::Proposing
    }
}

/// One entry in the proposal book: the sorted dealer set proposed
/// by a given sender, plus a flag tracking whether the local
/// observer has *validated* it under external validity.
#[derive(Debug, Clone)]
pub struct ProposalEntry {
    pub dealers: Vec<Replica>,
    pub validated: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ACSInstanceState {
    pub round: usize,
    pub myid: usize,

    /// Locally AVSS-completed dealers. Updated by the AVSS path
    /// before each re-validation pass.
    pub completed_dealers: HashSet<Replica>,

    /// Dealers that the AVSS / accountability path has
    /// permanently blamed; these MUST be filtered out of every
    /// proposal we ever generate or accept.
    pub banned_dealers: HashSet<Replica>,

    /// proposer_id -> proposal entry (latest seen content; an
    /// honest sender broadcasts its proposal exactly once, so
    /// equivocation by Byzantines is caught here).
    pub proposals: HashMap<Replica, ProposalEntry>,

    /// proposer IDs whose proposal we have already validated.
    pub validated_proposers: BTreeSet<Replica>,

    /// w1_sender -> set of validated_proposers they reported.
    pub w1_received: HashMap<Replica, BTreeSet<Replica>>,

    /// W1 senders we have ratified (their `validated_proposers`
    /// is a subset of our local `validated_proposers`).
    pub w1_ratified: BTreeSet<Replica>,

    /// w2_sender -> set of W1 senders they reported.
    pub w2_received: HashMap<Replica, BTreeSet<Replica>>,

    /// W2 senders we have ratified.
    pub w2_ratified: BTreeSet<Replica>,

    /// Has this node already broadcast its own ACSPropose?
    pub propose_sent: bool,
    /// Has this node already broadcast its own ACSWitness1?
    pub w1_sent: bool,
    /// Has this node already broadcast its own ACSWitness2?
    pub w2_sent: bool,
    /// Has this node finalized the decision?
    pub decided: bool,

    /// Final decision outputs, set exactly once.
    pub decided_proposers: Option<Vec<Replica>>,
    pub decided_dealers: Option<Vec<Replica>>,

    pub phase: ACSPhase,
}

impl ACSInstanceState {
    pub fn new(round: usize, myid: usize) -> Self {
        Self {
            round,
            myid,
            completed_dealers: HashSet::new(),
            banned_dealers: HashSet::new(),
            proposals: HashMap::new(),
            validated_proposers: BTreeSet::new(),
            w1_received: HashMap::new(),
            w1_ratified: BTreeSet::new(),
            w2_received: HashMap::new(),
            w2_ratified: BTreeSet::new(),
            propose_sent: false,
            w1_sent: false,
            w2_sent: false,
            decided: false,
            decided_proposers: None,
            decided_dealers: None,
            phase: ACSPhase::Proposing,
        }
    }

    /// Refresh the local AVSS-completion view. The AVSS pipeline
    /// calls this each time a new dealer transitions to
    /// AVSS-completed so that newly-buffered proposals can be
    /// re-validated.
    pub fn note_completed(&mut self, dealer: Replica) {
        if !self.banned_dealers.contains(&dealer) {
            self.completed_dealers.insert(dealer);
        }
    }

    /// Register a malicious dealer learnt either inline (invalid
    /// AVSS packet) or post-hoc (commitment audit).
    pub fn ban_dealer(&mut self, dealer: Replica) {
        self.banned_dealers.insert(dealer);
        self.completed_dealers.remove(&dealer);
        // Drop the dealer from every cached proposal so a stale
        // proposal cannot keep them alive.
        for entry in self.proposals.values_mut() {
            entry.dealers.retain(|d| *d != dealer);
            entry.validated = false; // force re-validation
        }
        self.validated_proposers.clear();
    }

    /// Build the local proposal payload (sorted, deduplicated,
    /// banned dealers removed). May return `None` if this node has
    /// fewer than n-f locally completed dealers.
    pub fn build_local_proposal(&self, threshold: usize) -> Option<Vec<Replica>> {
        let mut payload: Vec<Replica> = self
            .completed_dealers
            .iter()
            .copied()
            .filter(|d| !self.banned_dealers.contains(d))
            .collect();
        payload.sort_unstable();
        payload.dedup();
        if payload.len() < threshold {
            return None;
        }
        Some(payload)
    }

    /// Record an incoming `ACSPropose`. Returns `true` if the
    /// proposal moved into the validated state as a result of this
    /// call (so the driver can re-evaluate Witness1 conditions).
    ///
    /// If the same proposer sends a different proposal later
    /// (Byzantine equivocation) the new one is discarded and the
    /// proposer is permanently rejected from the local view.
    pub fn record_propose(&mut self, proposer: Replica, dealers: Vec<Replica>) -> bool {
        // Drop dealers we have already banned.
        let mut sanitized: Vec<Replica> = dealers
            .into_iter()
            .filter(|d| !self.banned_dealers.contains(d))
            .collect();
        sanitized.sort_unstable();
        sanitized.dedup();

        if let Some(prev) = self.proposals.get(&proposer) {
            if prev.dealers != sanitized {
                log::warn!(
                    "[PPT][ACS] proposer {} round {} equivocated; refusing to update its proposal",
                    proposer,
                    self.round
                );
                return false;
            }
            if prev.validated {
                return false;
            }
        }

        let validated = self.is_proposal_externally_valid(&sanitized);
        self.proposals.insert(
            proposer,
            ProposalEntry {
                dealers: sanitized,
                validated,
            },
        );
        if validated {
            self.validated_proposers.insert(proposer)
        } else {
            false
        }
    }

    /// Re-validate every still-pending proposal against the latest
    /// AVSS-completion view. Returns the proposer IDs that newly
    /// became validated.
    pub fn revalidate_pending(&mut self) -> Vec<Replica> {
        let mut newly_validated = Vec::new();
        let proposer_ids: Vec<Replica> = self.proposals.keys().copied().collect();
        for proposer in proposer_ids {
            let entry_validated = self
                .proposals
                .get(&proposer)
                .map(|e| e.validated)
                .unwrap_or(false);
            if entry_validated {
                continue;
            }
            let dealers = self
                .proposals
                .get(&proposer)
                .map(|e| e.dealers.clone())
                .unwrap_or_default();
            if self.is_proposal_externally_valid(&dealers) {
                if let Some(entry) = self.proposals.get_mut(&proposer) {
                    entry.validated = true;
                }
                if self.validated_proposers.insert(proposer) {
                    newly_validated.push(proposer);
                }
            }
        }
        newly_validated
    }

    fn is_proposal_externally_valid(&self, dealers: &[Replica]) -> bool {
        if dealers.is_empty() {
            return false;
        }
        for d in dealers.iter().copied() {
            if self.banned_dealers.contains(&d) {
                return false;
            }
            if !self.completed_dealers.contains(&d) {
                return false;
            }
        }
        true
    }

    /// Record a `Witness1` from `sender`. Returns `true` if
    /// `sender` was newly ratified (i.e. its `validated_proposers`
    /// is now a subset of our local `validated_proposers`).
    pub fn record_w1(&mut self, sender: Replica, validated: Vec<Replica>) -> bool {
        let v: BTreeSet<Replica> = validated.into_iter().collect();
        self.w1_received.insert(sender, v.clone());
        self.try_ratify_w1_sender(sender)
    }

    /// Re-evaluate every cached Witness1 against the current
    /// validated set. Returns IDs newly ratified.
    pub fn rerate_w1(&mut self) -> Vec<Replica> {
        let mut newly = Vec::new();
        let senders: Vec<Replica> = self.w1_received.keys().copied().collect();
        for s in senders {
            if self.w1_ratified.contains(&s) {
                continue;
            }
            if self.try_ratify_w1_sender(s) {
                newly.push(s);
            }
        }
        newly
    }

    fn try_ratify_w1_sender(&mut self, sender: Replica) -> bool {
        let v = match self.w1_received.get(&sender) {
            Some(v) => v.clone(),
            None => return false,
        };
        if v.iter().all(|p| self.validated_proposers.contains(p)) {
            self.w1_ratified.insert(sender)
        } else {
            false
        }
    }

    /// Record a `Witness2` from `sender`. Returns `true` if newly
    /// ratified.
    pub fn record_w2(&mut self, sender: Replica, witnessed: Vec<Replica>) -> bool {
        let v: BTreeSet<Replica> = witnessed.into_iter().collect();
        self.w2_received.insert(sender, v);
        self.try_ratify_w2_sender(sender)
    }

    /// Re-evaluate every cached Witness2 against the current
    /// w1_ratified set. Returns IDs newly ratified.
    pub fn rerate_w2(&mut self) -> Vec<Replica> {
        let mut newly = Vec::new();
        let senders: Vec<Replica> = self.w2_received.keys().copied().collect();
        for s in senders {
            if self.w2_ratified.contains(&s) {
                continue;
            }
            if self.try_ratify_w2_sender(s) {
                newly.push(s);
            }
        }
        newly
    }

    fn try_ratify_w2_sender(&mut self, sender: Replica) -> bool {
        let v = match self.w2_received.get(&sender) {
            Some(v) => v.clone(),
            None => return false,
        };
        if v.iter().all(|w| self.w1_ratified.contains(w)) {
            self.w2_ratified.insert(sender)
        } else {
            false
        }
    }

    /// Should we broadcast our local Witness1 now?
    pub fn ready_to_send_w1(&self, threshold: usize) -> bool {
        !self.w1_sent && self.validated_proposers.len() >= threshold
    }

    /// Should we broadcast our local Witness2 now?
    pub fn ready_to_send_w2(&self, threshold: usize) -> bool {
        !self.w2_sent && self.w1_ratified.len() >= threshold
    }

    /// Should we finalise now?
    pub fn ready_to_decide(&self, threshold: usize) -> bool {
        !self.decided && self.w2_ratified.len() >= threshold
    }

    /// Compute the deterministic decision and store it. Idempotent
    /// — returns `None` once already decided.
    pub fn finalize_decision(&mut self) -> Option<(Vec<Replica>, Vec<Replica>)> {
        if self.decided {
            return None;
        }
        // Decided proposer set = sorted-union over k ∈ w2_ratified of W1[k].validated.
        let mut proposers: BTreeSet<Replica> = BTreeSet::new();
        for k in self.w2_ratified.iter().copied() {
            if let Some(v) = self.w1_received.get(&k) {
                for p in v.iter().copied() {
                    proposers.insert(p);
                }
            }
        }
        // Safety: every proposer in this union has been validated locally
        // (ratification of W1 senders requires their validated set ⊆ our
        // local validated set). Validation in turn requires the dealer set to
        // be locally AVSS-complete, so dealers below are well-defined.
        let mut dealers: BTreeSet<Replica> = BTreeSet::new();
        for j in proposers.iter().copied() {
            if let Some(entry) = self.proposals.get(&j) {
                if !entry.validated {
                    log::error!(
                        "[PPT][ACS-BUG] decided proposer {} not validated locally; this should be impossible",
                        j
                    );
                    return None;
                }
                for d in entry.dealers.iter().copied() {
                    if !self.banned_dealers.contains(&d) {
                        dealers.insert(d);
                    }
                }
            } else {
                log::error!(
                    "[PPT][ACS-BUG] decided proposer {} has no proposal locally; cannot finalize",
                    j
                );
                return None;
            }
        }

        let proposers_vec: Vec<Replica> = proposers.into_iter().collect();
        let dealers_vec: Vec<Replica> = dealers.into_iter().collect();
        self.decided = true;
        self.phase = ACSPhase::Decided;
        self.decided_proposers = Some(proposers_vec.clone());
        self.decided_dealers = Some(dealers_vec.clone());

        Some((proposers_vec, dealers_vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(threshold: usize, completed: &[Replica]) -> ACSInstanceState {
        let mut st = ACSInstanceState::new(0, 0);
        for d in completed.iter().copied() {
            st.note_completed(d);
        }
        // sanity: threshold is what the driver would pass as n-f.
        let _ = threshold;
        st
    }

    #[test]
    fn proposal_validation_is_external_validity() {
        let mut st = fresh(3, &[1, 2, 3]);

        // Proposal with all dealers locally completed: validates immediately.
        assert!(st.record_propose(1, vec![1, 2, 3]));
        assert!(st.proposals[&1].validated);
        assert!(st.validated_proposers.contains(&1));

        // Proposal with a dealer we have not yet seen: buffered.
        assert!(!st.record_propose(2, vec![1, 2, 4]));
        assert!(!st.proposals[&2].validated);
        assert!(!st.validated_proposers.contains(&2));

        // After AVSS completes for dealer 4, re-validation passes.
        st.note_completed(4);
        let newly = st.revalidate_pending();
        assert_eq!(newly, vec![2]);
        assert!(st.proposals[&2].validated);
        assert!(st.validated_proposers.contains(&2));
    }

    #[test]
    fn equivocating_proposal_is_rejected() {
        let mut st = fresh(3, &[1, 2, 3]);
        assert!(st.record_propose(1, vec![1, 2]));
        assert!(!st.record_propose(1, vec![1, 3])); // different content from same proposer
        assert_eq!(st.proposals[&1].dealers, vec![1, 2]);
    }

    #[test]
    fn banned_dealer_is_purged_from_proposals_and_completion() {
        let mut st = fresh(3, &[1, 2, 3]);
        st.record_propose(7, vec![1, 2, 3]);
        assert!(st.proposals[&7].validated);

        st.ban_dealer(2);

        // Banned dealer removed from completed set, validated marker dropped.
        assert!(!st.completed_dealers.contains(&2));
        assert!(!st.validated_proposers.contains(&7));
        assert_eq!(st.proposals[&7].dealers, vec![1, 3]);
    }

    #[test]
    fn full_acs_run_decides_deterministic_set() {
        // n = 4, f = 1, threshold = 3.
        let threshold = 3;
        let completed = vec![10, 11, 12, 13];
        let mut nodes: Vec<ACSInstanceState> = (0..4)
            .map(|i| {
                let mut st = ACSInstanceState::new(0, i);
                for d in completed.iter().copied() {
                    st.note_completed(d);
                }
                st
            })
            .collect();

        // Each node makes its proposal: identical content, full set.
        let proposals: Vec<(Replica, Vec<Replica>)> = (0..4)
            .map(|p| (p as Replica, completed.clone()))
            .collect();

        for st in nodes.iter_mut() {
            for (p, dealers) in proposals.iter() {
                st.record_propose(*p, dealers.clone());
            }
        }

        // W1 from each node: their validated set.
        let w1_payloads: Vec<(Replica, Vec<Replica>)> = (0..4)
            .map(|s| {
                let st = &nodes[s as usize];
                (s as Replica, st.validated_proposers.iter().copied().collect())
            })
            .collect();
        for st in nodes.iter_mut() {
            for (s, v) in w1_payloads.iter() {
                st.record_w1(*s, v.clone());
            }
            assert!(st.ready_to_send_w2(threshold));
        }

        // W2 from each node: their ratified W1 set.
        let w2_payloads: Vec<(Replica, Vec<Replica>)> = (0..4)
            .map(|s| {
                let st = &nodes[s as usize];
                (s as Replica, st.w1_ratified.iter().copied().collect())
            })
            .collect();
        for st in nodes.iter_mut() {
            for (s, v) in w2_payloads.iter() {
                st.record_w2(*s, v.clone());
            }
            assert!(st.ready_to_decide(threshold));
        }

        // All honest nodes finalise on the SAME deterministic dealer set.
        let mut decisions = Vec::new();
        for st in nodes.iter_mut() {
            let (_proposers, dealers) = st.finalize_decision().expect("decision");
            decisions.push(dealers);
        }
        assert!(decisions.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(decisions[0], vec![10, 11, 12, 13]);
    }

    #[test]
    fn finalize_skips_banned_dealers() {
        let threshold = 3;
        let completed = vec![10, 11, 12, 13];
        let mut st = ACSInstanceState::new(0, 0);
        for d in completed.iter().copied() {
            st.note_completed(d);
        }

        // 4 proposals
        for p in 0..4 {
            st.record_propose(p as Replica, completed.clone());
        }

        // Synthesise a complete W1 / W2 quorum.
        for s in 0..4 {
            st.record_w1(
                s as Replica,
                st.validated_proposers.iter().copied().collect(),
            );
        }
        let w1_set: Vec<Replica> = st.w1_ratified.iter().copied().collect();
        for s in 0..4 {
            st.record_w2(s as Replica, w1_set.clone());
        }

        // Ban dealer 11 BEFORE finalise.
        st.ban_dealer(11);
        // After the ban, validated_proposers were cleared; we must
        // re-run validation so honest proposals are picked up again.
        st.revalidate_pending();
        // Re-rate W1 and W2 so the previously cached witnesses (which
        // now reference proposers we have just re-validated) become
        // ratified.
        st.rerate_w1();
        st.rerate_w2();
        assert!(st.ready_to_decide(threshold));
        let (_proposers, dealers) = st.finalize_decision().expect("decision");
        assert!(!dealers.contains(&11));
        assert_eq!(dealers, vec![10, 12, 13]);
    }
}
