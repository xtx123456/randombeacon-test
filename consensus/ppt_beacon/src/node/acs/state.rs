//! Per-round state container for the new PPT ACS pipeline:
//! Bracha RBC + n parallel Mostefaoui-Moumen-Raynal ABAs + self-
//! bootstrap common coin.
//!
//! This module holds **only** the state struct and trivial helpers.
//! All protocol logic (RBC inputs, ABA inputs, coin pumping, decision
//! finalisation) lives in `acs::protocol`, which owns a `Context` and
//! actually broadcasts / dispatches messages.

use std::collections::{HashMap, HashSet};

use crypto::hash::Hash;
use types::Replica;

use super::aba_driver::AcsRoundState as AbaRoundDriver;
use super::rbc::RbcInstanceState;

/// One ACS round's state: n RBC instances (one per proposer) plus
/// the n-parallel ABA driver, plus the deferred-input book that
/// implements PPT's "wait for AVSS totality before feeding ABA(j)
/// input=1" rule.
pub struct AcsRound {
    pub round: types::Round,
    pub myid: Replica,
    pub n: usize,
    pub f: usize,

    /// One Bracha RBC instance per proposer index `j ∈ [0, n)`.
    pub rbc: Vec<RbcInstanceState>,
    /// Once we have ≥ n-f locally AVSS-completed dealers, the ACS
    /// driver flips this to true and broadcasts our own RBC SEND.
    pub rbc_self_send_done: bool,

    /// `proposer_id -> delivered RBC payload bytes`. Populated when
    /// the corresponding RBC instance reaches the `Delivered` state.
    /// The bytes are the proposer's claimed AVSS-completed-dealer
    /// set; we keep them so the post-ACS audit and any future
    /// debugging can recover what the proposer said. The current
    /// ACS does NOT use the contents to compute its dealer-set
    /// output (the output is `{j : ABA(j) decided 1}`), but the
    /// payload bytes remain on hand for future protocol extensions.
    pub rbc_delivered_payload: HashMap<usize, Vec<u8>>,

    /// Pending ABA-input-1 candidates: proposer j had its RBC
    /// delivered, but at the moment of delivery the local view did
    /// not yet contain dealer j as AVSS-completed. We re-evaluate
    /// these on every AVSS-completion change.
    ///
    /// Pattern parallels `pending_avss_for_theta` in `Context`.
    pub deferred_inputs: HashSet<usize>,

    /// The n parallel MMR ABA driver. Holds per-instance state and
    /// the all-decided latch.
    pub aba: AbaRoundDriver,

    /// Has each ABA instance had its input fed in yet?
    /// `aba_input_fed[j] == true` ⇔ we have called `aba.set_input(j, _)`
    /// (with either a 1 or a 0).
    pub aba_input_fed: Vec<bool>,

    /// Coin-feeding bookkeeping: `(aba_instance_id, aba_round) ∈
    /// coin_fed_for` ⇔ we have already called `aba.handle_coin(j, r,
    /// _)` for that pair. Keeps the coin pump idempotent on multi-
    /// trigger paths.
    pub coin_fed_for: HashSet<(usize, u64)>,

    /// Set once we have triggered the "force input 0 on undecided
    /// instances" rule (after observing ≥ n-f decisions of 1).
    pub forced_zero_round_started: bool,

    /// Set once we have called `Context::finalize_acs_round` for
    /// this round. Idempotent latch.
    pub finalized: bool,

    /// Banned dealers seen so far. Not propagated by ACS itself —
    /// the global `Context::banned_dealers` is the source of truth;
    /// we keep this only as a per-round snapshot for diagnostics.
    pub banned_snapshot: HashSet<Replica>,
}

impl AcsRound {
    pub fn new(round: types::Round, myid: Replica, n: usize, f: usize) -> Self {
        let rbc: Vec<RbcInstanceState> = (0..n)
            .map(|j| RbcInstanceState::new(myid, j as Replica, n, f))
            .collect();
        Self {
            round,
            myid,
            n,
            f,
            rbc,
            rbc_self_send_done: false,
            rbc_delivered_payload: HashMap::new(),
            deferred_inputs: HashSet::new(),
            aba: AbaRoundDriver::new(myid, n, f),
            aba_input_fed: vec![false; n],
            coin_fed_for: HashSet::new(),
            forced_zero_round_started: false,
            finalized: false,
            banned_snapshot: HashSet::new(),
        }
    }

    /// External-validity / banning hook: drop any pending input
    /// candidate for `dealer` and never feed it again. Idempotent.
    pub fn ban_dealer(&mut self, dealer: Replica) {
        self.banned_snapshot.insert(dealer);
        let dealer_idx = dealer as usize;
        if dealer_idx < self.n {
            self.deferred_inputs.remove(&dealer_idx);
        }
    }

    /// Compute final ACS dealer set: `{ j : ABA(j) decided 1 }`,
    /// filtered against the global banned-dealer list (passed in by
    /// the caller, since `AcsRound` doesn't directly own
    /// `Context::banned_dealers`). Returns `None` until every
    /// instance has decided.
    pub fn compute_decided_dealers(
        &self,
        banned: &HashSet<Replica>,
    ) -> Option<Vec<Replica>> {
        let bset = self.aba.maybe_compute_acs_output()?;
        let mut out: Vec<Replica> = bset
            .into_iter()
            .map(|j| j as Replica)
            .filter(|d| !banned.contains(d))
            .collect();
        out.sort_unstable();
        Some(out)
    }

    /// Convenience: return the cached payload-hash of the proposer's
    /// delivered RBC (used by tests / future audit).
    pub fn rbc_delivered_hash(&self, j: usize) -> Option<Hash> {
        self.rbc_delivered_payload
            .get(&j)
            .map(|p| crypto::hash::do_hash(p.as_slice()))
    }
}
