//! Mostefaoui-Moumen-Raynal (MMR 2014) signature-free Asynchronous
//! Binary Agreement (ABA) — single-instance state machine.
//!
//! This module is **pure logic**: no I/O, no hashing, no
//! cryptography. The driver in `acs::aba_driver` calls into this
//! state machine, takes its emitted side-effects (`AbaAction`s), and
//! actually broadcasts the resulting BVAL/AUX wire messages.
//!
//! Algorithm summary (MMR 2014, signature-free, with common coin):
//!
//! ```text
//! upon initialization with input v_in ∈ {0,1}:
//!     est := v_in
//!     r   := 0
//!     decided := None
//!
//! loop forever (round r ← r+1):
//!     broadcast BVAL(r, est)
//!
//!     upon receiving BVAL(r, b) from at least f+1 distinct nodes:
//!         if we never broadcast BVAL(r, b) yet:
//!             broadcast BVAL(r, b)        -- "amplify" rule
//!
//!     upon receiving BVAL(r, b) from at least 2f+1 distinct nodes:
//!         bin_values_r := bin_values_r ∪ {b}
//!         if AUX(r, *) not yet broadcast and bin_values_r non-empty:
//!             broadcast AUX(r, w) for some w ∈ bin_values_r
//!
//!     wait until ∃ values ⊆ bin_values_r with |values| ∈ {1,2} and
//!         #{j : received AUX(r, b_j) ∧ b_j ∈ values} ≥ n - f
//!
//!     s := common_coin(r) ∈ {0, 1}
//!     if values = {v}:
//!         est := v
//!         if v == s and decided == None:
//!             decided := Some(v)
//!     else (values = {0, 1}):
//!         est := s
//! ```
//!
//! Termination (Theorem 7, MMR 2014): a node decides within O(1)
//! expected rounds once the network is stable, given an unpredictable
//! common coin.
//!
//! Agreement (Theorem 6, MMR 2014): if any honest node decides v in
//! round r, every honest node decides v by round r+1 — the "decide-
//! and-keep-running" pattern below preserves Validity by sticking
//! `est` to the decided value forever after.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use types::Replica;

/// One-side-effect emitted by `step_*` calls. The driver translates
/// these into wire messages and calls back into the state machine
/// for self-delivery, exactly like the existing `broadcast(...);
/// process_*(self.myid, ...)` pattern in the AVSS code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbaAction {
    /// Broadcast `BVAL(round, value)` to every peer including self.
    SendBval { aba_round: u64, value: bool },
    /// Broadcast `AUX(round, value)` to every peer including self.
    SendAux { aba_round: u64, value: bool },
    /// Local notification: this instance has decided `value`. The
    /// driver records it; the instance keeps running because MMR
    /// agreement requires a decided node to keep amplifying for at
    /// most one further round so all other honest nodes also decide.
    Decided { value: bool },
}

/// Per-round bookkeeping inside one ABA instance. We keep distinct
/// sender sets per (round, value) so a Byzantine peer that flips its
/// vote inside a round contributes at most once per side, and so
/// senders that arrive out of order in time are still counted
/// correctly.
#[derive(Debug, Default, Clone)]
struct AbaRoundState {
    /// senders of BVAL(r, 0)
    bval_senders_0: HashSet<Replica>,
    /// senders of BVAL(r, 1)
    bval_senders_1: HashSet<Replica>,
    /// did we already broadcast BVAL(r, 0)?
    own_bval_sent_0: bool,
    /// did we already broadcast BVAL(r, 1)?
    own_bval_sent_1: bool,
    /// `bin_values_r` — values that have crossed the 2f+1 threshold.
    bin_values: BTreeSet<bool>,

    /// senders of AUX(r, 0)
    aux_senders_0: HashSet<Replica>,
    /// senders of AUX(r, 1)
    aux_senders_1: HashSet<Replica>,
    /// did we already broadcast our own AUX(r, *)?
    own_aux_sent: bool,
    /// the value we put in our own AUX, if any (to keep the protocol
    /// self-consistent after a peer-bval push grows bin_values).
    own_aux_value: Option<bool>,

    /// did the driver feed us coin(r) already?
    coin_received: bool,
    coin_value: Option<bool>,

    /// did we already advance out of this round?
    advanced: bool,
}

/// One ABA instance. `myid` and `n`/`f` are remembered for sender
/// counting; they are NOT used for any other purpose (no message
/// filtering by sender — the driver is responsible for de-duplicating
/// duplicate wire messages from the same sender).
#[derive(Debug, Clone)]
pub struct AbaInstance {
    /// The peer ID this state machine represents (used for the BVAL/
    /// AUX self-delivery pattern; we just remember it so the caller
    /// can label its own broadcasts when it self-delivers).
    pub myid: Replica,
    pub n: usize,
    pub f: usize,
    /// Has the local node fed the protocol an input value yet?
    pub input_set: bool,
    pub current_est: bool,
    /// 0-based "ABA round" index.
    pub current_round: u64,
    /// Per-round state, including past rounds (we keep them so a
    /// late-arriving message for a previous round still updates the
    /// counters even though it can no longer affect `est`).
    rounds: BTreeMap<u64, AbaRoundState>,
    /// Final decision (set at most once).
    pub decided_value: Option<bool>,
}

impl AbaInstance {
    pub fn new(myid: Replica, n: usize, f: usize) -> Self {
        Self {
            myid,
            n,
            f,
            input_set: false,
            current_est: false,
            current_round: 0,
            rounds: BTreeMap::new(),
            decided_value: None,
        }
    }

    fn round_state(&mut self, r: u64) -> &mut AbaRoundState {
        self.rounds.entry(r).or_default()
    }

    /// n - f, "honest quorum" threshold.
    fn n_minus_f(&self) -> usize {
        self.n - self.f
    }

    /// Set the local input bit. Idempotent on the first call;
    /// subsequent calls are ignored (the input is fixed once set).
    /// Returns the actions to broadcast (i.e. our first BVAL).
    pub fn set_input(&mut self, v: bool) -> Vec<AbaAction> {
        if self.input_set {
            return Vec::new();
        }
        self.input_set = true;
        self.current_est = v;
        self.current_round = 0;
        self.bval_self_emit(0, v)
    }

    /// Internal: record that we are emitting BVAL(r, v) and produce
    /// the corresponding `AbaAction::SendBval`. Idempotent.
    fn bval_self_emit(&mut self, r: u64, v: bool) -> Vec<AbaAction> {
        let already_sent = {
            let st = self.round_state(r);
            let already = if v { st.own_bval_sent_1 } else { st.own_bval_sent_0 };
            if !already {
                if v { st.own_bval_sent_1 = true; } else { st.own_bval_sent_0 = true; }
            }
            already
        };
        if already_sent {
            Vec::new()
        } else {
            vec![AbaAction::SendBval { aba_round: r, value: v }]
        }
    }

    /// Handle inbound `BVAL(round, value)` from `sender`. Returns the
    /// new actions the driver must perform. Self-delivery: when the
    /// driver itself broadcasts a BVAL, it MUST also call this with
    /// `sender == myid` so the local count includes itself.
    pub fn handle_bval(&mut self, r: u64, value: bool, sender: Replica) -> Vec<AbaAction> {
        let mut out = Vec::new();

        let (count, f) = {
            let st = self.round_state(r);
            let bucket = if value { &mut st.bval_senders_1 } else { &mut st.bval_senders_0 };
            bucket.insert(sender);
            let count = bucket.len();
            (count, self.f)
        };

        // Amplify rule: f+1 distinct senders ⇒ relay BVAL(r, value) if not already sent.
        if count >= f + 1 {
            out.extend(self.bval_self_emit(r, value));
        }

        // Threshold rule: 2f+1 distinct senders ⇒ promote into bin_values.
        let bin_grew = if count >= 2 * f + 1 {
            let st = self.round_state(r);
            st.bin_values.insert(value)
        } else {
            false
        };

        if bin_grew {
            // First entry of bin_values triggers our own AUX. If our
            // own AUX is already sent, MMR explicitly says we do NOT
            // re-emit AUX — the consequence is just that the AUX
            // counters can later admit a `values_r = {0,1}` decision
            // candidate, which is fine.
            let own_aux_to_send = {
                let st = self.round_state(r);
                if !st.own_aux_sent {
                    st.own_aux_sent = true;
                    st.own_aux_value = Some(value);
                    Some(value)
                } else {
                    None
                }
            };
            if let Some(v) = own_aux_to_send {
                out.push(AbaAction::SendAux { aba_round: r, value: v });
            }
            // bin_values changed: maybe AUX threshold + coin already
            // satisfy a decision candidate; try to advance.
            out.extend(self.maybe_advance_round(r));
        }

        out
    }

    /// Handle inbound `AUX(round, value)` from `sender`. Returns
    /// follow-up actions (typically empty, but may include a
    /// `Decided` once both the AUX threshold and the coin are in).
    pub fn handle_aux(&mut self, r: u64, value: bool, sender: Replica) -> Vec<AbaAction> {
        {
            let st = self.round_state(r);
            let bucket = if value { &mut st.aux_senders_1 } else { &mut st.aux_senders_0 };
            bucket.insert(sender);
        }
        self.maybe_advance_round(r)
    }

    /// Driver feeds us the common coin for round `r` (any-time;
    /// can arrive before or after the AUX threshold).
    pub fn handle_coin(&mut self, r: u64, coin: bool) -> Vec<AbaAction> {
        {
            let st = self.round_state(r);
            if !st.coin_received {
                st.coin_received = true;
                st.coin_value = Some(coin);
            }
        }
        self.maybe_advance_round(r)
    }

    /// Try to apply the round-advancement rule for round `r`. Idempotent.
    fn maybe_advance_round(&mut self, r: u64) -> Vec<AbaAction> {
        // Only advance the *current* round; messages for past rounds
        // still update counters but cannot retro-trigger another
        // advancement.
        if r != self.current_round {
            return Vec::new();
        }

        let nmf = self.n_minus_f();

        let (advance_with, coin) = {
            let st = self.rounds.get(&r).cloned().unwrap_or_default();

            if st.advanced {
                return Vec::new();
            }

            // Compute candidate `values` set. The MMR condition is
            // values ⊆ bin_values, |values| ∈ {1, 2}, AUX-count(values) ≥ n-f.
            // We try every non-empty subset of bin_values.
            let bin: Vec<bool> = st.bin_values.iter().copied().collect();
            if bin.is_empty() {
                return Vec::new();
            }

            let aux0 = st.aux_senders_0.len();
            let aux1 = st.aux_senders_1.len();

            let mut chosen: Option<(BTreeSet<bool>, usize)> = None;

            // Singletons.
            for &b in &bin {
                let count = if b { aux1 } else { aux0 };
                if count >= nmf {
                    let mut s = BTreeSet::new();
                    s.insert(b);
                    chosen = Some((s, count));
                    break; // any singleton is enough
                }
            }

            // Pair {0,1} — only if both ∈ bin_values.
            //
            // The MMR 2014 advancement rule requires the
            // candidate AUX count to be the number of DISTINCT
            // senders whose AUX(r, *) lies in `values`, not the
            // sum of per-bucket counts. A Byzantine peer that
            // equivocates and ships AUX(r, 0) AND AUX(r, 1) ends
            // up in both `aux_senders_0` and `aux_senders_1`; the
            // naive `aux0 + aux1` count double-counts that peer.
            //
            // For n = 4, f = 1: a single Byzantine equivocator
            // plus one honest AUX(r, 1) gives aux0 = {B}, aux1 =
            // {B, honest_a}, |aux0| + |aux1| = 3 = n-f, which the
            // buggy code accepts as a pair advancement -- but the
            // distinct-sender union is only {B, honest_a} (size 2
            // < n-f), so MMR Theorem 6 / 7's safety + termination
            // proof would not actually apply at that point.
            //
            // The singleton case above is already correct because
            // `aux_senders_b` is itself a HashSet<Replica>, so its
            // `.len()` is the distinct-sender count.
            if chosen.is_none() && bin.contains(&false) && bin.contains(&true) {
                let pair_distinct =
                    st.aux_senders_0.union(&st.aux_senders_1).count();
                if pair_distinct >= nmf {
                    let mut s = BTreeSet::new();
                    s.insert(false);
                    s.insert(true);
                    chosen = Some((s, pair_distinct));
                }
            }

            let chosen = match chosen {
                Some((s, _)) => s,
                None => return Vec::new(),
            };

            // Need the coin to actually advance.
            let coin = match st.coin_value {
                Some(c) => c,
                None => return Vec::new(),
            };

            (chosen, coin)
        };

        // Mark advanced.
        {
            let st = self.round_state(r);
            st.advanced = true;
        }

        let mut out = Vec::new();

        let new_est: bool;
        let mut decided_now: Option<bool> = None;

        if advance_with.len() == 1 {
            let v = *advance_with.iter().next().unwrap();
            new_est = v;
            if self.decided_value.is_none() && v == coin {
                self.decided_value = Some(v);
                decided_now = Some(v);
            }
        } else {
            // values = {0, 1}: estimate ← coin.
            new_est = coin;
        }

        // Once decided, est is locked to the decided value forever
        // after — this is the trick that makes "decide-and-continue"
        // safe (Lemma 5, MMR 2014).
        if let Some(d) = self.decided_value {
            self.current_est = d;
        } else {
            self.current_est = new_est;
        }

        if let Some(v) = decided_now {
            out.push(AbaAction::Decided { value: v });
        }

        // Move to round r+1 and broadcast our BVAL.
        self.current_round = r + 1;
        out.extend(self.bval_self_emit(self.current_round, self.current_est));

        // Self-deliver: the driver does this through `handle_bval(self_id, ...)`.
        // Don't double-emit here.
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n_f(n: usize) -> (usize, usize) {
        (n, (n - 1) / 3)
    }

    /// Drive a fully synchronous all-honest run to completion.
    fn run_to_decision(inputs: Vec<bool>, n: usize, coin_seq: Vec<bool>) -> Vec<bool> {
        let (n_, f_) = n_f(n);
        assert_eq!(inputs.len(), n_);

        let mut instances: Vec<AbaInstance> = (0..n_)
            .map(|i| AbaInstance::new(i as Replica, n_, f_))
            .collect();

        // Pending: list of (sender, action) yet to be delivered to all instances.
        let mut pending: Vec<(Replica, AbaAction)> = Vec::new();

        for i in 0..n_ {
            let acts = instances[i].set_input(inputs[i]);
            for a in acts {
                pending.push((i as Replica, a));
            }
        }

        // Deliver in lockstep. Cap at 50 outer iterations to detect
        // infinite-loop bugs; a correct n=4 run finishes in <10 rounds.
        let coin_fn = |r: u64| {
            *coin_seq
                .get(r as usize)
                .unwrap_or(coin_seq.last().expect("coin_seq non-empty"))
        };

        for _ in 0..1000 {
            if instances.iter().all(|i| i.decided_value.is_some()) {
                break;
            }
            let mut next_pending: Vec<(Replica, AbaAction)> = Vec::new();
            for (sender, action) in pending.drain(..) {
                match action {
                    AbaAction::SendBval { aba_round, value } => {
                        for (i, inst) in instances.iter_mut().enumerate() {
                            let acts = inst.handle_bval(aba_round, value, sender);
                            for a in acts {
                                next_pending.push((i as Replica, a));
                            }
                        }
                    }
                    AbaAction::SendAux { aba_round, value } => {
                        for (i, inst) in instances.iter_mut().enumerate() {
                            let acts = inst.handle_aux(aba_round, value, sender);
                            for a in acts {
                                next_pending.push((i as Replica, a));
                            }
                        }
                    }
                    AbaAction::Decided { .. } => {}
                }
            }
            // Coin pump: feed the coin for every round any instance
            // is currently waiting on.
            for (i, inst) in instances.iter_mut().enumerate() {
                let r = inst.current_round;
                if !inst.rounds.get(&r).map(|s| s.advanced).unwrap_or(false) {
                    let acts = inst.handle_coin(r, coin_fn(r));
                    for a in acts {
                        next_pending.push((i as Replica, a));
                    }
                }
            }
            pending = next_pending;
        }

        instances.iter().map(|i| i.decided_value.unwrap_or(false)).collect()
    }

    #[test]
    fn unanimous_input_decides_unanimously_in_round_zero() {
        // n=4, f=1. All inputs = 1 → every node decides 1 in round 0.
        let decisions = run_to_decision(vec![true, true, true, true], 4, vec![true, false, true]);
        assert!(decisions.iter().all(|&v| v));
    }

    #[test]
    fn unanimous_zero_input_decides_zero() {
        // Coin-0 happens to align: every node should still decide 0.
        let decisions = run_to_decision(vec![false, false, false, false], 4, vec![false, true, false]);
        assert!(decisions.iter().all(|&v| !v));
    }

    #[test]
    fn split_input_with_coin_drives_consensus() {
        // n=4, f=1. Inputs split 2-2. With a deterministic coin
        // sequence the protocol must terminate on a single value
        // identical for all honest nodes.
        let decisions = run_to_decision(vec![true, true, false, false], 4, vec![true, false, true, false]);
        let v0 = decisions[0];
        assert!(decisions.iter().all(|&v| v == v0), "agreement broken: {:?}", decisions);
    }

    #[test]
    fn validity_when_all_inputs_match_decided_value_equals_input() {
        // Validity (MMR Lemma 2 / Theorem 6): if every honest input
        // is v, every honest node decides v. The coin sequence does
        // not change the *decided value* (only the latency) — it can
        // flip 0/1, but the decided value is always the unanimous input.
        // Pick coin sequences that DO eventually align with the
        // unanimous input so termination happens in finite time.
        let decisions = run_to_decision(vec![true, true, true, true], 4, vec![false, true]);
        assert!(decisions.iter().all(|&v| v));
        let decisions = run_to_decision(vec![false, false, false, false], 4, vec![true, false]);
        assert!(decisions.iter().all(|&v| !v));
    }

    #[test]
    fn equivocating_bval_counted_only_once_per_sender_value_pair() {
        // A single sender that BVAL(0,0) and then BVAL(0,1) should
        // count for both buckets but only once each. The internal
        // sender set deduplicates.
        let mut inst = AbaInstance::new(0, 4, 1);
        inst.set_input(false);
        // sender 1 sends BVAL(0,0) twice → counter remains 1.
        let _ = inst.handle_bval(0, false, 1);
        let _ = inst.handle_bval(0, false, 1);
        let st = inst.rounds.get(&0).unwrap();
        assert_eq!(st.bval_senders_0.len(), 1);
        // sender 1 also sends BVAL(0,1) → that bucket also has 1.
        let _ = inst.handle_bval(0, true, 1);
        let st = inst.rounds.get(&0).unwrap();
        assert_eq!(st.bval_senders_1.len(), 1);
    }

    #[test]
    fn amplify_rule_relays_bval_after_f_plus_one_distinct_senders() {
        // n=4, f=1. Local input = 0; receive BVAL(0,1) from senders
        // 1, 2 (f+1 = 2). The instance must relay its own BVAL(0,1).
        let mut inst = AbaInstance::new(3, 4, 1);
        let _initial = inst.set_input(false);
        let mut got_relay = false;
        for sender in [1u32, 2u32].iter().copied() {
            let acts = inst.handle_bval(0, true, sender as Replica);
            for a in acts {
                if let AbaAction::SendBval { aba_round: 0, value: true } = a {
                    got_relay = true;
                }
            }
        }
        assert!(got_relay, "expected amplification BVAL(0,1) after 2 distinct senders");
    }

    #[test]
    fn aux_emitted_only_after_2f_plus_one_bval_threshold() {
        // n=4, f=1. AUX(0, v) must NOT be emitted until BVAL(0, v)
        // has 2f+1 = 3 distinct senders. The state machine treats
        // self-broadcast as an explicit self-delivery via handle_bval,
        // matching the driver pattern; so we count senders 0..=2 here.
        let mut inst = AbaInstance::new(3, 4, 1);
        let _ = inst.set_input(true);
        // Self-deliver our own BVAL(0, 1):
        let _ = inst.handle_bval(0, true, 3);
        // sender 1 → 2 distinct.
        let acts = inst.handle_bval(0, true, 1);
        for a in &acts {
            if matches!(a, AbaAction::SendAux { .. }) {
                panic!("AUX emitted too early at 2 senders: {:?}", acts);
            }
        }
        // sender 2 → 3 distinct == 2f+1, AUX MUST emit.
        let acts = inst.handle_bval(0, true, 2);
        let any_aux = acts.iter().any(|a| matches!(a, AbaAction::SendAux { .. }));
        assert!(any_aux, "AUX should fire at the 2f+1 threshold, got {:?}", acts);
    }

    #[test]
    fn pair_case_uses_distinct_sender_union_under_aux_equivocation() {
        // Regression: the pair-case AUX threshold MUST count
        // distinct senders, not the sum |aux_0| + |aux_1|.
        //
        // A Byzantine peer that equivocates and ships both AUX(r, 0)
        // and AUX(r, 1) ends up in both `aux_senders_0` and
        // `aux_senders_1`. The pre-fix code summed the bucket sizes,
        // so that single Byzantine peer was double-counted. MMR
        // Theorem 6/7's safety + termination proof requires a count
        // of DISTINCT senders -- the same way the singleton rule
        // already counted (via `HashSet::len`).
        //
        // We construct a scenario where:
        //   * `bin_values = {0, 1}`,
        //   * `aux_senders_0 = {peer 0, peer 1}`,
        //   * `aux_senders_1 = {peer 0}`,
        //   * neither singleton crosses n-f.
        //
        // Then |aux_0| + |aux_1| = 2 + 1 = 3 = n-f and pre-fix
        // would have prematurely advanced via the pair case, but
        // the distinct-sender union is {peer 0, peer 1} = 2 < n-f
        // and post-fix MUST NOT advance.
        //
        // After feeding the coin we assert that the instance is
        // still in round 0 and undecided.
        let mut inst = AbaInstance::new(3, 4, 1);
        let _ = inst.set_input(false);

        // Push BVAL(0, 1) to 2f+1 = 3 distinct senders -> bin gains 1.
        let _ = inst.handle_bval(0, true, 0);
        let _ = inst.handle_bval(0, true, 1);
        let _ = inst.handle_bval(0, true, 2);
        // Self-deliver our own BVAL(0, 0).
        let _ = inst.handle_bval(0, false, 3);
        // Push BVAL(0, 0) to 2f+1 distinct senders -> bin gains 0.
        let _ = inst.handle_bval(0, false, 0);
        let _ = inst.handle_bval(0, false, 1);
        let st = inst.rounds.get(&0).unwrap();
        assert!(
            st.bin_values.contains(&false) && st.bin_values.contains(&true),
            "bin_values must be {{0, 1}} to even reach the pair-case rule"
        );

        // Feed AUXes from EXACTLY 2 distinct senders, with one of
        // them equivocating. Crucially we do NOT self-deliver any
        // local AUX that the state machine emitted as a side effect
        // of BVAL -> bin_values transitions: those are returned as
        // `AbaAction::SendAux` actions but never inserted into
        // `aux_senders_*` unless the driver explicitly calls
        // handle_aux(myid, ...). That matches the wire model and
        // lets us control aux_senders_* deterministically.
        let _ = inst.handle_aux(0, false, 0); // Byzantine peer 0 -> aux_0
        let _ = inst.handle_aux(0, true, 0);  // Byzantine peer 0 -> aux_1 (equivocation)
        let _ = inst.handle_aux(0, false, 1); // honest peer 1 -> aux_0

        let st = inst.rounds.get(&0).unwrap();
        assert_eq!(st.aux_senders_0.len(), 2, "aux_senders_0 = {{0, 1}}");
        assert_eq!(st.aux_senders_1.len(), 1, "aux_senders_1 = {{0}}");
        // sum = 3 (would pass pre-fix); distinct union = 2 (must
        // not pass post-fix).
        assert_eq!(
            st.aux_senders_0.union(&st.aux_senders_1).count(),
            2,
            "distinct AUX-sender union counted across both buckets must be 2"
        );

        // Feed the coin and assert the instance did NOT advance.
        let _ = inst.handle_coin(0, true);
        let st = inst.rounds.get(&0).unwrap();
        assert!(
            !st.advanced,
            "post-fix: pair-case MUST NOT advance round when only 2 distinct \
             AUX senders contributed (pre-fix sum = 3 would have erroneously advanced)"
        );
        assert_eq!(
            inst.current_round, 0,
            "instance must still be in round 0 after pair-case rejection"
        );
        assert!(
            inst.decided_value.is_none(),
            "instance must not have decided in round 0 from Byzantine-only equivocation"
        );
    }

    #[test]
    fn coin_influences_decision_when_aux_is_singleton() {
        // n=4, f=1. After everyone unanimously AUXes 1 in round 0,
        // values = {1}; if coin(0) == 1, decide 1; if coin(0) == 0,
        // est := 1 but no decision yet — keep going.
        // We reuse the simulator: with all-1 inputs and coin = 1
        // everyone decides in round 0. With all-1 inputs and coin = 0,
        // they still decide on round 1 with coin = 1.
        let dec = run_to_decision(vec![true, true, true, true], 4, vec![false, true]);
        assert!(dec.iter().all(|&v| v));
    }
}
