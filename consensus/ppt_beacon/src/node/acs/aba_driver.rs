//! Driver for the n parallel MMR ABA instances inside one ACS round.
//!
//! Per ACS round (one PPT beacon round), the ACS protocol has n
//! parallel ABA instances, indexed by `aba_instance_id ∈ [0, n)`.
//! The instance with index `j` decides:
//!
//!   - `1`  iff the local node believes peer `j` has a valid
//!           proposal (RBC delivered + external validity passed),
//!   - `0`  otherwise.
//!
//! ACS output is `{ j : aba(j) decided 1 }`. Validity of the n-f
//! lower bound on the output size follows from MMR ABA's standard
//! property that at least n-f honest nodes ride into the protocol
//! with input 1 for at least n-f instances.
//!
//! This module exposes:
//!
//!   - `AcsRoundState` — a self-contained per-round struct holding
//!     all n ABA instances, the dispatcher tables (by aba_instance_id
//!     and aba_round), and the deferred-input book.
//!   - `AbaDriverAction` — the side-effects the state struct emits
//!     to the network layer: BVAL/AUX broadcasts and the eventual
//!     ACS-decision callback.
//!
//! The ACS-protocol layer (`acs/protocol.rs`) is the piece that
//! actually owns a `Context` and turns `AbaDriverAction`s into
//! `CoinMsg::ACSAba*` broadcasts on the network.

use std::collections::{BTreeSet, HashMap};

use types::Replica;

use super::aba::{AbaAction, AbaInstance};

/// Side-effects emitted by `AcsRoundState` operations. The driver in
/// `acs/protocol.rs` translates these into wire broadcasts and
/// applies follow-up calls back into the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbaDriverAction {
    /// Broadcast `ACSAbaBval(round, aba_instance_id, aba_round, value)`
    /// and self-deliver it.
    Bval { aba_instance_id: usize, aba_round: u64, value: bool },
    /// Broadcast `ACSAbaAux(round, aba_instance_id, aba_round, value)`
    /// and self-deliver it.
    Aux { aba_instance_id: usize, aba_round: u64, value: bool },
    /// Local notification: ABA instance `aba_instance_id` decided
    /// `value`. The driver records the result; once every instance
    /// has decided, ACS produces its dealer-set output.
    Decided { aba_instance_id: usize, value: bool },
}

/// State of one ACS round's n parallel ABA instances. This struct
/// is `Send`-friendly — the ABA logic is pure and does no I/O — so
/// the driver can keep it inside `Context::acs_round_state` without
/// extra synchronisation.
#[derive(Debug)]
pub struct AcsRoundState {
    pub myid: Replica,
    pub n: usize,
    pub f: usize,

    /// One ABA instance per peer index `j ∈ [0, n)`.
    instances: Vec<AbaInstance>,

    /// Has instance `j` had its input fed in yet? Inputs come from
    /// the RBC layer (or, in the bootstrap commit before RBC is
    /// wired up, directly from `ACSPropose` deliveries). Each
    /// instance receives an input exactly once.
    input_set: Vec<bool>,

    /// Which ABA instances have decided, and to what value.
    decisions: HashMap<usize, bool>,

    /// True once every instance has decided. Latches; never reset.
    pub all_decided: bool,

    /// True once we have picked the final output. Latches.
    pub output_emitted: bool,
}

impl AcsRoundState {
    pub fn new(myid: Replica, n: usize, f: usize) -> Self {
        Self {
            myid,
            n,
            f,
            instances: (0..n).map(|_| AbaInstance::new(myid, n, f)).collect(),
            input_set: vec![false; n],
            decisions: HashMap::new(),
            all_decided: false,
            output_emitted: false,
        }
    }

    /// Threshold "n-f" for the ABA-1 fast-path: once we see at least
    /// n-f decisions of `1`, every remaining undecided instance can
    /// safely be input as `0` (they would otherwise stall waiting
    /// for an input that never comes from a Byzantine peer).
    pub fn n_minus_f(&self) -> usize {
        self.n - self.f
    }

    /// Number of decisions of value `1` we have seen so far.
    pub fn count_decisions_one(&self) -> usize {
        self.decisions.values().filter(|v| **v).count()
    }

    /// Has instance `j` decided yet?
    pub fn has_decided(&self, j: usize) -> bool {
        self.decisions.contains_key(&j)
    }

    pub fn decision_for(&self, j: usize) -> Option<bool> {
        self.decisions.get(&j).copied()
    }

    /// All n decisions in canonical order, missing slots reported as
    /// `None`. Used by the ACS protocol layer to compute the final
    /// dealer-set output.
    pub fn all_decisions(&self) -> Vec<Option<bool>> {
        (0..self.n).map(|j| self.decisions.get(&j).copied()).collect()
    }

    /// Set the input bit for ABA instance `j`. Returns the
    /// initial-broadcast actions (typically a single
    /// `Bval { aba_round: 0, value }`). Idempotent: a second call
    /// for the same `j` is dropped on the floor.
    pub fn set_input(&mut self, j: usize, value: bool) -> Vec<AbaDriverAction> {
        if j >= self.n {
            return Vec::new();
        }
        if self.input_set[j] {
            return Vec::new();
        }
        self.input_set[j] = true;
        let acts = self.instances[j].set_input(value);
        Self::translate_actions(j, acts)
    }

    /// Has the input been fed to instance `j`?
    pub fn input_was_set(&self, j: usize) -> bool {
        self.input_set.get(j).copied().unwrap_or(false)
    }

    /// Inbound `ACSAbaBval(_, j, r, v)` from `sender` (which may be
    /// the local node itself for self-delivery). Returns follow-up
    /// actions to broadcast.
    pub fn handle_bval(
        &mut self,
        j: usize,
        r: u64,
        value: bool,
        sender: Replica,
    ) -> Vec<AbaDriverAction> {
        if j >= self.n {
            return Vec::new();
        }
        let acts = self.instances[j].handle_bval(r, value, sender);
        let mut out = Self::translate_actions(j, acts);
        out.extend(self.process_decisions_in(j));
        out
    }

    /// Inbound `ACSAbaAux(_, j, r, v)` from `sender`.
    pub fn handle_aux(
        &mut self,
        j: usize,
        r: u64,
        value: bool,
        sender: Replica,
    ) -> Vec<AbaDriverAction> {
        if j >= self.n {
            return Vec::new();
        }
        let acts = self.instances[j].handle_aux(r, value, sender);
        let mut out = Self::translate_actions(j, acts);
        out.extend(self.process_decisions_in(j));
        out
    }

    /// Driver feeds coin(j, r) into instance `j` for ABA round `r`.
    /// Idempotent.
    pub fn handle_coin(&mut self, j: usize, r: u64, coin: bool) -> Vec<AbaDriverAction> {
        if j >= self.n {
            return Vec::new();
        }
        let acts = self.instances[j].handle_coin(r, coin);
        let mut out = Self::translate_actions(j, acts);
        out.extend(self.process_decisions_in(j));
        out
    }

    /// What ABA round is instance `j` currently waiting for the
    /// coin on? The driver uses this to decide which coin bit to
    /// derive next.
    pub fn current_aba_round(&self, j: usize) -> Option<u64> {
        if j >= self.n { return None; }
        Some(self.instances[j].current_round)
    }

    /// Translate the pure-logic `AbaAction`s into driver actions
    /// labelled with the ABA instance id.
    fn translate_actions(j: usize, acts: Vec<AbaAction>) -> Vec<AbaDriverAction> {
        let mut out = Vec::with_capacity(acts.len());
        for a in acts {
            match a {
                AbaAction::SendBval { aba_round, value } => {
                    out.push(AbaDriverAction::Bval { aba_instance_id: j, aba_round, value });
                }
                AbaAction::SendAux { aba_round, value } => {
                    out.push(AbaDriverAction::Aux { aba_instance_id: j, aba_round, value });
                }
                AbaAction::Decided { value } => {
                    out.push(AbaDriverAction::Decided { aba_instance_id: j, value });
                }
            }
        }
        out
    }

    /// Process any newly observed decision in instance `j`. Updates
    /// the local decision book and the `all_decided` latch. Returns
    /// no extra follow-up actions itself — the `Decided` AbaAction
    /// has already been translated and queued by `translate_actions`.
    fn process_decisions_in(&mut self, j: usize) -> Vec<AbaDriverAction> {
        if let Some(v) = self.instances[j].decided_value {
            self.decisions.entry(j).or_insert(v);
        }
        if self.decisions.len() == self.n {
            self.all_decided = true;
        }
        Vec::new()
    }

    /// Compute `{ j : decided 1 }` if the instance is fully decided,
    /// else `None`. Driver calls this after receiving an
    /// `AbaDriverAction::Decided` to see if the round has finished.
    pub fn maybe_compute_acs_output(&self) -> Option<BTreeSet<usize>> {
        if !self.all_decided {
            return None;
        }
        let mut out = BTreeSet::new();
        for (j, v) in self.decisions.iter() {
            if *v {
                out.insert(*j);
            }
        }
        Some(out)
    }

    /// Mark the round's output as emitted (so the driver's
    /// idempotency latch can avoid double-emit).
    pub fn mark_output_emitted(&mut self) {
        self.output_emitted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `n` parallel ABA instances with synchronous, reliable,
    /// in-order broadcast. Useful as a baseline correctness check
    /// on the driver's translation layer.
    fn run_parallel(
        inputs: Vec<Vec<bool>>, // inputs[node][instance]
        n: usize,
        coin_seq: Vec<bool>,
    ) -> Vec<Vec<bool>> {
        let f = (n - 1) / 3;
        assert_eq!(inputs.len(), n);
        for v in &inputs {
            assert_eq!(v.len(), n);
        }

        let mut nodes: Vec<AcsRoundState> = (0..n)
            .map(|i| AcsRoundState::new(i as Replica, n, f))
            .collect();

        // Pending: (sender_node_id, AbaDriverAction).
        let mut pending: Vec<(Replica, AbaDriverAction)> = Vec::new();

        for (i, inputs_i) in inputs.iter().enumerate() {
            for (j, &v) in inputs_i.iter().enumerate() {
                let acts = nodes[i].set_input(j, v);
                for a in acts {
                    pending.push((i as Replica, a));
                }
            }
        }

        let coin_fn = |r: u64| {
            *coin_seq
                .get(r as usize)
                .unwrap_or(coin_seq.last().expect("non-empty"))
        };

        for _ in 0..2000 {
            if nodes.iter().all(|n| n.all_decided) {
                break;
            }
            let mut next: Vec<(Replica, AbaDriverAction)> = Vec::new();
            for (sender, action) in pending.drain(..) {
                match action {
                    AbaDriverAction::Bval { aba_instance_id, aba_round, value } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_bval(aba_instance_id, aba_round, value, sender);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    AbaDriverAction::Aux { aba_instance_id, aba_round, value } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_aux(aba_instance_id, aba_round, value, sender);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    AbaDriverAction::Decided { .. } => {}
                }
            }
            // Coin pump for every (j, current_round) pair.
            for (i, node) in nodes.iter_mut().enumerate() {
                for j in 0..n {
                    if node.has_decided(j) {
                        continue;
                    }
                    let r = node.current_aba_round(j).unwrap_or(0);
                    let acts = node.handle_coin(j, r, coin_fn(r));
                    for a in acts {
                        next.push((i as Replica, a));
                    }
                }
            }
            pending = next;
        }

        nodes
            .iter()
            .map(|n| {
                (0..n.n)
                    .map(|j| n.decision_for(j).unwrap_or(false))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn parallel_aba_decides_one_for_unanimous_one_inputs() {
        // n = 4, f = 1. Every node feeds 1 to every instance →
        // every instance must decide 1 at every node.
        let inputs = vec![
            vec![true, true, true, true],
            vec![true, true, true, true],
            vec![true, true, true, true],
            vec![true, true, true, true],
        ];
        let decisions = run_parallel(inputs, 4, vec![true, false]);
        for d in &decisions {
            assert_eq!(d, &vec![true, true, true, true], "every instance must decide 1");
        }
    }

    #[test]
    fn parallel_aba_agrees_across_nodes_on_split_inputs() {
        // n = 4, f = 1. Inputs split for some instances. After
        // termination every node must agree on the per-instance
        // decision, and at least n-f instances must have decided 1
        // (Validity of ACS).
        let inputs = vec![
            vec![true, true, false, true],
            vec![true, true, true, true],
            vec![true, false, true, true],
            vec![true, true, true, false],
        ];
        let decisions = run_parallel(inputs, 4, vec![true, false, true, false]);
        // Agreement: all nodes must produce the same decision vector.
        let first = decisions[0].clone();
        for d in &decisions {
            assert_eq!(d, &first, "honest nodes must agree");
        }
        // Validity: at least n-f = 3 instances decided 1.
        let ones = first.iter().filter(|&&v| v).count();
        assert!(ones >= 3, "at least n-f instances must decide 1, got {}", ones);
    }
}
