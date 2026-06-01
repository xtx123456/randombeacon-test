//! End-to-end simulation tests of the ACS pipeline (Bracha RBC +
//! n parallel MMR ABA + self-bootstrap coin) at the **state-
//! machine** level, with no I/O.
//!
//! These tests exercise the same protocol-level message flow as
//! the live `Context::process_acs_*` handlers but run all n
//! replicas inside a single test process with synchronous reliable
//! delivery. They validate the two highest-level safety properties
//! the protocol must guarantee:
//!
//!   1. **Agreement on the ACS output set**: every honest replica
//!      decides exactly the same `{ j : ABA(j) = 1 }` index set.
//!   2. **Validity / size lower bound**: the agreed set has size
//!      ≥ n - f when every replica feeds input=1 to every ABA
//!      instance (the unanimous-AVSS-completion case).

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crypto::hash::Hash;
    use types::Replica;

    use super::super::aba_driver::AbaDriverAction;
    use super::super::coin::coin_bit_from_seed;
    use super::super::rbc::RbcAction;
    use super::super::state::AcsRound;

    /// One simulation step's "side effect" produced by some replica
    /// `i`. The simulator delivers each effect to every replica in
    /// the round-robin loop.
    #[derive(Debug, Clone)]
    enum Wire {
        RbcSend { proposer: Replica, payload: Vec<u8> },
        RbcEcho { proposer: Replica, payload_hash: Hash },
        RbcReady { proposer: Replica, payload_hash: Hash },
        AbaBval { aba_id: usize, aba_round: u64, value: bool },
        AbaAux { aba_id: usize, aba_round: u64, value: bool },
    }

    /// Per-replica state for the simulator: mirrors what `Context`
    /// holds for one round, minus the network plumbing.
    struct Replica_ {
        myid: Replica,
        n: usize,
        f: usize,
        local_completed: HashSet<Replica>,
        banned: HashSet<Replica>,
        acs: AcsRound,
        coin_seed: Vec<u8>,
    }

    impl Replica_ {
        fn new(
            myid: Replica,
            n: usize,
            f: usize,
            local_completed: HashSet<Replica>,
            coin_seed: Vec<u8>,
        ) -> Self {
            Self {
                myid,
                n,
                f,
                local_completed,
                banned: HashSet::new(),
                acs: AcsRound::new(0, myid, n, f),
                coin_seed,
            }
        }

        fn build_proposal_bytes(&self) -> Vec<u8> {
            let mut local: Vec<Replica> = self.local_completed.iter().copied().collect();
            local.sort_unstable();
            let mut buf = Vec::with_capacity(4 + 4 * local.len());
            buf.extend_from_slice(&(local.len() as u32).to_be_bytes());
            for d in local {
                buf.extend_from_slice(&d.to_be_bytes());
            }
            buf
        }

        /// Kick off our own RBC.
        fn start_self_rbc(&mut self) -> Vec<(Replica, Wire)> {
            let payload = self.build_proposal_bytes();
            let acts = self.acs.rbc[self.myid as usize].proposer_send(payload);
            self.translate_rbc(self.myid as Replica, acts)
        }

        fn translate_rbc(
            &self,
            proposer: Replica,
            acts: Vec<RbcAction>,
        ) -> Vec<(Replica, Wire)> {
            acts.into_iter()
                .filter_map(|a| match a {
                    RbcAction::SendSend { payload } => {
                        Some((self.myid, Wire::RbcSend { proposer, payload }))
                    }
                    RbcAction::SendEcho { payload_hash } => {
                        Some((self.myid, Wire::RbcEcho { proposer, payload_hash }))
                    }
                    RbcAction::SendReady { payload_hash } => {
                        Some((self.myid, Wire::RbcReady { proposer, payload_hash }))
                    }
                    RbcAction::Delivered { .. } => None,
                })
                .collect()
        }

        fn translate_aba(&self, acts: Vec<AbaDriverAction>) -> Vec<(Replica, Wire)> {
            acts.into_iter()
                .filter_map(|a| match a {
                    AbaDriverAction::Bval { aba_instance_id, aba_round, value } => {
                        Some((self.myid, Wire::AbaBval { aba_id: aba_instance_id, aba_round, value }))
                    }
                    AbaDriverAction::Aux { aba_instance_id, aba_round, value } => {
                        Some((self.myid, Wire::AbaAux { aba_id: aba_instance_id, aba_round, value }))
                    }
                    AbaDriverAction::Decided { .. } => None,
                })
                .collect()
        }

        /// On RBC delivery → maybe feed ABA input.
        fn on_rbc_delivered(&mut self, proposer: Replica) -> Vec<(Replica, Wire)> {
            let j = proposer as usize;
            if self.acs.aba_input_fed[j] {
                return Vec::new();
            }
            let bit = if self.banned.contains(&proposer) {
                Some(false)
            } else if self.local_completed.contains(&proposer) {
                Some(true)
            } else {
                None
            };
            match bit {
                Some(b) => {
                    self.acs.aba_input_fed[j] = true;
                    let acts = self.acs.aba.set_input(j, b);
                    self.translate_aba(acts)
                }
                None => {
                    self.acs.deferred_inputs.insert(j);
                    Vec::new()
                }
            }
        }

        /// Run RBC.handle_send and consume the actions, returning
        /// any newly-emitted Wire effects (and triggering ABA-input
        /// if delivery resulted).
        fn handle_rbc_send(&mut self, proposer: Replica, payload: Vec<u8>) -> Vec<(Replica, Wire)> {
            let p = proposer as usize;
            if p >= self.n { return Vec::new(); }
            let acts = self.acs.rbc[p].handle_send(proposer, payload.clone());
            let mut out = Vec::new();
            let mut delivered_now = false;
            for a in &acts {
                if matches!(a, RbcAction::Delivered { .. }) {
                    delivered_now = true;
                }
            }
            out.extend(self.translate_rbc(proposer, acts));
            if delivered_now {
                self.acs.rbc_delivered_payload.insert(p, payload);
                out.extend(self.on_rbc_delivered(proposer));
            }
            out
        }

        fn handle_rbc_echo(
            &mut self,
            proposer: Replica,
            sender: Replica,
            payload_hash: Hash,
        ) -> Vec<(Replica, Wire)> {
            let p = proposer as usize;
            if p >= self.n { return Vec::new(); }
            let acts = self.acs.rbc[p].handle_echo(sender, payload_hash);
            let mut out = Vec::new();
            let mut delivered_now = false;
            let mut delivered_payload: Option<Vec<u8>> = None;
            for a in &acts {
                if let RbcAction::Delivered { payload } = a {
                    delivered_now = true;
                    delivered_payload = Some(payload.clone());
                }
            }
            out.extend(self.translate_rbc(proposer, acts));
            if delivered_now {
                self.acs.rbc_delivered_payload.insert(p, delivered_payload.unwrap_or_default());
                out.extend(self.on_rbc_delivered(proposer));
            }
            out
        }

        fn handle_rbc_ready(
            &mut self,
            proposer: Replica,
            sender: Replica,
            payload_hash: Hash,
        ) -> Vec<(Replica, Wire)> {
            let p = proposer as usize;
            if p >= self.n { return Vec::new(); }
            let acts = self.acs.rbc[p].handle_ready(sender, payload_hash);
            let mut out = Vec::new();
            let mut delivered_now = false;
            let mut delivered_payload: Option<Vec<u8>> = None;
            for a in &acts {
                if let RbcAction::Delivered { payload } = a {
                    delivered_now = true;
                    delivered_payload = Some(payload.clone());
                }
            }
            out.extend(self.translate_rbc(proposer, acts));
            if delivered_now {
                self.acs.rbc_delivered_payload.insert(p, delivered_payload.unwrap_or_default());
                out.extend(self.on_rbc_delivered(proposer));
            }
            out
        }

        fn handle_aba_bval(
            &mut self,
            aba_id: usize,
            aba_round: u64,
            value: bool,
            sender: Replica,
        ) -> Vec<(Replica, Wire)> {
            let acts = self.acs.aba.handle_bval(aba_id, aba_round, value, sender);
            self.translate_aba(acts)
        }

        fn handle_aba_aux(
            &mut self,
            aba_id: usize,
            aba_round: u64,
            value: bool,
            sender: Replica,
        ) -> Vec<(Replica, Wire)> {
            let acts = self.acs.aba.handle_aux(aba_id, aba_round, value, sender);
            self.translate_aba(acts)
        }

        fn pump_coins(&mut self) -> Vec<(Replica, Wire)> {
            let mut out = Vec::new();
            for j in 0..self.n {
                if !self.acs.aba_input_fed[j] {
                    continue;
                }
                let curr = self.acs.aba.current_aba_round(j).unwrap_or(0);
                for r in 0..=curr {
                    if self.acs.coin_fed_for.contains(&(j, r)) {
                        continue;
                    }
                    let bit = coin_bit_from_seed(&self.coin_seed, j, r);
                    self.acs.coin_fed_for.insert((j, r));
                    let acts = self.acs.aba.handle_coin(j, r, bit);
                    out.extend(self.translate_aba(acts));
                }
            }
            out
        }

        fn force_zero_if_ready(&mut self) -> Vec<(Replica, Wire)> {
            let threshold = self.n - self.f;
            if self.acs.forced_zero_round_started {
                return Vec::new();
            }
            let ones = self.acs.aba.count_decisions_one();
            if ones < threshold {
                return Vec::new();
            }
            self.acs.forced_zero_round_started = true;
            let mut out = Vec::new();
            for j in 0..self.n {
                if !self.acs.aba_input_fed[j] {
                    self.acs.aba_input_fed[j] = true;
                    let acts = self.acs.aba.set_input(j, false);
                    out.extend(self.translate_aba(acts));
                }
            }
            out
        }
    }

    /// Run the full ACS pipeline across `n` honest replicas to
    /// completion, with reliable in-order delivery. Returns each
    /// replica's `{ j : ABA(j) = 1 }` index set.
    fn run_acs_to_decision(
        n: usize,
        local_completed_per_replica: Vec<HashSet<Replica>>,
        coin_seed: Vec<u8>,
    ) -> Vec<HashSet<usize>> {
        assert_eq!(local_completed_per_replica.len(), n);
        let f = (n - 1) / 3;

        let mut replicas: Vec<Replica_> = (0..n)
            .map(|i| {
                Replica_::new(
                    i as Replica,
                    n,
                    f,
                    local_completed_per_replica[i].clone(),
                    coin_seed.clone(),
                )
            })
            .collect();

        let mut pending: Vec<(Replica, Wire)> = Vec::new();

        // Each replica kicks off its own RBC.
        for i in 0..n {
            let acts = replicas[i].start_self_rbc();
            pending.extend(acts);
        }

        for _ in 0..50_000 {
            // Termination check: every replica's ABA driver fully decided.
            if replicas.iter().all(|r| r.acs.aba.all_decided) {
                break;
            }
            let mut next: Vec<(Replica, Wire)> = Vec::new();
            for (sender, wire) in pending.drain(..) {
                match wire {
                    Wire::RbcSend { proposer, payload } => {
                        for r in replicas.iter_mut() {
                            // Only authoritative if proposer == sender.
                            if sender != proposer { continue; }
                            let acts = r.handle_rbc_send(proposer, payload.clone());
                            next.extend(acts);
                        }
                    }
                    Wire::RbcEcho { proposer, payload_hash } => {
                        for r in replicas.iter_mut() {
                            let acts = r.handle_rbc_echo(proposer, sender, payload_hash);
                            next.extend(acts);
                        }
                    }
                    Wire::RbcReady { proposer, payload_hash } => {
                        for r in replicas.iter_mut() {
                            let acts = r.handle_rbc_ready(proposer, sender, payload_hash);
                            next.extend(acts);
                        }
                    }
                    Wire::AbaBval { aba_id, aba_round, value } => {
                        for r in replicas.iter_mut() {
                            let acts = r.handle_aba_bval(aba_id, aba_round, value, sender);
                            next.extend(acts);
                        }
                    }
                    Wire::AbaAux { aba_id, aba_round, value } => {
                        for r in replicas.iter_mut() {
                            let acts = r.handle_aba_aux(aba_id, aba_round, value, sender);
                            next.extend(acts);
                        }
                    }
                }
            }
            // After each delivery wave: pump coins, then check the
            // n-f-decided-1 force-zero rule.
            for r in replicas.iter_mut() {
                let acts = r.pump_coins();
                next.extend(acts);
            }
            for r in replicas.iter_mut() {
                let acts = r.force_zero_if_ready();
                next.extend(acts);
            }
            for r in replicas.iter_mut() {
                let acts = r.pump_coins();
                next.extend(acts);
            }
            pending = next;
        }

        replicas
            .into_iter()
            .map(|r| {
                let banned: HashSet<Replica> = HashSet::new();
                r.acs.compute_decided_dealers(&banned)
                    .map(|v| v.into_iter().map(|d| d as usize).collect())
                    .unwrap_or_default()
            })
            .collect()
    }

    #[test]
    fn e2e_acs_agreement_unanimous_avss_completion_n4() {
        // n=4: every replica has every dealer locally completed.
        // Property: every honest replica decides the SAME index set,
        // and the set has size ≥ n-f = 3.
        let all: HashSet<Replica> = (0..4).map(|i| i as Replica).collect();
        let local = vec![all.clone(); 4];
        let decisions = run_acs_to_decision(4, local, b"e2e-genesis-seed".to_vec());
        let first = &decisions[0];
        for d in &decisions {
            assert_eq!(d, first, "agreement broken: {:?}", decisions);
        }
        assert!(first.len() >= 3, "size lower bound (n-f=3) violated, got {}", first.len());
    }

    #[test]
    fn e2e_acs_agreement_partial_avss_completion_n4() {
        // n=4: replica i has dealers [0..3] EXCEPT dealer 3 (so all
        // three honest replicas miss dealer 3). When dealer 3 is
        // missing locally, ABA(3)'s input is initially deferred at
        // every replica, then the n-f-decided-1 rule forces input=0
        // on ABA(3). Decisions converge.
        let local: Vec<HashSet<Replica>> = (0..4)
            .map(|_| {
                let mut s = HashSet::new();
                s.insert(0); s.insert(1); s.insert(2);
                s
            })
            .collect();
        let decisions = run_acs_to_decision(4, local, b"e2e-partial-seed".to_vec());
        let first = &decisions[0];
        for d in &decisions {
            assert_eq!(d, first, "agreement broken: {:?}", decisions);
        }
        assert!(first.len() >= 3, "size lower bound (n-f=3) violated, got {}", first.len());
    }
}
