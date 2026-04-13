use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct ACSInstanceState {
    pub round: usize,
    pub myid: usize,
    pub completed_dealers: HashSet<usize>,
    pub proposed_set: HashSet<usize>,
    pub decided_set: Option<HashSet<usize>>,
    pub init_sent: bool,
    pub output_sent: bool,
    pub final_decided: bool,
    pub final_decided_set: Option<HashSet<usize>>,
    pub outputs_seen: HashMap<usize, HashSet<usize>>,
    pub final_outputs_seen: HashMap<usize, HashSet<usize>>,
}

impl ACSInstanceState {
    pub fn new(round: usize, myid: usize) -> Self {
        Self {
            round,
            myid,
            completed_dealers: HashSet::new(),
            proposed_set: HashSet::new(),
            decided_set: None,
            init_sent: false,
            output_sent: false,
            final_decided: false,
            final_decided_set: None,
            outputs_seen: HashMap::new(),
            final_outputs_seen: HashMap::new(),
        }
    }

    pub fn mark_completed(&mut self, dealer: usize) {
        self.completed_dealers.insert(dealer);
    }

    pub fn set_proposal_from_completed(&mut self) {
        self.proposed_set = self.completed_dealers.clone();
    }

    pub fn record_output(&mut self, from: usize, dealers: HashSet<usize>) {
        self.outputs_seen.insert(from, dealers);
    }

    pub fn try_decide_union(&mut self, threshold: usize) -> bool {
        if self.decided_set.is_some() {
            return true;
        }
        if self.outputs_seen.len() < threshold {
            return false;
        }
        let mut union_set = HashSet::new();
        for s in self.outputs_seen.values() {
            union_set.extend(s.iter().copied());
        }
        self.decided_set = Some(union_set);
        true
    }
}


impl ACSInstanceState {
    pub fn record_final_output(&mut self, from: usize, dealers: HashSet<usize>) {
        self.final_outputs_seen.insert(from, dealers);
    }
}
