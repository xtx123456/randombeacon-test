use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ACSPhase {
    CollectingInit,
    OutputBroadcast,
    Finalized,
}

impl Default for ACSPhase {
    fn default() -> Self {
        ACSPhase::CollectingInit
    }
}

#[derive(Debug, Clone, Default)]
pub struct ACSInstanceState {
    pub round: usize,
    pub myid: usize,

    /// Local completed dealers collected directly from the AVSS path.
    pub completed_dealers: HashSet<usize>,
    pub proposed_set: HashSet<usize>,

    /// Local candidate built from ACSInit quorum.
    pub decided_set: Option<HashSet<usize>>,

    pub init_sent: bool,
    pub output_sent: bool,

    /// Final ACS decision: only set once we observe n-f identical ACSOutput payloads.
    pub final_decided: bool,
    pub final_decided_set: Option<HashSet<usize>>,

    /// sender -> ACSInit proposal
    pub outputs_seen: HashMap<usize, HashSet<usize>>,

    /// sender -> ACSOutput payload
    pub final_outputs_seen: HashMap<usize, HashSet<usize>>,

    pub phase: ACSPhase,
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
            phase: ACSPhase::CollectingInit,
        }
    }

    pub fn mark_completed(&mut self, dealer: usize) {
        self.completed_dealers.insert(dealer);
    }

    pub fn set_proposal_from_completed(&mut self) {
        self.proposed_set = self.completed_dealers.clone();
    }

    pub fn record_init(&mut self, from: usize, dealers: HashSet<usize>) {
        self.outputs_seen.insert(from, dealers);
    }

    /// Backward-compatible alias.
    pub fn record_output(&mut self, from: usize, dealers: HashSet<usize>) {
        self.record_init(from, dealers);
    }

    /// Build exactly one local candidate once we have n-f ACSInit messages.
    /// For performance, keep the repo's original quorum-union rule here.
    pub fn maybe_build_output(&mut self, threshold: usize) -> Option<HashSet<usize>> {
        if let Some(existing) = self.decided_set.clone() {
            return Some(existing);
        }

        if self.outputs_seen.len() < threshold {
            return None;
        }

        let mut union_set = HashSet::new();
        for dealers in self.outputs_seen.values() {
            union_set.extend(dealers.iter().copied());
        }

        self.decided_set = Some(union_set.clone());
        self.phase = ACSPhase::OutputBroadcast;
        Some(union_set)
    }

    pub fn mark_output_sent(&mut self) {
        self.output_sent = true;
    }

    pub fn record_final_output(&mut self, from: usize, dealers: HashSet<usize>) {
        self.final_outputs_seen.insert(from, dealers);
    }

    /// Finalize only when we have n-f identical ACSOutput payloads.
    pub fn try_finalize_from_outputs(&mut self, threshold: usize) -> Option<HashSet<usize>> {
        if self.final_decided {
            return None;
        }

        let mut vote_count: HashMap<Vec<usize>, usize> = HashMap::new();
        for dealers in self.final_outputs_seen.values() {
            let key = Self::canonical_vec(dealers);
            *vote_count.entry(key).or_insert(0) += 1;
        }

        let winning_vec = vote_count
            .into_iter()
            .find_map(|(dealers, count)| if count >= threshold { Some(dealers) } else { None })?;

        let decided: HashSet<usize> = winning_vec.into_iter().collect();

        self.final_decided = true;
        self.final_decided_set = Some(decided.clone());
        self.phase = ACSPhase::Finalized;

        Some(decided)
    }

    pub fn final_decision_vec(&self) -> Option<Vec<usize>> {
        self.final_decided_set
            .as_ref()
            .map(Self::canonical_vec)
    }

    fn canonical_vec(dealers: &HashSet<usize>) -> Vec<usize> {
        let mut v: Vec<usize> = dealers.iter().copied().collect();
        v.sort_unstable();
        v
    }
}
