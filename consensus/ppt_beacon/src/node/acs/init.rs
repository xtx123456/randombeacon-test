use std::collections::HashSet;

use super::state::ACSInstanceState;

pub fn build_local_proposal(st: &mut ACSInstanceState) -> HashSet<usize> {
    st.set_proposal_from_completed();
    st.proposed_set.clone()
}
