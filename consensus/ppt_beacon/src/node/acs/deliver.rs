use std::collections::HashSet;

use super::state::ACSInstanceState;

pub fn handle_local_output(
    st: &mut ACSInstanceState,
    from: usize,
    dealers: HashSet<usize>,
    threshold: usize,
) -> Option<HashSet<usize>> {
    st.record_output(from, dealers);
    if st.try_decide_union(threshold) {
        return st.decided_set.clone();
    }
    None
}
