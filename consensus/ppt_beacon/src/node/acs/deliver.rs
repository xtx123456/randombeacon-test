use std::collections::HashSet;

use super::state::ACSInstanceState;

pub fn handle_local_output(
    st: &mut ACSInstanceState,
    from: usize,
    dealers: HashSet<usize>,
    threshold: usize,
    support_threshold: usize,
) -> Option<HashSet<usize>> {
    st.record_init(from, dealers);
    st.maybe_build_output(threshold, support_threshold)
}
