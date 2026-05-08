//! The original hashrand `gather/` module is unreachable in pure
//! PPT mode (the dispatcher in `process.rs` drops every Gather*
//! message). Its implementation also references functions that no
//! longer exist after the P0 ACS refactor (e.g. `process_acs_init`),
//! so it would break compilation if left in place. The module is
//! kept as an empty namespace only because external users of
//! `crate::node::gather::*` may exist; new code MUST NOT add anything
//! here.
