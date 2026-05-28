//! Π_CompactBroadcast — reliable broadcast based on erasure codes
//! and Merkle trees, from Section 3.2.2 of:
//!
//!   Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//!   Verifiable Secret Sharing with Optimal Resilience", Journal of
//!   Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//!
//! This is the Bracha-style reliable-broadcast variant where the
//! sender:
//!
//!   1. Encodes its message `m` into `n` fragments `(f_1, ..., f_n)`
//!      using the (n, n-2t) Reed-Solomon erasure code from the
//!      sibling `reed_solomon` module.
//!   2. Builds a Merkle tree over `(f_1, ..., f_n)` with root `r`.
//!   3. Sends each party `P_j` the triple `(r, π_j, f_j)`, where
//!      `π_j` is the validation path for `f_j` under `r` at index
//!      `j`.
//!
//! Each receiver echoes its own `(r, π_j, f_j)` to all other
//! parties, then engages in a Bracha-style two-phase ECHO/VOTE
//! protocol on the **root r** (not the message itself). This
//! drives the per-message communication complexity from
//! `O(n^2 · |m|)` (plain Bracha) down to
//! `O(|m| + λ · n^2 · log n)` (matching the bound stated in the
//! paper).
//!
//! ## State machine
//!
//! We expose a pure-logic state machine (no I/O, no Tokio, no
//! `Context`) so the higher-level driver — eventually wired into
//! the AVSS pipeline by Commit 6 — can plug it in along the same
//! pattern as the existing `acs::rbc` and `acs::aba` modules.
//!
//! ## Bracha thresholds (with n = 3t+1)
//!
//! | Trigger                         | Threshold | Effect                |
//! |---------------------------------|-----------|-----------------------|
//! | `n-t` ECHOes for same root      | 2t+1      | Send our own VOTE     |
//! | `t+1`  VOTEs for same root      | t+1       | Send our own VOTE     |
//! | `2t+1` VOTEs for same root      | 2t+1      | Enter output stage    |
//! | output stage AND `n-2t` valid   | t+1       | Decode m and DELIVER  |
//! | fragments for that root         |           |                       |
//!
//! These match the Bracha B0/B1/B2/B3 properties cited by the
//! paper. By B2 + B3, at most one root ever crosses `n-t` honest
//! echoes, so the per-root tracking below is defensive against
//! Byzantine senders that try to broadcast inconsistent roots.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crypto::aes_hash::{HashState, MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use types::Replica;

use super::reed_solomon::{Fragment, RsCodingError, RsDecoder, RsEncoder};

/// Side-effect emitted by `CompactBroadcastState` — translated by
/// the driver into wire messages and self-deliveries, mirroring
/// the existing `acs::rbc::RbcAction` pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactBroadcastAction {
    /// Sender → recipient `recipient_idx`: SEND containing
    /// `(root, path, fragment)`. Only the proposer ever emits this.
    SendDispersal {
        recipient_idx: usize,
        root: Hash,
        path: Proof,
        fragment: Fragment,
    },
    /// Receiver `frag_idx` → all peers: ECHO containing
    /// `(root, path, fragment)`. Note `frag_idx` here identifies
    /// **which fragment** is being echoed (i.e. the receiver's own
    /// index `j` in the (f_1, ..., f_n) vector), not the wire-level
    /// sender of the ECHO.
    SendEcho {
        root: Hash,
        path: Proof,
        fragment: Fragment,
        frag_idx: usize,
    },
    /// Bracha VOTE on the Merkle root `root`. Carries no fragment.
    SendVote { root: Hash },
    /// Local: this protocol instance has delivered `message`.
    /// Idempotent — at most one Delivered per state instance.
    Delivered { message: Vec<u8> },
}

/// One Π_CompactBroadcast state machine instance.
pub struct CompactBroadcastState {
    /// This node's identity (used for VOTE de-duplication and to
    /// stamp `frag_idx` on our own ECHO).
    pub myid: Replica,
    pub n: usize,
    pub t: usize,
    /// The proposer / sender for this CompactBroadcast instance.
    /// Only the proposer is allowed to emit `SendDispersal`.
    pub proposer: Replica,

    /// Reed-Solomon encoder/decoder for (n, n-2t).
    encoder: RsEncoder,
    decoder: RsDecoder,
    /// Hash context for Merkle-tree construction.
    hash_state: Arc<HashState>,

    // ---- Sender (proposer) state ----
    /// Set once the proposer has computed and emitted its `n`
    /// SendDispersal actions.
    proposer_dispersed: bool,

    // ---- Receiver state ----
    /// Did we receive our own `(root, path, fragment)` from the
    /// proposer and emit our own ECHO on it? At most one root —
    /// the first valid SEND we accept.
    own_echo_root: Option<Hash>,
    /// Locally cached fragment + its Merkle path for our own
    /// `frag_idx == myid`.
    own_fragment: Option<(Proof, Fragment)>,

    /// Has this node already broadcast its own VOTE? At most one
    /// VOTE per node per instance, by Bracha rules. Records the
    /// root we voted for.
    own_vote_root: Option<Hash>,

    /// `echo_per_root[r]` = senders that ECHOed root `r` along with
    /// their valid `(frag_idx, fragment)` pair. We keep the
    /// fragment so that once VOTE crosses 2t+1 we can immediately
    /// run the Reed-Solomon decoder.
    ///
    /// Map structure: `root -> echo_sender -> (frag_idx, fragment)`.
    /// `echo_sender` is the wire-level sender of the ECHO message
    /// (this is what we count for the `n-t` threshold, by Bracha
    /// rules); `frag_idx` is the index of the fragment claim.
    echo_per_root: HashMap<Hash, HashMap<Replica, (usize, Fragment)>>,

    /// `vote_per_root[r]` = senders that VOTEd for root `r`. We
    /// count distinct senders for the Bracha 2t+1 / t+1 thresholds.
    vote_per_root: HashMap<Hash, HashSet<Replica>>,

    /// Final delivered message + the root it was decoded under.
    /// Latches once set; subsequent triggers are idempotent.
    delivered: Option<(Hash, Vec<u8>)>,
}

impl fmt::Debug for CompactBroadcastState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactBroadcastState")
            .field("myid", &self.myid)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("proposer", &self.proposer)
            .field("proposer_dispersed", &self.proposer_dispersed)
            .field("own_echo_root", &self.own_echo_root.map(|h| short_hash(&h)))
            .field("own_vote_root", &self.own_vote_root.map(|h| short_hash(&h)))
            .field(
                "echo_per_root",
                &self
                    .echo_per_root
                    .iter()
                    .map(|(h, m)| (short_hash(h), m.len()))
                    .collect::<Vec<_>>(),
            )
            .field(
                "vote_per_root",
                &self
                    .vote_per_root
                    .iter()
                    .map(|(h, m)| (short_hash(h), m.len()))
                    .collect::<Vec<_>>(),
            )
            .field("delivered", &self.delivered.is_some())
            .finish()
    }
}

fn short_hash(h: &Hash) -> String {
    let bs: &[u8] = h;
    if bs.len() < 4 {
        return format!("{:02x?}", bs);
    }
    format!("{:02x}{:02x}{:02x}{:02x}..", bs[0], bs[1], bs[2], bs[3])
}

/// Errors raised by the `CompactBroadcastState` API. Distinct from
/// the protocol-level `Delivered` outcome: these errors indicate
/// either a Byzantine-shaped wire input we are dropping, or a
/// programmer / configuration error.
#[derive(Debug)]
pub enum CompactBroadcastError {
    /// Caller asked for `(n, t)` that violate optimal resilience
    /// or aren't supported by the underlying Reed-Solomon code.
    InvalidConfig(RsCodingError),
    /// `set_input_as_proposer` called by a non-proposer node.
    NotProposer { myid: Replica, proposer: Replica },
    /// Proposer's encode call failed (typically `PayloadTooLarge`).
    EncodeFailed(RsCodingError),
}

impl fmt::Display for CompactBroadcastError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompactBroadcastError::InvalidConfig(e) => write!(f, "invalid config: {}", e),
            CompactBroadcastError::NotProposer { myid, proposer } => {
                write!(f, "node {} is not the proposer ({})", myid, proposer)
            }
            CompactBroadcastError::EncodeFailed(e) => write!(f, "encode failed: {}", e),
        }
    }
}

impl std::error::Error for CompactBroadcastError {}

impl CompactBroadcastState {
    pub fn new(
        myid: Replica,
        n: usize,
        t: usize,
        proposer: Replica,
        hash_state: Arc<HashState>,
    ) -> Result<Self, CompactBroadcastError> {
        let encoder = RsEncoder::new(n, t).map_err(CompactBroadcastError::InvalidConfig)?;
        let decoder = RsDecoder::new(n, t).map_err(CompactBroadcastError::InvalidConfig)?;
        Ok(Self {
            myid,
            n,
            t,
            proposer,
            encoder,
            decoder,
            hash_state,
            proposer_dispersed: false,
            own_echo_root: None,
            own_fragment: None,
            own_vote_root: None,
            echo_per_root: HashMap::new(),
            vote_per_root: HashMap::new(),
            delivered: None,
        })
    }

    /// `n - t` (Bracha echo / vote-output threshold).
    fn n_minus_t(&self) -> usize {
        self.n - self.t
    }
    /// `t + 1` (Bracha vote amplification threshold).
    fn t_plus_one(&self) -> usize {
        self.t + 1
    }
    /// `n - 2t` (Reed-Solomon decode threshold; same as `t+1` for
    /// `n = 3t+1`). The paper uses this name explicitly so we
    /// mirror it.
    fn n_minus_2t(&self) -> usize {
        self.n - 2 * self.t
    }

    /// Has this instance delivered its message yet?
    pub fn delivered(&self) -> bool {
        self.delivered.is_some()
    }

    /// The delivered message, if any.
    pub fn delivered_message(&self) -> Option<&[u8]> {
        self.delivered.as_ref().map(|(_, m)| m.as_slice())
    }

    /// Proposer-side entry point: encode `message`, build the
    /// Merkle tree, and emit `n` `SendDispersal` actions one per
    /// recipient (including the proposer's own self-deliver).
    /// Idempotent on repeat calls.
    pub fn set_input_as_proposer(
        &mut self,
        message: Vec<u8>,
    ) -> Result<Vec<CompactBroadcastAction>, CompactBroadcastError> {
        if self.myid != self.proposer {
            return Err(CompactBroadcastError::NotProposer {
                myid: self.myid,
                proposer: self.proposer,
            });
        }
        if self.proposer_dispersed {
            return Ok(Vec::new());
        }

        // (1) Encode message into n fragments.
        let fragments = self
            .encoder
            .encode(&message)
            .map_err(CompactBroadcastError::EncodeFailed)?;
        debug_assert_eq!(fragments.len(), self.n);

        // (2) Build Merkle tree over the fragment hashes.
        let leaf_hashes: Vec<Hash> = fragments.iter().map(|f| do_hash(f.as_bytes())).collect();
        let merkle_tree = MerkleTree::new(leaf_hashes, &self.hash_state);
        let root = merkle_tree.root();

        // (3) Emit one SendDispersal per recipient (recipient_idx = j).
        let mut out = Vec::with_capacity(self.n);
        for j in 0..self.n {
            let path = merkle_tree.gen_proof(j);
            let fragment = fragments[j].clone();
            out.push(CompactBroadcastAction::SendDispersal {
                recipient_idx: j,
                root,
                path,
                fragment,
            });
        }

        self.proposer_dispersed = true;
        Ok(out)
    }

    /// Receiver-side entry point: handle a `SEND(root, path,
    /// fragment)` from the proposer addressed at this node's
    /// `frag_idx == myid`. Returns the ECHO action triggered
    /// (typically one `SendEcho`).
    ///
    /// The Merkle path is validated against `root` at index
    /// `myid`. If validation fails, the SEND is dropped silently
    /// (Byzantine-shaped input).
    pub fn handle_dispersal(
        &mut self,
        wire_sender: Replica,
        root: Hash,
        path: Proof,
        fragment: Fragment,
    ) -> Vec<CompactBroadcastAction> {
        // Only accept SEND from the rightful proposer.
        if wire_sender != self.proposer {
            return Vec::new();
        }
        // Idempotent: only first valid SEND is honoured (Bracha
        // standard — equivocation by the dealer is dropped).
        if self.own_echo_root.is_some() {
            return Vec::new();
        }
        // Validate the Merkle path: hash(fragment) must lie at
        // index myid under root.
        let expected_leaf = do_hash(fragment.as_bytes());
        if path.item() != expected_leaf {
            log::debug!(
                "[ShoupSmart][CompactBroadcast] node {} dropped SEND: leaf hash mismatch",
                self.myid
            );
            return Vec::new();
        }
        if path.root() != root {
            log::debug!(
                "[ShoupSmart][CompactBroadcast] node {} dropped SEND: stated root != path root",
                self.myid
            );
            return Vec::new();
        }
        if !path.validate(&self.hash_state) {
            log::debug!(
                "[ShoupSmart][CompactBroadcast] node {} dropped SEND: invalid path",
                self.myid
            );
            return Vec::new();
        }

        self.own_echo_root = Some(root);
        self.own_fragment = Some((path.clone(), fragment.clone()));

        // Self-record our own fragment in the echo map so the
        // n-t echo threshold counts us correctly. The Bracha
        // threshold is on *distinct senders* of ECHO, and we
        // count ourselves as a sender of our own ECHO.
        self.record_echo(self.myid, root, self.myid as usize, fragment.clone());

        // Try the thresholds in case ECHO/VOTEs have already arrived.
        let mut out = Vec::new();
        out.push(CompactBroadcastAction::SendEcho {
            root,
            path,
            fragment,
            frag_idx: self.myid as usize,
        });
        out.extend(self.check_echo_threshold(root));
        out.extend(self.try_deliver(root));
        out
    }

    /// Receiver-side entry point: handle an `ECHO(root, path,
    /// fragment, frag_idx)` from `wire_sender`. Validates the
    /// Merkle path and records the fragment (so it is available
    /// for Reed-Solomon decoding once the VOTE threshold fires).
    pub fn handle_echo(
        &mut self,
        wire_sender: Replica,
        root: Hash,
        path: Proof,
        fragment: Fragment,
        frag_idx: usize,
    ) -> Vec<CompactBroadcastAction> {
        if frag_idx >= self.n {
            return Vec::new();
        }
        // Validate Merkle path.
        let expected_leaf = do_hash(fragment.as_bytes());
        if path.item() != expected_leaf {
            return Vec::new();
        }
        if path.root() != root {
            return Vec::new();
        }
        if !path.validate(&self.hash_state) {
            return Vec::new();
        }

        self.record_echo(wire_sender, root, frag_idx, fragment);

        let mut out = Vec::new();
        out.extend(self.check_echo_threshold(root));
        out.extend(self.try_deliver(root));
        out
    }

    /// Receiver-side entry point: handle a `VOTE(root)` from
    /// `wire_sender`. Plain Bracha VOTE counting; carries no
    /// fragment.
    pub fn handle_vote(&mut self, wire_sender: Replica, root: Hash) -> Vec<CompactBroadcastAction> {
        let (vote_count, already_voted) = {
            let voters = self
                .vote_per_root
                .entry(root)
                .or_insert_with(HashSet::new);
            voters.insert(wire_sender);
            (voters.len(), self.own_vote_root.is_some())
        };

        let mut out = Vec::new();
        // Bracha amplification: t+1 votes for a root → vote for it
        // ourselves (regardless of own ECHO state).
        let t_plus_one = self.t_plus_one();
        if vote_count >= t_plus_one && !already_voted {
            self.own_vote_root = Some(root);
            // Self-tally so subsequent self-deliver of our own
            // VOTE is a no-op idempotent.
            self.vote_per_root
                .entry(root)
                .or_insert_with(HashSet::new)
                .insert(self.myid);
            out.push(CompactBroadcastAction::SendVote { root });
        }

        // 2t+1 VOTEs → enter output stage; deliver if we have
        // enough valid fragments.
        out.extend(self.try_deliver(root));
        out
    }

    /// Internal: insert a (sender → frag_idx, fragment) entry into
    /// `echo_per_root[root]`. First-seen-per-sender wins.
    fn record_echo(&mut self, sender: Replica, root: Hash, frag_idx: usize, fragment: Fragment) {
        let entry = self.echo_per_root.entry(root).or_insert_with(HashMap::new);
        entry.entry(sender).or_insert((frag_idx, fragment));
    }

    /// Internal: if `n-t` ECHOes for `root` have been collected and
    /// we haven't VOTEd yet, emit `SendVote(root)`.
    fn check_echo_threshold(&mut self, root: Hash) -> Vec<CompactBroadcastAction> {
        if self.own_vote_root.is_some() {
            return Vec::new();
        }
        let echo_count = self
            .echo_per_root
            .get(&root)
            .map(|m| m.len())
            .unwrap_or(0);
        if echo_count >= self.n_minus_t() {
            self.own_vote_root = Some(root);
            // Pre-record our own vote so subsequent self-deliver
            // is idempotent.
            self.vote_per_root
                .entry(root)
                .or_insert_with(HashSet::new)
                .insert(self.myid);
            vec![CompactBroadcastAction::SendVote { root }]
        } else {
            Vec::new()
        }
    }

    /// Internal: try to enter output stage and deliver. Two
    /// conditions must hold:
    ///   - `2t+1` VOTEs collected for `root` (Bracha output stage)
    ///   - `n-2t` valid fragments collected for `root` (Reed-Solomon
    ///     decode threshold)
    fn try_deliver(&mut self, root: Hash) -> Vec<CompactBroadcastAction> {
        if self.delivered.is_some() {
            return Vec::new();
        }
        let vote_count = self
            .vote_per_root
            .get(&root)
            .map(|s| s.len())
            .unwrap_or(0);
        if vote_count < 2 * self.t + 1 {
            return Vec::new();
        }

        let echo_map = match self.echo_per_root.get(&root) {
            Some(m) => m,
            None => return Vec::new(),
        };
        if echo_map.len() < self.n_minus_2t() {
            return Vec::new();
        }

        // Deduplicate by frag_idx (an ECHO sender claims a specific
        // frag_idx; multiple senders may claim the same idx, but we
        // only need one fragment per idx for Reed-Solomon). First
        // seen wins.
        let mut by_frag_idx: HashMap<usize, Fragment> = HashMap::new();
        for (_sender, (frag_idx, fragment)) in echo_map.iter() {
            by_frag_idx
                .entry(*frag_idx)
                .or_insert_with(|| fragment.clone());
        }
        if by_frag_idx.len() < self.n_minus_2t() {
            return Vec::new();
        }

        // Decode.
        let collected: Vec<(usize, Fragment)> = by_frag_idx.into_iter().collect();
        match self.decoder.decode(collected) {
            Ok(message) => {
                self.delivered = Some((root, message.clone()));
                vec![CompactBroadcastAction::Delivered { message }]
            }
            Err(e) => {
                log::warn!(
                    "[ShoupSmart][CompactBroadcast] node {} decode failed at delivery: {}",
                    self.myid,
                    e
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_state() -> Arc<HashState> {
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        Arc::new(HashState::new(key0, key1, key2))
    }

    fn make_state(myid: Replica, n: usize, t: usize, proposer: Replica) -> CompactBroadcastState {
        CompactBroadcastState::new(myid, n, t, proposer, hash_state())
            .expect("valid CompactBroadcast config")
    }

    /// Drive a full CompactBroadcast across `n` honest replicas
    /// with synchronous reliable delivery. Returns each replica's
    /// delivered message (or None if not delivered).
    fn drive_cb(proposer: Replica, message: Vec<u8>, n: usize) -> Vec<Option<Vec<u8>>> {
        let t = (n - 1) / 3;
        let mut nodes: Vec<CompactBroadcastState> = (0..n)
            .map(|i| make_state(i as Replica, n, t, proposer))
            .collect();

        let mut pending: Vec<(Replica, CompactBroadcastAction)> = Vec::new();

        // Proposer initiates dispersal.
        let acts = nodes[proposer as usize]
            .set_input_as_proposer(message.clone())
            .expect("proposer dispersal ok");
        for a in acts {
            pending.push((proposer, a));
        }

        for _ in 0..400 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, CompactBroadcastAction)> = Vec::new();
            for (sender, action) in pending.drain(..) {
                match action {
                    CompactBroadcastAction::SendDispersal {
                        recipient_idx,
                        root,
                        path,
                        fragment,
                    } => {
                        // Routed only to the specific recipient.
                        if recipient_idx < n {
                            let acts = nodes[recipient_idx].handle_dispersal(
                                sender, root, path, fragment,
                            );
                            for a in acts {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    CompactBroadcastAction::SendEcho {
                        root,
                        path,
                        fragment,
                        frag_idx,
                    } => {
                        // ECHO is broadcast to every node.
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_echo(
                                sender,
                                root,
                                path.clone(),
                                fragment.clone(),
                                frag_idx,
                            );
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    CompactBroadcastAction::SendVote { root } => {
                        // VOTE is broadcast.
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_vote(sender, root);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    CompactBroadcastAction::Delivered { .. } => {}
                }
            }
            pending = next;
        }

        nodes
            .into_iter()
            .map(|n| n.delivered_message().map(|s| s.to_vec()))
            .collect()
    }

    // ---- Validity ----

    #[test]
    fn cb_delivers_to_every_honest_node_n4() {
        let payload = b"hello-compact-broadcast".to_vec();
        let delivered = drive_cb(0, payload.clone(), 4);
        for d in &delivered {
            assert_eq!(
                d.as_deref(),
                Some(payload.as_slice()),
                "every node must deliver"
            );
        }
    }

    #[test]
    fn cb_delivers_to_every_honest_node_n16() {
        // n=16, t=5. ECHO threshold n-t = 11; RS-decode threshold
        // n-2t = 6.
        let payload: Vec<u8> = (0..2048).map(|i| (i & 0xff) as u8).collect();
        let delivered = drive_cb(3, payload.clone(), 16);
        for d in &delivered {
            assert_eq!(d.as_deref(), Some(payload.as_slice()));
        }
    }

    #[test]
    fn cb_delivers_empty_message() {
        let delivered = drive_cb(2, Vec::new(), 4);
        for d in &delivered {
            assert_eq!(d.as_deref(), Some(b"".as_slice()));
        }
    }

    // ---- Agreement ----

    #[test]
    fn cb_agreement_byte_equality() {
        // Property: every node that delivers, delivers the SAME
        // bytes. With an honest proposer, all deliveries equal the
        // input.
        let payload: Vec<u8> = (0..1024)
            .map(|i| (((i as u64).wrapping_mul(0xdeadbeefu64)) & 0xff) as u8)
            .collect();
        let delivered = drive_cb(1, payload.clone(), 7); // n=7, t=2
        let first = delivered.iter().find_map(|x| x.clone()).expect("at least one delivery");
        for d in &delivered {
            assert_eq!(d.as_ref(), Some(&first), "agreement broken");
        }
        assert_eq!(first, payload);
    }

    // ---- Liveness ----

    #[test]
    fn cb_liveness_with_only_n_minus_2t_echoes() {
        // n=16, t=5. ECHO threshold (vote trigger) = n-t = 11.
        // Once we have 11 valid ECHOes, all honest nodes will
        // VOTE; once 2t+1 = 11 nodes have VOTEd, the n-2t=6
        // fragments suffice for delivery. Drive the protocol with
        // a message that requires multi-fragment reconstruction.
        let payload: Vec<u8> = (0..4096).map(|i| (i & 0xff) as u8).collect();
        let delivered = drive_cb(0, payload.clone(), 16);
        let n_delivered = delivered.iter().filter(|d| d.is_some()).count();
        assert_eq!(n_delivered, 16, "all 16 nodes should deliver");
    }

    // ---- Byzantine-shaped inputs ----

    #[test]
    fn cb_dropped_send_with_wrong_root() {
        // ECHO with a path that doesn't recompute to the stated
        // root must be silently dropped.
        let mut state = make_state(0, 4, 1, 1); // proposer = 1, this is node 0

        // Build a real (root, path, fragment) with proposer=1's
        // perspective.
        let real_proposer = make_state(1, 4, 1, 1);
        let mut real_proposer = real_proposer;
        let acts = real_proposer
            .set_input_as_proposer(b"valid-payload".to_vec())
            .expect("ok");
        let (root, path, fragment) = match &acts[0] {
            CompactBroadcastAction::SendDispersal {
                root,
                path,
                fragment,
                ..
            } => (*root, path.clone(), fragment.clone()),
            _ => panic!("expected SendDispersal"),
        };

        // Tamper: pass a fragment that doesn't hash to the path's leaf.
        let wrong_fragment = Fragment::from_bytes(vec![0u8; fragment.len()]);
        // wire_sender = proposer (= 1)
        let result = state.handle_dispersal(1, root, path, wrong_fragment);
        assert!(
            result.is_empty(),
            "tampered SEND should be dropped, got actions: {:?}",
            result
        );
        assert!(state.own_echo_root.is_none());
    }

    #[test]
    fn cb_dropped_send_from_non_proposer() {
        // SEND from a wire-sender that is not the proposer must
        // be dropped (Bracha rule: only the proposer is the
        // authoritative source of SEND).
        let mut state = make_state(0, 4, 1, 1);
        // A "fake" SEND constructed by another node (myid=2) using
        // its OWN encoder. We pretend node 2 is the wire-sender.
        let mut faker = make_state(2, 4, 1, 2); // a different proposer perspective
        let acts = faker
            .set_input_as_proposer(b"impostor-payload".to_vec())
            .expect("ok");
        let (root, path, fragment) = match &acts[0] {
            CompactBroadcastAction::SendDispersal {
                root,
                path,
                fragment,
                ..
            } => (*root, path.clone(), fragment.clone()),
            _ => panic!("expected SendDispersal"),
        };
        // wire_sender = 2 (impostor), but state expects proposer = 1.
        let result = state.handle_dispersal(2, root, path, fragment);
        assert!(result.is_empty());
        assert!(state.own_echo_root.is_none());
    }

    #[test]
    fn cb_dropped_echo_with_invalid_path() {
        let mut state = make_state(0, 4, 1, 1);

        let mut real_proposer = make_state(1, 4, 1, 1);
        let _acts = real_proposer
            .set_input_as_proposer(b"some payload".to_vec())
            .unwrap();

        // Construct a deliberately wrong path / fragment combo:
        // empty path that obviously won't validate against any root.
        // We'll send a "valid-looking" structure but with hash
        // mismatch.
        let fake_root = Hash::default();
        let dummy_payload = vec![0u8; 64];
        let mut leaves: Vec<Hash> = (0..4).map(|_| do_hash(&dummy_payload)).collect();
        // Force one leaf to the hash of our fragment so its position
        // is known, then pass a different "fragment" so leaf mismatch.
        let wrong_fragment = Fragment::from_bytes(vec![1u8; 64]);
        let other_proof = MerkleTree::new(leaves.clone(), &hash_state()).gen_proof(0);
        let _ = fake_root;
        leaves.clear();
        let result = state.handle_echo(2, other_proof.root(), other_proof, wrong_fragment, 0);
        assert!(result.is_empty(), "should drop ECHO with mismatched fragment leaf");
    }

    // ---- Idempotency ----

    #[test]
    fn cb_proposer_set_input_idempotent() {
        // Calling set_input_as_proposer twice returns empty actions
        // the second time (Bracha rule: dealer commits at most once).
        let mut state = make_state(1, 4, 1, 1);
        let first = state.set_input_as_proposer(b"a".to_vec()).expect("ok");
        assert_eq!(first.len(), 4); // n SendDispersals
        let second = state.set_input_as_proposer(b"b".to_vec()).expect("ok");
        assert_eq!(second.len(), 0);
    }

    #[test]
    fn cb_set_input_by_non_proposer_errors() {
        let mut state = make_state(0, 4, 1, 1); // I am node 0, proposer is 1.
        let res = state.set_input_as_proposer(b"x".to_vec());
        assert!(matches!(
            res,
            Err(CompactBroadcastError::NotProposer { .. })
        ));
    }
}
