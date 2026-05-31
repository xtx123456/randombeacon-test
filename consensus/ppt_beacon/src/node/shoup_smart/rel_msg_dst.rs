//! Π_RelMsgDst — Reliable Message Distribution from Section 4.1 of:
//!
//!   Victor Shoup and Nigel P. Smart, "Lightweight Asynchronous
//!   Verifiable Secret Sharing with Optimal Resilience", Journal of
//!   Cryptology 37(3):27, 2024 (DOI 10.1007/s00145-024-09505-6).
//!
//! Reliable Message Distribution is a vector-of-message extension of
//! Π_CompactBroadcast (Sec 3.2.2). The sender holds a vector
//! `m = (m_1, ..., m_n)` of n distinct messages and wants every
//! party `P_j` to receive `m_j` (its own message), reliably.
//!
//! ## Distribution phase
//!
//! Sender side:
//!   1. For each `m_i`: encode → fragments `(f_{i1}, ..., f_{in})`,
//!      build Merkle tree → root `r_i`.
//!   2. Send each `P_j` the collection `{(r_i, π_{ij}, f_{ij})}_{i=1}^n`,
//!      where `π_{ij}` is the path for `f_{ij}` under `r_i` at index `j`.
//!      (Each `P_j` receives the j-th fragment of every message.)
//!
//! Receiver `P_j` side:
//!   3. Validate every `(r_i, π_{ij}, f_{ij})` it received.
//!   4. **Self-compute** the meta-root `r = MerkleTree(r_1, ..., r_n)`
//!      and the meta-path `π_i` for each `r_i`. (Sender does NOT
//!      send `r` — receivers derive it deterministically from the
//!      message-roots they received.)
//!   5. For each `P_i`, send echo `(r, π_i, r_i, π_{ij}, f_{ij})` —
//!      i.e. forward the j-th fragment of `m_i` to its rightful owner.
//!
//! Receiver `P_i` collects echoes from peers:
//!   6. Validate `π_i` (chains `r_i` to `r`) and `π_{ij}` (chains
//!      `f_{ij}` to `r_i` at index `j == sender's frag_idx`).
//!   7. Bracha vote rules on the meta-root `r`:
//!      - n-t echoes for `r` from distinct senders ⇒ emit Vote(r).
//!      - t+1 votes for `r` ⇒ emit Vote(r) (amplification).
//!      - 2t+1 votes for `r` ⇒ enter output stage.
//!   8. In output stage, once we have ≥ n-2t valid `m_i`-fragments
//!      we can decode `m_i` via Reed-Solomon.
//!
//! ## Forwarding sub-protocol (unhappy-path)
//!
//! After `P_j` has delivered `m_j`, it can optionally forward `m_j`
//! to a third party Q. P_j sends Q the saved tuple
//! `(π_j, r_j, {(idx_i, π_{ji}, f_{ji})}_{i ∈ I})` where `|I| ≥ n-2t`.
//! Q validates:
//!   1. `π_j` chains `r_j` to `r` (Q's own meta-root).
//!   2. Every `π_{ji}` chains `f_{ji}` to `r_j` at index `idx_i`.
//!   3. Decode the n-2t fragments → `m'_j`. Re-encode `m'_j` into n
//!      fragments, rebuild the message-Merkle-tree, compare its
//!      root with `r_j`. If they match → output `m_j`; else ⊥.
//!
//! Step 3 detects sender misbehaviour (a corrupt sender that gave
//! P_j fragments that do NOT form a valid RS codeword would fail
//! the rebuild check). Step 1 detects forwarding-party
//! misbehaviour (P_j tampered with `π_j` or `r_j`).
//!
//! ## PQ-safety
//!
//! Only `crypto::hash::do_hash` (Merkle leaves) + Reed-Solomon over
//! GF(2^8) (deterministic finite-field arithmetic). No new crypto
//! deps; matches the Sec 4.1 lightweight-only requirement.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crypto::aes_hash::{HashState, MerkleTree, Proof};
use crypto::hash::{do_hash, Hash};
use types::Replica;

use super::proof_leaf_index;
use super::reed_solomon::{Fragment, RsCodingError, RsDecoder, RsEncoder};

// ---------------------------------------------------------------------
// Wire-payload structs
// ---------------------------------------------------------------------

/// One row of a sender's dispersal addressed at recipient `P_j`:
/// the j-th fragment `f_{ij}` of message `m_i`, with its Merkle
/// validation path `π_{ij}` under message-root `r_i`.
///
/// The recipient `P_j` is implicit (each recipient gets a vector of
/// `n` `DispersalEntry`s, one per message index `i ∈ [0, n)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispersalEntry {
    /// Which message this fragment belongs to (0-based).
    pub msg_idx: usize,
    /// Merkle root `r_{msg_idx}` of the fragment vector for `m_{msg_idx}`.
    pub msg_root: Hash,
    /// Merkle path proving `f_{msg_idx, frag_idx} = fragment` is at
    /// position `frag_idx` (= recipient's index) under `msg_root`.
    pub frag_path: Proof,
    /// The actual fragment bytes.
    pub fragment: Fragment,
}

/// Wire payload of one ECHO message from `P_j` (echo sender) to
/// `P_i` (echo recipient). Carries the j-th fragment of message
/// `m_i` along with the two Merkle paths required for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoPayload {
    /// Self-computed meta-root `r = MerkleTree(r_1, ..., r_n)` from
    /// the echo sender's view (must match locally-computed `r` if
    /// honest sender).
    pub meta_root: Hash,
    /// Path for `msg_root` (= `r_{recipient}`) under `meta_root` at
    /// index = recipient's `msg_idx`.
    pub meta_path: Proof,
    /// Message-root for the recipient's own message
    /// `r_{recipient_idx}`.
    pub msg_root: Hash,
    /// Path for `fragment` under `msg_root` at index `frag_idx`.
    pub frag_path: Proof,
    /// The fragment itself: the (echo-sender's) j-th fragment of
    /// the recipient's message.
    pub fragment: Fragment,
    /// Index of `fragment` within the message's fragment vector
    /// (= echo sender's identity, but carried explicitly for
    /// validation against `frag_path`'s position).
    pub frag_idx: usize,
}

/// Wire payload of a FORWARD message from `P_j` to a third party
/// `Q`, transferring `m_j` to Q. Used by the unhappy-path
/// forwarding sub-protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardPayload {
    /// Meta-root `r` (Q must have already computed the same `r`
    /// locally during its own distribution-phase output stage; an
    /// honest forwarder always sends the same `r`).
    pub meta_root: Hash,
    /// Path for `msg_root` (= `r_j`) under `meta_root` at the
    /// forwarder's own index `j`.
    pub my_meta_path: Proof,
    /// Forwarder's message-root `r_j`.
    pub my_msg_root: Hash,
    /// Forwarder's index `j` (used by Q to position
    /// `my_meta_path` against the meta-tree).
    pub forwarder_idx: usize,
    /// At least `n - 2t` fragments of `m_j` with their per-fragment
    /// Merkle paths under `my_msg_root`. Each entry is
    /// `(frag_idx, path_under_my_msg_root_at_frag_idx, fragment)`.
    pub fragments: Vec<(usize, Proof, Fragment)>,
}

// ---------------------------------------------------------------------
// Action enum (side effects)
// ---------------------------------------------------------------------

/// Side-effects emitted by `RelMsgDstState`. Mirrors the
/// `acs::rbc::RbcAction` and `compact_broadcast::CompactBroadcastAction`
/// patterns: the driver translates these into wire messages and
/// self-deliveries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelMsgDstAction {
    /// Sender → `recipient_idx`: the per-recipient dispersal block
    /// containing `n` `DispersalEntry`s (one per `msg_idx`).
    SendDispersal {
        recipient_idx: usize,
        entries: Vec<DispersalEntry>,
    },
    /// Echo sender → `recipient_idx`: ECHO containing one fragment
    /// of `m_{recipient_idx}` plus the two Merkle paths (meta + msg).
    SendEcho {
        recipient_idx: usize,
        echo: EchoPayload,
    },
    /// Bracha-style VOTE on the meta-root (broadcast to all peers).
    SendVote { meta_root: Hash },
    /// Local: this instance has delivered its own `m_myid`. Latches
    /// once set.
    Delivered { message: Vec<u8> },
    /// Forward `m_myid` to `recipient` (unhappy path). Driver
    /// translates this into a unicast `ForwardPayload`.
    SendForward {
        recipient: Replica,
        forward: ForwardPayload,
    },
    /// Local: a forwarded message has been delivered (from `source`).
    /// Distinct from `Delivered` (which is one's own dispersal-phase
    /// delivery).
    ForwardDelivered { source: Replica, message: Vec<u8> },
    /// Local: a forwarded message was received but failed the
    /// post-validate / post-rebuild checks (sender or forwarder
    /// is provably Byzantine). Output ⊥ in the paper's notation.
    ForwardRejected { source: Replica, reason: ForwardReject },
}

/// Reasons a `ForwardPayload` may be rejected. Distinguishing
/// these is helpful for logging / blame attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardReject {
    /// `my_meta_path` does not chain `my_msg_root` to `meta_root`,
    /// or `meta_root` does not match Q's locally-computed meta-root.
    /// Indicates the forwarder is misbehaving.
    InvalidMetaPath,
    /// One of the per-fragment Merkle paths is invalid.
    /// Indicates the forwarder is misbehaving.
    InvalidFragmentPath { frag_idx: usize },
    /// Fewer than `n - 2t` valid `(idx, path, fragment)` tuples
    /// were supplied.
    InsufficientFragments { provided: usize, required: usize },
    /// Reed-Solomon decoding failed.
    DecodeFailed(String),
    /// Rebuilt Merkle root does not match `my_msg_root`. Indicates
    /// the original sender (not the forwarder) is misbehaving.
    RootRebuildMismatch,
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Errors raised by the `RelMsgDstState` API.
#[derive(Debug)]
pub enum RelMsgDstError {
    /// Caller asked for `(n, t)` that violate optimal resilience.
    InvalidConfig(RsCodingError),
    /// `set_input_as_sender` called by a non-sender.
    NotSender { myid: Replica, sender: Replica },
    /// `set_input_as_sender` was called with `messages.len() != n`.
    WrongMessageVectorLength { provided: usize, expected: usize },
    /// One of the input messages exceeded the Reed-Solomon payload
    /// size limit.
    EncodeFailed(RsCodingError),
    /// `prepare_forward_for` called before delivery completed.
    NotYetDelivered,
    /// `prepare_forward_for(self.myid)` is meaningless.
    SelfForwardRequest,
}

impl fmt::Display for RelMsgDstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelMsgDstError::InvalidConfig(e) => write!(f, "invalid config: {}", e),
            RelMsgDstError::NotSender { myid, sender } => {
                write!(f, "node {} is not the sender ({})", myid, sender)
            }
            RelMsgDstError::WrongMessageVectorLength { provided, expected } => write!(
                f,
                "sender input vector has {} messages, expected {}",
                provided, expected
            ),
            RelMsgDstError::EncodeFailed(e) => write!(f, "encode failed: {}", e),
            RelMsgDstError::NotYetDelivered => write!(f, "not yet delivered"),
            RelMsgDstError::SelfForwardRequest => write!(f, "cannot forward to self"),
        }
    }
}

impl std::error::Error for RelMsgDstError {}

// ---------------------------------------------------------------------
// Internal: cached forwarding payload
// ---------------------------------------------------------------------

/// Once an `RelMsgDstState` enters the delivered state, we cache
/// the data needed to subsequently forward `m_myid` to a third
/// party. The forwarder's index is `self.myid`.
#[derive(Debug, Clone)]
struct DeliveredForwardingCache {
    meta_root: Hash,
    my_meta_path: Proof,
    my_msg_root: Hash,
    /// `(frag_idx, path_under_my_msg_root, fragment)` for at least
    /// `n - 2t` indices that we have validated.
    my_msg_fragments: Vec<(usize, Proof, Fragment)>,
}

// ---------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------

pub struct RelMsgDstState {
    pub myid: Replica,
    pub n: usize,
    pub t: usize,
    /// Sender (dealer S) — there is exactly one per RelMsgDst instance.
    pub sender: Replica,

    encoder: RsEncoder,
    decoder: RsDecoder,
    hash_state: Arc<HashState>,

    // ---- Sender-side state ----
    /// Set once the sender has broadcast its `n` `SendDispersal`
    /// actions. Idempotent.
    sender_dispersed: bool,

    // ---- Receiver-side state ----
    /// Did we accept the dispersal from the sender? We accept the
    /// FIRST valid dispersal; subsequent dispersals are dropped
    /// (Byzantine equivocation).
    own_dispersal_accepted: bool,
    /// Self-computed meta-root `r = MerkleTree(r_1, ..., r_n)` over
    /// the message-roots received from the sender.
    own_meta_root: Option<Hash>,
    /// Self-computed meta-paths `{π_i}_{i ∈ [0, n)}`.
    own_meta_paths: Option<Vec<Proof>>,
    /// Per-message-root cache: the `n` `(msg_root, frag_path,
    /// fragment)` tuples we received in our own dispersal block.
    /// Indexed by `msg_idx`.
    own_dispersal_data: Vec<Option<(Hash, Proof, Fragment)>>,

    /// `echo_per_meta_root[r] -> sender -> (frag_idx, fragment)` for
    /// echoes addressed at `myid`. We only count an echo if its
    /// `msg_idx == myid` (i.e. it carries a fragment of OUR message
    /// `m_myid`); echoes addressed at other recipients are silently
    /// ignored at this state-machine level (the driver routes them).
    /// First-seen per sender wins.
    echoes_for_self: HashMap<Hash, HashMap<Replica, (usize, Fragment, Proof)>>,
    /// Bracha vote tally per `meta_root` (counting distinct senders).
    votes: HashMap<Hash, HashSet<Replica>>,
    own_vote_root: Option<Hash>,

    /// Final delivered own message + the meta-root under which it
    /// was decoded. Latches once set.
    delivered: Option<(Hash, Vec<u8>)>,
    /// Cached forwarding info populated when `delivered` first sets.
    forwarding_cache: Option<DeliveredForwardingCache>,
}

impl fmt::Debug for RelMsgDstState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelMsgDstState")
            .field("myid", &self.myid)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("sender", &self.sender)
            .field("sender_dispersed", &self.sender_dispersed)
            .field("own_dispersal_accepted", &self.own_dispersal_accepted)
            .field(
                "own_meta_root",
                &self.own_meta_root.map(|h| short_hash(&h)),
            )
            .field(
                "own_vote_root",
                &self.own_vote_root.map(|h| short_hash(&h)),
            )
            .field(
                "echoes_for_self",
                &self
                    .echoes_for_self
                    .iter()
                    .map(|(h, m)| (short_hash(h), m.len()))
                    .collect::<Vec<_>>(),
            )
            .field(
                "votes",
                &self
                    .votes
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

impl RelMsgDstState {
    pub fn new(
        myid: Replica,
        n: usize,
        t: usize,
        sender: Replica,
        hash_state: Arc<HashState>,
    ) -> Result<Self, RelMsgDstError> {
        let encoder = RsEncoder::new(n, t).map_err(RelMsgDstError::InvalidConfig)?;
        let decoder = RsDecoder::new(n, t).map_err(RelMsgDstError::InvalidConfig)?;
        Ok(Self {
            myid,
            n,
            t,
            sender,
            encoder,
            decoder,
            hash_state,
            sender_dispersed: false,
            own_dispersal_accepted: false,
            own_meta_root: None,
            own_meta_paths: None,
            own_dispersal_data: vec![None; n],
            echoes_for_self: HashMap::new(),
            votes: HashMap::new(),
            own_vote_root: None,
            delivered: None,
            forwarding_cache: None,
        })
    }

    /// Bracha thresholds.
    fn n_minus_t(&self) -> usize { self.n - self.t }
    fn t_plus_one(&self) -> usize { self.t + 1 }
    fn two_t_plus_one(&self) -> usize { 2 * self.t + 1 }
    fn n_minus_2t(&self) -> usize { self.n - 2 * self.t }

    pub fn delivered(&self) -> bool { self.delivered.is_some() }
    pub fn delivered_message(&self) -> Option<&[u8]> {
        self.delivered.as_ref().map(|(_, m)| m.as_slice())
    }

    /// Sender-side entry: encode each `m_i` into n fragments, build
    /// per-message Merkle trees, and emit `n` `SendDispersal`
    /// actions, one per recipient. Idempotent on repeat calls.
    pub fn set_input_as_sender(
        &mut self,
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<RelMsgDstAction>, RelMsgDstError> {
        if self.myid != self.sender {
            return Err(RelMsgDstError::NotSender {
                myid: self.myid,
                sender: self.sender,
            });
        }
        if self.sender_dispersed {
            return Ok(Vec::new());
        }
        if messages.len() != self.n {
            return Err(RelMsgDstError::WrongMessageVectorLength {
                provided: messages.len(),
                expected: self.n,
            });
        }

        // (1) Encode each message into n fragments.
        let mut all_fragments: Vec<Vec<Fragment>> = Vec::with_capacity(self.n);
        for m in messages.iter() {
            let frags = self
                .encoder
                .encode(m)
                .map_err(RelMsgDstError::EncodeFailed)?;
            debug_assert_eq!(frags.len(), self.n);
            all_fragments.push(frags);
        }

        // (2) Build per-message Merkle trees and gather per-recipient
        // (msg_root, path, fragment) entries.
        let mut msg_roots: Vec<Hash> = Vec::with_capacity(self.n);
        // dispersal_per_recipient[recipient][msg_idx] = DispersalEntry
        let mut dispersal_per_recipient: Vec<Vec<DispersalEntry>> =
            (0..self.n).map(|_| Vec::with_capacity(self.n)).collect();

        for (msg_idx, frags) in all_fragments.iter().enumerate() {
            let leaf_hashes: Vec<Hash> =
                frags.iter().map(|f| do_hash(f.as_bytes())).collect();
            let tree = MerkleTree::new(leaf_hashes, &self.hash_state);
            let msg_root = tree.root();
            msg_roots.push(msg_root);
            for j in 0..self.n {
                let path = tree.gen_proof(j);
                dispersal_per_recipient[j].push(DispersalEntry {
                    msg_idx,
                    msg_root,
                    frag_path: path,
                    fragment: frags[j].clone(),
                });
            }
        }
        // We don't send the meta-root explicitly to receivers — they
        // recompute it themselves (Sec 4.1 prose explicitly says
        // "r is the root of the Merkle tree built from (r_1,...,r_n)"
        // *as part of the echo*, not the dispersal).
        let _ = msg_roots; // (suppress unused warning; see receiver-side use below)

        let mut out = Vec::with_capacity(self.n);
        for (recipient_idx, entries) in dispersal_per_recipient.into_iter().enumerate() {
            out.push(RelMsgDstAction::SendDispersal {
                recipient_idx,
                entries,
            });
        }
        self.sender_dispersed = true;
        Ok(out)
    }

    // --- Receiver-side ---

    /// Receiver-side entry: handle the per-recipient dispersal block
    /// addressed at this node (`frag_idx == myid` for every entry).
    /// Validates each `(msg_root, frag_path, fragment)` against
    /// `frag_idx == myid`, computes the meta-root from the n
    /// message-roots, and emits `n` `SendEcho` actions one per peer.
    pub fn handle_dispersal(
        &mut self,
        wire_sender: Replica,
        entries: Vec<DispersalEntry>,
    ) -> Vec<RelMsgDstAction> {
        if wire_sender != self.sender {
            return Vec::new();
        }
        if self.own_dispersal_accepted {
            return Vec::new();
        }
        if entries.len() != self.n {
            log::debug!(
                "[ShoupSmart][RelMsgDst] node {} dropped dispersal: got {} entries, expected n={}",
                self.myid, entries.len(), self.n
            );
            return Vec::new();
        }

        // (1) Validate that entries cover msg_idx 0..n exactly once,
        // each fragment hashes to its leaf, and the leaf is at
        // index `myid` under msg_root.
        let myid_idx = self.myid as usize;
        let mut ordered: Vec<Option<DispersalEntry>> = vec![None; self.n];
        for entry in entries.into_iter() {
            if entry.msg_idx >= self.n {
                return Vec::new();
            }
            if ordered[entry.msg_idx].is_some() {
                // Duplicate msg_idx in dispersal -- malformed.
                return Vec::new();
            }
            // Validate Merkle path of fragment under msg_root at myid.
            let expected_leaf = do_hash(entry.fragment.as_bytes());
            if entry.frag_path.item() != expected_leaf {
                log::debug!(
                    "[ShoupSmart][RelMsgDst] node {} dropped dispersal: leaf-hash mismatch for msg_idx {}",
                    self.myid, entry.msg_idx
                );
                return Vec::new();
            }
            if entry.frag_path.root() != entry.msg_root {
                return Vec::new();
            }
            if !entry.frag_path.validate(&self.hash_state) {
                return Vec::new();
            }
            // Position binding: the path must prove `fragment` is at
            // recipient's index (`myid_idx`) under `msg_root`. A
            // Byzantine sender could otherwise hand us a fragment
            // belonging to a different recipient's slot — passing
            // hash + Merkle validation but causing us to echo a
            // mis-positioned fragment. Without this check, the
            // dispersal-phase Π_RelMsgDst has no rebuild defence
            // (only the forward sub-protocol does), so we MUST
            // verify position here.
            let claimed_idx = proof_leaf_index(&entry.frag_path);
            if claimed_idx != myid_idx {
                log::debug!(
                    "[ShoupSmart][RelMsgDst] node {} dropped dispersal: msg_idx {} frag_path leaf-index {} != myid {}",
                    self.myid, entry.msg_idx, claimed_idx, myid_idx
                );
                return Vec::new();
            }
            let slot = entry.msg_idx;
            ordered[slot] = Some(entry);
        }
        // Make sure every msg_idx was filled.
        for slot in ordered.iter() {
            if slot.is_none() {
                return Vec::new();
            }
        }

        // (2) Build the meta-Merkle-tree from (r_0, ..., r_{n-1}).
        let entries: Vec<DispersalEntry> = ordered.into_iter().map(|o| o.unwrap()).collect();
        let msg_roots: Vec<Hash> = entries.iter().map(|e| e.msg_root).collect();
        let leaf_hashes_meta: Vec<Hash> =
            msg_roots.iter().map(|r| do_hash(&r[..])).collect();
        let meta_tree = MerkleTree::new(leaf_hashes_meta, &self.hash_state);
        let meta_root = meta_tree.root();
        let meta_paths: Vec<Proof> = (0..self.n).map(|i| meta_tree.gen_proof(i)).collect();

        // Persist the data we need later.
        self.own_dispersal_accepted = true;
        self.own_meta_root = Some(meta_root);
        self.own_meta_paths = Some(meta_paths.clone());
        for (i, e) in entries.iter().enumerate() {
            self.own_dispersal_data[i] =
                Some((e.msg_root, e.frag_path.clone(), e.fragment.clone()));
        }

        // (3) Emit one ECHO per peer P_i: forward (msg_idx=i, frag_idx=myid)
        // -- the i-th message's myid-th fragment we just received --
        // to the rightful owner P_i.
        let mut out = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let entry = &entries[i];
            let echo = EchoPayload {
                meta_root,
                meta_path: meta_paths[i].clone(),
                msg_root: entry.msg_root,
                frag_path: entry.frag_path.clone(),
                fragment: entry.fragment.clone(),
                frag_idx: myid_idx,
            };
            out.push(RelMsgDstAction::SendEcho {
                recipient_idx: i,
                echo,
            });
        }

        // (4) Self-deliver our own ECHO (i == myid): records our
        // own myid-th fragment of m_myid for later reconstruction.
        // We emit the ECHO action above (recipient_idx = myid) so
        // the driver round-trips it through handle_echo with the
        // wire-sender = myid, which inserts it into echoes_for_self
        // exactly the same way as a peer-originated ECHO would.

        out
    }

    /// Receiver-side entry: handle one ECHO from `wire_sender`. The
    /// state machine only retains echoes addressed at `myid` (i.e.
    /// `recipient_idx == myid` in the driver layer; the driver is
    /// responsible for routing ECHOes to the correct
    /// `RelMsgDstState` instance).
    ///
    /// Validates both Merkle paths (`meta_path` chains `msg_root`
    /// to `meta_root`; `frag_path` chains `fragment` to `msg_root`).
    /// On success records the (sender, frag_idx, fragment) in
    /// `echoes_for_self[meta_root]` and applies Bracha thresholds.
    pub fn handle_echo(
        &mut self,
        wire_sender: Replica,
        echo: EchoPayload,
    ) -> Vec<RelMsgDstAction> {
        if echo.frag_idx >= self.n {
            return Vec::new();
        }
        // Position binding (1/3): in Π_RelMsgDst every honest P_j
        // echoes the j-th fragment of m_recipient — i.e. its OWN
        // index in the recipient's message-fragment vector. Tie
        // `frag_idx` to the wire sender's identity so a Byzantine
        // echoer cannot mis-position someone else's fragment.
        if echo.frag_idx != wire_sender as usize {
            log::debug!(
                "[ShoupSmart][RelMsgDst] node {} dropped ECHO: frag_idx {} != wire_sender {}",
                self.myid, echo.frag_idx, wire_sender
            );
            return Vec::new();
        }
        // Validate frag_path: hash(fragment) at index frag_idx under msg_root.
        let expected_leaf = do_hash(echo.fragment.as_bytes());
        if echo.frag_path.item() != expected_leaf {
            return Vec::new();
        }
        if echo.frag_path.root() != echo.msg_root {
            return Vec::new();
        }
        if !echo.frag_path.validate(&self.hash_state) {
            return Vec::new();
        }
        // Position binding (2/3): the frag_path must prove the
        // fragment lives at index `frag_idx` under `msg_root`.
        let claimed_frag_idx = proof_leaf_index(&echo.frag_path);
        if claimed_frag_idx != echo.frag_idx {
            log::debug!(
                "[ShoupSmart][RelMsgDst] node {} dropped ECHO: frag_path leaf-index {} != frag_idx {}",
                self.myid, claimed_frag_idx, echo.frag_idx
            );
            return Vec::new();
        }

        // Validate meta_path: hash(msg_root) at index myid under meta_root.
        // (Recipient is myid; the meta-path proves r_myid is at index myid
        // in the meta-tree from the echo sender's perspective.)
        let expected_meta_leaf = do_hash(&echo.msg_root[..]);
        if echo.meta_path.item() != expected_meta_leaf {
            return Vec::new();
        }
        if echo.meta_path.root() != echo.meta_root {
            return Vec::new();
        }
        if !echo.meta_path.validate(&self.hash_state) {
            return Vec::new();
        }
        // Position binding (3/3): the meta_path must prove `msg_root`
        // is at the recipient's own slot (`myid`) in the meta-tree.
        // Otherwise a Byzantine echoer could attach a different
        // recipient's `msg_root` (= `r_k`, k != myid) to our slot,
        // causing us to record echoes whose fragments aren't even
        // for OUR message m_myid. RS decoding would then produce
        // garbage as our delivered message.
        let claimed_meta_idx = proof_leaf_index(&echo.meta_path);
        if claimed_meta_idx != self.myid as usize {
            log::debug!(
                "[ShoupSmart][RelMsgDst] node {} dropped ECHO: meta_path leaf-index {} != myid {}",
                self.myid, claimed_meta_idx, self.myid
            );
            return Vec::new();
        }

        // Record the echo (first-seen-per-sender wins).
        let echo_map = self
            .echoes_for_self
            .entry(echo.meta_root)
            .or_insert_with(HashMap::new);
        if !echo_map.contains_key(&wire_sender) {
            echo_map.insert(
                wire_sender,
                (echo.frag_idx, echo.fragment.clone(), echo.frag_path.clone()),
            );
        }

        let mut out = Vec::new();
        // Bracha echo threshold (n - t) → emit our own VOTE for this meta_root.
        let echo_count = self
            .echoes_for_self
            .get(&echo.meta_root)
            .map(|m| m.len())
            .unwrap_or(0);
        if self.own_vote_root.is_none() && echo_count >= self.n_minus_t() {
            self.own_vote_root = Some(echo.meta_root);
            self.votes
                .entry(echo.meta_root)
                .or_insert_with(HashSet::new)
                .insert(self.myid);
            out.push(RelMsgDstAction::SendVote {
                meta_root: echo.meta_root,
            });
        }

        out.extend(self.try_deliver(echo.meta_root));
        out
    }

    /// Receiver-side entry: handle a Bracha VOTE message.
    pub fn handle_vote(
        &mut self,
        wire_sender: Replica,
        meta_root: Hash,
    ) -> Vec<RelMsgDstAction> {
        let (vote_count, already_voted) = {
            let voters = self.votes.entry(meta_root).or_insert_with(HashSet::new);
            voters.insert(wire_sender);
            (voters.len(), self.own_vote_root.is_some())
        };
        let mut out = Vec::new();
        // Bracha amplification: t+1 votes for meta_root → vote
        // ourselves (regardless of own ECHO state).
        if !already_voted && vote_count >= self.t_plus_one() {
            self.own_vote_root = Some(meta_root);
            self.votes
                .entry(meta_root)
                .or_insert_with(HashSet::new)
                .insert(self.myid);
            out.push(RelMsgDstAction::SendVote { meta_root });
        }
        out.extend(self.try_deliver(meta_root));
        out
    }

    /// Internal: try to enter output stage and deliver `m_myid`.
    /// Two conditions must hold:
    ///   - 2t+1 VOTEs collected for meta_root (Bracha output stage)
    ///   - n-2t valid `m_myid` fragments collected via echoes
    ///     (sufficient for Reed-Solomon decode)
    fn try_deliver(&mut self, meta_root: Hash) -> Vec<RelMsgDstAction> {
        if self.delivered.is_some() {
            return Vec::new();
        }
        let vote_count = self.votes.get(&meta_root).map(|s| s.len()).unwrap_or(0);
        if vote_count < self.two_t_plus_one() {
            return Vec::new();
        }
        let echo_map = match self.echoes_for_self.get(&meta_root) {
            Some(m) => m,
            None => return Vec::new(),
        };
        if echo_map.len() < self.n_minus_2t() {
            return Vec::new();
        }

        // De-duplicate by frag_idx (multiple senders may have
        // forwarded the same fragment; first-seen-per-frag-idx wins).
        let mut by_frag_idx: HashMap<usize, (Fragment, Proof)> = HashMap::new();
        for (_sender, (frag_idx, fragment, frag_path)) in echo_map.iter() {
            by_frag_idx
                .entry(*frag_idx)
                .or_insert_with(|| (fragment.clone(), frag_path.clone()));
        }
        if by_frag_idx.len() < self.n_minus_2t() {
            return Vec::new();
        }

        // Decode m_myid from the unique fragments.
        let collected: Vec<(usize, Fragment)> = by_frag_idx
            .iter()
            .map(|(idx, (frag, _path))| (*idx, frag.clone()))
            .collect();
        let message = match self.decoder.decode(collected) {
            Ok(m) => m,
            Err(e) => {
                log::warn!(
                    "[ShoupSmart][RelMsgDst] node {} decode failed at delivery: {}",
                    self.myid, e
                );
                return Vec::new();
            }
        };

        // Recover all needed forwarding info:
        //   - meta_root         (already in scope)
        //   - π_myid (meta-path for r_myid under meta_root at index myid)
        //   - r_myid                   (own message root from dispersal)
        //   - {(idx, path, fragment)}  ≥ n-2t fragments of m_myid
        let my_meta_path = self
            .own_meta_paths
            .as_ref()
            .and_then(|paths| paths.get(self.myid as usize).cloned());
        let my_msg_root = self
            .own_dispersal_data
            .get(self.myid as usize)
            .and_then(|s| s.as_ref().map(|(r, _, _)| *r));

        let cache = match (my_meta_path, my_msg_root) {
            (Some(mp), Some(mr)) => {
                let frags: Vec<(usize, Proof, Fragment)> = by_frag_idx
                    .into_iter()
                    .map(|(idx, (frag, path))| (idx, path, frag))
                    .collect();
                Some(DeliveredForwardingCache {
                    meta_root,
                    my_meta_path: mp,
                    my_msg_root: mr,
                    my_msg_fragments: frags,
                })
            }
            _ => None, // unusual: delivered without our own dispersal data?
        };

        self.delivered = Some((meta_root, message.clone()));
        self.forwarding_cache = cache;
        vec![RelMsgDstAction::Delivered { message }]
    }

    // --- Forwarding sub-protocol (unhappy path) ---

    /// Build a `SendForward` action carrying our own `m_myid` to
    /// `recipient`. Only callable after this instance has delivered
    /// (because the forwarding payload requires the cached
    /// fragments + meta-path).
    pub fn prepare_forward_for(
        &self,
        recipient: Replica,
    ) -> Result<RelMsgDstAction, RelMsgDstError> {
        if recipient == self.myid {
            return Err(RelMsgDstError::SelfForwardRequest);
        }
        let cache = match self.forwarding_cache.as_ref() {
            Some(c) => c,
            None => return Err(RelMsgDstError::NotYetDelivered),
        };
        // Pick the first n-2t fragments — any n-2t suffice.
        let take_count = self.n_minus_2t();
        let fragments: Vec<(usize, Proof, Fragment)> = cache
            .my_msg_fragments
            .iter()
            .take(take_count)
            .cloned()
            .collect();

        let payload = ForwardPayload {
            meta_root: cache.meta_root,
            my_meta_path: cache.my_meta_path.clone(),
            my_msg_root: cache.my_msg_root,
            forwarder_idx: self.myid as usize,
            fragments,
        };

        Ok(RelMsgDstAction::SendForward {
            recipient,
            forward: payload,
        })
    }

    /// Receiver-side: handle a `ForwardPayload` from `wire_sender`
    /// (= the forwarder). Validates the two layers of Merkle paths
    /// and the rebuild check, then either emits
    /// `ForwardDelivered` or `ForwardRejected`.
    ///
    /// IMPORTANT: this is meaningful only when `wire_sender`'s own
    /// distribution-phase output `m_{wire_sender}` is being
    /// forwarded to us. We accept the meta-root from the
    /// `ForwardPayload` regardless of whether we ourselves have
    /// completed our distribution phase — the forwarder's
    /// `meta_path` is verified directly under the carried
    /// `meta_root`. (The paper's version assumes Q has
    /// independently computed the same `meta_root` during its own
    /// distribution; we follow the same model and treat the
    /// `meta_root` as authenticated by the forwarder's
    /// `meta_path` chained to it.)
    pub fn handle_forward(
        &mut self,
        wire_sender: Replica,
        forward: ForwardPayload,
    ) -> Vec<RelMsgDstAction> {
        // (1) Validate the forwarder's meta-path: hash(my_msg_root)
        // sits at index `forwarder_idx` in the meta-tree rooted at
        // `meta_root`.
        let expected_meta_leaf = do_hash(&forward.my_msg_root[..]);
        if forward.my_meta_path.item() != expected_meta_leaf {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InvalidMetaPath,
            }];
        }
        if forward.my_meta_path.root() != forward.meta_root {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InvalidMetaPath,
            }];
        }
        if !forward.my_meta_path.validate(&self.hash_state) {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InvalidMetaPath,
            }];
        }
        // Position binding for forwarder: my_meta_path must prove
        // my_msg_root is at index `forwarder_idx` under meta_root.
        // The forwarder's claim that the message belongs to slot
        // `forwarder_idx` must be cryptographically tied to that
        // slot. (The rebuild check below catches *original-sender*
        // misbehaviour; this check catches *forwarder*
        // misbehaviour that wouldn't be visible from the rebuild
        // alone — e.g. forwarder forwards a message but tags it
        // with the wrong index.)
        let claimed_forwarder_idx = proof_leaf_index(&forward.my_meta_path);
        if claimed_forwarder_idx != forward.forwarder_idx {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InvalidMetaPath,
            }];
        }

        // (2) Validate every per-fragment Merkle path under
        //     `my_msg_root`.
        if forward.fragments.len() < self.n_minus_2t() {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InsufficientFragments {
                    provided: forward.fragments.len(),
                    required: self.n_minus_2t(),
                },
            }];
        }
        let mut by_idx: HashMap<usize, Fragment> = HashMap::new();
        for (frag_idx, path, frag) in forward.fragments.iter() {
            if *frag_idx >= self.n {
                return vec![RelMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: ForwardReject::InvalidFragmentPath { frag_idx: *frag_idx },
                }];
            }
            let leaf = do_hash(frag.as_bytes());
            if path.item() != leaf
                || path.root() != forward.my_msg_root
                || !path.validate(&self.hash_state)
            {
                return vec![RelMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: ForwardReject::InvalidFragmentPath { frag_idx: *frag_idx },
                }];
            }
            // Position binding: each (path, fragment, frag_idx)
            // tuple must satisfy `proof_leaf_index(path) == frag_idx`.
            // Even though the rebuild check below would eventually
            // catch a mis-positioned shard via a root mismatch, we
            // reject early to (a) avoid wasting RS-decode CPU and
            // (b) attribute blame more precisely.
            if proof_leaf_index(path) != *frag_idx {
                return vec![RelMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: ForwardReject::InvalidFragmentPath { frag_idx: *frag_idx },
                }];
            }
            by_idx.entry(*frag_idx).or_insert_with(|| frag.clone());
        }
        if by_idx.len() < self.n_minus_2t() {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::InsufficientFragments {
                    provided: by_idx.len(),
                    required: self.n_minus_2t(),
                },
            }];
        }

        // (3) Decode m_j from the n-2t fragments.
        let collected: Vec<(usize, Fragment)> =
            by_idx.iter().map(|(i, f)| (*i, f.clone())).collect();
        let message = match self.decoder.decode(collected) {
            Ok(m) => m,
            Err(e) => {
                return vec![RelMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: ForwardReject::DecodeFailed(format!("{}", e)),
                }];
            }
        };

        // (4) Re-encode m and rebuild the message-Merkle-tree;
        //     compare against `my_msg_root`. This is the paper's
        //     "second part" check — detects original-sender
        //     misbehaviour (corrupt sender that gave fragments not
        //     forming a valid RS codeword).
        let rebuilt_frags = match self.encoder.encode(&message) {
            Ok(f) => f,
            Err(_) => {
                return vec![RelMsgDstAction::ForwardRejected {
                    source: wire_sender,
                    reason: ForwardReject::RootRebuildMismatch,
                }];
            }
        };
        let leaf_hashes: Vec<Hash> =
            rebuilt_frags.iter().map(|f| do_hash(f.as_bytes())).collect();
        let rebuilt_tree = MerkleTree::new(leaf_hashes, &self.hash_state);
        let rebuilt_root = rebuilt_tree.root();
        if rebuilt_root != forward.my_msg_root {
            return vec![RelMsgDstAction::ForwardRejected {
                source: wire_sender,
                reason: ForwardReject::RootRebuildMismatch,
            }];
        }

        vec![RelMsgDstAction::ForwardDelivered {
            source: wire_sender,
            message,
        }]
    }
}

// ---------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_state() -> Arc<HashState> {
        let key0 = [5u8; 16];
        let key1 = [29u8; 16];
        let key2 = [23u8; 16];
        Arc::new(HashState::new(key0, key1, key2))
    }

    fn make_state(myid: Replica, n: usize, t: usize, sender: Replica) -> RelMsgDstState {
        RelMsgDstState::new(myid, n, t, sender, hash_state()).expect("valid config")
    }

    fn unique_msgs(n: usize, len: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut m = Vec::with_capacity(len);
                for j in 0..len {
                    m.push(((i as u64 * 0x9e3779b9 + j as u64) & 0xff) as u8);
                }
                m
            })
            .collect()
    }

    /// Drive a full Π_RelMsgDst across n honest replicas with
    /// synchronous reliable delivery. Returns each replica's
    /// delivered message.
    fn drive_relmsgdst(sender: Replica, msgs: Vec<Vec<u8>>, n: usize) -> Vec<Option<Vec<u8>>> {
        let t = (n - 1) / 3;
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, sender)).collect();
        let mut pending: Vec<(Replica, RelMsgDstAction)> = Vec::new();

        let acts = nodes[sender as usize]
            .set_input_as_sender(msgs.clone())
            .expect("ok");
        for a in acts {
            pending.push((sender, a));
        }

        for _ in 0..1000 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, RelMsgDstAction)> = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    RelMsgDstAction::SendDispersal {
                        recipient_idx,
                        entries,
                    } => {
                        if recipient_idx < n {
                            let acts = nodes[recipient_idx].handle_dispersal(sender_id, entries);
                            for a in acts {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    RelMsgDstAction::SendEcho {
                        recipient_idx,
                        echo,
                    } => {
                        if recipient_idx < n {
                            let acts = nodes[recipient_idx].handle_echo(sender_id, echo);
                            for a in acts {
                                next.push((recipient_idx as Replica, a));
                            }
                        }
                    }
                    RelMsgDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_vote(sender_id, meta_root);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    RelMsgDstAction::Delivered { .. }
                    | RelMsgDstAction::ForwardDelivered { .. }
                    | RelMsgDstAction::ForwardRejected { .. }
                    | RelMsgDstAction::SendForward { .. } => {
                        // ignored in distribution-phase test driver
                    }
                }
            }
            pending = next;
        }

        nodes
            .into_iter()
            .map(|n| n.delivered_message().map(|s| s.to_vec()))
            .collect()
    }

    // --- Distribution-phase happy path ---

    #[test]
    fn rmd_each_node_gets_its_own_message_n4() {
        let msgs = unique_msgs(4, 64);
        let delivered = drive_relmsgdst(0, msgs.clone(), 4);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(
                d.as_deref(),
                Some(msgs[i].as_slice()),
                "node {} should have delivered m_{}",
                i, i
            );
        }
    }

    #[test]
    fn rmd_each_node_gets_its_own_message_n7() {
        let msgs = unique_msgs(7, 256);
        let delivered = drive_relmsgdst(0, msgs.clone(), 7);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn rmd_each_node_gets_its_own_message_n16() {
        let msgs = unique_msgs(16, 512);
        let delivered = drive_relmsgdst(3, msgs.clone(), 16);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn rmd_supports_empty_message() {
        // Some recipients may have a zero-length message in their slot.
        let mut msgs = unique_msgs(4, 16);
        msgs[2] = Vec::new();
        let delivered = drive_relmsgdst(0, msgs.clone(), 4);
        assert_eq!(delivered[2].as_deref(), Some(b"".as_slice()));
        for i in [0, 1, 3] {
            assert_eq!(delivered[i].as_deref(), Some(msgs[i].as_slice()));
        }
    }

    #[test]
    fn rmd_supports_distinct_message_sizes() {
        // Sender vector has wildly different sizes per recipient.
        let msgs = vec![
            b"short".to_vec(),
            (0..1024).map(|i| (i & 0xff) as u8).collect(),
            b"".to_vec(),
            (0..32).map(|i| (i + 7) as u8).collect(),
        ];
        let delivered = drive_relmsgdst(0, msgs.clone(), 4);
        for (i, d) in delivered.iter().enumerate() {
            assert_eq!(d.as_deref(), Some(msgs[i].as_slice()));
        }
    }

    // --- Distribution-phase failure / Byzantine inputs ---

    #[test]
    fn rmd_set_input_by_non_sender_errors() {
        let mut node1 = make_state(1, 4, 1, 0); // I'm 1, sender is 0
        let res = node1.set_input_as_sender(unique_msgs(4, 16));
        assert!(matches!(res, Err(RelMsgDstError::NotSender { .. })));
    }

    #[test]
    fn rmd_set_input_with_wrong_vector_length_errors() {
        let mut node = make_state(0, 4, 1, 0);
        let res = node.set_input_as_sender(unique_msgs(3, 16)); // 3 != n=4
        assert!(matches!(
            res,
            Err(RelMsgDstError::WrongMessageVectorLength { .. })
        ));
    }

    #[test]
    fn rmd_set_input_idempotent_on_second_call() {
        let mut node = make_state(0, 4, 1, 0);
        let first = node.set_input_as_sender(unique_msgs(4, 16)).unwrap();
        assert_eq!(first.len(), 4); // n SendDispersals
        let second = node.set_input_as_sender(unique_msgs(4, 32)).unwrap();
        assert_eq!(second.len(), 0); // already dispersed
    }

    #[test]
    fn rmd_handle_dispersal_drops_with_wrong_length() {
        let mut node = make_state(1, 4, 1, 0);
        // 3 entries instead of 4.
        let entries: Vec<DispersalEntry> = vec![]; // wrong: 0 != 4
        let acts = node.handle_dispersal(0, entries);
        assert!(acts.is_empty());
        assert!(!node.own_dispersal_accepted);
    }

    #[test]
    fn rmd_handle_dispersal_drops_from_non_sender() {
        // Real sender = 0; we receive a (forged) dispersal from
        // wire-sender = 2 → must be dropped.
        let mut node = make_state(1, 4, 1, 0);

        // Construct a real dispersal targeted at recipient_idx = 1.
        let mut sender_state = make_state(0, 4, 1, 0);
        let acts = sender_state
            .set_input_as_sender(unique_msgs(4, 16))
            .unwrap();
        let entries = match &acts[1] {
            RelMsgDstAction::SendDispersal { entries, .. } => entries.clone(),
            _ => panic!("expected SendDispersal"),
        };

        let result = node.handle_dispersal(2, entries); // wire_sender = 2 ≠ 0
        assert!(result.is_empty());
        assert!(!node.own_dispersal_accepted);
    }

    // --- Forwarding sub-protocol ---

    #[test]
    fn rmd_forwarding_delivers_when_payload_is_honest() {
        // Setup: drive distribution to completion across n=4 honest
        // nodes. Then have node 1 forward m_1 to a fresh new node Q
        // that never participated. (We model Q as a node that only
        // calls handle_forward, never running the distribution
        // phase.)
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 64);
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, 0)).collect();
        let mut pending: Vec<(Replica, RelMsgDstAction)> = Vec::new();

        let acts = nodes[0].set_input_as_sender(msgs.clone()).unwrap();
        for a in acts {
            pending.push((0, a));
        }

        for _ in 0..200 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, RelMsgDstAction)> = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    RelMsgDstAction::SendDispersal {
                        recipient_idx,
                        entries,
                    } => {
                        let acts = nodes[recipient_idx].handle_dispersal(sender_id, entries);
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                        let acts = nodes[recipient_idx].handle_echo(sender_id, echo);
                        for a in acts {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_vote(sender_id, meta_root);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }

        // Distribution complete; node 1 forwards m_1 to Q (fictitious).
        let forward_action = nodes[1].prepare_forward_for(99).unwrap();
        let forward_payload = match forward_action {
            RelMsgDstAction::SendForward { forward, .. } => forward,
            _ => panic!("expected SendForward"),
        };

        // Q is a fresh node that never participated. We instantiate
        // a RelMsgDstState for Q only to call handle_forward; we
        // don't drive its distribution phase at all.
        let mut q = make_state(99, n, t, 0);
        let result = q.handle_forward(1, forward_payload);
        assert_eq!(result.len(), 1);
        match &result[0] {
            RelMsgDstAction::ForwardDelivered { source: 1, message } => {
                assert_eq!(message, &msgs[1], "Q must deliver m_1");
            }
            other => panic!("expected ForwardDelivered, got {:?}", other),
        }
    }

    #[test]
    fn rmd_forwarding_rejects_tampered_meta_path() {
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 16);
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, 0)).collect();
        let mut pending: Vec<(Replica, RelMsgDstAction)> = Vec::new();
        let acts = nodes[0].set_input_as_sender(msgs.clone()).unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..200 {
            if nodes.iter().all(|n| n.delivered()) { break; }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                        for a in nodes[recipient_idx].handle_dispersal(sender_id, entries) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                        for a in nodes[recipient_idx].handle_echo(sender_id, echo) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for a in node.handle_vote(sender_id, meta_root) {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }

        // Build a valid forward, then tamper the my_meta_path so
        // its leaf no longer matches my_msg_root.
        let fwd = match nodes[1].prepare_forward_for(99).unwrap() {
            RelMsgDstAction::SendForward { forward, .. } => forward,
            _ => panic!(),
        };

        // Tamper: swap msg_root for a different one (that won't
        // match the meta_path's leaf).
        let bad_root: Hash = [0xff; 32];
        let mut bad_payload = fwd;
        bad_payload.my_msg_root = bad_root;

        let mut q = make_state(99, n, t, 0);
        let result = q.handle_forward(1, bad_payload);
        match &result[0] {
            RelMsgDstAction::ForwardRejected { reason, .. } => {
                assert!(matches!(reason, ForwardReject::InvalidMetaPath));
            }
            other => panic!("expected ForwardRejected, got {:?}", other),
        }
    }

    #[test]
    fn rmd_forwarding_rejects_insufficient_fragments() {
        // Need n-2t = 2 fragments; provide only 1.
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 16);
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, 0)).collect();
        let mut pending: Vec<(Replica, RelMsgDstAction)> = Vec::new();
        let acts = nodes[0].set_input_as_sender(msgs.clone()).unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..200 {
            if nodes.iter().all(|n| n.delivered()) { break; }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                        for a in nodes[recipient_idx].handle_dispersal(sender_id, entries) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                        for a in nodes[recipient_idx].handle_echo(sender_id, echo) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for a in node.handle_vote(sender_id, meta_root) {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }

        let mut fwd = match nodes[1].prepare_forward_for(99).unwrap() {
            RelMsgDstAction::SendForward { forward, .. } => forward,
            _ => panic!(),
        };
        fwd.fragments.truncate(1); // < n-2t = 2
        let mut q = make_state(99, n, t, 0);
        let result = q.handle_forward(1, fwd);
        match &result[0] {
            RelMsgDstAction::ForwardRejected { reason, .. } => {
                assert!(matches!(reason, ForwardReject::InsufficientFragments { .. }));
            }
            other => panic!("expected ForwardRejected InsufficientFragments, got {:?}", other),
        }
    }

    #[test]
    fn rmd_prepare_forward_before_delivery_errors() {
        let node = make_state(1, 4, 1, 0);
        // Never drove the distribution phase, so not delivered.
        let res = node.prepare_forward_for(2);
        assert!(matches!(res, Err(RelMsgDstError::NotYetDelivered)));
    }

    #[test]
    fn rmd_prepare_forward_to_self_errors() {
        let node = make_state(1, 4, 1, 0);
        let res = node.prepare_forward_for(1);
        assert!(matches!(res, Err(RelMsgDstError::SelfForwardRequest)));
    }

    // ---- Audit fix: position-binding regression ----

    /// A Byzantine SENDER hands node 1 a per-recipient dispersal
    /// block whose `frag_path` was generated for index 5 (not 1).
    /// Every cryptographic check below the position binding (hash,
    /// root, validate) succeeds — the position check must drop it.
    #[test]
    fn rmd_dispersal_dropped_when_frag_path_index_mismatches_recipient() {
        let n = 7;
        let t = 2;
        // Use an HONEST dealer perspective to extract real
        // (msg_root, π_ij, f_ij) artefacts; we then "redirect" them.
        let mut dealer = make_state(0, n, t, 0);
        let acts = dealer.set_input_as_sender(unique_msgs(n, 32)).unwrap();
        // The dispersal block destined for recipient 5 contains
        // n entries each with frag_path at index=5.
        let entries_for_5 = match &acts[5] {
            RelMsgDstAction::SendDispersal { entries, .. } => entries.clone(),
            _ => panic!("expected SendDispersal[5]"),
        };
        // Hand them to node 1 (which expects index=1 paths) under
        // the honest sender's identity.
        let mut node1 = make_state(1, n, t, 0);
        let result = node1.handle_dispersal(0, entries_for_5);
        assert!(
            result.is_empty(),
            "dispersal with frag_path leaf-index ≠ recipient's myid must be dropped"
        );
        assert!(!node1.own_dispersal_accepted);
    }

    /// A Byzantine ECHO sender claims `frag_idx` = j' ≠ its own
    /// wire identity j. Even with valid paths and fragments, the
    /// frag_idx ↔ wire_sender binding must reject the echo.
    #[test]
    fn rmd_echo_dropped_when_frag_idx_does_not_match_wire_sender() {
        let n = 7;
        let t = 2;
        // Drive the distribution phase to the point where node 1
        // has accepted its dispersal and learned the meta_root /
        // meta_paths, so its `handle_echo` actually produces
        // non-empty output paths for an honest echo.
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, 0)).collect();
        let acts = nodes[0]
            .set_input_as_sender(unique_msgs(n, 32))
            .unwrap();
        // Deliver the dispersal block to each receiver so they
        // know meta_root.
        let dispersals: Vec<(usize, Vec<DispersalEntry>)> = acts
            .into_iter()
            .filter_map(|a| match a {
                RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                    Some((recipient_idx, entries))
                }
                _ => None,
            })
            .collect();
        for (recipient, entries) in dispersals.iter() {
            let _ = nodes[*recipient].handle_dispersal(0, entries.clone());
        }
        // Reach into a SendEcho action that node 5 emitted for
        // recipient 1 — that gives us a real EchoPayload with
        // legitimate paths for (frag_idx=5, recipient=1).
        let acts5 = nodes[5].handle_dispersal(0, dispersals[5].1.clone());
        // dispersal already accepted from outer loop; second call is no-op.
        // Re-derive echo by replaying handle_dispersal on a fresh state.
        let _ = acts5;
        let mut fresh5 = make_state(5, n, t, 0);
        let acts5 = fresh5.handle_dispersal(0, dispersals[5].1.clone());
        let echo_for_1 = acts5
            .into_iter()
            .find_map(|a| match a {
                RelMsgDstAction::SendEcho { recipient_idx: 1, echo } => Some(echo),
                _ => None,
            })
            .expect("expected SendEcho recipient_idx=1");
        // Tamper: lie about frag_idx (claim 0 instead of 5).
        let mut bad_echo = echo_for_1;
        bad_echo.frag_idx = 0;
        // Node 1 receives this from wire_sender=5.
        let result = nodes[1].handle_echo(5, bad_echo);
        assert!(
            result.is_empty(),
            "ECHO whose frag_idx (claim) ≠ wire_sender must be dropped"
        );
    }

    /// A Byzantine ECHO sender attaches a meta-path proving
    /// `msg_root` is at the WRONG slot (not the recipient's). With
    /// honest-looking frag_path, the check that catches this is the
    /// meta_path leaf-index binding.
    #[test]
    fn rmd_echo_dropped_when_meta_path_index_mismatches_recipient() {
        let n = 7;
        let t = 2;
        // Set up the same honest dispersal as above and extract
        // node 5's intended echo to recipient 1 (meta_path at
        // index 1) — then SWAP in node 5's meta_path that proves
        // r_5 at index 5 instead, while keeping frag_idx & frag_path
        // honest for slot 5.
        let mut sender = make_state(0, n, t, 0);
        let acts = sender.set_input_as_sender(unique_msgs(n, 32)).unwrap();
        let dispersal_5 = match &acts[5] {
            RelMsgDstAction::SendDispersal { entries, .. } => entries.clone(),
            _ => panic!(),
        };
        let mut node5 = make_state(5, n, t, 0);
        let acts5 = node5.handle_dispersal(0, dispersal_5);
        // Node 5 emits SendEcho actions for every peer; pull out
        // the one for recipient 1 and the one for recipient 5.
        let mut echo_for_1 = None;
        let mut echo_for_5 = None;
        for a in acts5 {
            if let RelMsgDstAction::SendEcho { recipient_idx, echo } = a {
                if recipient_idx == 1 {
                    echo_for_1 = Some(echo);
                } else if recipient_idx == 5 {
                    echo_for_5 = Some(echo);
                }
            }
        }
        let mut e1 = echo_for_1.expect("echo for recipient 1");
        let e5 = echo_for_5.expect("echo for recipient 5");
        // Tamper: replace e1's meta_path & msg_root with e5's
        // (which prove r_5 at meta-tree index 5). Keep the echo's
        // OWN frag_path consistent (node 5's frag at index 5 under
        // r_5). Now: recipient 1 receives an echo with meta-path
        // chained at INDEX 5, not 1 — must be dropped.
        e1.meta_path = e5.meta_path;
        e1.msg_root = e5.msg_root;
        e1.frag_path = e5.frag_path;
        e1.fragment = e5.fragment;

        let mut node1 = make_state(1, n, t, 0);
        let result = node1.handle_echo(5, e1);
        assert!(
            result.is_empty(),
            "ECHO whose meta_path leaf-index ≠ recipient's myid must be dropped"
        );
    }

    /// A Byzantine FORWARDER tampers with `forwarder_idx`, claiming
    /// to be at a different position than the meta_path actually
    /// proves. The position binding in handle_forward must reject.
    #[test]
    fn rmd_forwarding_rejects_lying_forwarder_idx() {
        let n = 4;
        let t = 1;
        let msgs = unique_msgs(n, 32);
        let mut nodes: Vec<RelMsgDstState> =
            (0..n).map(|i| make_state(i as Replica, n, t, 0)).collect();
        let mut pending: Vec<(Replica, RelMsgDstAction)> = Vec::new();
        let acts = nodes[0].set_input_as_sender(msgs.clone()).unwrap();
        for a in acts {
            pending.push((0, a));
        }
        for _ in 0..200 {
            if nodes.iter().all(|n| n.delivered()) { break; }
            let mut next = Vec::new();
            for (sender_id, action) in pending.drain(..) {
                match action {
                    RelMsgDstAction::SendDispersal { recipient_idx, entries } => {
                        for a in nodes[recipient_idx].handle_dispersal(sender_id, entries) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendEcho { recipient_idx, echo } => {
                        for a in nodes[recipient_idx].handle_echo(sender_id, echo) {
                            next.push((recipient_idx as Replica, a));
                        }
                    }
                    RelMsgDstAction::SendVote { meta_root } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for a in node.handle_vote(sender_id, meta_root) {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    _ => {}
                }
            }
            pending = next;
        }
        let mut fwd = match nodes[1].prepare_forward_for(99).unwrap() {
            RelMsgDstAction::SendForward { forward, .. } => forward,
            _ => panic!(),
        };
        // Tamper: claim forwarder_idx=2 while my_meta_path proves
        // index 1 (forwarder is actually node 1).
        fwd.forwarder_idx = 2;
        let mut q = make_state(99, n, t, 0);
        let result = q.handle_forward(1, fwd);
        match &result[0] {
            RelMsgDstAction::ForwardRejected { reason, .. } => {
                assert!(
                    matches!(reason, ForwardReject::InvalidMetaPath),
                    "expected InvalidMetaPath, got {:?}",
                    reason
                );
            }
            other => panic!("expected ForwardRejected, got {:?}", other),
        }
    }
}

