//! Bracha-style Reliable Broadcast (RBC) state machine for the
//! ACS Phase-1 proposals.
//!
//! Standard textbook Bracha RBC (signature-free, threshold 3f+1):
//!
//! ```text
//! Sender (proposer) p_j:
//!     broadcast SEND(payload_bytes)
//!
//! On receiving SEND from p_j (only the first one is authoritative):
//!     compute h := H(payload_bytes)
//!     broadcast ECHO(h)
//!
//! On receiving ECHO(h) from at least n - f distinct nodes (or
//! READY(h) from at least f+1 distinct nodes):
//!     if not yet sent READY(h'):
//!         broadcast READY(h)
//!
//! On receiving READY(h) from at least 2f+1 distinct nodes:
//!     deliver(payload_bytes)  -- only if we have the payload bytes
//!                                that hash to h.
//! ```
//!
//! Properties:
//!
//!   - **Validity**: if proposer is honest and broadcasts payload p,
//!     every honest node delivers p.
//!   - **Agreement**: every honest node that delivers a payload
//!     delivers the *same* payload bytes — equivocation by a
//!     Byzantine sender does not let two honest nodes deliver
//!     different bytes for the same RBC instance, because both
//!     would have to commit to the same payload-hash via the
//!     ECHO/READY threshold.
//!   - **Integrity**: each RBC instance delivers at most once.
//!
//! PQ-safety: `do_hash` is the only crypto primitive used, exactly
//! as required by the PPT brief.
//!
//! This module is a **pure state machine** like `aba.rs`: no I/O,
//! no networking, no `Context`. The driver owns one
//! `RbcInstanceState` per (round, proposer) pair.

use std::collections::HashSet;

use crypto::hash::{do_hash, Hash};
use types::Replica;

/// Side-effects emitted by the RBC state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbcAction {
    /// Broadcast our own SEND. Only the proposer ever emits this;
    /// receivers re-broadcast ECHO instead.
    SendSend { payload: Vec<u8> },
    /// Broadcast ECHO(h).
    SendEcho { payload_hash: Hash },
    /// Broadcast READY(h).
    SendReady { payload_hash: Hash },
    /// Local: this RBC instance has delivered its payload bytes.
    Delivered { payload: Vec<u8> },
}

/// Per (round, proposer) RBC instance state. The driver routes
/// inbound `ACSRbcSend / ACSRbcEcho / ACSRbcReady` messages to the
/// instance whose `proposer` matches the wire field.
#[derive(Debug, Clone)]
pub struct RbcInstanceState {
    /// Local node id (for logging only — RBC is sender-agnostic).
    pub myid: Replica,
    /// The proposer this RBC instance speaks for.
    pub proposer: Replica,
    pub n: usize,
    pub f: usize,

    /// First SEND content received from `proposer`. After it is set,
    /// any subsequent SEND from `proposer` is treated as Byzantine
    /// equivocation and ignored (Bracha RBC standard rule).
    payload: Option<Vec<u8>>,
    /// Hash of `payload`, cached so the ECHO/READY paths don't
    /// re-hash on every threshold check.
    payload_hash: Option<Hash>,

    /// echo_senders[h] = set of replicas that ECHO'd hash h.
    /// Multiple distinct hashes are tracked because a Byzantine
    /// proposer + a few Byzantine echoers could try to split the
    /// network on hash; the threshold rule still works because
    /// only one h can ever cross n-f honest echoes (n=3f+1).
    echo_senders_per_hash:
        std::collections::HashMap<Hash, HashSet<Replica>>,
    /// ready_senders[h] = set of replicas that READY'd hash h.
    ready_senders_per_hash:
        std::collections::HashMap<Hash, HashSet<Replica>>,

    /// Have we ourselves emitted ECHO yet? (RBC says exactly once
    /// per instance.)
    own_echo_sent: bool,
    /// And READY?
    own_ready_sent: bool,
    /// And finally delivered?
    delivered: bool,
}

impl RbcInstanceState {
    pub fn new(myid: Replica, proposer: Replica, n: usize, f: usize) -> Self {
        Self {
            myid,
            proposer,
            n,
            f,
            payload: None,
            payload_hash: None,
            echo_senders_per_hash: std::collections::HashMap::new(),
            ready_senders_per_hash: std::collections::HashMap::new(),
            own_echo_sent: false,
            own_ready_sent: false,
            delivered: false,
        }
    }

    pub fn delivered(&self) -> bool {
        self.delivered
    }

    pub fn delivered_payload(&self) -> Option<&[u8]> {
        if self.delivered { self.payload.as_deref() } else { None }
    }

    /// Local proposer entry: produce the SEND broadcast for our own
    /// payload. Idempotent.
    pub fn proposer_send(&mut self, payload: Vec<u8>) -> Vec<RbcAction> {
        if self.payload.is_some() {
            return Vec::new();
        }
        let hash = do_hash(payload.as_slice());
        self.payload_hash = Some(hash);
        let mut out = vec![RbcAction::SendSend { payload: payload.clone() }];
        // Self-echo: as soon as we accept our own SEND we proceed
        // to ECHO. The driver also needs to call self-deliver
        // (handle_send with sender == self) to complete the round
        // trip, but the action below saves a round-trip.
        if !self.own_echo_sent {
            self.own_echo_sent = true;
            out.push(RbcAction::SendEcho { payload_hash: hash });
        }
        // Cache locally so payload+hash are present.
        self.payload = Some(payload);
        out
    }

    /// Inbound `ACSRbcSend(_, proposer, payload)`. Returns the ECHO
    /// follow-up if this is the first SEND we accept.
    pub fn handle_send(&mut self, sender: Replica, payload: Vec<u8>) -> Vec<RbcAction> {
        if sender != self.proposer {
            // Not the rightful proposer — drop.
            return Vec::new();
        }
        if self.payload.is_some() {
            return Vec::new();
        }
        let h = do_hash(payload.as_slice());
        self.payload_hash = Some(h);
        self.payload = Some(payload);

        let mut out = Vec::new();
        if !self.own_echo_sent {
            self.own_echo_sent = true;
            out.push(RbcAction::SendEcho { payload_hash: h });
        }
        // Run threshold checks in case ECHO/READY for this hash
        // were already cached from out-of-order delivery.
        out.extend(self.check_thresholds(h));
        out
    }

    /// Inbound `ACSRbcEcho(_, proposer, payload_hash)` from `sender`.
    pub fn handle_echo(&mut self, sender: Replica, payload_hash: Hash) -> Vec<RbcAction> {
        let entry = self
            .echo_senders_per_hash
            .entry(payload_hash)
            .or_insert_with(HashSet::new);
        entry.insert(sender);
        self.check_thresholds(payload_hash)
    }

    /// Inbound `ACSRbcReady(_, proposer, payload_hash)` from `sender`.
    pub fn handle_ready(&mut self, sender: Replica, payload_hash: Hash) -> Vec<RbcAction> {
        let entry = self
            .ready_senders_per_hash
            .entry(payload_hash)
            .or_insert_with(HashSet::new);
        entry.insert(sender);
        self.check_thresholds(payload_hash)
    }

    /// Threshold checks for a particular `payload_hash`.
    fn check_thresholds(&mut self, h: Hash) -> Vec<RbcAction> {
        let mut out = Vec::new();
        let n_minus_f = self.n - self.f;
        let f_plus_one = self.f + 1;
        let two_f_plus_one = 2 * self.f + 1;

        let echo_count = self
            .echo_senders_per_hash
            .get(&h)
            .map(|s| s.len())
            .unwrap_or(0);
        let ready_count = self
            .ready_senders_per_hash
            .get(&h)
            .map(|s| s.len())
            .unwrap_or(0);

        if !self.own_ready_sent && (echo_count >= n_minus_f || ready_count >= f_plus_one) {
            self.own_ready_sent = true;
            out.push(RbcAction::SendReady { payload_hash: h });
        }

        if !self.delivered && ready_count >= two_f_plus_one {
            // Need the payload bytes to actually deliver. If we don't
            // have them yet (ECHO/READY observed before SEND), defer
            // — the SEND, when it eventually arrives, will retry
            // delivery via `handle_send`.
            if let Some(payload) = self.payload.clone() {
                if let Some(local_h) = self.payload_hash {
                    if local_h == h {
                        self.delivered = true;
                        out.push(RbcAction::Delivered { payload });
                    }
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n_f(n: usize) -> (usize, usize) {
        (n, (n - 1) / 3)
    }

    /// Drive one RBC instance across `n` honest replicas with
    /// synchronous reliable delivery.
    fn drive_rbc(
        proposer: Replica,
        payload: Vec<u8>,
        n: usize,
    ) -> Vec<Option<Vec<u8>>> {
        let (n_, f_) = n_f(n);
        let mut nodes: Vec<RbcInstanceState> = (0..n_)
            .map(|i| RbcInstanceState::new(i as Replica, proposer, n_, f_))
            .collect();

        let mut pending: Vec<(Replica, RbcAction)> = Vec::new();
        // Proposer kicks off SEND.
        let acts = nodes[proposer as usize].proposer_send(payload.clone());
        for a in acts {
            pending.push((proposer, a));
        }

        for _ in 0..200 {
            if nodes.iter().all(|n| n.delivered()) {
                break;
            }
            let mut next: Vec<(Replica, RbcAction)> = Vec::new();
            for (sender, action) in pending.drain(..) {
                match action {
                    RbcAction::SendSend { payload } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_send(sender, payload.clone());
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    RbcAction::SendEcho { payload_hash } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_echo(sender, payload_hash);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    RbcAction::SendReady { payload_hash } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            let acts = node.handle_ready(sender, payload_hash);
                            for a in acts {
                                next.push((i as Replica, a));
                            }
                        }
                    }
                    RbcAction::Delivered { .. } => {}
                }
            }
            pending = next;
        }

        nodes
            .into_iter()
            .map(|n| n.delivered_payload().map(|s| s.to_vec()))
            .collect()
    }

    #[test]
    fn rbc_delivers_proposers_payload_to_every_honest_node() {
        let payload = b"hello-rbc-world".to_vec();
        let delivered = drive_rbc(0, payload.clone(), 4);
        for d in &delivered {
            assert_eq!(d.as_deref(), Some(payload.as_slice()), "every node must deliver");
        }
    }

    #[test]
    fn rbc_agreement_under_byte_equality() {
        // Property: every node that delivers, delivers the SAME
        // bytes (i.e. byte-equality across all honest deliveries).
        let payload = b"some-larger-payload-that-includes-binary-bytes\x00\x01\x02".to_vec();
        let delivered = drive_rbc(2, payload.clone(), 4);
        let first_delivered = delivered.iter().find_map(|x| x.clone()).expect("at least one delivery");
        for d in &delivered {
            assert_eq!(d.as_ref(), Some(&first_delivered));
        }
    }

    #[test]
    fn rbc_n16_works_when_n_minus_f_echo_threshold_reached() {
        // n=16, f=5. 11 ECHOes for the same hash (one of which is
        // the proposer's own self-echo) trigger the READY round
        // and eventual delivery at every node.
        let payload = b"n16-rbc-payload".to_vec();
        let delivered = drive_rbc(3, payload.clone(), 16);
        for d in &delivered {
            assert_eq!(d.as_deref(), Some(payload.as_slice()));
        }
    }
}
