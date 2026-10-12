//! Hash-bound Bracha RBC with retrieval from honest payload holders.
//! SEND is authenticated to the proposer; ECHO/READY votes bind a payload hash.
//! A READY quorum can fetch its selected payload even when the proposer withheld
//! SEND, or sent this recipient a conflicting first SEND. Responses never replace
//! the quorum requirement. Requesters are remembered across message reordering.
use std::collections::{HashMap, HashSet};
use crypto::hash::{do_hash, Hash};
use types::Replica;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbcAction {
    SendSend { payload: Vec<u8> },
    SendEcho { payload_hash: Hash },
    SendReady { payload_hash: Hash },
    RequestPayload { payload_hash: Hash },
    SendPayload { recipient: Replica, payload_hash: Hash, payload: Vec<u8> },
    Delivered { payload: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct RbcInstanceState {
    pub myid: Replica,
    pub proposer: Replica,
    pub n: usize,
    pub f: usize,
    payload: Option<Vec<u8>>,
    payload_hash: Option<Hash>,
    echo_senders_per_hash: HashMap<Hash, HashSet<Replica>>,
    ready_senders_per_hash: HashMap<Hash, HashSet<Replica>>,
    echo_by_sender: HashMap<Replica, Hash>,
    ready_by_sender: HashMap<Replica, Hash>,
    requested: HashSet<Hash>,
    requesters: HashMap<Hash, HashSet<Replica>>,
    own_echo_sent: bool,
    own_ready_sent: bool,
    delivered: bool,
}

impl RbcInstanceState {
    pub fn new(myid: Replica, proposer: Replica, n: usize, f: usize) -> Self {
        Self { myid, proposer, n, f, payload: None, payload_hash: None,
            echo_senders_per_hash: HashMap::new(), ready_senders_per_hash: HashMap::new(),
            echo_by_sender: HashMap::new(), ready_by_sender: HashMap::new(),
            requested: HashSet::new(), requesters: HashMap::new(),
            own_echo_sent: false, own_ready_sent: false, delivered: false }
    }
    pub fn delivered(&self) -> bool { self.delivered }
    pub fn delivered_payload(&self) -> Option<&[u8]> {
        if self.delivered { self.payload.as_deref() } else { None }
    }
    pub fn proposer_send(&mut self, payload: Vec<u8>) -> Vec<RbcAction> {
        if self.myid != self.proposer || self.payload.is_some() { return Vec::new(); }
        let mut out = vec![RbcAction::SendSend { payload: payload.clone() }];
        out.extend(self.handle_send(self.proposer, payload));
        out
    }
    fn answer_waiters(&mut self, hash: Hash) -> Vec<RbcAction> {
        if self.payload_hash != Some(hash) { return Vec::new(); }
        let payload = match self.payload.as_ref() { Some(value) => value, None => return Vec::new() };
        self.requesters.remove(&hash).unwrap_or_default().into_iter()
            .map(|recipient| RbcAction::SendPayload { recipient, payload_hash: hash, payload: payload.clone() }).collect()
    }
    pub fn handle_send(&mut self, sender: Replica, payload: Vec<u8>) -> Vec<RbcAction> {
        if sender != self.proposer || sender >= self.n || self.own_echo_sent { return Vec::new(); }
        let hash = do_hash(&payload);
        self.own_echo_sent = true;
        // A fetched quorum payload takes precedence over a late conflicting SEND.
        if !self.delivered && self.requested.is_empty() {
            self.payload = Some(payload); self.payload_hash = Some(hash);
        } else if self.payload.is_none() {
            self.payload = Some(payload); self.payload_hash = Some(hash);
        }
        let mut out = vec![RbcAction::SendEcho { payload_hash: hash }];
        out.extend(self.answer_waiters(hash));
        out.extend(self.check_thresholds(hash));
        out
    }
    pub fn handle_echo(&mut self, sender: Replica, hash: Hash) -> Vec<RbcAction> {
        if sender >= self.n || self.echo_by_sender.contains_key(&sender) { return Vec::new(); }
        self.echo_by_sender.insert(sender, hash);
        self.echo_senders_per_hash.entry(hash).or_default().insert(sender);
        self.check_thresholds(hash)
    }
    pub fn handle_ready(&mut self, sender: Replica, hash: Hash) -> Vec<RbcAction> {
        if sender >= self.n || self.ready_by_sender.contains_key(&sender) { return Vec::new(); }
        self.ready_by_sender.insert(sender, hash);
        self.ready_senders_per_hash.entry(hash).or_default().insert(sender);
        self.check_thresholds(hash)
    }
    pub fn handle_request(&mut self, sender: Replica, hash: Hash) -> Vec<RbcAction> {
        if sender >= self.n { return Vec::new(); }
        if self.payload_hash == Some(hash) {
            if let Some(payload) = self.payload.as_ref() {
                return vec![RbcAction::SendPayload { recipient: sender, payload_hash: hash, payload: payload.clone() }];
            }
        }
        // One pending request per peer bounds unauthenticated hash choices by n.
        if self.requesters.values().any(|peers| peers.contains(&sender)) { return Vec::new(); }
        self.requesters.entry(hash).or_default().insert(sender);
        Vec::new()
    }
    pub fn handle_payload(&mut self, sender: Replica, hash: Hash, payload: Vec<u8>) -> Vec<RbcAction> {
        if sender >= self.n || self.delivered || !self.requested.contains(&hash) || do_hash(&payload) != hash {
            return Vec::new();
        }
        self.payload = Some(payload); self.payload_hash = Some(hash);
        let mut out = self.answer_waiters(hash);
        out.extend(self.check_thresholds(hash));
        out
    }
    fn check_thresholds(&mut self, hash: Hash) -> Vec<RbcAction> {
        let mut out = Vec::new();
        let echoes = self.echo_senders_per_hash.get(&hash).map(|peers| peers.len()).unwrap_or(0);
        let ready = self.ready_senders_per_hash.get(&hash).map(|peers| peers.len()).unwrap_or(0);
        if !self.own_ready_sent && (echoes >= self.n-self.f || ready >= self.f+1) {
            self.own_ready_sent = true;
            out.push(RbcAction::SendReady { payload_hash: hash });
        }
        if !self.delivered && ready >= self.f+1 && self.payload_hash != Some(hash)
            && self.requested.insert(hash) {
            out.push(RbcAction::RequestPayload { payload_hash: hash });
        }
        if !self.delivered && ready >= 2*self.f+1 && self.payload_hash == Some(hash) {
            if let Some(payload) = self.payload.clone() {
                self.delivered = true;
                out.push(RbcAction::Delivered { payload });
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
                    RbcAction::RequestPayload { payload_hash } => {
                        for (i, node) in nodes.iter_mut().enumerate() {
                            for action in node.handle_request(sender, payload_hash) { next.push((i, action)); }
                        }
                    }
                    RbcAction::SendPayload { recipient, payload_hash, payload } => {
                        for action in nodes[recipient].handle_payload(sender, payload_hash, payload) {
                            next.push((recipient, action));
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
